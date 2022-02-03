{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Backend.Util(
  withWebAuthnBackend
) where

import Control.Concurrent.MVar
import Control.Monad
import Control.Monad.IO.Class
import Crypto.Hash (hash)
import qualified Crypto.WebAuthn as WA
import qualified Data.Aeson as A
import Data.Bifunctor
import qualified Data.Map.Strict as M
import Data.Pool
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Validation
import Snap.Internal.Core
import Snap.Extras.JSON
import Time.System

import Database.Beam.Postgres
import Gargoyle.PostgreSQL.Connect
import Obelisk.Route.Frontend

import Common.Api
import Common.RouteUtil

import Backend.DB.DB

finishWithError :: (MonadSnap m) => T.Text -> m a
finishWithError err = do
  writeLBS $ A.encode $ (Left (ServerError err) :: Either ServerError String)
  getResponse >>= finishWith

sendData :: (MonadSnap m, A.ToJSON a) => a -> m ()
sendData = writeLBS . A.encode . toRight
  where
    toRight :: a -> Either String a
    toRight = Right

defaultRegistrationOptions :: T.Text -> WA.Challenge -> IO (WA.CredentialOptions 'WA.Registration)
defaultRegistrationOptions userName challenge = do
  userHandle <- liftIO $ WA.generateUserHandle
  let
    userEntity =
      WA.CredentialUserEntity
        { WA.cueId = userHandle,
          WA.cueDisplayName = WA.UserAccountDisplayName userName,
          WA.cueName = WA.UserAccountName userName
        }
  pure $ WA.CredentialOptionsRegistration
    { WA.corRp = WA.CredentialRpEntity {WA.creId = Nothing, WA.creName = "ACME"},
      WA.corUser = userEntity,
      WA.corChallenge = challenge,
      WA.corPubKeyCredParams =
        [ WA.CredentialParameters
            { WA.cpTyp = WA.CredentialTypePublicKey,
              WA.cpAlg = WA.CoseAlgorithmES256
            },
          WA.CredentialParameters
            { WA.cpTyp = WA.CredentialTypePublicKey,
              WA.cpAlg = WA.CoseAlgorithmRS256
            }
        ],
      WA.corTimeout = Nothing,
      WA.corExcludeCredentials = [],
      WA.corAuthenticatorSelection =
        Just
          WA.AuthenticatorSelectionCriteria
            { WA.ascAuthenticatorAttachment = Nothing,
              WA.ascResidentKey = WA.ResidentKeyRequirementDiscouraged,
              WA.ascUserVerification = WA.UserVerificationRequirementPreferred
            },
      WA.corAttestation = WA.AttestationConveyancePreferenceDirect,
      WA.corExtensions = Nothing
    }

defaultAuthenticationOptions :: WA.Challenge -> [WA.CredentialEntry] -> WA.CredentialOptions 'WA.Authentication
defaultAuthenticationOptions challenge credentials = WA.CredentialOptionsAuthentication
  { WA.coaRpId = Nothing
  , WA.coaTimeout = Nothing
  , WA.coaChallenge = challenge
  , WA.coaAllowCredentials = map mkCredentialDescriptor credentials
  , WA.coaUserVerification = WA.UserVerificationRequirementPreferred
  , WA.coaExtensions = Nothing
  }

writeOptionsToMVar :: WA.Challenge -> a -> MVar (M.Map WA.Challenge a) -> IO ()
writeOptionsToMVar challenge opts optsMVarMap = do
  optsMap <- takeMVar optsMVarMap
  putMVar optsMVarMap $ M.insert challenge opts optsMap

webAuthnRouteHandler
  :: (MonadSnap m)
  => Pool Connection
  -> MVar (M.Map WA.Challenge (WA.CredentialOptions 'WA.Registration))
  -> MVar (M.Map WA.Challenge (WA.CredentialOptions 'WA.Authentication))
  -> WA.Origin
  -> WA.RpIdHash
  -> R WebAuthnRoute
  -> m ()
webAuthnRouteHandler pool registerOptionMapVar loginOptionMapVar origin rpIdHash = \case
  WebAuthnRoute_Register :/ registerRoute -> case registerRoute of
    RegisterRoute_Begin -> do
      loginDataEither <- getJSON
      case loginDataEither of
        Left err -> finishWithError $ "Could not read username: " <> T.pack err
        Right (LoginData userName) -> do
          -- Check if there already is a user by this name
          userExists <- liftIO $ checkIfUserExists pool userName
          when userExists $ finishWithError "User already exists"
          challenge <- liftIO $ WA.generateChallenge
          credOpts <- liftIO $ defaultRegistrationOptions userName challenge
          liftIO $ writeOptionsToMVar challenge credOpts registerOptionMapVar
          sendData $ WA.encodeCredentialOptionsRegistration credOpts

    RegisterRoute_Complete -> do
      dateTime <- liftIO dateCurrent

      credential <- first T.pack <$> getJSON
      cred <- case credential >>= WA.decodeCredentialRegistration WA.allSupportedFormats of
        Left err -> finishWithError err
        Right result -> pure result

      let challenge = WA.ccdChallenge $ WA.arrClientData $ WA.cResponse cred
      registerOptionMap <- liftIO $ takeMVar registerOptionMapVar
      forM_ (M.lookup challenge registerOptionMap) $ \credOpts -> do
        case WA.verifyRegistrationResponse origin rpIdHash mempty dateTime credOpts cred of
          Failure nonEmptyErrorList -> finishWithError $ T.pack $ show nonEmptyErrorList
          Success registrationResponse -> do
            liftIO $ do
              putMVar registerOptionMapVar $ M.delete challenge registerOptionMap
              insertUser pool $ WA.corUser credOpts
              insertCredentialEntry pool $ WA.rrEntry registrationResponse
            sendData $ BackendResponse "You have registered successfully"

  WebAuthnRoute_Login :/ loginRoute -> case loginRoute of
    LoginRoute_Begin -> do
      loginDataEither <- getJSON
      case loginDataEither of
        Left err -> finishWithError $ "Could not read username: " <> T.pack err
        Right (LoginData username) -> do
          liftIO $ print username
          credentials <- liftIO $ getCredentialEntryByUser pool username
          when (null credentials) $ finishWithError "User not found, please register first"

          challenge <- liftIO WA.generateChallenge
          let credOpts = defaultAuthenticationOptions challenge credentials
          liftIO $ writeOptionsToMVar challenge credOpts loginOptionMapVar
          sendData $ WA.encodeCredentialOptionsAuthentication credOpts

    LoginRoute_Complete -> do
      credential <- first T.pack <$> getJSON
      cred <- case credential >>= WA.decodeCredentialAuthentication of
        Left err -> finishWithError $ "Could not decode credential: " <> err
        Right result -> pure result

      entryMaybe <- liftIO $ getCredentialEntryByCredentialId pool $ WA.cIdentifier cred
      entry <- case entryMaybe of
        Nothing -> finishWithError "Credential Entry does not exist"
        Just entry -> pure entry

      let challenge = WA.ccdChallenge $ WA.araClientData $ WA.cResponse cred
      loginOptionMap <- liftIO $ takeMVar loginOptionMapVar
      forM_ (M.lookup challenge loginOptionMap) $ \credOpts -> do
        liftIO $ putMVar loginOptionMapVar $ M.delete challenge loginOptionMap
        WA.AuthenticationResult newSigCount <- case WA.verifyAuthenticationResponse origin rpIdHash (Just (WA.ceUserHandle entry)) entry credOpts cred of
          Failure nonEmptyErrorList -> finishWithError $ T.pack $ show nonEmptyErrorList
          Success result -> pure result
        case newSigCount of
          WA.SignatureCounterZero -> sendData $ BackendResponse "You were logged in."
          WA.SignatureCounterUpdated counter -> do
            liftIO $ updateSignatureCounter pool (WA.cIdentifier cred) counter
            sendData $ BackendResponse "You were logged in."
          WA.SignatureCounterPotentiallyCloned -> finishWithError "Signature Counter Cloned"

withWebAuthnBackend
  :: ( webAuthnRouteHandler ~ (R WebAuthnRoute -> Snap ())
     , serveRouteHandler ~ (R backendRoute -> Snap ())
     , serveType ~ ((R backendRoute -> Snap ()) -> IO ())
     )
  => (webAuthnRouteHandler -> serveRouteHandler)
  -> serveType
  -> IO ()
withWebAuthnBackend routeMatcher =
  \serve ->
    withDb "db" $ \pool -> do

      -- Initialise the database
      initDb pool

      registerOptionMapVar <- newMVar mempty :: IO (MVar (M.Map WA.Challenge (WA.CredentialOptions 'WA.Registration)))
      loginOptionMapVar <- newMVar mempty :: IO (MVar (M.Map WA.Challenge (WA.CredentialOptions 'WA.Authentication)))

      let
        origin = WA.Origin "http://localhost:8000"
        rpIdHash = WA.RpIdHash $ hash $ T.encodeUtf8 "localhost"
      serve (routeMatcher $ webAuthnRouteHandler pool registerOptionMapVar loginOptionMapVar origin rpIdHash)

mkCredentialDescriptor :: WA.CredentialEntry -> WA.CredentialDescriptor
mkCredentialDescriptor credEntry =
  WA.CredentialDescriptor
    { WA.cdTyp = WA.CredentialTypePublicKey,
      WA.cdId = WA.ceCredentialId credEntry,
      WA.cdTransports = Just $ WA.ceTransports credEntry
    }
