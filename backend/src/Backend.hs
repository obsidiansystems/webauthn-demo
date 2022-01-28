{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Backend where

import Control.Concurrent.MVar
import Control.Monad
import Control.Monad.IO.Class
import Crypto.Hash (hash)
import qualified Crypto.WebAuthn as WA
import qualified Data.Aeson as A
import Data.Bifunctor
import qualified Data.Map.Strict as M
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.Validation
import Snap.Internal.Core
import Snap.Extras.JSON
import Time.System

import Gargoyle.PostgreSQL.Connect

import Common.Api
import Common.Route
import Obelisk.Backend
import Obelisk.Route.Frontend

import Backend.DB.DB
import Backend.Util

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

backend :: Backend BackendRoute FrontendRoute
backend = Backend
  { _backend_run = \serve -> withDb "db" $ \pool -> do

    -- Initialise the database
    initDb pool

    -- Map this, 
    registerOptionMapVar <- newMVar mempty :: IO (MVar (M.Map WA.Challenge (WA.CredentialOptions 'WA.Registration)))
    loginOptionMapVar <- newMVar mempty :: IO (MVar (M.Map WA.Challenge (WA.CredentialOptions 'WA.Authentication)))

    let
      origin = WA.Origin "http://localhost:8000"
      rpIdHash = WA.RpIdHash $ hash $ T.encodeUtf8 "localhost"

    serve $ \case
      BackendRoute_Missing :/ () -> do
        writeBS "Does not exist"
        pure ()
      
      BackendRoute_WebAuthn :/ webAuthnRoute -> case webAuthnRoute of
        WebAuthnRoute_Register :/ registerRoute -> case registerRoute of
          RegisterRoute_Begin -> do
            loginDataEither <- getJSON
            case loginDataEither of
              Right (LoginData userName) -> do
                -- Check if there already is a user by this name
                userExists <- liftIO $ checkIfUserExists pool userName
                when userExists $ finishWithError "User already exists"
                challenge <- liftIO $ WA.generateChallenge
                credOpts <- liftIO $ defaultRegistrationOptions userName challenge
                liftIO $ writeOptionsToMVar challenge credOpts registerOptionMapVar
                writeLBS $ A.encode $ WA.encodeCredentialOptionsRegistration credOpts
              _ -> pure ()
          RegisterRoute_Complete -> do
            dateTime <- liftIO dateCurrent

            credential <- first T.pack <$> getJSON
            cred <- case credential >>= WA.decodeCredentialRegistration WA.allSupportedFormats of
              Left err -> do
                fail $ show err
              Right result -> pure result

            let challenge = WA.ccdChallenge $ WA.arrClientData $ WA.cResponse cred
            registerOptionMap <- liftIO $ takeMVar registerOptionMapVar
            forM_ (M.lookup challenge registerOptionMap) $ \credOpts -> do
              case WA.verifyRegistrationResponse origin rpIdHash mempty dateTime credOpts cred of
                Failure _ -> pure ()
                Success registrationResponse -> liftIO $ do
                  insertUser pool $ WA.corUser credOpts
                  insertCredentialEntry pool $ WA.rrEntry registrationResponse
                  pure ()

              liftIO $ putMVar registerOptionMapVar $ M.delete challenge registerOptionMap

              writeLBS "You have registered successfully"
              pure ()
        WebAuthnRoute_Login :/ loginRoute -> case loginRoute of
          LoginRoute_Begin -> do
            usernameEither <- getJSON
            case usernameEither of
              Left _ -> finishWithError "Could not read username"
              Right (LoginData username) -> do
                liftIO $ print username
                credentials <- liftIO $ getCredentialEntryByUser pool username
                when (null credentials) $ finishWithError "User not found, please register first"

                challenge <- liftIO WA.generateChallenge
                let credOpts = defaultAuthenticationOptions challenge credentials
                liftIO $ writeOptionsToMVar challenge credOpts loginOptionMapVar
                writeLBS $ A.encode $ WA.encodeCredentialOptionsAuthentication credOpts
                pure ()
          LoginRoute_Complete -> do
            credential <- first T.pack <$> getJSON
            cred <- case credential >>= WA.decodeCredentialAuthentication of
              Left err -> do
                fail $ show err
              Right result -> pure result

            entryMaybe <- liftIO $ getCredentialEntryByCredentialId pool $ WA.cIdentifier cred
            entry <- case entryMaybe of
              Nothing -> finishWithError "Credential Entry does not exist"
              Just entry -> pure entry

            let challenge = WA.ccdChallenge $ WA.araClientData $ WA.cResponse cred
            loginOptionMap <- liftIO $ takeMVar loginOptionMapVar
            forM_ (M.lookup challenge loginOptionMap) $ \credOpts -> do
              liftIO $ putMVar loginOptionMapVar $ M.delete challenge loginOptionMap
              case WA.verifyAuthenticationResponse origin rpIdHash (Just (WA.ceUserHandle entry)) entry credOpts cred of
                Failure errs{-@(err :| _)-} -> do
                  fail $ show errs
                Success _ -> do
                  writeLBS "You were logged in."
                  pure ()
  , _backend_routeEncoder = fullRouteEncoder
  }

mkCredentialDescriptor :: WA.CredentialEntry -> WA.CredentialDescriptor
mkCredentialDescriptor credEntry =
  WA.CredentialDescriptor
    { WA.cdTyp = WA.CredentialTypePublicKey,
      WA.cdId = WA.ceCredentialId credEntry,
      WA.cdTransports = Just $ WA.ceTransports credEntry
    }