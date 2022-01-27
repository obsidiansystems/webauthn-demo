{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Backend where

import qualified Data.ByteString.Base64 as B64
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

defaultPkcco :: WA.CredentialUserEntity -> WA.Challenge -> WA.CredentialOptions 'WA.Registration
defaultPkcco userEntity challenge =
  WA.CredentialOptionsRegistration
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
      
      BackendRoute_Register :/ RegisterRoute_Begin -> do
        req <- getRequest
        loginDataEither <- getJSON
        case loginDataEither of
          Right (LoginData name) -> do
            -- Check if there already is a user by this name
            userExists <- liftIO $ checkIfUserExists pool name
            when userExists $ finishWithError "User already exists"

            (userHandle, challenge) <- liftIO $ (,) <$> WA.generateUserHandle <*> WA.generateChallenge
            let
              user =
                WA.CredentialUserEntity
                  { WA.cueId = userHandle,
                    WA.cueDisplayName = WA.UserAccountDisplayName name,
                    WA.cueName = WA.UserAccountName name
                  }
            -- liftIO $ do
            -- writeLBS $ A.encode $ defaultPkcco user $ WA.Challenge $ B64.encode "Man"
            let
              credOpts = defaultPkcco user challenge
            liftIO $ do
              registerOptionMap <- takeMVar registerOptionMapVar
              putMVar registerOptionMapVar $ M.insert challenge credOpts registerOptionMap
            writeLBS $ A.encode $ WA.encodeCredentialOptionsRegistration credOpts
          _ -> pure ()
      BackendRoute_Register :/ RegisterRoute_Complete -> do
        dateTime <- liftIO dateCurrent

        credential <- first T.pack <$> getJSON
        cred <- case credential >>= WA.decodeCredentialRegistration WA.allSupportedFormats of
          Left err -> do
            fail $ show err
          Right result -> pure result

        let challenge = WA.ccdChallenge $ WA.arrClientData $ WA.cResponse cred
        registerOptionMap <- liftIO $ readMVar registerOptionMapVar
        forM_ (M.lookup challenge registerOptionMap) $ \credOpts -> do
          case WA.verifyRegistrationResponse origin rpIdHash mempty dateTime credOpts cred of
            Failure _ -> pure ()
            Success registrationResponse -> liftIO $ do
              insertUser pool $ WA.corUser credOpts
              insertCredentialEntry pool $ WA.rrEntry registrationResponse
              pure ()

          writeLBS "You have registered successfully"
          pure ()
      BackendRoute_Login :/ LoginRoute_Begin -> do
        usernameEither <- getJSON
        case usernameEither of
          Left _ -> finishWithError "Could not read username"
          Right (LoginData username) -> do
            liftIO $ print username
            credentials <- liftIO $ getCredentialEntryByUser pool username
            when (null credentials) $ finishWithError "User not found, please register first"

            challenge <- liftIO $ do
              -- putMVar loginCredentialEntry credential
              WA.generateChallenge
            let
              credOpts = WA.CredentialOptionsAuthentication
                { WA.coaRpId = Nothing
                , WA.coaTimeout = Nothing
                , WA.coaChallenge = challenge
                , WA.coaAllowCredentials = map mkCredentialDescriptor credentials
                , WA.coaUserVerification = WA.UserVerificationRequirementPreferred
                , WA.coaExtensions = Nothing
                }
            liftIO $ do
              loginOptionMap <- takeMVar loginOptionMapVar
              putMVar loginOptionMapVar $ M.insert challenge credOpts loginOptionMap
            writeLBS $ A.encode $ WA.encodeCredentialOptionsAuthentication credOpts
            pure ()
      BackendRoute_Login :/ LoginRoute_Complete -> do
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
        loginOptionMap <- liftIO $ readMVar loginOptionMapVar
        forM_ (M.lookup challenge loginOptionMap) $ \credOpts -> do


          case WA.verifyAuthenticationResponse origin rpIdHash (Just (WA.ceUserHandle entry)) entry credOpts cred of
            Failure errs{-@(err :| _)-} -> do
              fail $ show errs
            Success result -> do
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