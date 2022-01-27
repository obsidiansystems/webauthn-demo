{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}

module Common.Api where

import qualified Crypto.WebAuthn as WA
import qualified Data.Aeson as A
import Data.Aeson.GADT.TH
import qualified Data.Text as T


data LoginData = LoginData
  { name :: T.Text

  }
  deriving Show

instance A.ToJSON LoginData where
  toJSON (LoginData n) = A.object
    [ "name" A..= n
    ]

instance A.FromJSON LoginData where
  parseJSON = A.withObject "LoginData" $ \o -> LoginData
    <$> o A..: "name"

newtype Error = Error T.Text

instance A.ToJSON Error where
  toJSON (Error err) = A.object ["error" A..= err]

instance A.FromJSON Error where
  parseJSON = A.withObject "Error" $ \o ->
    Error <$> o A..: "error"


-- instance A.FromJSON (WA.CredentialOptions c) where
--   parseJSON (A.Object o) = do
--     tag <- o A..: "tag"
--     case tag of
--       "CredentialOptionsRegistration" -> WA.CredentialOptionsRegistration
--         <$> o A..: "corRp"
--         <*> o A..: "corUser"
--         <*> o A..: "corChallenge"
--         <*> o A..: "corPubKeyCredParams"
--         <*> o A..: "corTimeout"
--         <*> o A..: "corExcludeCredentials"
--         <*> o A..: "corAuthenticatorSelection"
--         <*> o A..: "corAttestation"
--         <*> o A..: "corExtensions"
      
--       "CredentialOptionsAuthentication" -> WA.CredentialOptionsAuthentication
--         <$> o A..: "coaChallenge"
--         <*> o A..: "coaTimeout"
--         <*> o A..: "coaRpId"
--         <*> o A..: "coaAllowCredentials"
--         <*> o A..: "coaUserVerification"
--         <*> o A..: "coaExtensions"


commonStuff :: String
commonStuff = "Here is a string defined in Common.Api"

-- deriveFromJSONGADT ''WA.CredentialOptions
-- deriveJSON ''WA.CredentialOptions 'WA.Registration
