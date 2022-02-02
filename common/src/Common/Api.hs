{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Common.Api where

import qualified Data.Aeson as A
import Data.Aeson.TH
import qualified Data.Text as T

newtype LoginData = LoginData
  { name :: T.Text }
  deriving Show

instance A.ToJSON LoginData where
  toJSON (LoginData n) = A.object
    [ "name" A..= n ]

instance A.FromJSON LoginData where
  parseJSON = A.withObject "LoginData" $ \o -> LoginData
    <$> o A..: "name"

data Error
  = Error_Client ClientError
  | Error_Server ServerError
  deriving (Eq, Show)

newtype ClientError = ClientError T.Text deriving (Eq, Show)
newtype ServerError = ServerError T.Text deriving (Eq, Show)

deriveJSON defaultOptions ''Error
deriveJSON defaultOptions ''ClientError
deriveJSON defaultOptions ''ServerError

newtype BackendResponse = BackendResponse T.Text
  deriving (Show, A.ToJSON, A.FromJSON)

webAuthnBaseUrl :: T.Text
webAuthnBaseUrl = "webauthn"
