{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FlexibleContexts #-}

module Common.Api where

import qualified Data.Aeson as A
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

newtype Error = Error T.Text

instance A.ToJSON Error where
  toJSON (Error err) = A.object ["error" A..= err]

instance A.FromJSON Error where
  parseJSON = A.withObject "Error" $ \o ->
    Error <$> o A..: "error"

webAuthnBaseUrl :: T.Text
webAuthnBaseUrl = "webauthn"
