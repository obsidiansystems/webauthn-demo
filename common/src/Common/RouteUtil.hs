{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

module Common.RouteUtil where

import Data.Text (Text)
import Data.Universe

import Obelisk.Route
import Obelisk.Route.TH

data RegisterRoute
  = RegisterRoute_Begin
  | RegisterRoute_Complete
  deriving (Show, Eq, Ord, Enum, Bounded)

instance Universe RegisterRoute

registerRouteEncoder :: Encoder (Either Text) (Either Text) RegisterRoute PageName
registerRouteEncoder = enumEncoder $ \case
  RegisterRoute_Begin -> (["begin"], mempty)
  RegisterRoute_Complete -> (["complete"], mempty)

data LoginRoute
  = LoginRoute_Begin
  | LoginRoute_Complete
  deriving (Show, Eq, Ord, Enum, Bounded)

instance Universe LoginRoute

loginRouteEncoder :: Encoder (Either Text) (Either Text) LoginRoute PageName
loginRouteEncoder = enumEncoder $ \case
  LoginRoute_Begin -> (["begin"], mempty)
  LoginRoute_Complete -> (["complete"], mempty)

data WebAuthnRoute :: * -> * where
  WebAuthnRoute_Login :: WebAuthnRoute LoginRoute
  WebAuthnRoute_Register :: WebAuthnRoute RegisterRoute

deriveRouteComponent ''WebAuthnRoute

webauthnRouteEncoder :: Encoder (Either Text) (Either Text) (R WebAuthnRoute) PageName
webauthnRouteEncoder = pathComponentEncoder $ \case
  WebAuthnRoute_Register -> PathSegment "register" registerRouteEncoder
  WebAuthnRoute_Login -> PathSegment "login" loginRouteEncoder
