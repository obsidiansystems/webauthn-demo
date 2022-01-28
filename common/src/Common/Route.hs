{-# LANGUAGE EmptyCase #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
module Common.Route where

{- -- You will probably want these imports for composing Encoders.
import Prelude hiding (id, (.))
import Control.Category
-}

-- import Data.IORef
import Data.Text (Text)
import Data.Functor.Identity
import Data.Universe

import Obelisk.Route
import Obelisk.Route.TH

data BackendRoute :: * -> * where
  -- | Used to handle unparseable routes.
  BackendRoute_Missing :: BackendRoute ()
  -- You can define any routes that will be handled specially by the backend here.
  -- i.e. These do not serve the frontend, but do something different, such as serving static files.
  BackendRoute_WebAuthn :: BackendRoute (R WebAuthnRoute)

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

data FrontendRoute :: * -> * where
  FrontendRoute_Main :: FrontendRoute ()
  -- This type is used to define frontend routes, i.e. ones for which the backend will serve the frontend.

fullRouteEncoder
  :: Encoder (Either Text) Identity (R (FullRoute BackendRoute FrontendRoute)) PageName
fullRouteEncoder = mkFullRouteEncoder
  (FullRoute_Backend BackendRoute_Missing :/ ())
  (\case
      BackendRoute_Missing -> PathSegment "missing" $ unitEncoder mempty
      BackendRoute_WebAuthn -> PathSegment "webauthn" webauthnRouteEncoder)
  (\case
      FrontendRoute_Main -> PathEnd $ unitEncoder mempty)

concat <$> mapM deriveRouteComponent
  [ ''BackendRoute
  , ''FrontendRoute
  ]
