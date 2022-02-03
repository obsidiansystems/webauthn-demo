{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Backend where

import Snap.Internal.Core

import Obelisk.Backend
import Obelisk.Route.Frontend

import Common.Route
import Backend.Util

backend :: Backend BackendRoute FrontendRoute
backend = Backend
  { _backend_run = withWebAuthnBackend $ \webAuthnRouteHandler -> \case
      BackendRoute_Missing :/ () -> writeBS "Does not exist"
      BackendRoute_WebAuthn :/ webAuthnRoute -> webAuthnRouteHandler webAuthnRoute
  , _backend_routeEncoder = fullRouteEncoder
  }
