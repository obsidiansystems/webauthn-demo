{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}

module Frontend where

import Control.Monad
import Control.Lens
import Language.Javascript.JSaddle

import Obelisk.Frontend
import Obelisk.Route
import Obelisk.Route.Frontend
import Obelisk.Generated.Static

import Reflex.Dom.Core hiding (Error)

import Common.Api
import Common.Route
import Util

frontend :: Frontend (R FrontendRoute)
frontend = Frontend
  { _frontend_head = do
      el "title" $ text "Obelisk Minimal Example"
      elAttr "link" ("href" =: $(static "main.css") <> "type" =: "text/css" <> "rel" =: "stylesheet") blank
  , _frontend_body = do
      subRoute_ $ \case
        FrontendRoute_Main -> prerender_ blank frontendMain
  }

frontendMain
  :: (DomBuilder t m, MonadJSM (Performable m), PerformEvent t m, TriggerEvent t m, MonadHold t m)
  => RoutedT t () m ()
frontendMain = do
  -- Create an input element for receiving username
  textDyn <- _inputElement_value <$> inputElement (def
    & inputElementConfig_elementConfig . elementConfig_initialAttributes
      .~ "placeholder" =: "Enter username"
    )

  -- Create two buttons, one for login, one for registration
  (eRegister, eLogin) <- el "div" $ do
    (e1, _) <- el' "button" $ text "Register"
    (e2, _) <- el' "button" $ text "Login"
    pure (e1, e2)
  let
    textRegisterEv = tag (current textDyn) $ domEvent Click eRegister
    textLoginEv = tag (current textDyn) $ domEvent Click eLogin

  registerEv <- setupRegisterWorkflow webAuthnBaseUrl textRegisterEv
  loginEv <- setupLoginWorkflow webAuthnBaseUrl textLoginEv

  let
    finalEv = either (divClass "error" . text) (divClass "correct" . text) <$> leftmost [registerEv, loginEv]

  void $ el "h1" $ widgetHold blank finalEv
