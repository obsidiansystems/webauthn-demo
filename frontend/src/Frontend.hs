{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

module Frontend where

import Control.Monad
import Control.Monad.IO.Class
import Control.Lens
import qualified Data.Aeson as A
import qualified Data.ByteString.Lazy as B
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Language.Javascript.JSaddle

import Obelisk.Frontend
import Obelisk.Route
import Obelisk.Route.Frontend
import Obelisk.Generated.Static

import Reflex.Dom.Core hiding (Error)

import Common.Api
import Common.Route
import Util

-- This runs in a monad that can be run on the client or the server.
-- To run code in a pure client or pure server context, use one of the
-- `prerender` functions.
-- frontend :: forall t r m . Routed t (FrontendRoute r) (RoutedT t (R FrontendRoute) m) => Frontend (R FrontendRoute)
frontend :: Frontend (R FrontendRoute)
frontend = Frontend
  { _frontend_head = do
      el "title" $ text "Obelisk Minimal Example"
      elAttr "link" ("href" =: $(static "main.css") <> "type" =: "text/css" <> "rel" =: "stylesheet") blank
  , _frontend_body = do
      subRoute_ $ \case
        FrontendRoute_Main ->
#if defined(ghcjs_HOST_OS)
          prerender_ blank frontendMain
#else
          pure ()
#endif
  }

#if defined(ghcjs_HOST_OS)
frontendMain
  :: (DomBuilder t m, MonadJSM (Performable m), PerformEvent t m, TriggerEvent t m, MonadHold t m)
  => RoutedT t () m ()
frontendMain = do

  -- Create an input element for receiving username
  textDyn <- _inputElement_value <$> inputElement (def
    & inputElementConfig_elementConfig . elementConfig_initialAttributes
      .~ "placeholder" =: "Enter username"
    )

  void $ el "div" $ do
    text "Attestation Type"
    (e, _) <- selectElement def $ mapM (el "option" . text) ["None", "Indirect", "Direct"]
    pure $ _selectElement_value e

  void $ el "div" $ do
    text "Authenticator Type"
    (e, _) <- selectElement def $ mapM (el "option" . text) ["Unspecified", "Cross Platform", "Platform (TPM)"]
    pure $ _selectElement_value e

  (eRegister, _) <- el' "button" $ text "Register"
  (eLogin, _) <- el' "button" $ text "Login"
  let
    clickRegister = domEvent Click eRegister
    clickLogin = domEvent Click eLogin

  (registerErrorEv, registerEv) <- setupRegisterWorkflow clickRegister textDyn

  (loginErrorEv, loginEv) <- setupLoginWorkflow clickLogin textDyn

  let
    errorEv =
      leftmost [registerErrorEv, loginErrorEv] <&> \err ->
        divClass "error" $ text err

    outputEv =
      leftmost [registerEv, loginEv] <&> \output ->
        divClass "correct" $ text output

  -- widgetHold_ blank $ leftmost [errorEv, outputEv]

  -- myDyn <- holdDyn "" $ leftmost [registerEv, loginEv]
  void $ el "h1" $ widgetHold blank $ leftmost [errorEv, outputEv]
  pure ()

setupRegisterWorkflow
  :: (TriggerEvent t m, PerformEvent t m, MonadJSM (Performable m))
  => Event t a
  -> Dynamic t T.Text
  -> m (Event t T.Text, Event t T.Text)
setupRegisterWorkflow clickEv textDyn = do
  (pkCredJsonEv, sendPkCredJSON) <- newTriggerEvent

  (registerBeginErrorEv, registerBeginEv) <- postJSONRequest "/webauthn/register/begin" $ T.decodeUtf8 . B.toStrict . A.encode . LoginData <$> tag (current textDyn) clickEv

  void $ performEvent $ ffor registerBeginEv $ \jsonText -> liftJSM $ do
    credentialOptionsObj <- jsonParse jsonText

    replacePropWithByteBuffer credentialOptionsObj "challenge"

    userObj <- objGetPropertyByName credentialOptionsObj (s "user") >>= makeObject
    replacePropWithByteBuffer userObj "id"
    objSetPropertyByName credentialOptionsObj (s "user") userObj

    navCredsMaybe <- getNavigatorCredentials
    forM_ navCredsMaybe $ \navCreds -> do
        pkObj <- create
        (pkObj <# s "publicKey") credentialOptionsObj
        promise <- navCreds ^. js1 (s "create") pkObj
        promise `jsThen` (\pkCreds -> do
          pkCredsObj <- makeObject pkCreds

          encodedPkCreds <- encodeBase64PublicKeyCredential pkCredsObj Attestation

          str <- jsonStringify encodedPkCreds

          liftIO $ sendPkCredJSON str
          )
  (registerCompleteErrorEv, registerCompleteEv) <- postJSONRequest "/webauthn/register/complete" pkCredJsonEv
  pure (leftmost [registerBeginErrorEv, registerCompleteErrorEv], registerCompleteEv)

setupLoginWorkflow
  :: (TriggerEvent t m, PerformEvent t m, MonadJSM (Performable m))
  => Event t a
  -> Dynamic t T.Text
  -> m (Event t T.Text, Event t T.Text)
setupLoginWorkflow clickEv textDyn = do
  (pkCredJsonEv, sendPkCredJson) <- newTriggerEvent

  (loginBeginErrorEv, loginBeginEv) <- postJSONRequest "/webauthn/login/begin" $ T.decodeUtf8 . B.toStrict . A.encode . LoginData <$> tag (current textDyn) clickEv

  void $ performEvent $ ffor loginBeginEv $ \credReqJson -> liftJSM $ do
    credReq <- jsonParse credReqJson
    replacePropWithByteBuffer credReq "challenge"

    (allowCreds :: [JSVal]) <- objGetPropertyByName credReq ("allowCredentials" :: String) >>= fromJSValUncheckedListOf
    forM_ allowCreds $ \allowCred -> do
      allowCredObj <- makeObject allowCred
      replacePropWithByteBuffer allowCredObj "id"

    objSetPropertyByName credReq ("allowCredentials" :: String) allowCreds

    credReqObj <- create
    objSetPropertyByName credReqObj ("publicKey" :: String) credReq

    navCredsMaybe <- getNavigatorCredentials
    forM_ navCredsMaybe $ \navCreds -> do
      promise <- navCreds ^. js1 (s "get") credReqObj
      promise `jsThen` (\pkCreds -> do
        pkCredsObj <- makeObject pkCreds
        encodedPkCreds <- encodeBase64PublicKeyCredential pkCredsObj Assertion

        str <- jsonStringify encodedPkCreds
        liftIO $ sendPkCredJson str
        )

  (loginCompleteErrorEv, loginCompleteEv) <- postJSONRequest "/webauthn/login/complete" pkCredJsonEv
  pure (leftmost [loginBeginErrorEv, loginCompleteErrorEv], loginCompleteEv)
#endif
