{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE StandaloneDeriving #-}

module Util where

import Control.Lens
import Control.Monad
import qualified Crypto.WebAuthn as WA
import qualified Data.Aeson as A
import qualified Data.ByteString.Base64.URL as B64
import qualified Data.ByteString.Lazy as B
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import GHC.Generics
import Language.Javascript.JSaddle
import Reflex.Dom.Core hiding (Error)

import Common.Api

s :: String -> String
s = id

consoleLog t = liftJSM $ do
  console <- jsg $ T.pack "console"
  console ^. js1 (T.pack "log") t
  pure ()

toArrayBuffer strVal = do
  bstrEither <- B64.decode . T.encodeUtf8 <$> valToText strVal
  pure $ bstrEither <&> \bstr -> do
    jsArray <- toJSValListOf $ B.unpack $ B.fromStrict bstr
    new (jsg $ s "Uint8Array") jsArray

replacePropWithByteBuffer :: _ => Object -> String -> m Object
replacePropWithByteBuffer someObj propName = liftJSM $ do
  propVal <- someObj ^. js propName
  eitherBuffer <- toArrayBuffer propVal
  forM_ eitherBuffer $ \buf ->
    objSetPropertyByName someObj propName buf
  pure someObj

toBase64UrlString propVal = do
  uint8Array <- new (jsg $ s "Uint8Array") propVal
  bytes <- B.toStrict . B.pack <$> fromJSValUncheckedListOf uint8Array
  pure $ T.decodeUtf8 $ B64.encode bytes

copyProperty :: MonadJSM m => Object -> Object -> String -> m ()
copyProperty = copyPropertyWithModification pure

-- copyPropertyWithBase64Url

copyPropertyWithModification :: (ToJSVal a, MonadJSM m) => (JSVal -> JSM a) -> Object -> Object -> String -> m ()
copyPropertyWithModification f oldObj newObj propName = liftJSM $ do
  propVal <- objGetPropertyByName oldObj propName
  isPropNull <- ghcjsPure $ isNull propVal
  newPropVal <- f propVal
  objSetPropertyByName newObj propName $ if isPropNull then pure propVal else toJSVal newPropVal

-- decodeCredentialOptions credOpts = do

getNavigatorCredentials = do
  nav <- jsg $ s "navigator"
  creds <- nav ^. js (s "credentials")
  cond <- ghcjsPure (isNull creds)
  pure $ if cond
    then Nothing
    else Just creds

jsThen promise accept = liftJSM $ do
  promise ^. js1 (s "then") (fun $ \_ _ [result] -> do
    accept result)

postJSONRequest :: _ => T.Text -> Event t T.Text -> m (Event t T.Text, Event t T.Text)
postJSONRequest url postDataEv = do
  let
    xhrEv = postDataEv <&> \postData ->
      XhrRequest "POST" url $ def
        & xhrRequestConfig_sendData .~ postData
        & xhrRequestConfig_headers .~ ("Content-type" =: "application/json")
  xhrResponseEv <- performRequestAsync xhrEv
  let
    responseTextEv = fmapMaybe _xhrResponse_responseText xhrResponseEv
  pure $ fanEither $ responseTextEv <&> \jsonText ->
    let
      errorEither = A.eitherDecodeStrict' $ T.encodeUtf8 jsonText
    in
      case errorEither of
        -- We failed to parse the json as an error, this means we succeeded
        Left _ -> Right jsonText
        -- We successfully parsed the json as an error, this means we got an error!!
        Right (Error err) -> Left err

jsonParse jsonText = do
  json <- jsg $ s "JSON"
  json ^. js1 (s "parse") jsonText >>= makeObject

jsonStringify object = do
  json <- jsg $ s "JSON"
  json ^. js1 (s "stringify") object >>= valToText

data AuthenticatorResponseType
  = Attestation   -- Registration
  | Assertion     -- Login

getPropsByAuthenticatorResponseType = \case
  Attestation -> ["attestationObject", "clientDataJSON"]
  Assertion -> ["authenticatorData", "clientDataJSON", "signature", "userHandle"]

encodeBase64PublicKeyCredential pkCredsObj authRespType = do
  newObj <- create

  -- Copy over properties as is.
  forM_ ["id", "type"] $ \prop ->
    copyProperty pkCredsObj newObj prop

  -- Copy property after encoding it to Base 64 url.
  copyPropertyWithModification toBase64UrlString pkCredsObj newObj "rawId"

  responseObj <- objGetPropertyByName pkCredsObj (s "response") >>= makeObject
  encodeBase64AuthenticatorResponse responseObj authRespType >>=
    objSetPropertyByName newObj (s "response")

  pkCredsObj ^. js0 (s "getClientExtensionResults") >>=
    objSetPropertyByName newObj (s "clientExtensionResults")

  pure newObj

encodeBase64AuthenticatorResponse responseObj authRespType = do
  newResponseObj <- create
  -- responseObj <- objGetPropertyByName pkCredsObj (s "response") >>= makeObject
  forM_ (getPropsByAuthenticatorResponseType authRespType) $ \prop ->
    copyPropertyWithModification toBase64UrlString responseObj newResponseObj prop
  -- copyPropertyWithModification toBase64UrlString responseObj newResponseObj 
  pure newResponseObj
