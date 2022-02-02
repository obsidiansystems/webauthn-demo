{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PartialTypeSignatures #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}

module Util(
  setupLoginWorkflow,
  setupRegisterWorkflow
) where

import Control.Lens
import Control.Monad
import Control.Monad.IO.Class
import qualified Crypto.WebAuthn.Model.WebIDL.Types as WA
import qualified Crypto.WebAuthn.WebIDL as WA
import qualified Data.Aeson as A
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import qualified Data.Map.Strict as M
import Data.Maybe (catMaybes)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Language.Javascript.JSaddle
import Reflex.Dom.Core hiding (Error)

import Common.Api


s :: String -> String
s = id

consoleLog :: (MonadJSM m, ToJSVal a0) => a0 -> m ()
consoleLog t = liftJSM $ do
  console <- jsg $ T.pack "console"
  void $ console ^. js1 (T.pack "log") t

byteStringToArrayBuffer :: B.ByteString -> JSM JSVal
byteStringToArrayBuffer bytes = do
  jsArray <- toJSValListOf $ B.unpack bytes
  new (jsg $ s "Uint8Array") jsArray

getNavigatorCredentials :: JSM (Maybe JSVal)
getNavigatorCredentials = do
  nav <- jsg $ s "navigator"
  creds <- nav ^. js (s "credentials")
  cond <- ghcjsPure (isNull creds)
  pure $ if cond
    then Nothing
    else Just creds

jsThen :: (MonadJSM m, MakeObject s) => s -> (JSVal -> JSM ()) -> m JSVal
jsThen promise accept = liftJSM $ do
  promise ^. js1 (s "then") (fun $ \_ _ [result] -> do
    accept result)

postJSONRequest
  :: (MonadJSM (Performable m), PerformEvent t m, TriggerEvent t m, IsXhrPayload a, A.FromJSON b)
  => T.Text
  -> Event t a
  -> m (Event t (Either Error b))
postJSONRequest url postDataEv = do
  let
    xhrEv = postDataEv <&> \postData ->
      XhrRequest "POST" url $ def
        & xhrRequestConfig_sendData .~ postData
        & xhrRequestConfig_headers .~ ("Content-type" =: "application/json")
  xhrResponseEv <- performRequestAsync xhrEv
  let
    responseTextEv = fmapMaybe _xhrResponse_responseText xhrResponseEv
  pure $ responseTextEv <&> \jsonText ->
    case A.eitherDecodeStrict' $ T.encodeUtf8 jsonText of
      Left err -> Left $ Error_Client $ ClientError $ T.pack err
      Right backendResponse ->
        case backendResponse of
          Left err -> Left $ Error_Server err
          Right res -> Right res

withObject :: (Object -> JSM ()) -> JSM JSVal
withObject f = do
  newObj <- obj
  f newObj
  toJSVal newObj

instance ToJSVal WA.PublicKeyCredentialRpEntity where
  toJSVal (WA.PublicKeyCredentialRpEntity rpId name) = do
    withObject $ \rpEntity -> do
      setPropertyMaybe rpEntity "id" rpId
      setProperty rpEntity "name" name

instance ToJSVal WA.PublicKeyCredentialUserEntity where

instance ToJSVal WA.BufferSource where
  toJSVal (WA.URLEncodedBase64 bytes) = byteStringToArrayBuffer bytes

instance ToJSVal WA.PublicKeyCredentialParameters where
  toJSVal (WA.PublicKeyCredentialParameters littype alg) = do
    withObject $ \credParam -> do
      setProperty credParam "type" littype
      setProperty credParam "alg" alg

instance ToJSVal WA.PublicKeyCredentialDescriptor where
  toJSVal (WA.PublicKeyCredentialDescriptor littype idBytes transports) = do
    withObject $ \credDesc -> do
      setProperty credDesc "type" littype
      setProperty credDesc "id" idBytes
      setPropertyMaybe credDesc "transports" transports

instance ToJSVal WA.AuthenticatorSelectionCriteria where
  toJSVal WA.AuthenticatorSelectionCriteria {..} = do
    withObject $ \authSelect -> do
      setPropertyMaybe authSelect "authenticatorAttachment" authenticatorAttachment
      setPropertyMaybe authSelect "residentKey" residentKey
      setPropertyMaybe authSelect "requireResidentKey" requireResidentKey
      setPropertyMaybe authSelect "userVerification" userVerification

instance (ToJSString k, ToJSVal v) => ToJSVal (M.Map k v) where
  toJSVal strictMap = do
    withObject $ \mapObj -> do
      forM_ (M.toList strictMap) $ \(key, value) ->
        objSetPropertyByName mapObj key value

instance ToJSVal WA.PublicKeyCredentialCreationOptions where
  toJSVal WA.PublicKeyCredentialCreationOptions {..} = do
    withObject $ \credOpt -> do
      setProperty credOpt "rp" rp
      setProperty credOpt "user" user
      setProperty credOpt "challenge" challenge
      setProperty credOpt "pubKeyCredParams" pubKeyCredParams
      setPropertyMaybe credOpt "timeout" timeout
      setPropertyMaybe credOpt "excludeCredentials" excludeCredentials
      setPropertyMaybe credOpt "authenticatorSelection" authenticatorSelection
      setPropertyMaybe credOpt "attestation" attestation
      setPropertyMaybe credOpt "extensions" extensions

instance ToJSVal WA.PublicKeyCredentialRequestOptions where
  toJSVal WA.PublicKeyCredentialRequestOptions {..} = do
    withObject $ \credOpt -> do
      setProperty credOpt "challenge" challenge
      setPropertyMaybe credOpt "timeout" timeout
      setPropertyMaybe credOpt "rpId" rpId
      setPropertyMaybe credOpt "allowCredentials" allowCredentials
      setPropertyMaybe credOpt "userVerification" userVerification
      setPropertyMaybe credOpt "extensions" extensions

getProperty :: (FromJSVal a) => Object -> String -> JSM (Maybe a)
getProperty ob name = objGetPropertyByName ob name >>= fromJSVal

getFunctionResult :: (FromJSVal a) => Object -> String -> JSM (Maybe a)
getFunctionResult ob name = ob ^. js0 name >>= fromJSVal

setProperty :: (ToJSVal a) => Object -> String -> a -> JSM ()
setProperty = objSetPropertyByName

setPropertyMaybe :: (ToJSVal a) => Object -> String -> Maybe a -> JSM ()
setPropertyMaybe object propName maybeProp = forM_ maybeProp $ setProperty object propName

data AuthenticatorResponseType
  = Attestation   -- Registration
  | Assertion     -- Login

getPropsByAuthenticatorResponseType :: AuthenticatorResponseType -> [String]
getPropsByAuthenticatorResponseType = \case
  Attestation -> ["attestationObject", "clientDataJSON"]
  Assertion -> ["authenticatorData", "clientDataJSON", "signature", "userHandle"]

encodeToText :: (A.ToJSON a) => a -> T.Text
encodeToText = T.decodeUtf8 . LB.toStrict . A.encode

wrapObjectPublicKey :: Object -> JSM Object
wrapObjectPublicKey objectToWrap = do
  wrapperObj <- create
  objSetPropertyByName wrapperObj (s "publicKey") objectToWrap
  pure wrapperObj

instance FromJSVal WA.BufferSource where
  fromJSVal value = do
    uint8Array <- new (jsg $ s "Uint8Array") value
    fmap (WA.URLEncodedBase64 . B.pack) <$> fromJSValListOf uint8Array

instance (FromJSString k, FromJSVal v, Ord k) => FromJSVal (M.Map k v) where
  fromJSVal value = do
    keys <- map fromJSString <$> propertyNames value
    values <- properties value >>= mapM fromJSVal
    pure $ Just $ M.fromList $ zip keys $ catMaybes values

instance FromJSVal response => FromJSVal (WA.PublicKeyCredential response) where
  fromJSVal value = do
    object <- makeObject value
    rawId <- getProperty object "rawId"
    response <- getProperty object "response"
    clientExtensionResults <- getFunctionResult object "getClientExtensionResults"
    pure $ WA.PublicKeyCredential <$> rawId <*> response <*> clientExtensionResults

instance FromJSVal WA.AuthenticatorAttestationResponse where
  fromJSVal value = do
    object <- makeObject value
    clientDataJSON <- getProperty object "clientDataJSON"
    attestationObject <- getProperty object "attestationObject"
    transports <- getFunctionResult object "getTransports"
    pure $ WA.AuthenticatorAttestationResponse <$> clientDataJSON <*> attestationObject <*> transports

instance FromJSVal WA.AuthenticatorAssertionResponse where
  fromJSVal value = do
    object <- makeObject value
    clientDataJSON <- getProperty object "clientDataJSON"
    authenticatorData <- getProperty object "authenticatorData"
    signature <- getProperty object "signature"
    userHandle <- getProperty object "userHandle"
    pure $ WA.AuthenticatorAssertionResponse <$> clientDataJSON <*> authenticatorData <*> signature <*> userHandle

getMethod :: AuthenticatorResponseType -> String
getMethod = \case
  Attestation -> "create"
  Assertion -> "get"

setupWorkflow
  :: (TriggerEvent t m, PerformEvent t m, MonadJSM (Performable m), A.FromJSON a, A.ToJSON b)
  => T.Text
  -> AuthenticatorResponseType
  -> Event t T.Text
  -> (a -> JSM JSVal, JSVal -> JSM b)
  -> m (Event t (Either Error BackendResponse))
setupWorkflow baseUrl authRespType usernameEv (to, from) = do
  (publicKeyCredentialEv, sendPublicKeyCredentialJson) <- newTriggerEvent

  (workflowBeginErrorEv, workflowBeginEv) <- fmap fanEither $ postJSONRequest (baseUrl <> "/begin") $ encodeToText . LoginData <$> usernameEv

  void $ performEvent $ ffor workflowBeginEv $ \credentialOptions -> liftJSM $ do
    credentialOptionsVal <- to credentialOptions
    wrapperObj <- wrapObjectPublicKey =<< makeObject credentialOptionsVal
    navCredsMaybe <- getNavigatorCredentials
    forM_ navCredsMaybe $ \navCreds -> do
        promise <- navCreds ^. js1 (getMethod authRespType) wrapperObj
        promise `jsThen` (\pkCreds -> do
          publicKeyCredentials <- from pkCreds
          liftIO $ sendPublicKeyCredentialJson $ encodeToText publicKeyCredentials
          )
  (workflowCompleteErrorEv, workflowCompleteEv) <- fanEither <$> postJSONRequest (baseUrl <> "/complete") publicKeyCredentialEv
  pure $ leftmost [Left <$> workflowBeginErrorEv, Left <$> workflowCompleteErrorEv, Right <$> workflowCompleteEv]

setupRegisterWorkflow
  :: (TriggerEvent t m, PerformEvent t m, MonadJSM (Performable m))
  => T.Text
  -> Event t T.Text
  -> m (Event t (Either Error BackendResponse))
setupRegisterWorkflow baseUrl usernameEv = setupWorkflow (baseUrl <> "/register") Attestation usernameEv (to, from)
  where
    to :: WA.PublicKeyCredentialCreationOptions -> JSM JSVal
    to = toJSVal

    from :: JSVal -> JSM (WA.PublicKeyCredential WA.AuthenticatorAttestationResponse)
    from = fromJSValUnchecked

setupLoginWorkflow
  :: (TriggerEvent t m, PerformEvent t m, MonadJSM (Performable m))
  => T.Text
  -> Event t T.Text
  -> m (Event t (Either Error BackendResponse))
setupLoginWorkflow baseUrl usernameEv = setupWorkflow (baseUrl <> "/login") Assertion usernameEv (to, from)
  where
    to :: WA.PublicKeyCredentialRequestOptions -> JSM JSVal
    to = toJSVal

    from :: JSVal -> JSM (WA.PublicKeyCredential WA.AuthenticatorAssertionResponse)
    from = fromJSValUnchecked
