module Backend.Util where

import qualified Data.Aeson as A
import qualified Data.Text as T
import Snap.Internal.Core

import Common.Api

finishWithError :: (MonadSnap m) => T.Text -> m a
finishWithError err = do
  writeLBS $ A.encode $ Error err
  getResponse >>= finishWith