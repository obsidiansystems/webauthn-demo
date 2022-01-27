{-# Language DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# Language TypeFamilies #-}

module Backend.DB.User where

import qualified Data.ByteString as B
import qualified Data.Text as T

import Database.Beam

data UserT f = UserT
  { handle :: C f B.ByteString
  , accountName :: C f T.Text
  , accountDisplayName :: C f T.Text
  } deriving (Generic, Beamable)

type User = UserT Identity
type UserId = PrimaryKey UserT Identity

instance Table UserT where
  data PrimaryKey UserT f = UserId (C f B.ByteString) deriving (Generic, Beamable)
  primaryKey = UserId . handle
