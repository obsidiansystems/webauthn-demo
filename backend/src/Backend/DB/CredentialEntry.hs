{-# Language DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# Language TypeFamilies #-}

module Backend.DB.CredentialEntry where

import qualified Data.ByteString as B
import Data.Word

import Database.Beam
import Backend.DB.User

data CredentialEntryT f = CredentialEntryT
  { credentialId :: C f B.ByteString
  , userHandle :: PrimaryKey UserT f
  , publicKey :: C f B.ByteString
  , signCounter :: C f Word32
  , transports :: C f Word32
  } deriving (Generic, Beamable)

type CredentialEntry = CredentialEntryT Identity
type CredentialEntryId = PrimaryKey CredentialEntryT Identity

instance Table CredentialEntryT where
  data PrimaryKey CredentialEntryT f = CredentialEntryId (C f B.ByteString) deriving (Generic, Beamable)
  primaryKey = CredentialEntryId . credentialId
