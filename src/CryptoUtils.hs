module CryptoUtils (calcHash, calcHashFromText) where

import qualified Crypto.Hash as Crypto
import qualified Data.ByteArray as BA
import           Data.ByteString
import           Data.Text.Encoding
import           Data.Text

calcHash :: ByteString -> ByteString
calcHash = BA.convert . Crypto.hashWith Crypto.Blake2b_256

calcHashFromText :: Text -> ByteString
calcHashFromText = calcHash . encodeUtf8