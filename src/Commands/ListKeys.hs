{-# LANGUAGE OverloadedStrings #-}

module Commands.ListKeys where

------------------------------------------------------------------------------
import qualified Data.ByteString as BS
import           Data.Maybe
import qualified Data.Text as T
import qualified Data.Text.IO as T
import           Text.Printf
------------------------------------------------------------------------------
import           Keys
import           Types.KeyType
import           Types.Env
import           Utils
------------------------------------------------------------------------------

printChainWeaverKeys :: BS.ByteString -> Maybe T.Text -> Maybe KeyIndex -> IO ()
printChainWeaverKeys seed mpass mInd =  do
  let xprv = seedToRoot seed mpass
  let getAndShow n = tshow (unKeyIndex n) <> ": " <> pubKeyToText (snd $ generateCryptoPairFromRoot xprv mpass n)
  let ind = fromMaybe 5 mInd
  putStrLn "ChainWeaver / Ecko Wallet derivation keys"
  mapM_ (T.putStrLn . getAndShow) [0..ind]

printKipKeys :: BS.ByteString -> Maybe KeyIndex -> IO ()
printKipKeys seed mInd =  do
  let getAndShow n = tshow (unKeyIndex n) <> ": " <> pubKeyToText (snd $ generateKipCryptoPairFromSeed seed n)
  let ind = fromMaybe 5 mInd
  putStrLn "KIP 0026 derivation keys"
  mapM_ (T.putStrLn . getAndShow) [0..ind]


printPlainKey :: PublicKey -> IO ()
printPlainKey pub = putStrLn $ "public: " <> (T.unpack $ pubKeyToText pub)

listKeysCommand :: Either FilePath ChainweaverFile -> Maybe KeyIndex -> Maybe DerivationType -> IO ()
listKeysCommand efc mInd mDeriv= do
  (keyfile, h) <- getKeyFile efc
  ekey <- readKadenaKey h
  case (ekey, mDeriv) of
    (Left e, _) -> printf "Error reading key from %s: %s\n" keyfile e
    (Right (HDRoot seed mpass), Just ChainWeaver) -> printChainWeaverKeys seed mpass mInd
    (Right (HDRoot seed _), Just KIP) -> printKipKeys seed mInd
    (Right (HDRoot seed mpass), Nothing) -> printChainWeaverKeys seed mpass mInd >> putStrLn "" >> printKipKeys seed mInd
    (Right (SingleKeyPair _ pub), _) -> printPlainKey pub
