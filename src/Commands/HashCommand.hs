{-# LANGUAGE DeriveGeneric #-}

module Commands.HashCommand
  ( hashCommand
  ) where

------------------------------------------------------------------------------
import           Chainweb.Api.Transaction
import           Chainweb.Api.Hash
import           Data.Bifunctor
import           System.FilePath
import qualified Data.ByteString.Lazy as LB
import qualified Data.Text as T
import qualified Data.Text.Lazy as LT
import qualified Data.Text.Lazy.Encoding as LT
import qualified Data.Map as M
import qualified Data.Aeson as A
import           Katip
------------------------------------------------------------------------------
import           Types.Env
import           Utils
import           Output

------------------------------------------------------------------------------

hashCommand :: Env -> HashCmdArgs -> IO ()
hashCommand e args = do
  case _hashCmdArgs_file args of
    [] -> putStrLn "No tx files specified"
    fs -> do
      logEnv e DebugS $ logStr $ "Parsing transactions from the following files:" <> (show $ _hashCmdArgs_file args)
      bss <- mapM LB.readFile fs
      outputEitherText $ first unlines $ combineHashes <$> (map extractHash) <$> parseAsJsonOrYaml False bss
      where
        combineHashes :: [T.Text] -> T.Text
        combineHashes | _hashCmdArgs_raw args = T.unlines
                      | otherwise = LT.toStrict . LT.decodeUtf8 . A.encode . M.fromList . zip fileNames

        fileNames = map takeFileName fs
        extractHash = hashB64U . _transaction_hash
