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
      outputEitherStringResults $ first unlines $ (zipWith prependFilename fs) <$> (map extractHash) <$> parseAsJsonOrYaml False bss
      where
        prependFilename | _hashCmdArgs_raw args = \_ h -> h
                        | otherwise = \fp h -> (takeFileName fp) <> ": " <> h

        extractHash = T.unpack . hashB64U . _transaction_hash
