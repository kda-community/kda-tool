{-# LANGUAGE OverloadedStrings #-}

module Output
  (
    outputResults
  , outputEitherResults
  ) where

------------------------------------------------------------------------------
import           Data.Aeson
import           Control.Lens hiding ((.=))
import           Data.Aeson.Lens
import           Data.String.Conv
import           Control.Monad
import           System.Exit
------------------------------------------------------------------------------

outputResults:: Bool -> [Object] -> IO ()
outputResults shortOutput results = do
  let out = Object $ mconcat results
  let status = out ^.. cosmos . key "result" . key "status" . _String
  if shortOutput
    then putStrLn $ toS $ encode status
    else putStrLn $ toS $ encode out
  when (any (/="success") status) $
    exitWith (ExitFailure 2)

outputEitherResults:: Bool -> Either String [Object] -> IO ()
outputEitherResults shortOutput eRes =
  case eRes of
    Left er -> putStrLn er >> exitFailure
    Right results -> outputResults shortOutput results