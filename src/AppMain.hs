{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}

module AppMain where

------------------------------------------------------------------------------
import           Control.Monad.IO.Class
import           Data.Aeson
import           Data.Default
import           Data.Version
import           Data.String (fromString)
import           Katip
import           Network.HTTP.Client hiding (withConnection)
import           Network.HTTP.Client.TLS
import           Options.Applicative
import           System.Directory
import           System.FilePath
import           System.IO
import           System.Random.MWC
import           Text.Printf
------------------------------------------------------------------------------
import           Commands.Cut
import           Commands.CombineSigs
import           Commands.GenTx
import           Commands.Keygen
import           Commands.ListKeys
import           Commands.HashCommand
import           Commands.Local
import           Commands.Mempool
import           Commands.Poll
import           Commands.Send
import           Commands.Sign
import           Commands.Verify
import           Commands.WalletSign
import           Types.Env
------------------------------------------------------------------------------


appMain :: Version -> IO ()
appMain version = do
    Args c severity verbosity mcf <- execParser opts
    mgr <- newManager tlsManagerSettings

    s1 <- liftIO $ mkHandleScribe ColorIfTerminal stderr
      (permitItem severity) verbosity
    le <- liftIO $ registerScribe "stderr" s1 defaultScribeSettings
      =<< initLogEnv "myapp" "production"

    logLE le DebugS $ fromStr $ printf "Logging with severity %s, verbosity %s"
      (show severity) (show verbosity)
    rand <- createSystemRandom

    systemConfig <- loadConfig le $ Just $ "/etc"  </> "kda" </> "config.json"
    userConfig <- loadConfig le =<< Just <$> getXdgDirectory XdgConfig ("kda" </> "config.json")
    cmdConfig <- loadConfig le mcf

    let cd = cmdConfig <> userConfig <> systemConfig

    logLE le DebugS $ logStr $ "Loaded config: " <> show cd
    let theEnv = Env mgr le cd rand
    case c of
      Cut hp ma mn -> cutCommand theEnv hp ma mn
      CombineSigs files -> combineSigsCommand theEnv files
      GenTx args -> genTxCommand theEnv args
      Hash args -> hashCommand theEnv args
      Keygen keyType -> keygenCommand keyType
      ListKeys kf ind deriv -> listKeysCommand kf ind deriv
      Local args -> localCommand theEnv args
      Mempool hp cid ma mn -> mempoolCommand hp ma mn cid
      Poll args -> pollCommand theEnv args
      Send args -> sendCommand theEnv args
      Sign args -> signCommand args
      Verify args -> verifyCommand args
      WalletSign args -> walletSignCommand theEnv args

  where
    opts = info (envP <**> simpleVersioner (showVersion version) <**> helper) $ mconcat
      [ fullDesc
      , header "kda - Command line tool for interacting with the Kadena blockchain"
      , footerDoc (Just theFooter)
      ]
    theFooter = fromString $ unlines
      [ "Run the following command to enable tab completion:"
      , ""
      , "source <(kda --bash-completion-script `which kda`)"
      ]


    loadConfig:: LogEnv -> Maybe FilePath -> IO (ConfigData)
    loadConfig _ Nothing = pure def
    loadConfig le (Just cf) = do
      configExists <- doesFileExist cf
      ecd <- if configExists
             then eitherDecodeFileStrict' cf <* logLoading
             else (pure $ Right def) <* logNotFound
      case ecd of
        Left e -> error (printf "Error parsing %s\n%s" cf e)
        Right cd -> pure cd

      where
        logNotFound = logLE le DebugS $ logStr $ "Config file not found " <> cf
        logLoading = logLE le DebugS $ logStr $ "Loading config from " <> cf