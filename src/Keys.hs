{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE AllowAmbiguousTypes #-}

module Keys where

------------------------------------------------------------------------------
import qualified Cardano.Crypto.Wallet as Crypto
import           Control.Applicative
import           Control.Error
import           Control.Lens
import           Control.Monad.IO.Class
import qualified Crypto.Encoding.BIP39 as Crypto
import qualified Crypto.Encoding.BIP39.English as Crypto
import           Crypto.Error
import qualified Crypto.PubKey.Ed25519 as ED25519
import           Crypto.MAC.HMAC
import           Crypto.Hash
import qualified Crypto.Random.Entropy
import           Data.Aeson
import           Data.Bifunctor
import           Data.Binary.Put
import           Data.Bits ((.|.))
import           Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as BA
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import           Data.Either (fromRight)
import qualified Data.ByteString.Base16 as B16
import qualified Data.Map as Map
import           Data.String (IsString, fromString)
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.IO as T
import           Data.Word (Word32)
import qualified Data.YAML.Aeson as YA
import           GHC.Natural
import           System.IO
import           System.IO.Echo
import           Text.Read (readMaybe)
------------------------------------------------------------------------------
import           Utils
import Data.Base16.Types (extractBase16)
------------------------------------------------------------------------------

mnemonicToRoot :: MnemonicPhrase -> Crypto.XPrv
mnemonicToRoot phrase = seedToRoot (phraseToSeed phrase) Nothing -- TODO: Empty passowrd

genMnemonic12 :: MonadIO m => m (Either Text (Crypto.MnemonicSentence 12))
genMnemonic12 = liftIO $ bimap tshow Crypto.entropyToWords . Crypto.toEntropy @128
  -- This size must be a 1/8th the size of the 'toEntropy' size: 128 / 8 = 16
  <$> Crypto.Random.Entropy.getEntropy @ByteString 16

-- KIP-0026 / SLIP-10 derivation
kipDerivSecretKey :: ByteString -> KeyIndex -> ED25519.SecretKey
kipDerivSecretKey seed ki = onCryptoFailure (error . show) id $ ED25519.secretKey pkey3
  where
    (pkey3, _)     = doDeriv pkey2 code2 (fromKeyIndex ki)
    (pkey2, code2) = doDeriv pkey1 code1 626
    (pkey1, code1) = doDeriv pkey0 code0 44
    (pkey0, code0) = doHmac "ed25519 seed" seed

    doDeriv:: ByteString -> ByteString -> Word32 -> (ByteString, ByteString)
    doDeriv pkey code idx = doHmac code $ LBS.toStrict $  runPut $ putWord8 0 >> putByteString pkey >> putWord32be (0x80000000 .|. idx)

    doHmac :: ByteArrayAccess ba => ByteString -> ba -> (ByteString, ByteString)
    doHmac key dta = BS.splitAt 32 $ BA.convert $ (hmac key dta :: HMAC SHA512)


generateKipCryptoPairFromSeed :: ByteString -> KeyIndex -> (SecretKey, PublicKey)
generateKipCryptoPairFromSeed seed ki = let skey = kipDerivSecretKey seed ki
                                        in (PlainSecretKey skey , PlainPublicKey $ ED25519.toPublic skey)


generateCryptoPairFromRoot :: Crypto.XPrv -> Maybe Text -> KeyIndex -> (SecretKey, PublicKey)
generateCryptoPairFromRoot root pass i =
  let hardenedIdx = 0x80000000 .|. (fromKeyIndex i)
      xprv = Crypto.deriveXPrv scheme (T.encodeUtf8 $ fromMaybe "" pass) root hardenedIdx
  in (CardanoSecretKey xprv, CardanoPublicKey $ Crypto.xpubPublicKey $ Crypto.toXPub xprv)
  where
    scheme = Crypto.DerivationScheme2

mkPhraseMapFromMnemonic
  :: forall mw.
     Crypto.ValidMnemonicSentence mw
  => Crypto.MnemonicSentence mw
  -> Map.Map WordKey Text
mkPhraseMapFromMnemonic = wordsToPhraseMap . T.words . baToText
  . Crypto.mnemonicSentenceToString @mw Crypto.english

newtype MnemonicPhrase = MnemonicPhrase [ Text ]
  deriving (Show, Eq)

-- TODO Allow 24-word phrases
mkMnemonicPhrase :: [Text] -> Maybe MnemonicPhrase
mkMnemonicPhrase lst
  | length lst == 12 = Just $ MnemonicPhrase lst
  | length lst == 24 = Just $ MnemonicPhrase lst
  | otherwise = Nothing

readPhraseFromFile :: FilePath -> IO (Maybe MnemonicPhrase)
readPhraseFromFile keyfile = mkMnemonicPhrase . T.words . T.strip <$> T.readFile keyfile

readPhraseFromHandle :: Handle -> IO (Maybe MnemonicPhrase)
readPhraseFromHandle h = mkMnemonicPhrase . T.words . T.strip <$> T.hGetContents h

-- TODO: Don't expose constructor; only create with 'mkKeyIndex'
newtype KeyIndex = KeyIndex { unKeyIndex :: Natural }
  deriving (Eq, Ord, Show, Read, Num, Enum)

fromKeyIndex :: KeyIndex -> Word32
fromKeyIndex = fromIntegral . naturalToInteger . unKeyIndex

phraseToSeed :: MnemonicPhrase -> Crypto.Seed
phraseToSeed (MnemonicPhrase lst) =
  let phraseMap = wordsToPhraseMap lst
      phrase = catchMnemonicError $ Crypto.mnemonicPhrase @12 $ textTo <$> Map.elems phraseMap
      sentence = catchMnemonicError $ Crypto.mnemonicPhraseToMnemonicSentence Crypto.english phrase
  in sentenceToSeed sentence
  where
    catchMnemonicError = either (error "Invalid Mnemonic") id

phraseToEitherSeed :: MnemonicPhrase -> Either String Crypto.Seed
phraseToEitherSeed (MnemonicPhrase lst) =
  case length lst of
    12 -> do
        phrase <- first show $ Crypto.mnemonicPhrase @12 phraseWords
        sentence <- first show $ Crypto.mnemonicPhraseToMnemonicSentence Crypto.english phrase
        pure $ sentenceToSeed sentence
    24 -> do
        phrase <- first show $ Crypto.mnemonicPhrase @24 phraseWords
        sentence <- first show $ Crypto.mnemonicPhraseToMnemonicSentence Crypto.english phrase
        pure $ sentenceToSeed sentence

    _ -> Left "Unknown Mnemonic Length"

  where
    phraseWords = textTo <$> (Map.elems $ wordsToPhraseMap lst)

-- for generation
sentenceToSeed :: Crypto.ValidMnemonicSentence mw => Crypto.MnemonicSentence mw -> Crypto.Seed
sentenceToSeed s = Crypto.sentenceToSeed s Crypto.english ""

-- |Takes a n-sentence crypto seed and a password, and produces an encrypted key that can be
-- unlocked with the password
-- TODO: enter password 2x, to confirm
seedToRoot :: ByteArrayAccess ba => ba -> Maybe Text -> Crypto.XPrv
seedToRoot seed password = Crypto.generate seed $ T.encodeUtf8 $ fromMaybe "" password

-- | Convenience function for unpacking byte array things into 'Text'
newtype WordKey = WordKey { _unWordKey :: Int }
  deriving (Show, Eq, Ord, Enum)

wordsToPhraseMap :: [Text] -> Map.Map WordKey Text
wordsToPhraseMap = Map.fromList . zip [WordKey 1 ..]

data KadenaKey
  = HDRoot ByteString (Maybe Text) --Seed + Maybe Chaibnweaver password
  | PlainKeyPair SecretKey PublicKey

data KeyPairYaml = KeyPairYaml
  { kpyPublic :: Text
  , kpySecret :: Text
  } deriving (Eq,Ord,Show,Read)

instance FromJSON KeyPairYaml where
  parseJSON = withObject "KeyPairYaml" $ \o -> do
    pubText <- o .: "public"
    secText <- o .: "secret"
    pure $ KeyPairYaml pubText secText

readKadenaKey :: Handle -> IO (Either String KadenaKey)
readKadenaKey h = do
  !rawStr <- withoutInputEcho $ T.hGetChunk h
  hClose h
  let t = T.strip rawStr
  case YA.decode1Strict $ T.encodeUtf8 t of
    Right (String s) -> runExceptT $
      ExceptT (decodeMnemonic t) <|> ExceptT (decodeEncryptedMnemonic s)
    Right v@(Object _) -> case fromJSON v of
      Error _ -> pure $ Left "Object is not valid key material"
      Success kpy -> do
        let mres = do
              pub <- maybeCryptoError . ED25519.publicKey =<< hush (fromB16 $ kpyPublic kpy)
              sec <- maybeCryptoError . ED25519.secretKey =<< hush (fromB16 $ kpySecret kpy)
              pure $ PlainKeyPair (PlainSecretKey sec) (PlainPublicKey pub)
        pure $ note "not a valid ED25519 key pair" mres
    Right _ -> pure $ Left "Invalid JSON type for key material"
    Left _ -> pure $ Left "Could not parse key material"

decodeMnemonic :: Text -> IO (Either String KadenaKey)
decodeMnemonic t = do
  case mkMnemonicPhrase $ T.words t of
    Nothing -> pure $ Left "not a valid mnemonic phrase"
    Just phrase -> do
       case phraseToEitherSeed phrase of
         Left _ -> pure $ Left "failed converting phrase to seed"
         Right seed -> pure $ Right $ HDRoot (BA.convert seed) Nothing

decodeEncryptedMnemonic :: Text -> IO (Either String KadenaKey)
decodeEncryptedMnemonic t =
  -- We now that a valid encrypted key has a length of 128
  case (BS.length seed) of
    128 -> do
      hSetBuffering stderr NoBuffering
      hPutStr stderr "Enter password to decrypt key: "
      pass <- T.pack <$> withoutInputEcho getLine
      hPutStrLn stderr ""
      return $ Right $ HDRoot seed (Just pass)
    _ -> pure $ Left "Could not decode HD key"

  where
    seed = (fromRight BS.empty . B16.decodeBase16Untyped . T.encodeUtf8) t

genPairFromPhrase :: MnemonicPhrase -> KeyIndex -> (SecretKey, PublicKey)
genPairFromPhrase phrase idx =
  generateCryptoPairFromRoot (mnemonicToRoot phrase) Nothing idx


data SecretKey = CardanoSecretKey Crypto.XPrv
               | PlainSecretKey ED25519.SecretKey

data PublicKey = CardanoPublicKey ByteString
               | PlainPublicKey ED25519.PublicKey
  deriving (Eq, Show)


newtype Signature = Signature Text
  deriving (Eq, Ord, Show)

newtype ParsedSignature = ParsedSignature ByteString
  deriving (Eq, Ord, Show)

parseSignature :: Text -> Either Text ParsedSignature
parseSignature x = do
  bs <- fromB16 x
  case BS.length bs of
    64 ->  pure $ ParsedSignature bs
    _ -> Left "Signature must be 128 hex characters"

pubKeyToText :: PublicKey -> Text
pubKeyToText (CardanoPublicKey pk) = toB16 pk
pubKeyToText (PlainPublicKey pk) = toB16 $ BA.convert pk

toPubKey :: Text -> Either Text PublicKey
toPubKey txt = do
  bs <- fromB16 txt
  case BS.length bs of
    32 -> pure $ CardanoPublicKey bs
    _ -> Left "PublicKey should be 64 hex characters"


sign :: SecretKey -> Maybe Text -> ByteString -> Signature
sign (CardanoSecretKey xprv) mpass = Signature . toB16 . Crypto.unXSignature . Crypto.sign @ByteString (T.encodeUtf8 (fromMaybe "" mpass)) xprv
sign (PlainSecretKey xprv) _ = Signature . toB16 . BA.convert . ED25519.sign xprv (ED25519.toPublic xprv)

verify :: PublicKey -> ParsedSignature -> ByteString -> Bool
verify (CardanoPublicKey pub) (ParsedSignature sig) msg = Crypto.verify xpub msg $ either (error . show) id $ Crypto.xsignature sig
  where
    dummyChainCode = BS.replicate 32 minBound
    xpub = case Crypto.xpub $ pub <> dummyChainCode of
              Right x -> x
              Left _ -> error "Invalid Public key"
verify (PlainPublicKey _ ) _ _ = error "Unsupported"

baToText :: ByteArrayAccess b => b -> Text
baToText = T.decodeUtf8 . BA.pack . BA.unpack

textTo :: IsString a => Text -> a
textTo = fromString . T.unpack

toB16 :: ByteString -> Text
toB16 = extractBase16 . B16.encodeBase16

fromB16 :: Text -> Either Text ByteString
fromB16 txt = B16.decodeBase16Untyped $ T.encodeUtf8 txt

readNatural :: String -> Maybe Natural
readNatural = readMaybe

fileOrStdin :: FilePath -> IO Handle
fileOrStdin fp =
  case fp of
    "-" -> pure stdin
    _ -> openFile fp ReadMode
