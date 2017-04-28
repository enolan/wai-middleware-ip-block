{-# LANGUAGE DeriveGeneric, FlexibleInstances, OverloadedStrings,
             RecordWildCards, ScopedTypeVariables #-}
module Network.Wai.Middleware.IpBlock
    ( ipBlockMiddleware
    , ipBlockMiddlewareFromFile
    , ipBlockMiddlewareFromFileEnv
    , ipBlockMiddlewareFromString
    , basicDenyResponse
    ) where

import Prelude hiding (lookup)

import Data.Aeson.Types (typeMismatch)
import qualified Data.ByteString.Char8 as B
import qualified Data.HashMap.Lazy as HM
import Data.IP
import Data.IP.RouteTable
import Data.Maybe
import Data.Semigroup
import qualified Data.Text as T
import Data.Yaml hiding (Parser)
import GHC.Generics
import Network.HTTP.Types
import Network.Socket (SockAddr(..))
import Network.Wai
import System.Environment (lookupEnv)
import System.Exit
import System.IO
import Text.Read (readMaybe)

ipBlockMiddleware :: Response -> BlockConfig -> Middleware
ipBlockMiddleware denyResponse BlockConfig{..} app req respond = do
  let forwardedHdr = listToMaybe $
        filter (\(nm, _) -> nm == "X-Forwarded-For") $ requestHeaders req
      sockIp = case remoteHost req of
          SockAddrInet _ hostAddr -> Just $ fromHostAddress hostAddr
          _                        -> Nothing
      mbIncomingIP = case forwardedHdr of
        Nothing -> sockIp
        Just (_, val) -> if trustForwardedFor
          then readMaybe $ B.unpack $ B.takeWhile (/= ',') val
          else sockIp
      iprt = foldl
        (\tbl RouteSpec{..} -> insert range allow tbl)
        empty $
        (RouteSpec "0.0.0.0/0" defaultAllow) : routeSpecs
  case mbIncomingIP of
    Nothing -> do
      hPutStrLn stderr $
        "wai-middleware-ip-block: Got request with unparsable IP:\n" <> show req
      respond denyResponse
    Just ip -> if shouldAllow ip iprt
      then app req respond
      else respond denyResponse

ipBlockMiddlewareFromString :: B.ByteString -> Response -> Middleware
ipBlockMiddlewareFromString cfgString denyResponse =
  case decodeEither cfgString of
    Right cfg ->
      ipBlockMiddleware denyResponse cfg
    Left einfo -> error $
      "wai-middleware-ip-block: parsing config failed: " <> show einfo

ipBlockMiddlewareFromFile :: FilePath -> Response -> IO Middleware
ipBlockMiddlewareFromFile path denyResponse = do
  mbTable <- decodeFileEither path
  case mbTable of
    Right cfg ->
      pure $ ipBlockMiddleware denyResponse cfg
    Left err  -> do
      hPutStrLn stderr $ "wai-middleware-ip-block file parsing failed: " <> show err
      exitFailure

-- | Create an IP blocking middleware with a configuration stored it a file
--   named by an environment variable.
ipBlockMiddlewareFromFileEnv :: String -> Response -> IO Middleware
ipBlockMiddlewareFromFileEnv env denyResponse = do
  mbPath <- lookupEnv env
  case mbPath of
    Just path -> ipBlockMiddlewareFromFile path denyResponse
    Nothing   -> do
      hPutStrLn stderr $
        "wai-middleware-ip-block environment variable " <> env <> " not found"
      exitFailure

shouldAllow :: IPv4 -> IPRTable IPv4 Bool -> Bool
shouldAllow ip iprt = case lookup (makeAddrRange ip 32) iprt of
  Just res -> res
  Nothing -> error $
    "wai-middleware-ip-block: Routing table missing an IP: " <>
    show ip <>
    " this should never happen"

basicDenyResponse :: Response
basicDenyResponse = responseLBS
  forbidden403
  [(hContentType, "text/plain")]
  "Request blocked by wai-middleware-ip-block"

data BlockConfig = BlockConfig
  {defaultAllow :: Bool,
   trustForwardedFor :: Bool,
   routeSpecs :: [RouteSpec]}
  deriving (Generic, Show)

data RouteSpec = RouteSpec {range :: AddrRange IPv4, allow :: Bool}
  deriving (Generic, Show)

-- This is easier using generics, but it means creating orphans for AddrRange
-- and IPv4
instance ToJSON BlockConfig

instance ToJSON RouteSpec where
  toJSON spec = object [("range", rangeJSON), "allow" .= allow spec]
    where
    rangeJSON = String $ T.pack $ show $ range spec

instance FromJSON BlockConfig

instance FromJSON RouteSpec where
  parseJSON (Object o) = RouteSpec <$> parseAddrRange <*> o .: "allow"
    where parseAddrRange = case HM.lookup "range" o of
            Just (String str) -> case readMaybe $ T.unpack str of
              Just adr -> return adr
              Nothing -> fail "Couldn't parse IP range"
            Just somethingElse -> typeMismatch "address range" somethingElse
            Nothing -> fail "missing key range"
  parseJSON somethingElse = typeMismatch "RouteSpec" somethingElse
