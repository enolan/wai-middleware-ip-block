{-# LANGUAGE DeriveGeneric, FlexibleInstances, OverloadedStrings,
             RecordWildCards, ScopedTypeVariables #-}
{-|
Module:      Network.Wai.Middleware.IpBlock
Description: Block incoming requests based on IP CIDR ranges.
Copyright:   (c) Echo Nolan 2017
License:     BSD-3
Maintainer:  echo@echonolan.net
Stability:   Experimental
Portability: GHC

This module contains WAI middlewares that block incoming requests based on IP
CIDR ranges specified in a YAML configuration file. Here's an example:

@
defaultAllow: false
trustForwardedFor: true
routeSpecs:
  - range: "67.189.87.218"
    allow: true
  - range: "20.20.0.0/16"
    allow: true
  - range: "20.20.1.0/24"
    allow: false
@

The @defaultAllow@ key determines what happens to a request when it doesn't
reside inside any of the specified ranges.

@trustForwardedFor@ determines whether the @X-Forwarded-For@ HTTP is used if
present. Note that if you aren't using a reverse proxy, an attacker can set
@X-Forwarded-For@ to anything they like, bypassing your rules.

Each item in @routeSpecs@ is composed of either a CIDR range or a single IP,
along with whether to allow requests from there. The rules are prioritized by
specificity.

In the above example, requests are denied by default. If a request comes from
@67.189.87.218@, it's allowed. If it comes from @20.20.*@, it's allowed, unless
it comes from @20.20.1.*@.

-}
module Network.Wai.Middleware.IpBlock
    ( ipBlockMiddlewareFromFile
    , ipBlockMiddlewareFromFileEnv
    , ipBlockMiddlewareFromString
    , ipBlockMiddleware
    , basicDenyResponse
    , BlockConfig(..)
    , RouteSpec(..)
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

-- | Block requests, creating a 'BlockConfig' yourself rather than using the
--   YAML format.
ipBlockMiddleware ::
     Response    -- ^ The 'Response' to send when denying a request
  -> BlockConfig -- ^ Blocking configuration
  -> Middleware
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

-- | Block requests, getting the configuration from a 'B.ByteString'.
ipBlockMiddlewareFromString ::
     B.ByteString -- ^ The YAML configuration.
  -> Response -- ^ The 'Response' to send when denying a request
  -> Middleware
ipBlockMiddlewareFromString cfgString denyResponse =
  case decodeEither cfgString of
    Right cfg ->
      ipBlockMiddleware denyResponse cfg
    Left einfo -> error $
      "wai-middleware-ip-block: parsing config failed: " <> show einfo

-- | Block requests using a configuration file.
ipBlockMiddlewareFromFile ::
     FilePath -- ^ The location of the configuration file.
  -> Response -- ^ The 'Response' to send when denying a request
  -> IO Middleware
ipBlockMiddlewareFromFile path denyResponse = do
  mbTable <- decodeFileEither path
  case mbTable of
    Right cfg ->
      pure $ ipBlockMiddleware denyResponse cfg
    Left err  -> do
      hPutStrLn stderr $ "wai-middleware-ip-block file parsing failed: " <> show err
      exitFailure

-- | Block requests using a configuration file whose path is specified in an
--   environment variable.
ipBlockMiddlewareFromFileEnv ::
     String   -- ^ The environment variable
  -> Response -- ^ The 'Response' to send when denying a request
  -> IO Middleware
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

-- | A 'Response' for blocked requests. Sends status 403 Forbidden and the
--   string "Request blocked by wai-middleware-ip-block"
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
