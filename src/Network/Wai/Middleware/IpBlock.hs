{-# Language OverloadedStrings, ScopedTypeVariables #-}
module Network.Wai.Middleware.IpBlock
    ( ipBlockMiddleware
    , ipBlockMiddlewareFromFile
    , ipBlockMiddlewareFromString
    , basicDenyResponse
    ) where

import Prelude hiding (lookup)

import Control.Monad
import qualified Data.ByteString.Char8 as B
import Data.IP
import Data.IP.RouteTable
import Data.Maybe
import Data.Semigroup
import Network.HTTP.Types
import Network.Socket (SockAddr(..))
import Network.Wai
import System.Exit
import System.IO
import Text.Read (readMaybe)
import Text.Trifecta hiding (Parser, dot)
import qualified Text.Trifecta as Tri

ipBlockMiddleware :: Response -> IPRTable IPv4 Bool -> Middleware
ipBlockMiddleware denyResponse iprt app req respond = do
  let forwarded = listToMaybe $
        filter (\(nm, _) -> nm == "X-Forwarded-For") $ requestHeaders req
      mbIncomingIP = case forwarded of
        Nothing -> case remoteHost req of
          SockAddrInet _ hostAddr -> Just $ fromHostAddress hostAddr
          _ -> Nothing
        Just (_, val) -> readMaybe $ B.unpack $ B.takeWhile (/= ',') val
  case mbIncomingIP of
    Nothing -> do
      hPutStrLn stderr $
        "wai-middleware-ip-block: Got request with unparsable IP:\n" <> show req
      respond denyResponse
    Just ip -> if shouldAllow ip iprt
      then app req respond
      else respond denyResponse

ipBlockMiddlewareFromString :: String -> Response -> Middleware
ipBlockMiddlewareFromString cfgString denyResponse =
  case parseString (runUnlined configParser) mempty cfgString of
    Success table -> ipBlockMiddleware denyResponse table
    Failure einfo -> error $
      "wai-middleware-ip-block: parsing config failed: " <> show einfo

ipBlockMiddlewareFromFile :: FilePath -> Response -> IO Middleware
ipBlockMiddlewareFromFile path denyResponse = do
  mbTable <- parseFromFile (runUnlined configParser) path
  case mbTable of
    Just table -> return $ ipBlockMiddleware denyResponse table
    Nothing    -> do
      hPutStrLn stderr "wai-middleware-ip-block file parsing failed, exiting"
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

{-
default deny
67.189.87.218 allow
20.20.0.0/16 allow
20.20.1.0/24 deny
-}

type Parser = Unlined Tri.Parser

configParser :: Parser (IPRTable IPv4 Bool)
configParser = fmap go configParser'
  where
  go :: (Bool, [(AddrRange IPv4, Bool)]) -> IPRTable IPv4 Bool
  go (defaultAllow, specs) =
     foldl
     (\tbl (addrRange, allow) -> insert addrRange allow tbl)
     empty $ ("0.0.0.0/0", defaultAllow) : specs

configParser' :: Parser (Bool, [(AddrRange IPv4, Bool)])
configParser' = do
  _ <- textSymbol "default"
  defaultAllow <- routingActionParser
  _ <- newline
  specs <- many (routingSpecParser <* newline)
  return (defaultAllow, specs)

routingSpecParser :: Parser (AddrRange IPv4, Bool)
routingSpecParser = do
  addrRange <- addrRangeParser
  someSpace
  act <- routingActionParser
  pure (addrRange, act)

addrRangeParser :: Parser (AddrRange IPv4)
addrRangeParser = try $ do
  let dot :: Parser () = void $ char '.'
  a <- ipOctetParser <* dot
  b <- ipOctetParser <* dot
  c <- ipOctetParser <* dot
  d <- ipOctetParser
  mbBits <- optional $ char '/' >> conditionalDecimalParser (<=32) "mask subnet bits > 32!"
  let ip = toIPv4 [a,b,c,d]
  return $ makeAddrRange ip (fromMaybe 32 mbBits)

ipOctetParser :: Parser Int
ipOctetParser = conditionalDecimalParser (<256) "Octet in IP >= 256!"

conditionalDecimalParser :: (Integer -> Bool) -> String -> Parser Int
conditionalDecimalParser f msg = decimal >>=
  (\i -> if f i
         then pure $ fromIntegral i
         else fail msg)

routingActionParser :: Parser Bool
routingActionParser = choice
  [symbol "deny" >> pure False, symbol "allow" >> pure True]
