{-# LANGUAGE OverloadedStrings #-}
module IpBlockTest where

import Network.Wai.Middleware.IpBlock

import qualified Data.ByteString.Char8 as BC
import Data.IP
import Network.HTTP.Types
import Network.Socket (SockAddr(..))
import Network.Wai
import Network.Wai.Test
import Test.Tasty.HUnit

basicMiddleware :: BlockConfig -> Middleware
basicMiddleware = ipBlockMiddleware basicDenyResponse

basicBlockConfig :: BlockConfig
basicBlockConfig = BlockConfig
  {defaultAllow = False, trustForwardedFor = False, routeSpecs = []}

case_noRouteSpecsDeny :: IO ()
case_noRouteSpecsDeny = do
  res <- runApp "2.3.4.5" (basicMiddleware basicBlockConfig) defaultRequest
  assertEqual "status code" forbidden403 (simpleStatus res)

case_noRouteSpecsAllow :: IO ()
case_noRouteSpecsAllow = do
  res <- runApp
    "2.3.4.5"
    (basicMiddleware basicBlockConfig {defaultAllow = True})
    defaultRequest
  assertEqual "status code" ok200 (simpleStatus res)

routeSpecsBlockConfig :: BlockConfig
routeSpecsBlockConfig =
  basicBlockConfig {routeSpecs = [
                       RouteSpec {range = "4.4.0.0/16", allow = True},
                       RouteSpec {range = "4.4.2.0/24", allow = False}]}

case_routeSpecsDefault :: IO ()
case_routeSpecsDefault = do
  res <- runApp "2.3.4.5" (basicMiddleware routeSpecsBlockConfig) defaultRequest
  assertEqual "status code" forbidden403 (simpleStatus res)

case_routeSpecsOuter :: IO ()
case_routeSpecsOuter = do
  res <-
    runApp "4.4.1.100" (basicMiddleware routeSpecsBlockConfig) defaultRequest
  assertEqual "status code" ok200 (simpleStatus res)

case_routeSpecsInner :: IO ()
case_routeSpecsInner = do
  res <-
    runApp "4.4.2.25" (basicMiddleware routeSpecsBlockConfig) defaultRequest
  assertEqual "status code" forbidden403 (simpleStatus res)

case_forwardedForDeny :: IO ()
case_forwardedForDeny = do
  res <-
    runApp
    "4.4.1.1"
    (basicMiddleware routeSpecsBlockConfig {trustForwardedFor = True})
    $ setForwardedFor "1.2.3.4" defaultRequest
  assertEqual "status code" forbidden403 (simpleStatus res)

case_forwardedForAllow :: IO ()
case_forwardedForAllow = do
  res <-
    runApp
    "1.2.3.4"
    (basicMiddleware routeSpecsBlockConfig {trustForwardedFor = True})
    $ setForwardedFor "4.4.1.1" defaultRequest
  assertEqual "status code" ok200 (simpleStatus res)

case_forwardedForIgnored :: IO ()
case_forwardedForIgnored = do
  res <-
    runApp
    "1.2.3.4"
    (basicMiddleware routeSpecsBlockConfig)
    $ setForwardedFor "4.4.1.1" defaultRequest
  assertEqual "status code" forbidden403 (simpleStatus res)

setForwardedFor :: IPv4 -> Request -> Request
setForwardedFor ip req = req { requestHeaders = requestHeaders'}
  where
  requestHeaders' =  ("X-Forwarded-For", BC.pack $ show ip) : requestHeaders req

runApp :: IPv4 -> Middleware -> Request -> IO SResponse
runApp ip mw req = runSession (request req') $ mw app
  where
  app _ respond = respond $ responseLBS status200 [] ""
  req' = req { remoteHost = SockAddrInet 32451 $ toHostAddress ip }
