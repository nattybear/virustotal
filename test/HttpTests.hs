{-# LANGUAGE OverloadedStrings #-}
module HttpTests (httpTests) where

import Control.Exception (AsyncException (..), throwIO, try)
import Control.Monad (unless)
import Data.Aeson (encode, object, (.=))
import qualified Data.ByteString.Lazy as Lazy
import qualified Network.HTTP.Client as HTTP
import qualified Network.HTTP.Types as Status
import qualified Network.Wai as Wai
import Network.Wai.Handler.Warp (testWithApplication)
import VirusTotal

httpTests :: IO ()
httpTests = do
  let application request respond = do
        check "GET" (Wai.requestMethod request == "GET")
        check "path" (Wai.pathInfo request == ["api", "v3", "ip_addresses", "2001:db8::1"])
        check "no query" (null (Wai.queryString request))
        check "API key header" (lookup "x-apikey" (Wai.requestHeaders request) == Just "test-secret")
        check "accept header" (lookup "Accept" (Wai.requestHeaders request) == Just "application/json")
        respond (Wai.responseLBS Status.status200 [] (body "2001:db8:0:0:0:0:0:1"))
  withMock application $ \client -> do
    check "client redacted" (show client == "Client <redacted>")
    result <- getIpReport client "2001:db8::1"
    check "IPv6 equivalent ID" (result == Right
      (IpReport "2001:db8:0:0:0:0:0:1" Nothing Nothing Nothing Nothing Nothing Nothing Nothing))
  withMock (\_ respond -> respond (Wai.responseLBS Status.status200 [] (body "192.0.2.1"))) $ \client -> do
    result <- getIpReport client "192.0.2.1"
    check "IPv4 success" (result == Right
      (IpReport "192.0.2.1" Nothing Nothing Nothing Nothing Nothing Nothing Nothing))
  mapM_ (\status -> responseTest status "test-secret" (Left (HttpError (Status.statusCode status))))
    [Status.status400, Status.status401, Status.status403, Status.status404,
     Status.status429, Status.status500, Status.status204]
  responseTest Status.status200 "not JSON" (Left InvalidResponse)
  responseTest Status.status200 "{}" (Left InvalidResponse)
  responseTest Status.status200 (body "192.0.2.2") (Left InvalidResponse)
  withMock (\_ respond -> respond (Wai.responseLBS Status.status302
    [("Location", "https://example.invalid/secret")] "")) $ \client -> do
      result <- getIpReport client "192.0.2.1"
      check "redirect refused" (result == Left (HttpError 302))
  manager <- HTTP.newManager HTTP.defaultManagerSettings
    { HTTP.managerModifyRequest = \request -> do
        check "production host" (HTTP.host request == "www.virustotal.com")
        check "HTTPS" (HTTP.secure request && HTTP.port request == 443)
        throwIO (HTTP.HttpExceptionRequest request HTTP.ConnectionTimeout) }
  result <- getIpReport (newClientWithManager manager "test-secret") "192.0.2.1"
  check "network error redacted" (result == Left NetworkError)
  rejecting <- HTTP.newManager HTTP.defaultManagerSettings
    { HTTP.managerModifyRequest = \_ -> fail "Unexpected HTTP request" }
  mapM_ (\address -> do
    invalid <- getIpReport (newClientWithManager rejecting "test-secret") address
    check "invalid IP rejected locally" (invalid == Left InvalidIpAddress))
    ["", "example.com", "192.0.2.999", "192.0.2.1/path", "::gg", "192.0.2.1?key=x"]
  mapM_ (\key -> do
    invalid <- getIpReport (newClientWithManager rejecting key) "192.0.2.1"
    check "invalid key rejected locally" (invalid == Left InvalidApiKey)) ["", "bad\r\nkey", "한글"]
  cancelling <- HTTP.newManager HTTP.defaultManagerSettings
    { HTTP.managerModifyRequest = \_ -> throwIO ThreadKilled }
  cancelled <- try (getIpReport (newClientWithManager cancelling "test-secret") "192.0.2.1")
    :: IO (Either AsyncException (Either VirusTotalError IpReport))
  check "cancellation propagates" (cancelled == Left ThreadKilled)
  putStrLn "All HTTP tests passed."

body :: String -> Lazy.ByteString
body address = encode (object ["data" .= object
  ["type" .= ("ip_address" :: String), "id" .= address, "attributes" .= object []]])

withMock :: Wai.Application -> (Client -> IO a) -> IO a
withMock application action = testWithApplication (pure application) $ \port -> do
  manager <- HTTP.newManager HTTP.defaultManagerSettings
    { HTTP.managerModifyRequest = \request -> pure request
      { HTTP.secure = False, HTTP.host = "127.0.0.1", HTTP.port = port } }
  action (newClientWithManager manager "test-secret")

responseTest :: Status.Status -> Lazy.ByteString -> Either VirusTotalError IpReport -> IO ()
responseTest status payload expected =
  withMock (\_ respond -> respond (Wai.responseLBS status [] payload)) $ \client -> do
    actual <- getIpReport client "192.0.2.1"
    check "response handling" (actual == expected)

check :: String -> Bool -> IO ()
check label passed = unless passed (fail label)
