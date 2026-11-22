{-# LANGUAGE OverloadedStrings #-}

-- | A small client for the VirusTotal API v3.
module VirusTotal
  ( Client
  , newClient
  , newClientWithManager
  , VirusTotalError (..)
  , getIpReport
  , IpReport (..)
  , AnalysisStats (..)
  , CommunityVotes (..)
  ) where

import           Control.Exception       (catch)
import           Data.Aeson              (FromJSON (..), eitherDecode',
                                          withObject, (.:), (.:?))
import           Data.Aeson.Types        (Parser)
import           Data.IP                 (IP)
import           Data.Text               (Text)
import qualified Data.Text               as Text
import qualified Data.Text.Encoding      as Text
import qualified Network.HTTP.Client     as HTTP
import           Network.HTTP.Client.TLS (tlsManagerSettings)
import           Network.HTTP.Types      (statusCode, urlEncode)
import           Numeric.Natural         (Natural)
import           Text.Read               (readMaybe)

-- | An IP address report, decoded from the complete API response envelope.
-- Unknown fields are ignored. Missing or null attributes become 'Nothing',
-- preserving the distinction between unavailable information and a zero value.
-- The ID is retained as text; this parser does not validate IP syntax.
data IpReport = IpReport
  { ipAddress           :: Text
    -- ^ Report ID (IPv4 or IPv6 address).
  , ipReputation        :: Maybe Integer
    -- ^ Community score: negative indicates malicious votes, positive harmless.
    -- This is separate from scanner verdict counts.
  , ipTotalVotes        :: Maybe CommunityVotes
    -- ^ Unweighted community votes.
  , ipLastAnalysisStats :: Maybe AnalysisStats
    -- ^ Scanner verdict counts. Undetected means no opinion, not harmless.
  , ipLastAnalysisDate  :: Maybe Integer
    -- ^ Last analysis time as Unix seconds in UTC.
  , ipCountry           :: Maybe Text
    -- ^ Country code.
  , ipAsn               :: Maybe Natural
    -- ^ Autonomous system number.
  , ipAsOwner           :: Maybe Text
    -- ^ Autonomous system owner.
  } deriving (Eq, Show)

-- | Nonnegative scanner verdict counts. All five documented fields are
-- required when the statistics object is present; unknown fields are ignored.
data AnalysisStats = AnalysisStats
  { analysisHarmless   :: Natural
  , analysisMalicious  :: Natural
  , analysisSuspicious :: Natural
  , analysisTimeout    :: Natural
  , analysisUndetected :: Natural
  } deriving (Eq, Show)

-- | Nonnegative, unweighted community vote counts. Both fields are required
-- when the votes object is present.
data CommunityVotes = CommunityVotes
  { votesHarmless  :: Natural
  , votesMalicious :: Natural
  } deriving (Eq, Show)

instance FromJSON IpReport where
  parseJSON = withObject "IP report response" $ \response -> do
    resource <- response .: "data"
    withObject "IP address resource" (\obj -> do
      resourceType <- obj .: "type" :: Parser Text
      if resourceType /= "ip_address"
        then fail "Expected ip_address resource"
        else do
          address <- obj .: "id"
          attributes <- obj .: "attributes"
          withObject "IP address attributes" (\attrs ->
            IpReport address
              <$> attrs .:? "reputation"
              <*> attrs .:? "total_votes"
              <*> attrs .:? "last_analysis_stats"
              <*> attrs .:? "last_analysis_date"
              <*> attrs .:? "country"
              <*> attrs .:? "asn"
              <*> attrs .:? "as_owner") attributes) resource

instance FromJSON AnalysisStats where
  parseJSON = withObject "Analysis statistics" $ \obj ->
    AnalysisStats
      <$> obj .: "harmless"
      <*> obj .: "malicious"
      <*> obj .: "suspicious"
      <*> obj .: "timeout"
      <*> obj .: "undetected"

instance FromJSON CommunityVotes where
  parseJSON = withObject "Community votes" $ \obj ->
    CommunityVotes <$> obj .: "harmless" <*> obj .: "malicious"


-- | An opaque client. Its 'Show' instance hides the API key.
data Client = Client HTTP.Manager Text

instance Show Client where
  show _ = "Client <redacted>"

-- | Create a client with a reusable TLS connection manager.
newClient :: Text -> IO Client
newClient key = do
  manager <- HTTP.newManager tlsManagerSettings
  pure (newClientWithManager manager key)

-- | Use a caller-managed connection manager. Its request hooks can inspect the
-- authentication header; use only trusted hooks and avoid logging secrets.
newClientWithManager :: HTTP.Manager -> Text -> Client
newClientWithManager = Client

-- | Failures omit response bodies and transport exception details so they
-- cannot expose the API key. HTTP errors retain their status code.
data VirusTotalError
  = InvalidIpAddress -- ^ Input is not an IPv4 or IPv6 address.
  | InvalidApiKey -- ^ API key is empty or contains non-visible ASCII characters.
  | HttpError Int -- ^ Non-200 response, including 401, 403, 404, and 429.
  | InvalidResponse -- ^ Malformed JSON, wrong response shape, or mismatched ID.
  | NetworkError -- ^ HTTP transport failure (including timeout).
  deriving (Eq, Show)

-- | Retrieve an IP reputation report using @GET /api/v3/ip_addresses/{ip}@.
-- Validates IP syntax before sending a request. Uses HTTPS and @x-apikey@,
-- a 30-second response timeout, and no redirects or automatic status retries.
-- Network failures are returned; asynchronous cancellation still propagates.
getIpReport :: Client -> Text -> IO (Either VirusTotalError IpReport)
getIpReport (Client manager key) address =
  case readMaybe (Text.unpack address) :: Maybe IP of
    Nothing -> pure (Left InvalidIpAddress)
    Just parsed
      | Text.null key || not (Text.all (\c -> c >= '!' && c <= '~') key) ->
          pure (Left InvalidApiKey)
      | otherwise -> action parsed `catch` handleHttpException
  where
    request = HTTP.defaultRequest
      { HTTP.secure = True
      , HTTP.host = "www.virustotal.com"
      , HTTP.port = 443
      , HTTP.path = "/api/v3/ip_addresses/" <> urlEncode True (Text.encodeUtf8 address)
      , HTTP.requestHeaders =
          [("Accept", "application/json"), ("x-apikey", Text.encodeUtf8 key)]
      , HTTP.redirectCount = 0
      , HTTP.responseTimeout = HTTP.responseTimeoutMicro 30000000
      , HTTP.checkResponse = \_ _ -> pure ()
      }
    action parsed = do
      response <- HTTP.httpLbs request manager
      let status = statusCode (HTTP.responseStatus response)
      pure $ if status /= 200
        then Left (HttpError status)
        else case eitherDecode' (HTTP.responseBody response) of
          Right info | (readMaybe (Text.unpack (ipAddress info)) :: Maybe IP)
                        == Just parsed -> Right info
          _ -> Left InvalidResponse

handleHttpException :: HTTP.HttpException -> IO (Either VirusTotalError a)
handleHttpException _ = pure (Left NetworkError)
