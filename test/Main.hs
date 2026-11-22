{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import           Control.Monad     (unless)
import           Data.Aeson        (Result (..), Value (..), eitherDecode',
                                    fromJSON, object, (.=))
import qualified Data.Aeson.KeyMap as KeyMap
import           HttpTests         (httpTests)
import           VirusTotal

main :: IO ()
main = do
  -- Synthetic documentation-shaped response; no live API request or real target.
  accepts "complete IPv4 report" (report "192.0.2.1" attributes) expected
  accepts "IPv6 report" (report "2001:db8::1" attributes)
    expected { ipAddress = "2001:db8::1" }
  accepts "missing optional attributes" (report "192.0.2.1" (object [])) emptyReport
  accepts "null optional attributes" (report "192.0.2.1" (object
    ["reputation" .= Null, "total_votes" .= Null, "last_analysis_stats" .= Null,
     "last_analysis_date" .= Null, "country" .= Null, "asn" .= Null,
     "as_owner" .= Null])) emptyReport
  accepts "unknown attributes" (withAttr "future_field" (object [])) expected
  accepts "zero reputation is present" (withAttr "reputation" (Number 0))
    expected { ipReputation = Just 0 }
  rejects "wrong resource type" (object ["data" .= object
    ["type" .= String "domain", "id" .= String "192.0.2.1", "attributes" .= attributes]])
  rejects "missing envelope" attributes
  rejects "API error envelope" (object ["error" .= object ["code" .= String "NotFoundError"]])
  rejects "missing ID" (object ["data" .= object
    ["type" .= String "ip_address", "attributes" .= attributes]])
  rejects "missing type" (object ["data" .= object
    ["id" .= String "192.0.2.1", "attributes" .= attributes]])
  rejects "missing attributes" (object ["data" .= object
    ["id" .= String "192.0.2.1", "type" .= String "ip_address"]])
  rejects "null attributes" (report "192.0.2.1" Null)
  rejects "wrong reputation type" (withAttr "reputation" (String "-10"))
  rejects "fractional reputation" (withAttr "reputation" (Number 0.5))
  rejects "wrong country type" (withAttr "country" (Number 1))
  rejects "negative ASN" (withAttr "asn" (Number (-1)))
  rejects "fractional timestamp" (withAttr "last_analysis_date" (Number 1.5))
  rejects "incomplete statistics" (withAttr "last_analysis_stats" (object []))
  rejects "negative verdict count" (withAttr "last_analysis_stats"
    (stats (Number (-1))))
  rejects "fractional verdict count" (withAttr "last_analysis_stats"
    (stats (Number 0.5)))
  rejects "incomplete votes" (withAttr "total_votes" (object ["harmless" .= (0 :: Int)]))
  rejects "negative votes" (withAttr "total_votes" (object
    ["harmless" .= (0 :: Int), "malicious" .= (-1 :: Int)]))
  case eitherDecode' "{broken" :: Either String IpReport of
    Left _  -> pure ()
    Right _ -> fail "malformed JSON accepted"
  putStrLn "All 24 IP report parsing tests passed."
  httpTests

report :: Value -> Value -> Value
report address attrs = object ["data" .= object
  ["id" .= address, "type" .= String "ip_address", "attributes" .= attrs]]

attributes :: Value
attributes = object
  ["reputation" .= (-10 :: Int), "total_votes" .= object
    ["harmless" .= (1 :: Int), "malicious" .= (2 :: Int)],
   "last_analysis_stats" .= stats (Number 2),
   "last_analysis_date" .= (1700000000 :: Integer),
   "country" .= String "ZZ", "asn" .= (64512 :: Int),
   "as_owner" .= String "Example network"]

stats :: Value -> Value
stats malicious = object
  ["harmless" .= (3 :: Int), "malicious" .= malicious,
   "suspicious" .= (1 :: Int), "timeout" .= (0 :: Int), "undetected" .= (4 :: Int)]

withAttr :: KeyMap.Key -> Value -> Value
withAttr key value = case attributes of
  Object attrs -> report "192.0.2.1" (Object (KeyMap.insert key value attrs))
  _            -> error "Expected object fixture"

expected :: IpReport
expected = IpReport "192.0.2.1" (Just (-10)) (Just (CommunityVotes 1 2))
  (Just (AnalysisStats 3 2 1 0 4)) (Just 1700000000)
  (Just "ZZ") (Just 64512) (Just "Example network")

emptyReport :: IpReport
emptyReport = IpReport "192.0.2.1" Nothing Nothing Nothing Nothing Nothing Nothing Nothing

accepts :: String -> Value -> IpReport -> IO ()
accepts label value wanted = case fromJSON value of
  Success actual -> unless (actual == wanted) (fail (label ++ ": unexpected result"))
  Error message -> fail (label ++ ": " ++ message)

rejects :: String -> Value -> IO ()
rejects label value = case fromJSON value :: Result IpReport of
  Error _   -> pure ()
  Success _ -> fail (label ++ ": unexpectedly accepted")
