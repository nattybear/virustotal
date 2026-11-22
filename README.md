# virustotal

A small Haskell client for the VirusTotal API v3.

## Status

IP reputation HTTP requests, response types, and JSON parsing are implemented.

## Design

- Simple/Boring Haskell: ordinary records and explicit IO functions.
- Add dependencies and abstractions only when needed.
- Keep API keys out of source code and diagnostic output.
- Build one endpoint at a time.

## Build

Requires GHC 9.8.4 and Cabal.

```sh
cabal build
```

## IP reports

`IpReport` decodes the complete JSON response for `GET /api/v3/ip_addresses/{ip}`, which retrieves an
IPv4 or IPv6 address report.

The report includes:

- Community reputation score (`reputation`) and votes (`total_votes`).
- Scanner verdict counts (`last_analysis_stats`).
- Last analysis time (`last_analysis_date`).
- Country, ASN, and AS owner when available.

Community reputation and scanner verdicts are separate signals. An undetected
verdict does not establish that an IP address is harmless.

Use `Data.Aeson.eitherDecode` to decode JSON as `Either String IpReport`.
Missing or null report attributes become `Nothing`; zero values remain `Just 0`.
If statistics or votes are present, their documented count fields are required
and must be nonnegative integers. Unknown JSON fields are ignored.
The response must contain `data.id`, `data.type` equal to `ip_address`, and an
attributes object. IP IDs are retained as text without IP syntax validation.
Analysis timestamps are represented as integer Unix seconds in UTC.

## Tests

```sh
cabal test
```

Tests use synthetic responses and a local HTTP server. They do not need a real
API key or access to VirusTotal.

## Query an IP report

```haskell
{-# LANGUAGE OverloadedStrings #-}
import qualified Data.Text as Text
import System.Environment (getEnv)
import VirusTotal

main :: IO ()
main = do
  key <- Text.pack <$> getEnv "VIRUSTOTAL_API_KEY"
  client <- newClient key
  result <- getIpReport client "192.0.2.1"
  case result of
    Left err -> print err
    Right report -> print report
```

The example uses a documentation address; choose an IP you intend to query.
Reuse the client across calls. `getIpReport` validates IPv4/IPv6 syntax locally.
Keys must be nonempty visible ASCII without whitespace.

Failures are `InvalidIpAddress`, `InvalidApiKey`, `HttpError status`,
`InvalidResponse`, or `NetworkError`. HTTP errors include 401 (authentication),
403 (permission), 404 (not found), and 429 (quota or rate limit). Error values
omit response bodies and exception details to avoid exposing secrets.
A successful report must have an ID matching the queried IP address.

Requests use a 30-second response timeout, do not follow redirects, and do not
retry HTTP status errors. The caller decides when to retry. Async cancellation
propagates normally. For custom manager configuration, use
`newClientWithManager`; trusted request hooks can see the key and must not log it.

VirusTotal's endpoint documentation states that queried indicators may be
scanned and added to its community-accessible dataset. See the IP report
reference below before querying confidential indicators.

VirusTotal API v3 authenticates requests using the `x-apikey` header over HTTPS.

## References

- https://docs.virustotal.com/reference/overview
- https://docs.virustotal.com/reference/authentication
- https://docs.virustotal.com/reference/ip-info
- https://docs.virustotal.com/reference/ip-object
- https://docs.virustotal.com/reference/errors
