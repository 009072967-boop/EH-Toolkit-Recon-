# Source policy

EthicalHawk Recon only collects information through the sources below. Every adapter lives in
`app/services/recon/` and implements the same `ReconAdapter` interface so this list stays accurate.

## Sources used

| Source | How it's accessed | Rate/scope limits |
| --- | --- | --- |
| Public recursive DNS | `dnspython` queries to standard resolvers | One query per record type per run |
| RDAP (`rdap.org`) | Single HTTPS GET per run | Bootstraps to the correct registry; no auth |
| Certificate Transparency (`crt.sh`) | Single HTTPS GET per run | Public CT log search, standard passive-recon technique |
| Wikipedia REST summary + opensearch APIs | HTTPS GET, official MediaWiki API endpoints | Built for programmatic access; no key required |
| Wikidata (`wikidata.org` API) | `wbgetentities` via the official MediaWiki API, item resolved from the confirmed Wikipedia article | 2-4 GETs per run; structured company background, official social accounts, founders/CEO/chair/board |
| SEC EDGAR (`data.sec.gov`, `sec.gov/Archives`) | Official submissions JSON + raw Form 3/4 XML, only for SEC registrants (CIK taken from Wikidata) | 1 + at most 25 GETs per run, 3 concurrent, identified User-Agent with `SEC_CONTACT_EMAIL` per SEC fair-access policy |
| The confirmed organization's own domain | HTTPS GET to `/`, a small fixed list of conventional paths (`/press`, `/leadership`, `/security.txt`, ...), and same-domain links from those pages whose path/text match about/team/leadership-style keywords (one bounded extra hop) | robots.txt is checked before every fetch; SSRF-guarded; capped response size; never leaves the confirmed domain/subdomains |

## What is explicitly not done

- No scraping of general-purpose search engines (Google, Bing, etc.) — those results would be
  outside the source's own API terms for automated collection.
- No open-ended crawling — link following is limited to keyword-matched pages on the confirmed
  domain, capped per label, with a single bounded second hop.
- No professional-network (e.g. LinkedIn) scraping for the People & Organization category, and no
  staff enumeration or email-address guessing. That category holds only professional names and
  titles the organization or a public record already publishes: Wikidata role statements, SEC
  Form 3/4 insider filings (directors/officers as filed), and the organization's own
  leadership/team pages (schema.org `Person` markup or name/title text). Only name and title are
  kept — Form 4 owner addresses and any `email`/`telephone` fields in page markup are never read.
  Customer testimonials (`Review.author`) and product/case-study pages are excluded, since they
  name people outside the organization.
- Social accounts are organization brand accounts only: LinkedIn is limited to `/company/` pages,
  and share/intent links are ignored.
- Public Profile runs store only Web Presence and Domains results, enforced in the pipeline
  (`MODE_CATEGORIES`) regardless of what a shared adapter returns.
- No authentication, no bypassing of paywalls/access controls/rate limits.
- No collection of personal contact details, credentials, or financial data.

## Safety controls (see also `docs/THREAT_MODEL.md`)

- `app/services/ssrf_guard.py` blocks requests to private/loopback/link-local/reserved address
  space and re-validates every redirect hop, for the two adapters that fetch a target-controlled
  URL (homepage + conventional paths).
- `app/services/recon/base.py::robots_allows` checks `robots.txt` before every fetch to the
  target's own domain.
- Per-run adapter concurrency, a global concurrent-job cap, a per-user hourly run limit, and a
  `RECON_KILL_SWITCH` environment flag are enforced in `app/services/pipeline.py` / `app/background.py`.
- Every adapter failure is caught individually (`AdapterError`) so one blocked/flaky source
  degrades a run to "incomplete source coverage" rather than failing the whole run or crashing
  the worker.
