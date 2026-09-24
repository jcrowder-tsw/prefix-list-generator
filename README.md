# bgpq4-arista

A tiny Flask service that wraps [`bgpq4`](https://github.com/bgp/bgpq4) and
returns prefix-list entries in the **`seq N permit X/Y [le N]` body format**
that Arista EOS expects when sourcing a prefix-list over HTTP
(`ip prefix-list NAME source http:...`).

Similar in spirit to [bgpq-proxy](https://github.com/peering-manager/bgpq-proxy),
but tailored to Arista's source-http loader instead of returning JSON.

## How it works

When Arista sources a prefix-list over HTTP, the switch already knows the
list name (from the parent `ip prefix-list NAME` command) and expects the
HTTP body to contain only the entries — `seq N permit X/Y [le N]` lines —
not bgpq4's default `ip prefix-list NAME permit ...` form.

So this service runs `bgpq4`, drops the `no ip prefix-list NAME` header,
strips the `ip|ipv6 prefix-list NAME ` prefix from each line, and prepends
sequence numbers starting at 1. The result is returned as `text/plain` and
goes straight into the switch's prefix-list when refreshed.

## Endpoints

```
GET /arista/as_set/<as-set>                # IPv4 — expand an AS-SET via IRR
GET /arista/as_set/<as-set>/v6             # IPv6
GET /arista/asn/<asn>                      # IPv4 — prefixes originated by a single ASN
GET /arista/asn/<asn>/v6                   # IPv6
GET /health
GET /
```

Any of the four list URLs takes an optional `/le/<N>` suffix (after `/v6`,
if present) to override the more-specifics allowance for that one list:

```
GET /arista/as_set/<as-set>/le/<N>         # IPv4, allow more-specifics up to /N
GET /arista/as_set/<as-set>/v6/le/<N>      # IPv6
GET /arista/asn/<asn>/le/<N>               # IPv4
GET /arista/asn/<asn>/v6/le/<N>            # IPv6
```

Notes:

- `<as-set>` is validated against a conservative IRR-object regex.
- `<asn>` accepts either `65000` or `AS65000` (case-insensitive); the value
  is normalized to `AS<n>` before being handed to `bgpq4`. Range-checked
  against the 32-bit AS space (`1..4294967295`).
- Family lives in the path (`/v6` suffix), not a query string — `?` is a glob
  character in zsh and tripped people up. The `/le/<N>` override is a path
  segment for the same reason.
- `/le/<N>` maps straight to `bgpq4 -R <N>` for that request. Without it the
  `BGPQ4_MAX_LENGTH_V4` / `_V6` default applies. Valid range is `0..32` for
  IPv4 and `0..128` for IPv6; anything else is a `400`. `0` means "omit `-R`"
  (exact route objects only, no `le` clause), mirroring the env-var
  semantics. Responses are cached per `(target, family, N)`, so a `/le/32`
  fetch never shares an entry with the default-policy fetch of the same
  object.

## Running

### Docker Compose

```sh
docker compose up -d --build
curl http://localhost:8080/arista/as_set/AS-HURRICANE
curl http://localhost:8080/arista/as_set/AS-HURRICANE/v6
curl http://localhost:8080/arista/asn/AS6939
curl http://localhost:8080/arista/asn/6939/v6
curl http://localhost:8080/arista/asn/AS6939/le/32
```

### Bare metal (dev)

```sh
apt-get install -y bgpq4
pip install -r requirements.txt
python app.py
```

## Configuration

All knobs are environment variables (see `docker-compose.yml`):

| Variable             | Default        | Notes                                                                   |
| -------------------- | -------------- | ----------------------------------------------------------------------- |
| `BGPQ4_CACHE_TTL`    | `3600`         | Seconds to cache each prefix-list in memory.                            |
| `BGPQ4_CACHE_MAX`    | `1024`         | Max distinct cached entries.                                            |
| `BGPQ4_SOURCES`      | *(empty)*      | Comma list passed to `bgpq4 -S`, e.g. `RIPE,RADB,APNIC,ARIN,NTTCOM`.    |
| `BGPQ4_HOST`         | *(empty)*      | IRR host (`bgpq4 -h`). Default = bgpq4 default (`rr.ntt.net`).          |
| `BGPQ4_AGGREGATE`    | `1`            | Pass `-A` (aggregate prefixes).                                         |
| `BGPQ4_MAX_LENGTH_V4`| `24`           | Pass `-R <N>` for IPv4. Aggregate but allow more-specifics up to /N. Set to `""` or `0` to omit `-R`. |
| `BGPQ4_MAX_LENGTH_V6`| `48`           | Same as above for IPv6. Default `/48` matches typical peering policy.   |
| `BGPQ4_TIMEOUT`      | `60`           | Subprocess timeout, seconds.                                            |
| `BGPQ4_BIN`          | `bgpq4`        | Path to bgpq4 binary.                                                   |
| `PORT`               | `8080`         | Listen port.                                                            |

With the defaults you get entries like `permit 4.7.0.0/16 le 24` for v4 and
`permit 2001:470::/32 le 48` for v6 — the AS-SET's aggregates plus any
more-specifics down to /24 (v4) and /48 (v6).

The env vars set the fleet-wide default. To loosen (or tighten) the allowance
for a single list, use the `/le/<N>` URL suffix instead of changing the env —
that way one PNI that needs to send you a /26 doesn't open up /26s from
everyone.

## Example response

```
$ curl -s http://localhost:8080/arista/as_set/AS-HURRICANE | head
seq 1 permit 4.7.0.0/16 le 24
seq 2 permit 5.39.96.0/19 le 24
seq 3 permit 8.7.198.0/24
seq 4 permit 12.0.0.0/8 le 24
...
```

Note the absence of `ip prefix-list NAME` on each line — that's intentional.
Arista's source-http loader prepends it from the parent declaration, so the
body returned here must contain only the entries. The prefix-list name lives
only on the switch; the URL no longer carries it.

## Arista EOS config example

On the switch:

```
! IPv4 — AS-SET
ip prefix-list PEER-HE source http:bgpq4-arista.example.net:8080/arista/as_set/AS-HURRICANE
!
! IPv6 — AS-SET
ipv6 prefix-list PEER-HE-V6 source http:bgpq4-arista.example.net:8080/arista/as_set/AS-HURRICANE/v6
!
! IPv4 — single ASN (prefixes originated by AS6939)
ip prefix-list HE-ORIG source http:bgpq4-arista.example.net:8080/arista/asn/AS6939
!
! IPv4 — PNI peer that needs to send us more-specifics down to /32
! (default policy elsewhere stays at /24; only this list uses -R 32)
ip prefix-list PNI-AS64496 source http:bgpq4-arista.example.net:8080/arista/asn/AS64496/le/32
```

> **Note:** Arista's CLI uses `http:` (single colon, no `//`) — it's not a
> standard URL form. The whole declaration is a single line; there's no
> indented `source` sub-command. The `http:` prefix is just how EOS spells
> "fetch this via HTTP." Use `https:` (same one-colon syntax) if you put a
> TLS terminator in front of the service.

Then refresh on demand:

```
switch# ip prefix-list PEER-HE refresh
```

…or schedule a periodic refresh via EOS event-handler / scheduler if you want
the switch to pull updates automatically.

## Notes / caveats

- The cache is per-worker, in-memory only. If you run multiple gunicorn workers
  each one warms its own cache. That's fine for this workload.
- IRR queries can be slow; the default 60s subprocess timeout protects the
  service from hanging requests.
- Input is regex-validated before being handed to `bgpq4`. The subprocess is
  invoked with an argument list (no shell), so shell metacharacters in the URL
  cannot cause command injection.
