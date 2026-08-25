# Hybrid ML-KEM TLS qualification

Hybrid TLS capability is supplied by the Python interpreter's native TLS library, not by the `azure-confidentialledger` package. Do not describe the package as supporting PQ TLS without naming a qualified Python distribution, operating system, and OpenSSL provider.

The manual live qualification prints Python and OpenSSL inventory; forces `X25519MLKEM768` with an external OpenSSL probe; runs an unforced OpenSSL handshake separately; and completes an authenticated `get_constitution()` SDK request.

Python's public `ssl` API cannot select or report TLS 1.3 named groups. The OpenSSL executable may also differ from the library loaded by Python. Consequently, the forced probe proves that the qualifying native environment can negotiate ML-KEM, while the SDK request proves that the normal Requests transport still works with certificate verification. A packet capture or server-side CCF telemetry is required to prove the SDK request's default negotiated group.

```bash
export AZURE_TEST_RUN_LIVE=true
export CONFIDENTIALLEDGER_RUN_HYBRID_TLS_QUALIFICATION=true
pytest -v -s tests/test_hybrid_ml_kem_tls.py
```

Set `CONFIDENTIALLEDGER_OPENSSL_PATH` when the qualifying OpenSSL executable is not on `PATH`.

## Support matrix

| Python distribution and OS | `ssl.OPENSSL_VERSION` | Forced external probe | SDK negotiated group | SDK request | Status |
| --- | --- | --- | --- | --- | --- |
| CPython 3.12.3 / Ubuntu 24.04 WSL2 | OpenSSL 3.0.13 | Failed: group unavailable | Not tested | Not run with hybrid evidence | Unsupported |
| Python 3.12 / Azure Linux 3 with SCOSSL 1.10 | To be captured | Pending | Requires packet/server telemetry | Pending | Not qualified |
| Python 3.9-3.13 / Linux with OpenSSL 3.5+ | To be captured per image | Pending | Requires packet/server telemetry | Pending | Not qualified |
| Python 3.9-3.13 / Windows | CPython OpenSSL build | Pending | Requires packet/server telemetry | Pending | Not qualified |

Classical fallback must remain enabled until every supported runtime row passes or is explicitly documented as an exception.