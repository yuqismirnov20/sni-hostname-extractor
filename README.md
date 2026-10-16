# SNI Hostname Extractor

Parses a TLS ClientHello byte stream and returns the Server Name Indication hostname.

```python
from sni_hostname_extractor import extract_sni, SNIExtractionError

record = b"\x16\x03\x01..."  # raw bytes from a captured TCP segment
try:
    hostname = extract_sni(record)
except SNIExtractionError as exc:
    hostname = None

# hostname is a str, or None when the ClientHello is valid but omits SNI.
```

The library exists for the narrow case where you have already captured a TCP
segment and need only the SNI value — not a full TLS stack, not a packet
capture framework, not a dependency tree. The trade-off is that it parses
exactly one TLS record and does not reassemble across segments. If your
capture might split the ClientHello across TCP segments, reassemble first.

`extract_sni` (alias: `parse_client_hello`) takes a bytes-like object and
returns `str | None`. It raises `SNIExtractionError`, a `ValueError` subclass,
for malformed input. The distinction between `None` and a raised error is
deliberate: a valid ClientHello that simply omits the Server Name extension
yields `None`, while truncated or structurally invalid bytes raise.

Edge case you will hit: the input must start at the TLS record layer
(ContentType `0x16`). If you hand it a buffer that begins inside the handshake
layer or includes an Ethernet/IP/TCP header, it will raise
`SNIExtractionError`. Strip link-layer and IP/TCP headers before calling.

The legacy record version field is accepted for values `0x0301`–`0x0304`.
Real ClientHellos use `0x0301` here regardless of the version actually
negotiated; the check exists to reject obviously non-TLS input, not to enforce
a specific TLS version.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

## Limitations

Values are coerced to floats, so very large integers lose precision. If you need
exact integer aggregates over a window, this is the wrong tool.

