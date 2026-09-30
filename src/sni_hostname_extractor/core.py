"""Parse a TLS ClientHello record and extract the SNI hostname.

The input is the raw bytes of a single TLS record as captured on the wire,
starting at the ContentType byte (0x16 for Handshake). We do not reassemble
across multiple records; the caller is responsible for handing us a complete
ClientHello in one buffer. This keeps the parser small and side-effect free.
"""

from __future__ import annotations


class SNIExtractionError(ValueError):
    """Raised when the byte stream cannot be parsed as a ClientHello carrying an SNI.

    A plain ValueError would do, but a named subclass lets callers distinguish
    parse failures from other ValueErrors they may raise themselves.
    """


def _read_uint(data: bytes, offset: int, length: int) -> int:
    if offset + length > len(data):
        raise SNIExtractionError("unexpected end of stream")
    return int.from_bytes(data[offset:offset + length], "big")


def _expect(data: bytes, offset: int, expected: bytes, what: str) -> int:
    if offset + len(expected) > len(data):
        raise SNIExtractionError(f"unexpected end of stream while reading {what}")
    actual = data[offset:offset + len(expected)]
    if actual != expected:
        raise SNIExtractionError(
            f"expected {what} {expected.hex()} but got {actual.hex()}"
        )
    return offset + len(expected)


def parse_client_hello(data: bytes) -> str | None:
    """Parse a TLS record and return the SNI hostname, or None if absent.

    Raises SNIExtractionError for malformed input. Returning None when the
    Server Name extension is simply not present is intentional: there is a
    real difference between "broken bytes" and "a valid ClientHello that
    omits SNI", and callers need to tell them apart.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SNIExtractionError("input must be bytes-like")
    data = bytes(data)
    if len(data) < 5:
        raise SNIExtractionError("record too short")

    # --- TLS record layer (RFC 5246 §6.2.1) ---
    off = 0
    off = _expect(data, off, b"\x16", "ContentType (handshake)")
    # Legacy version field: we accept 0x0301 (TLS 1.0) through 0x0304 (TLS 1.3).
    # Real captures use 0x0301 here regardless of negotiated version.
    legacy_version = _read_uint(data, off, 2)
    off += 2
    if legacy_version < 0x0301 or legacy_version > 0x0304:
        raise SNIExtractionError(f"unsupported legacy record version 0x{legacy_version:04x}")
    record_length = _read_uint(data, off, 2)
    off += 2
    if off + record_length > len(data):
        raise SNIExtractionError("record length exceeds available bytes")
    record = data[off:off + record_length]

    # --- Handshake layer (RFC 5246 §7.4) ---
    if len(record) < 4:
        raise SNIExtractionError("handshake message too short")
    hs_type = record[0]
    if hs_type != 0x01:
        raise SNIExtractionError(f"expected ClientHello (0x01), got 0x{hs_type:02x}")
    hs_length = int.from_bytes(record[1:4], "big")
    if 4 + hs_length > len(record):
        raise SNIExtractionError("handshake length exceeds record body")
    body = record[4:4 + hs_length]

    # --- ClientHello body (RFC 5246 §7.4.1.2) ---
    p = 0
    # client_version (2) + random (32)
    if len(body) < 34:
        raise SNIExtractionError("ClientHello body too short for version+random")
    p = 34
    # session_id
    if p >= len(body):
        raise SNIExtractionError("truncated before session_id length")
    sid_len = body[p]; p += 1
    if p + sid_len > len(body):
        raise SNIExtractionError("session_id overruns body")
    p += sid_len
    # cipher_suites
    if p + 2 > len(body):
        raise SNIExtractionError("truncated before cipher_suites length")
    cs_len = int.from_bytes(body[p:p + 2], "big"); p += 2
    if p + cs_len > len(body):
        raise SNIExtractionError("cipher_suites overruns body")
    p += cs_len
    # compression_methods
    if p >= len(body):
        raise SNIExtractionError("truncated before compression_methods length")
    cm_len = body[p]; p += 1
    if p + cm_len > len(body):
        raise SNIExtractionError("compression_methods overruns body")
    p += cm_len

    # extensions
    if p == len(body):
        return None  # No extensions block at all — valid, just no SNI.
    if p + 2 > len(body):
        raise SNIExtractionError("truncated before extensions length")
    ext_total = int.from_bytes(body[p:p + 2], "big"); p += 2
    if p + ext_total > len(body):
        raise SNIExtractionError("extensions block overruns body")
    ext_end = p + ext_total

    while p + 4 <= ext_end:
        ext_type = int.from_bytes(body[p:p + 2], "big"); p += 2
        ext_len = int.from_bytes(body[p:p + 2], "big"); p += 2
        if p + ext_len > ext_end:
            raise SNIExtractionError("extension length exceeds extensions block")
        ext_data = body[p:p + ext_len]
        p += ext_len
        if ext_type != 0x0000:
            continue
        return _parse_sni_extension(ext_data)

    return None


def _parse_sni_extension(ext_data: bytes) -> str:
    """Parse the server_name extension (RFC 6066 §3).

    The extension carries a ServerNameList. We only honour host_name (type 0);
    other name types are defined by the RFC but are not used in practice and
    we do not try to interpret them.
    """
    if len(ext_data) < 2:
        raise SNIExtractionError("server_name extension too short for list length")
    list_len = int.from_bytes(ext_data[0:2], "big")
    if 2 + list_len > len(ext_data):
        raise SNIExtractionError("ServerNameList length exceeds extension data")
    q = 2
    end = 2 + list_len
    while q + 3 <= end:
        name_type = ext_data[q]; q += 1
        name_len = int.from_bytes(ext_data[q:q + 2], "big"); q += 2
        if q + name_len > end:
            raise SNIExtractionError("server name length exceeds list")
        if name_type != 0x00:
            q += name_len
            continue
        raw = ext_data[q:q + name_len]
        try:
            hostname = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SNIExtractionError("SNI hostname is not valid ASCII") from exc
        if not _is_valid_hostname(hostname):
            raise SNIExtractionError(f"invalid SNI hostname: {hostname!r}")
        return hostname
    raise SNIExtractionError("server_name extension present but contains no host_name entry")


def _is_valid_hostname(hostname: str) -> bool:
    """Minimal hostname sanity check.

    We do not attempt full DNS-label validation (RFC 1035 §2.3.1 is long and
    mostly irrelevant to SNI extraction). We reject empty names, names with
    interior NULs, and names exceeding 253 bytes — enough to catch garbage
    without rejecting anything a real TLS client would send.
    """
    if not hostname:
        return False
    if len(hostname) > 253:
        return False
    if "\x00" in hostname:
        return False
    return True


def extract_sni(data: bytes) -> str | None:
    """Convenience wrapper around parse_client_hello.

    Exists so callers have a short, intention-revealing name to import.
    """
    return parse_client_hello(data)
