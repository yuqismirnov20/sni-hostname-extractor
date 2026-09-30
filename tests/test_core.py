import unittest

from sni_hostname_extractor import extract_sni, parse_client_hello, SNIExtractionError


def _build_client_hello(hostname: str | None = None, *, legacy_version: int = 0x0301) -> bytes:
    """Assemble a minimal ClientHello record for testing.

    Keeping the builder here, next to the tests, means the tests are
    self-describing: you can read exactly which bytes produce which case.
    """
    if hostname is not None:
        name_bytes = hostname.encode("ascii")
        server_name_entry = b"\x00" + len(name_bytes).to_bytes(2, "big") + name_bytes
        server_name_list = len(server_name_entry).to_bytes(2, "big") + server_name_entry
        ext = b"\x00\x00" + len(server_name_list).to_bytes(2, "big") + server_name_list
        extensions = len(ext).to_bytes(2, "big") + ext
    else:
        extensions = b"\x00\x00"

    body = (
        b"\x03\x03"  # client_version
        + b"\x00" * 32  # random
        + b"\x00"  # session_id length 0
        + b"\x00\x2d"  # cipher_suites length 45
        + b"\xc0\x2c\xc0\x2b\xc0\x30\xc0\x2f\x00\x9e\x00\x9f\x00\xa2\x00\xa3\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\xba\x00\xc0\x00\xbc\x00\x0a\x00\xff\x01\x00\x00\x67\x00\x00\x00\x16\x00\x00\x00"
        + b"\x01"  # compression_methods length 1
        + b"\x00"  # null compression
        + extensions
    )

    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16" + legacy_version.to_bytes(2, "big") + len(handshake).to_bytes(2, "big") + handshake
    return record


class TestHappyPath(unittest.TestCase):
    def test_extracts_simple_hostname(self):
        data = _build_client_hello("example.org")
        self.assertEqual(extract_sni(data), "example.org")

    def test_parse_and_extract_are_aliases(self):
        data = _build_client_hello("host.example.org")
        self.assertEqual(parse_client_hello(data), extract_sni(data))

    def test_no_sni_extension_returns_none(self):
        data = _build_client_hello(None)
        self.assertIsNone(extract_sni(data))

    def test_accepts_tls12_legacy_version(self):
        data = _build_client_hello("a.io", legacy_version=0x0303)
        self.assertEqual(extract_sni(data), "a.io")

    def test_accepts_tls13_legacy_version(self):
        data = _build_client_hello("b.io", legacy_version=0x0304)
        self.assertEqual(extract_sni(data), "b.io")


class TestMalformed(unittest.TestCase):
    def test_empty_input_raises(self):
        with self.assertRaises(SNIExtractionError):
            extract_sni(b"")

    def test_non_handshake_content_type_raises(self):
        data = _build_client_hello("x.io")
        data = b"\x17" + data[1:]  # 0x17 = ApplicationData
        with self.assertRaises(SNIExtractionError):
            extract_sni(data)

    def test_non_clienthello_handshake_type_raises(self):
        data = bytearray(_build_client_hello("x.io"))
        # handshake type is at offset 5 (record header 5 bytes)
        data[5] = 0x02  # ServerHello
        with self.assertRaises(SNIExtractionError):
            extract_sni(bytes(data))

    def test_unsupported_legacy_version_raises(self):
        data = _build_client_hello("x.io", legacy_version=0x0200)
        with self.assertRaises(SNIExtractionError):
            extract_sni(data)

    def test_record_length_exceeds_buffer_raises(self):
        data = bytearray(_build_client_hello("x.io"))
        # Inflate the record length field (bytes 3-4) beyond available data.
        data[3:5] = (9999).to_bytes(2, "big")
        with self.assertRaises(SNIExtractionError):
            extract_sni(bytes(data))

    def test_non_bytes_input_raises(self):
        with self.assertRaises(SNIExtractionError):
            extract_sni("not bytes")  # type: ignore[arg-type]

    def test_memoryview_input_works(self):
        data = memoryview(_build_client_hello("mv.io"))
        self.assertEqual(extract_sni(data), "mv.io")


class TestSNIEdgeCases(unittest.TestCase):
    def test_trailing_garbage_after_record_ignored(self):
        data = _build_client_hello("trail.io") + b"\xff\xff\xff"
        self.assertEqual(extract_sni(data), "trail.io")

    def test_other_extension_before_sni(self):
        # Build a ClientHello with a non-SNI extension first, then SNI.
        name_bytes = b"after.io"
        sne = b"\x00" + len(name_bytes).to_bytes(2, "big") + name_bytes
        snl = len(sne).to_bytes(2, "big") + sne
        sni_ext = b"\x00\x00" + len(snl).to_bytes(2, "big") + snl
        # ec_point_formats (type 0x000b), one byte payload
        other_ext = b"\x00\x0b" + b"\x00\x01" + b"\x00"
        exts = len(sni_ext + other_ext).to_bytes(2, "big") + other_ext + sni_ext
        body = (
            b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + b"\x00\x02\xc0\x2c"
            + b"\x01\x00"
            + exts
        )
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
        self.assertEqual(extract_sni(record), "after.io")

    def test_sni_with_non_host_name_entry_then_host_name(self):
        # ServerNameList with a non-host entry (type 0x01) followed by a host entry.
        host = b"mixed.io"
        host_entry = b"\x00" + len(host).to_bytes(2, "big") + host
        other_entry = b"\x01" + b"\x00\x03" + b"abc"
        snl = len(other_entry + host_entry).to_bytes(2, "big") + other_entry + host_entry
        sni_ext = b"\x00\x00" + len(snl).to_bytes(2, "big") + snl
        exts = len(sni_ext).to_bytes(2, "big") + sni_ext
        body = (
            b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + b"\x00\x02\xc0\x2c"
            + b"\x01\x00"
            + exts
        )
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
        self.assertEqual(extract_sni(record), "mixed.io")

    def test_sni_extension_with_no_host_name_entry_raises(self):
        # ServerNameList containing only a non-host entry.
        other_entry = b"\x01" + b"\x00\x03" + b"abc"
        snl = len(other_entry).to_bytes(2, "big") + other_entry
        sni_ext = b"\x00\x00" + len(snl).to_bytes(2, "big") + snl
        exts = len(sni_ext).to_bytes(2, "big") + sni_ext
        body = (
            b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + b"\x00\x02\xc0\x2c"
            + b"\x01\x00"
            + exts
        )
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
        with self.assertRaises(SNIExtractionError):
            extract_sni(record)

    def test_non_ascii_hostname_raises(self):
        name_bytes = "café.io".encode("utf-8")
        sne = b"\x00" + len(name_bytes).to_bytes(2, "big") + name_bytes
        snl = len(sne).to_bytes(2, "big") + sne
        sni_ext = b"\x00\x00" + len(snl).to_bytes(2, "big") + snl
        exts = len(sni_ext).to_bytes(2, "big") + sni_ext
        body = (
            b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + b"\x00\x02\xc0\x2c"
            + b"\x01\x00"
            + exts
        )
        hs = b"\x01" + len(body).to_bytes(3, "big") + body
        record = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
        with self.assertRaises(SNIExtractionError):
            extract_sni(record)


if __name__ == "__main__":
    unittest.main()
