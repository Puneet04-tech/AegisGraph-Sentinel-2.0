import hashlib
from pathlib import Path

from src.api.main import _hash_file_sha256


def test_hash_file_sha256_streams_in_requested_chunk_size(monkeypatch):
    payload = b"0123456789"
    read_sizes = []

    class FakeHandle:
        def __init__(self):
            self.offset = 0

        def read(self, size=-1):
            read_sizes.append(size)
            if self.offset >= len(payload):
                return b""

            if size < 0:
                size = len(payload) - self.offset

            chunk = payload[self.offset:self.offset + size]
            self.offset += len(chunk)
            return chunk

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: FakeHandle())

    digest = _hash_file_sha256(Path("graph.graphml"), chunk_size=4)

    assert digest == hashlib.sha256(payload).hexdigest()
    assert read_sizes == [4, 4, 4, 4]
