"""Unit tests for the feature hashing encoder."""

import pytest

from src.features.hashing_encoder import (
    HashingEncoder,
    encode_sentence,
    ngram_tokens,
)


class TestHashingEncoderTransform:
    def test_transform_returns_index_in_range(self):
        encoder = HashingEncoder(n_features=100)
        for value in ["fraud", "benign", "mule", "acct_123"]:
            mapped = encoder.transform(value)
            assert 0 <= mapped["index"] < 100
            assert mapped["sign"] in (-1, 1)

    def test_transform_is_deterministic(self):
        encoder = HashingEncoder(n_features=50, seed=7)
        assert encoder.transform("acct") == encoder.transform("acct")

    def test_transform_deterministic_across_instances(self):
        a = HashingEncoder(n_features=50, seed=7)
        b = HashingEncoder(n_features=50, seed=7)
        assert a.transform("value") == b.transform("value")

    def test_transform_handles_non_string(self):
        encoder = HashingEncoder()
        assert encoder.transform(123) == encoder.transform("123")
        assert encoder.transform(None) == encoder.transform("")

    def test_different_seeds_produce_different_indices(self):
        a = HashingEncoder(n_features=1000, seed=1)
        b = HashingEncoder(n_features=1000, seed=2)
        values = [f"v{i}" for i in range(50)]
        different = sum(
            1 for v in values if a.transform(v)["index"] != b.transform(v)["index"]
        )
        assert different >= 40

    def test_init_rejects_non_positive_features(self):
        with pytest.raises(ValueError):
            HashingEncoder(n_features=0)


class TestHashingEncoderVectorize:
    def test_vectorize_length(self):
        encoder = HashingEncoder(n_features=10)
        vector = encoder.vectorize("cat")
        assert len(vector) == 10

    def test_vectorize_sparse_with_sign(self):
        encoder = HashingEncoder(n_features=10)
        vector = encoder.vectorize("cat")
        mapped = encoder.transform("cat")
        non_zero = [i for i, v in enumerate(vector) if v != 0]
        assert non_zero == [mapped["index"]]
        assert vector[mapped["index"]] == mapped["sign"]

    def test_vectorize_deterministic(self):
        encoder = HashingEncoder(n_features=10)
        assert encoder.vectorize("x") == encoder.vectorize("x")

    def test_encode_returns_int_index(self):
        encoder = HashingEncoder(n_features=10)
        index = encoder.encode("x")
        assert isinstance(index, int)
        assert 0 <= index < 10
        assert index == encoder.transform("x")["index"]


class TestNgramTokens:
    def test_basic_bigrams(self):
        assert ngram_tokens("abc", n=2) == ["ab", "bc"]

    def test_lowercases_input(self):
        assert ngram_tokens("ABC", n=2) == ["ab", "bc"]

    def test_n_greater_than_length(self):
        assert ngram_tokens("ab", n=3) == []

    def test_empty_text(self):
        assert ngram_tokens("", n=2) == []

    def test_single_char_bigram(self):
        assert ngram_tokens("a", n=2) == []

    def test_trigram(self):
        assert ngram_tokens("abcd", n=3) == ["abc", "bcd"]

    def test_strips_whitespace(self):
        assert ngram_tokens("  abc  ", n=2) == ["ab", "bc"]

    def test_rejects_non_positive_n(self):
        with pytest.raises(ValueError):
            ngram_tokens("abc", n=0)


class TestEncodeSentence:
    def test_returns_vector_of_correct_length(self):
        vector = encode_sentence("hello world", n_features=50)
        assert len(vector) == 50

    def test_deterministic(self):
        assert encode_sentence("hello") == encode_sentence("hello")

    def test_has_non_zero_entries(self):
        vector = encode_sentence("fraud transaction alert", n_features=30)
        assert any(v != 0 for v in vector)

    def test_different_texts_differ(self):
        a = encode_sentence("account take over", n_features=200)
        b = encode_sentence("wire transfer", n_features=200)
        assert a != b

    def test_empty_text_yields_zero_vector(self):
        vector = encode_sentence("", n_features=20)
        assert vector == [0] * 20
