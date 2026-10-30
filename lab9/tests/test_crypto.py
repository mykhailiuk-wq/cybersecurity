"""Модульні тести криптографічних примітивів."""

from __future__ import annotations

import unittest

from common.crypto import (
    HASHES,
    algorithm_spec,
    compute_response,
    digest,
    new_secret,
    normalize_algorithm,
    random_bytes,
)


class AlgorithmTests(unittest.TestCase):
    def test_names_are_normalised(self) -> None:
        self.assertEqual(normalize_algorithm("SHA256"), "SHA256")
        self.assertEqual(normalize_algorithm("sha-256"), "SHA256")
        self.assertEqual(normalize_algorithm(" sha_256 "), "SHA256")
        self.assertEqual(normalize_algorithm("CALG_SHA_256"), "SHA256")
        self.assertEqual(normalize_algorithm("CALG_SHA1"), "SHA1")
        self.assertEqual(normalize_algorithm("md5"), "MD5")

    def test_unknown_algorithm_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            normalize_algorithm("ROT13")
        with self.assertRaises(ValueError):
            normalize_algorithm("")

    def test_digest_sizes_match_cryptoapi_spec(self) -> None:
        for name, spec in HASHES.items():
            with self.subTest(algorithm=name):
                self.assertEqual(len(digest(name, b"data")), spec.digest_size)
                self.assertEqual(algorithm_spec(name), spec)


class ResponseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = b"0123456789abcdef0123456789abcdef"
        self.challenge = bytes(range(32))
        self.user_id = "student10"

    def test_response_is_deterministic(self) -> None:
        first = compute_response("SHA256", self.secret, self.challenge, self.user_id)
        second = compute_response("SHA256", self.secret, self.challenge, self.user_id)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 32)

    def test_response_depends_on_every_input(self) -> None:
        base = compute_response("SHA256", self.secret, self.challenge, self.user_id)
        self.assertNotEqual(
            base, compute_response("SHA512", self.secret, self.challenge, self.user_id)
        )
        self.assertNotEqual(
            base,
            compute_response("SHA256", b"x" * 32, self.challenge, self.user_id),
        )
        self.assertNotEqual(
            base,
            compute_response("SHA256", self.secret, b"\x00" * 32, self.user_id),
        )
        self.assertNotEqual(
            base,
            compute_response("SHA256", self.secret, self.challenge, "other-user"),
        )

    def test_response_uses_selected_hash_function(self) -> None:
        for name, spec in HASHES.items():
            with self.subTest(algorithm=name):
                response = compute_response(
                    name, self.secret, self.challenge, self.user_id
                )
                self.assertEqual(len(response), spec.digest_size)


class RandomTests(unittest.TestCase):
    def test_random_bytes(self) -> None:
        self.assertEqual(random_bytes(0), b"")
        self.assertEqual(len(random_bytes(1)), 1)
        self.assertEqual(len(random_bytes(32)), 32)
        self.assertNotEqual(random_bytes(32), random_bytes(32))

    def test_new_secret_default_length(self) -> None:
        self.assertEqual(len(new_secret()), 32)
        self.assertEqual(len(new_secret(16)), 16)

    def test_negative_size_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            random_bytes(-1)


if __name__ == "__main__":
    unittest.main()
