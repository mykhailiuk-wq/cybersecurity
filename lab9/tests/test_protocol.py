"""Тести протоколу: розбір адрес, валідація полів, кадрування JSON."""

from __future__ import annotations

import socket
import threading
import unittest

from common.protocol import (
    MAX_MESSAGE_BYTES,
    ConnectionClosed,
    JsonChannel,
    ProtocolError,
    format_enroll_code,
    normalize_enroll_code,
    parse_endpoint,
    validate_user_id,
)


class EndpointTests(unittest.TestCase):
    def test_host_and_port(self) -> None:
        self.assertEqual(parse_endpoint("127.0.0.1:5555"), ("127.0.0.1", 5555))
        self.assertEqual(parse_endpoint("localhost"), ("localhost", 5555))
        self.assertEqual(parse_endpoint("192.168.0.10:1234"), ("192.168.0.10", 1234))
        self.assertEqual(parse_endpoint("[::1]:6000"), ("::1", 6000))
        self.assertEqual(parse_endpoint("[::1]"), ("::1", 5555))

    def test_invalid_endpoint(self) -> None:
        for value in ("", "   ", ":5555", "host:0", "host:70000", "host:abc"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_endpoint(value)


class ValidationTests(unittest.TestCase):
    def test_user_id(self) -> None:
        self.assertEqual(validate_user_id("student10"), "student10")
        self.assertEqual(validate_user_id("a.b-c_1"), "a.b-c_1")
        for value in ("ab", "a" * 65, "-bad", "bad space", "кирилиця"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_user_id(value)

    def test_enroll_code(self) -> None:
        normalized = normalize_enroll_code("abcd-1234-ef56-7890")
        self.assertEqual(normalized, "ABCD1234EF567890")
        self.assertEqual(format_enroll_code(normalized), "ABCD-1234-EF56-7890")
        for value in ("", "xyz", "ABCD"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_enroll_code(value)


class ChannelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.left, self.right = socket.socketpair()
        self.left.settimeout(2)
        self.right.settimeout(2)
        self.addCleanup(self.left.close)
        self.addCleanup(self.right.close)
        self.writer = JsonChannel(self.left)
        self.reader = JsonChannel(self.right)
        self.addCleanup(self.writer.close)
        self.addCleanup(self.reader.close)

    def test_round_trip(self) -> None:
        message = {"type": "hello", "id": "student10", "text": "кирилиця"}
        self.writer.send(message)
        self.assertEqual(self.reader.recv(), message)

    def test_invalid_json_is_rejected(self) -> None:
        self.left.sendall(b"not-json\n")
        with self.assertRaises(ProtocolError):
            self.reader.recv()

    def test_non_object_is_rejected(self) -> None:
        self.left.sendall(b"[1, 2, 3]\n")
        with self.assertRaises(ProtocolError):
            self.reader.recv()

    def test_closed_connection(self) -> None:
        # makefile() тримає власне посилання на сокет, тому закриваємо
        # напрямок запису — читач отримає EOF.
        self.left.shutdown(socket.SHUT_WR)
        with self.assertRaises(ConnectionClosed):
            self.reader.recv()

    def test_oversized_message_is_rejected(self) -> None:
        payload = b'{"x":"' + b"A" * (MAX_MESSAGE_BYTES + 10) + b'"}\n'
        thread = threading.Thread(target=self.left.sendall, args=(payload,))
        thread.start()
        self.addCleanup(thread.join, 2)
        with self.assertRaises(ProtocolError):
            self.reader.recv()


if __name__ == "__main__":
    unittest.main()
