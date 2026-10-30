"""Модульні тести політики Белла-ЛаПадула без категорій."""

from __future__ import annotations

import unittest

from common.security import (
    ALL_RIGHTS,
    authorize,
    effective_rights,
    level_name,
    mandatory_check,
    mandatory_create_check,
    parse_level,
    parse_rights,
    parse_role,
    rights_text,
    sorted_rights,
    validate_object_name,
)


class LevelTests(unittest.TestCase):
    def test_aliases_and_numbers(self) -> None:
        for value, expected in (
            (1, 1),
            ("1", 1),
            ("U", 1),
            ("public", 1),
            ("CONFIDENTIAL", 2),
            ("S", 3),
            ("TOP_SECRET", 4),
            ("top secret", 4),
        ):
            with self.subTest(value=value):
                self.assertEqual(parse_level(value), expected)

    def test_names(self) -> None:
        self.assertEqual(level_name(1), "UNCLASSIFIED")
        self.assertEqual(level_name(4), "TOP_SECRET")

    def test_invalid_levels(self) -> None:
        for value in (0, 5, "SECRET-2", "", True, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_level(value)


class RightTests(unittest.TestCase):
    def test_parse_rights(self) -> None:
        self.assertEqual(parse_rights("read, append"), {"read", "append"})
        self.assertEqual(parse_rights(["write", "delete"]), {"write", "delete"})
        self.assertEqual(parse_rights("", allow_empty=True), set())
        self.assertEqual(parse_rights("r,a", allow_empty=True), {"read", "append"})

    def test_owner_cannot_be_granted(self) -> None:
        with self.assertRaises(ValueError):
            parse_rights("owner")

    def test_unknown_right(self) -> None:
        with self.assertRaises(ValueError):
            parse_rights("execute")

    def test_rights_order(self) -> None:
        self.assertEqual(
            rights_text({"delete", "read", "owner", "append", "write"}),
            "owner, read, append, write, delete",
        )
        self.assertEqual(sorted_rights({"write", "read"}), ["read", "write"])

    def test_object_name(self) -> None:
        self.assertEqual(validate_object_name("report-2026.txt"), "report-2026.txt")
        for value in ("", "-bad", "a" * 65, "кирилиця", "with space"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_object_name(value)

    def test_roles(self) -> None:
        self.assertEqual(parse_role("ADMIN"), "admin")
        self.assertEqual(parse_role("user"), "user")
        with self.assertRaises(ValueError):
            parse_role("root")


class MandatoryTests(unittest.TestCase):
    def test_read_no_read_up(self) -> None:
        self.assertTrue(mandatory_check("read", 3, 2)[0])
        self.assertTrue(mandatory_check("read", 2, 2)[0])
        self.assertFalse(mandatory_check("read", 1, 2)[0])

    def test_append_no_write_down(self) -> None:
        self.assertTrue(mandatory_check("append", 1, 2)[0])
        self.assertTrue(mandatory_check("append", 2, 2)[0])
        self.assertFalse(mandatory_check("append", 3, 2)[0])

    def test_write_requires_equal_level(self) -> None:
        self.assertTrue(mandatory_check("write", 2, 2)[0])
        self.assertFalse(mandatory_check("write", 3, 2)[0])
        self.assertFalse(mandatory_check("write", 1, 2)[0])

    def test_delete_is_not_mandatory(self) -> None:
        for subject in (1, 2, 3, 4):
            self.assertTrue(mandatory_check("delete", subject, 3)[0])

    def test_create_cannot_write_down(self) -> None:
        self.assertTrue(mandatory_create_check(2, 3)[0])
        self.assertTrue(mandatory_create_check(2, 2)[0])
        self.assertFalse(mandatory_create_check(2, 1)[0])


class AuthorizeTests(unittest.TestCase):
    def test_owner_has_all_rights_but_mandatory_still_applies(self) -> None:
        rights = effective_rights("alice", "alice", set())
        self.assertEqual(rights, set(ALL_RIGHTS))
        allowed, reason = authorize(
            "read",
            user_id="alice",
            owner_id="alice",
            subject_level=2,
            object_level=3,
            acl_rights=set(),
        )
        self.assertFalse(allowed)
        self.assertIn("no-read-up", reason)

    def test_acl_right_is_required(self) -> None:
        allowed, reason = authorize(
            "read",
            user_id="bob",
            owner_id="alice",
            subject_level=4,
            object_level=1,
            acl_rights=set(),
        )
        self.assertFalse(allowed)
        self.assertIn("дискреційна", reason)

    def test_acl_and_mandatory_must_both_allow(self) -> None:
        self.assertTrue(
            authorize(
                "read",
                user_id="bob",
                owner_id="alice",
                subject_level=4,
                object_level=1,
                acl_rights={"read"},
            )[0]
        )
        self.assertFalse(
            authorize(
                "read",
                user_id="bob",
                owner_id="alice",
                subject_level=1,
                object_level=2,
                acl_rights={"read"},
            )[0]
        )


if __name__ == "__main__":
    unittest.main()
