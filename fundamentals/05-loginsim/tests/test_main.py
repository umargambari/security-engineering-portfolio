"""Tests for Login Simulator."""

import os
import tempfile
import pytest

from src.main import (
    hash_password,
    verify_password,
    register_user,
    login_user,
    get_user_status,
)


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.remove(path)  # start with a non-existent file, like a fresh install
    yield path
    if os.path.exists(path):
        os.remove(path)


class TestPasswordHashing:
    def test_hash_password_returns_valid_bcrypt_hash(self):
        hashed = hash_password("correcthorsebattery")
        assert hashed.startswith("$2b$")

    def test_hash_password_same_password_different_hashes(self):
        h1 = hash_password("samepassword")
        h2 = hash_password("samepassword")
        assert h1 != h2

    def test_verify_password_correct(self):
        hashed = hash_password("mypassword")
        assert verify_password("mypassword", hashed) is True


class TestRegistration:
    def test_register_new_user(self, temp_db):
        result = register_user("alice", "password123", db_path=temp_db)
        assert result is True
        status = get_user_status("alice", db_path=temp_db)
        assert status is not None

    def test_register_duplicate_returns_false(self, temp_db):
        register_user("bob", "password123", db_path=temp_db)
        result = register_user("bob", "differentpassword", db_path=temp_db)
        assert result is False

    def test_stored_password_is_hashed(self, temp_db):
        register_user("carol", "plaintextpassword", db_path=temp_db)
        status = get_user_status("carol", db_path=temp_db)
        # Re-load raw to inspect the stored hash directly
        import json
        with open(temp_db) as f:
            users = json.load(f)
        assert users["carol"]["password_hash"] != "plaintextpassword"
        assert users["carol"]["password_hash"].startswith("$2b$")


class TestLogin:
    def test_login_correct_credentials(self, temp_db):
        register_user("dave", "correctpassword", db_path=temp_db)
        result = login_user("dave", "correctpassword", db_path=temp_db)
        assert result["success"] is True

    def test_login_wrong_password(self, temp_db):
        register_user("eve", "correctpassword", db_path=temp_db)
        result = login_user("eve", "wrongpassword", db_path=temp_db)
        assert result["success"] is False

    def test_five_failed_logins_locks_account(self, temp_db):
        register_user("frank", "correctpassword", db_path=temp_db)
        for _ in range(5):
            login_user("frank", "wrongpassword", db_path=temp_db)
        status = get_user_status("frank", db_path=temp_db)
        assert status["locked"] is True

    def test_locked_account_rejects_correct_credentials(self, temp_db):
        register_user("grace", "correctpassword", db_path=temp_db)
        for _ in range(5):
            login_user("grace", "wrongpassword", db_path=temp_db)
        result = login_user("grace", "correctpassword", db_path=temp_db)
        assert result["success"] is False


class TestUserStatus:
    def test_status_none_for_nonexistent_user(self, temp_db):
        status = get_user_status("nobody", db_path=temp_db)
        assert status is None

    def test_status_shows_failed_attempts_count(self, temp_db):
        register_user("henry", "correctpassword", db_path=temp_db)
        login_user("henry", "wrongpassword", db_path=temp_db)
        login_user("henry", "wrongpassword", db_path=temp_db)
        status = get_user_status("henry", db_path=temp_db)
        assert status["failed_attempts"] == 2

    def test_status_shows_locked_after_lockout(self, temp_db):
        register_user("iris", "correctpassword", db_path=temp_db)
        for _ in range(5):
            login_user("iris", "wrongpassword", db_path=temp_db)
        status = get_user_status("iris", db_path=temp_db)
        assert status["locked"] is True
