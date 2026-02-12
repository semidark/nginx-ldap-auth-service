"""
Tests for the header-based authorization endpoint (/check-header).

This endpoint is designed for Kerberos/SPNEGO authentication where NGINX
handles authentication and passes the username via a trusted header.
"""

import pytest
from bonsai import LDAPError


class TestCheckHeaderEndpoint:
    """Tests for the /check-header endpoint."""

    def test_check_header_success(self, client, mock_user_manager):
        """Test successful authorization with valid header and authorized user."""
        mock_user_manager.is_authorized.return_value = True

        response = client.get(
            "/check-header",
            headers={
                "x-ldap-user": "testuser",
                "x-authorization-filter": "(&(uid={username})(memberOf=cn=admins,dc=example,dc=com))",
            },
        )

        assert response.status_code == 200
        assert response.headers.get("x-auth-user") == "testuser"
        assert response.headers.get("cache-control") == "no-cache"

    def test_check_header_missing_header(self, client, mock_user_manager):
        """Test that missing X-Ldap-User header returns 401."""
        response = client.get("/check-header")

        assert response.status_code == 401
        assert "x-auth-user" not in response.headers
        assert response.headers.get("cache-control") == "no-cache"

    def test_check_header_not_authorized(self, client, mock_user_manager):
        """Test that user not in required group returns 403."""
        mock_user_manager.is_authorized.return_value = False

        response = client.get(
            "/check-header",
            headers={
                "x-ldap-user": "testuser",
                "x-authorization-filter": "(&(uid={username})(memberOf=cn=admins,dc=example,dc=com))",
            },
        )

        assert response.status_code == 403
        assert "x-auth-user" not in response.headers

    def test_check_header_no_filter(self, client, mock_user_manager):
        """Test that when no authorization filter is provided, all users are authorized."""
        response = client.get(
            "/check-header",
            headers={"x-ldap-user": "testuser"},
        )

        assert response.status_code == 200
        assert response.headers.get("x-auth-user") == "testuser"
        mock_user_manager.is_authorized.assert_not_called()

    def test_check_header_ldap_error(self, client, mock_user_manager):
        """Test that LDAP errors return 500."""
        mock_user_manager.is_authorized.side_effect = LDAPError("Connection failed")

        response = client.get(
            "/check-header",
            headers={
                "x-ldap-user": "testuser",
                "x-authorization-filter": "(&(uid={username})(memberOf=cn=admins,dc=example,dc=com))",
            },
        )

        assert response.status_code == 500

    def test_check_header_cache_hit(self, client, mock_user_manager):
        """Test that cached results are used (LDAP not queried on second request)."""
        from nginx_ldap_auth.app.cache import reset_cache

        reset_cache()
        mock_user_manager.is_authorized.return_value = True

        headers = {
            "x-ldap-user": "cacheuser",
            "x-authorization-filter": "(&(uid={username})(memberOf=cn=testers,dc=example,dc=com))",
        }

        # First request - should query LDAP
        response1 = client.get("/check-header", headers=headers)
        assert response1.status_code == 200
        assert mock_user_manager.is_authorized.call_count == 1

        # Second request - should use cache
        response2 = client.get("/check-header", headers=headers)
        assert response2.status_code == 200
        assert mock_user_manager.is_authorized.call_count == 1  # Still 1 (cache hit)

        reset_cache()

    def test_check_header_cache_different_filters(self, client, mock_user_manager):
        """Test that different authorization filters result in different cache entries."""
        from nginx_ldap_auth.app.cache import reset_cache

        reset_cache()
        mock_user_manager.is_authorized.return_value = True

        # Request with filter A
        response1 = client.get(
            "/check-header",
            headers={
                "x-ldap-user": "testuser",
                "x-authorization-filter": "(memberOf=cn=groupA,dc=example,dc=com)",
            },
        )
        assert response1.status_code == 200
        assert mock_user_manager.is_authorized.call_count == 1

        # Request with filter B - different cache key, queries LDAP again
        response2 = client.get(
            "/check-header",
            headers={
                "x-ldap-user": "testuser",
                "x-authorization-filter": "(memberOf=cn=groupB,dc=example,dc=com)",
            },
        )
        assert response2.status_code == 200
        assert mock_user_manager.is_authorized.call_count == 2

        reset_cache()

    def test_check_header_custom_header_name(self, client, mock_user_manager, mocker):
        """Test that custom header name from settings works."""
        from nginx_ldap_auth.app import header_auth

        mocker.patch.object(
            header_auth.settings, "ldap_trusted_user_header", "X-Remote-User"
        )

        response = client.get(
            "/check-header",
            headers={"x-remote-user": "customuser"},
        )

        assert response.status_code == 200
        assert response.headers.get("x-auth-user") == "customuser"

    def test_check_header_uses_settings_filter(self, client, mock_user_manager, mocker):
        """Test that settings.ldap_authorization_filter is used when header not provided."""
        from nginx_ldap_auth.app import header_auth
        from nginx_ldap_auth.app.cache import reset_cache

        reset_cache()

        mocker.patch.object(
            header_auth.settings,
            "ldap_authorization_filter",
            "(&(uid={username})(memberOf=cn=default,dc=example,dc=com))",
        )
        mock_user_manager.is_authorized.return_value = True

        response = client.get(
            "/check-header",
            headers={"x-ldap-user": "testuser"},
        )

        assert response.status_code == 200
        mock_user_manager.is_authorized.assert_called_once()
        call_args = mock_user_manager.is_authorized.call_args
        assert "memberOf=cn=default" in call_args[0][1]

        reset_cache()


class TestAuthCache:
    """Tests for the authorization cache module."""

    @pytest.mark.asyncio
    async def test_cache_get_set(self):
        """Test cache get/set operations."""
        from nginx_ldap_auth.app.cache import (
            get_cached_authorization,
            reset_cache,
            set_cached_authorization,
        )

        reset_cache()

        # Initially empty
        result = await get_cached_authorization("user1", "(filter1)")
        assert result is None

        # Set and get
        await set_cached_authorization("user1", "(filter1)", True)
        result = await get_cached_authorization("user1", "(filter1)")
        assert result is True

        # Different filter
        result = await get_cached_authorization("user1", "(filter2)")
        assert result is None

        # Set unauthorized
        await set_cached_authorization("user2", "(filter1)", False)
        result = await get_cached_authorization("user2", "(filter1)")
        assert result is False

        reset_cache()

    @pytest.mark.asyncio
    async def test_authorization_lock_prevents_concurrent_access(self):
        """Test that authorization_lock serializes access for same key."""
        import asyncio

        from nginx_ldap_auth.app.cache import authorization_lock, reset_cache

        reset_cache()

        execution_order = []

        async def task(task_id: str, delay: float):
            async with authorization_lock("user1", "(filter1)"):
                execution_order.append(f"{task_id}_start")
                await asyncio.sleep(delay)
                execution_order.append(f"{task_id}_end")

        # Start two tasks concurrently for the same key
        await asyncio.gather(
            task("A", 0.1),
            task("B", 0.1),
        )

        # With locking, one task must complete before the other starts
        # Either A_start, A_end, B_start, B_end OR B_start, B_end, A_start, A_end
        assert execution_order[0].endswith("_start")
        assert execution_order[1].endswith("_end")
        assert execution_order[2].endswith("_start")
        assert execution_order[3].endswith("_end")

        reset_cache()

    @pytest.mark.asyncio
    async def test_authorization_lock_different_keys_concurrent(self):
        """Test that different keys can be accessed concurrently."""
        import asyncio

        from nginx_ldap_auth.app.cache import authorization_lock, reset_cache

        reset_cache()

        execution_order = []

        async def task(task_id: str, username: str, delay: float):
            async with authorization_lock(username, "(filter1)"):
                execution_order.append(f"{task_id}_start")
                await asyncio.sleep(delay)
                execution_order.append(f"{task_id}_end")

        # Start two tasks concurrently for different keys
        await asyncio.gather(
            task("A", "user1", 0.1),
            task("B", "user2", 0.1),
        )

        # Different keys should allow concurrent access
        # Both should start before either ends
        starts = [e for e in execution_order if e.endswith("_start")]
        ends = [e for e in execution_order if e.endswith("_end")]

        # Both starts should happen before both ends (concurrent execution)
        first_end_idx = execution_order.index(ends[0])
        assert execution_order.index(starts[0]) < first_end_idx
        assert execution_order.index(starts[1]) < first_end_idx

        reset_cache()
