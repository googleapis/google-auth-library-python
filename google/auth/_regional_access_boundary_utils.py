"""Utilities for Regional Access Boundary management."""

import threading
import datetime

from google.auth import _helpers
from google.auth import exceptions
from google.auth._default import _LOGGER


# The default lifetime for a cached Regional Access Boundary.
DEFAULT_REGIONAL_ACCESS_BOUNDARY_TTL = datetime.timedelta(hours=6)

# The initial cooldown period for a failed Regional Access Boundary lookup.
DEFAULT_REGIONAL_ACCESS_BOUNDARY_COOLDOWN = datetime.timedelta(minutes=15)


class _RegionalAccessBoundaryRefreshThread(threading.Thread):
    """Thread for background refreshing of the Regional Access Boundary."""

    def __init__(self, credentials, request):
        super(_RegionalAccessBoundaryRefreshThread, self).__init__()
        self._credentials = credentials
        self._request = request

    def run(self):
        """
        Performs the Regional Access Boundary lookup. This method is run in a separate thread.

        It includes a short-term retry loop for transient server errors. If the
        lookup fails completely, it sets a longer-term cooldown period on the
        credential to avoid overwhelming the lookup service.
        """
        regional_access_boundary_info = self._credentials._lookup_regional_access_boundary_with_retry(
            self._request
        )

        if regional_access_boundary_info:
            # On success, update the boundary and its expiry, and clear any cooldown.
            self._credentials._regional_access_boundary = regional_access_boundary_info
            self._credentials._regional_access_boundary_expiry = (
                _helpers.utcnow() + DEFAULT_REGIONAL_ACCESS_BOUNDARY_TTL
            )
            self._credentials._regional_access_boundary_cooldown_expiry = None
            if _helpers.is_logging_enabled(_LOGGER):
                _LOGGER.debug(
                    "Asynchronous Regional Access Boundary lookup successful."
                )
        else:
            # On complete failure, set a cooldown period. The existing
            # _regional_access_boundary and _regional_access_boundary_expiry
            # will be kept as they are considered safe to use until explicitly
            # invalidated by a "stale Regional Access Boundary" API error.
            if _helpers.is_logging_enabled(_LOGGER):
                _LOGGER.warning(
                    "Asynchronous Regional Access Boundary lookup failed. Entering cooldown."
                )

            self._credentials._regional_access_boundary_cooldown_expiry = (
                _helpers.utcnow() + DEFAULT_REGIONAL_ACCESS_BOUNDARY_COOLDOWN
            )


class _RegionalAccessBoundaryRefreshManager(object):
    """Manages a thread for background refreshing of the Regional Access Boundary."""

    def __init__(self):
        self._lock = threading.Lock()
        self._worker = None

    def start_refresh(self, credentials, request):
        """
        Starts a background thread to refresh the Regional Access Boundary if one is not already running.

        Args:
            credentials (CredentialsWithRegionalAccessBoundary): The credentials
                to refresh.
            request (google.auth.transport.Request): The object used to make
                HTTP requests.
        """
        with self._lock:
            if self._worker and self._worker.is_alive():
                # A refresh is already in progress.
                return

            self._worker = _RegionalAccessBoundaryRefreshThread(credentials, request)
            self._worker.start()
