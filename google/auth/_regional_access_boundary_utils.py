"""Utilities for Regional Access Boundary management."""

import datetime
import threading

from google.auth import _helpers
from google.auth._default import _LOGGER


# The default lifetime for a cached Regional Access Boundary.
DEFAULT_REGIONAL_ACCESS_BOUNDARY_TTL = datetime.timedelta(hours=6)

# The initial cooldown period for a failed Regional Access Boundary lookup.
DEFAULT_REGIONAL_ACCESS_BOUNDARY_COOLDOWN = datetime.timedelta(minutes=15)

# The maximum cooldown period for a failed Regional Access Boundary lookup.
MAX_REGIONAL_ACCESS_BOUNDARY_COOLDOWN = datetime.timedelta(hours=6)


class _RegionalAccessBoundaryRefreshThread(threading.Thread):
    """Thread for background refreshing of the Regional Access Boundary."""

    def __init__(self, credentials, request):
        super(_RegionalAccessBoundaryRefreshThread, self).__init__()
        self.daemon = True
        self._credentials = credentials
        self._request = request

    def run(self):
        """
        Performs the Regional Access Boundary lookup and updates the credential's state.

        This method is run in a separate thread. It delegates the actual lookup
        to the credentials object's `_lookup_regional_access_boundary` method.
        Based on the lookup's outcome (success or complete failure after retries),
        it updates the credential's cached Regional Access Boundary information,
        its expiry, its cooldown expiry, and its exponential cooldown duration.
        """
        regional_access_boundary_info = (
            self._credentials._lookup_regional_access_boundary(self._request)
        )

        with self._credentials._stale_boundary_lock:  # Acquire the lock
            if regional_access_boundary_info:
                # On success, update the boundary and its expiry, and clear any cooldown.
                self._credentials._regional_access_boundary = (
                    regional_access_boundary_info
                )
                self._credentials._regional_access_boundary_expiry = (
                    _helpers.utcnow() + DEFAULT_REGIONAL_ACCESS_BOUNDARY_TTL
                )
                self._credentials._regional_access_boundary_cooldown_expiry = None
                # Reset the cooldown duration on success.
                self._credentials._current_rab_cooldown_duration = (
                    DEFAULT_REGIONAL_ACCESS_BOUNDARY_COOLDOWN
                )
                if _helpers.is_logging_enabled(_LOGGER):
                    _LOGGER.debug(
                        "Asynchronous Regional Access Boundary lookup successful."
                    )
            else:
                # On complete failure, calculate the next exponential cooldown duration and set the cooldown expiry.
                if _helpers.is_logging_enabled(_LOGGER):
                    _LOGGER.warning(
                        "Asynchronous Regional Access Boundary lookup failed. Entering cooldown."
                    )
                self._credentials._regional_access_boundary_cooldown_expiry = (
                    _helpers.utcnow() + self._credentials._current_rab_cooldown_duration
                )
                new_cooldown_duration = (
                    self._credentials._current_rab_cooldown_duration * 2
                )
                self._credentials._current_rab_cooldown_duration = min(
                    new_cooldown_duration, MAX_REGIONAL_ACCESS_BOUNDARY_COOLDOWN
                )
                # If the proactive refresh failed, clear any existing expired RAB data.
                # This ensures we don't continue using stale data.
                self._credentials._regional_access_boundary = None
                self._credentials._regional_access_boundary_expiry = None


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
