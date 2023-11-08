from google.auth.compute_engine import _metadata
import google.auth.transport.requests

req = google.auth.transport.requests.Request()

_metadata.get_universe_domain(req)