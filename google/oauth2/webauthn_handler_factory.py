import sys

from typing import List

from google.oauth2.webauthn_handler import WebAuthnHandler, PluginHandler

class WebauthnHandlerFactory:
  handlers: List[WebAuthnHandler]

  def __init__(self):
    self.handlers = [PluginHandler()]

  def get_handler(self) -> WebAuthnHandler:
    for handler in self.handlers:
      if handler.is_available():
        return handler
    return None