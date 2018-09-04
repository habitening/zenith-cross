"""Configuration settings.

This module is for configuration settings that can be stored in a source
repository. DO NOT store client ID or client secret in this module because
they will be exposed. There is a separate YAML configuration file for those
secrets.
"""

HASH_KEY = '_hash'
"""String special key to store the hashed user ID in the session."""

LOGOUT_KEY = '_logout'
"""String special key to store in the session to log out."""
