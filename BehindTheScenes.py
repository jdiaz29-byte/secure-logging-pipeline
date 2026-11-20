import os
import re
import hmac
import hashlib
import ipaddress
import threading

# Fields that should stay hidden
SECRET_FIELDS = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "refresh_token",
    "session_cookie",
    "cookie"
}

# Fields that contain personal information

EMAIL_FIELDS = {"email", "email_address"}
IP_FIELDS = {"ip", "client_ip, ip"}
PHONE_FIELDS = {"phone", "phone_number"}
NAME_FIELDS = {"name", "full_name"}
USER_AGENT_FIELDS = {"user_agent"}

# HMAC-SHA-256 Secret Key

HMAC_key = os.environ.get("LOG_MAC_KEY")

# Storing sensitive values to be stored
REGISTERED_SECRETS = set()

SECRET_LOCK = threading.Lock()

def register_secret(value):
    """
    Register a sensitive value so it can be removed
    from future log messages.
    """

    if value is None:
        return

    with SECRET_LOCK:
        REGISTERED_SECRETS.add(str(value))

