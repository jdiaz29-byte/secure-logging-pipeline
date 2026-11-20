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

# ==========================================
# 2. SECRET REGISTRATION
# ==========================================

def register_secret(value):
    """Remember sensitive values that must not be logged."""
    if value:
        REGISTERED_SECRETS.add(str(value))

# ==========================================
# 3. INDIVIDUAL REDACTION FUNCTIONS
# ==========================================

def redact_email(email):
    return "***@" + str(email).split("@")[-1]

def truncate_ip(ip):

    address = ipaddress.ip_address(str(ip))

    if address.version != 4:
        raise ValueError("Only IPv4 addresses are supported")

    network = ipaddress.ip_network(
        f"{address}/16",
        strict=False
    )

    return str(network.network_address) + "/16"

def hash_phone(phone):

    if not HMAC_KEY:
        raise RuntimeError("HMAC key is not configured")

    phone = re.sub(r"\D", "", str(phone))

    return hmac.new(
        HMAC_KEY.encode("utf-8"),
        phone.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()[:12]

def identify_user_agent(user_agent):

    user_agent = str(user_agent).lower()

    if "edg/" in user_agent:
        return "Edge"

    elif "firefox/" in user_agent:
        return "Firefox"

    elif "chrome/" in user_agent:
        return "Chrome"

    elif "safari/" in user_agent:
        return "Safari"

    else:
        return "Other"

# ==========================================
# 4. DATA REDACTION
# ==========================================

def redact_text(text):

    text = str(text)

    for secret in sorted(REGISTERED_SECRETS, key=len, reverse=True):
        text = text.replace(secret, "[REMOVED]")


    text = re.sub(
        r'(?i)\b(password|passwd|pwd|token|api_key|secret)\s*[:=]\s*["\']?[^"\'\s,;]+',
        r'\1=[REMOVED]', text
    )

    text = re.sub(
        r'(?i)\bBearer\s+\S+',
        "Bearer [REMOVED]", text
    )

    text = re.sub(
        r'(?i)\bCookie:\s*[^\r\n]+',
        "Cookie: [REMOVED]", text
    )

    # Email addresses
    text = re.sub(
        r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}',
        lambda m: redact_email(m.group()), text
    )

    # IPv4 addresses
    def clean_ip(match):
        try:
            return truncate_ip(match.group())
        except ValueError:
            return "[INVALID IP]"

    text = re.sub(
        r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',
        clean_ip, text
    )

    # Common US phone numbers
    text = re.sub(
        r'(?<!\w)(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\w)',
        lambda m: "phone#" + hash_phone(m.group()), text
    )

    return text


def redact_data(data):

    if isinstance(data, dict):
        result = {}

        for key, value in data.items():
            field = str(key).lower().replace("-", "_")

            if field in SECRET_FIELDS or field in NAME_FIELDS:
                continue
            elif field in EMAIL_FIELDS:
                result[key] = redact_email(value)
            elif field in IP_FIELDS:
                result[key] = truncate_ip(value)
            elif field in PHONE_FIELDS:
                result[key] = "phone#" + hash_phone(value)
            elif field in USER_AGENT_FIELDS:
                result[key] = identify_user_agent(value)
            else:
                result[key] = redact_data(value)

        return result

    if isinstance(data, list):
        return [redact_data(item) for item in data]

    if isinstance(data, str):
        return redact_text(data)

    return data

# ==========================================
# 5. LOGGING FILTER
# ==========================================

class RedactionFilter(logging.Filter):
    def filter(self,record):
        try:
            message = record.getMessage()

            if record.exc_info:
                message += "\n" + logging.Formatter().formatException(
                    record.exc_info
                )

            record.msg = redact_text(message)
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None

        except Exception:
            record.msg = "[REDACTION FAILED - RECORD BLOCKED]"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None

        return True

# ==========================================
# 6. JSON FORMATTER
# ==========================================

class SecureFormatter(logging.Formatter):

    def format(self, record):
        return json.dumps({
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage())
        })

# ==========================================
# 7. LOGGING SETUP
# ==========================================

def configure_logging(log_file = "logs/secure.log"):

    if not HMAC_KEY:
        raise RuntimeError("LOG_HMAC_KEY is required")

    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)

    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.addFilter(RedactionFilter())
    handler.setFormatter(SecureFormatter())