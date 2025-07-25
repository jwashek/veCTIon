import re

def detect_ioc_type(ioc):
    ioc = ioc.strip().lower()

    # IPv4
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ioc):
        return "ip"

    # Hashes
    if re.match(r"^[a-f0-9]{32}$", ioc):
        return "md5"
    if re.match(r"^[a-f0-9]{40}$", ioc):
        return "sha1"
    if re.match(r"^[a-f0-9]{64}$", ioc):
        return "sha256"

    # Domain
    if re.match(r"^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}$", ioc):
        return "domain"

    # URL
    if re.match(r"^https?://", ioc):
        return "url"

    return "unknown"
