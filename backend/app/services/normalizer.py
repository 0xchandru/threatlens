import re
import ipaddress
from app.models.ioc import IOCType

PATTERNS = {
    IOCType.sha256: re.compile(r'^[a-fA-F0-9]{64}$'),
    IOCType.sha1:   re.compile(r'^[a-fA-F0-9]{40}$'),
    IOCType.md5:    re.compile(r'^[a-fA-F0-9]{32}$'),
    IOCType.url:    re.compile(r'^(https?|ftp)://[^\s/$.?#].[^\s]*$', re.IGNORECASE),
    IOCType.domain: re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    ),
}


class NormalizedIOC:
    def __init__(self, value: str, ioc_type: IOCType):
        self.value    = value.strip().lower()
        self.ioc_type = ioc_type

    def is_private_ip(self) -> bool:
        if self.ioc_type != IOCType.ip:
            return False
        try:
            return ipaddress.ip_address(self.value).is_private
        except ValueError:
            return False


def detect_and_normalize(raw_input: str) -> NormalizedIOC:
    value = raw_input.strip()

    try:
        ipaddress.ip_address(value)
        return NormalizedIOC(value, IOCType.ip)
    except ValueError:
        pass

    for ioc_type in (IOCType.sha256, IOCType.sha1, IOCType.md5):
        if PATTERNS[ioc_type].match(value):
            return NormalizedIOC(value.lower(), ioc_type)

    if PATTERNS[IOCType.url].match(value):
        return NormalizedIOC(value, IOCType.url)

    domain_check = value.lstrip("*.")
    if PATTERNS[IOCType.domain].match(domain_check):
        return NormalizedIOC(value, IOCType.domain)

    raise ValueError(f"Cannot determine IOC type for: {value!r}")
