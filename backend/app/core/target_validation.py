import ipaddress
import socket
from urllib.parse import urlparse


def _is_public_ip(ip: str) -> bool:
    ip_obj = ipaddress.ip_address(ip)
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def validate_target_is_safe(target_url: str) -> None:
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Target URL must include a valid hostname.")

    # Block obvious local hostnames early.
    if hostname.lower() in {"localhost"} or hostname.lower().endswith(".local"):
        raise ValueError("Localhost or local network targets are not allowed.")

    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValueError("Could not resolve target hostname.") from exc

    resolved_ips = {item[4][0] for item in addr_info}
    for ip in resolved_ips:
        if not _is_public_ip(ip):
            raise ValueError("Target resolves to a non-public IP address and is blocked.")
