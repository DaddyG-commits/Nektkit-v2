#!/usr/bin/env python3
"""
============================================================
 NETKIT v3.0
 Network Reconnaissance & Service Intelligence Engine

 Features:
   - Asynchronous TCP port discovery
   - TLS-aware service identification
   - HTTP response fingerprinting
   - Service banner collection
   - TLS certificate inspection
   - Bounded concurrency
   - Structured JSON reporting
   - Atomic report writing

 Standard library only.
 Python 3.9+
============================================================
"""

import argparse
import asyncio
import json
import os
import socket
import ssl
import sys
import tempfile
import time

from datetime import datetime, timezone
from pathlib import Path


VERSION = "3.0"

# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP-SUBMISSION",
    993: "IMAPS",
    995: "POP3S",
}

TLS_PORTS = {
    443,
    465,
    993,
    995,
}

HTTP_PORTS = {
    80,
    443,
}

DEFAULT_TIMEOUT = 3.0
DEFAULT_CONCURRENCY = 20
MAX_BANNER_SIZE = 4096

REPORT_DIRECTORY = Path("reports")

# ============================================================
# COLORS
# ============================================================

class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    GRAY = "\033[90m"


def log(message, color=Colors.RESET):
    print(f"{color}{message}{Colors.RESET}")


def print_banner():

    banner = f"""
{Colors.CYAN}
 _   _ _____ _____ _  ___ _____
| \\ | | ____|_   _| |/ (_)__  /
|  \\| |  _|   | | | ' /| | / /
| |\\  | |___  | | | . \\| |/ /_
|_| \\_|_____| |_| |_|\\_\\_/____/

 NETKIT v{VERSION}
 Network Reconnaissance Engine
{Colors.RESET}
"""

    print(banner)


# ============================================================
# SSL CONFIGURATION
# ============================================================

def create_ssl_context():

    context = ssl.create_default_context()

    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    return context


SSL_CONTEXT = create_ssl_context()


# ============================================================
# HOST RESOLUTION
# ============================================================

async def resolve_host(host):

    loop = asyncio.get_running_loop()

    try:

        addresses = await loop.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM
        )

        resolved = sorted({
            item[4][0]
            for item in addresses
        })

        return resolved

    except socket.gaierror as exc:

        raise RuntimeError(
            f"Host resolution failed: {exc}"
        )


# ============================================================
# CERTIFICATE EXTRACTION
# ============================================================

def extract_certificate(writer):

    ssl_object = writer.get_extra_info("ssl_object")

    if ssl_object is None:
        return None

    certificate = ssl_object.getpeercert()

    cipher = ssl_object.cipher()

    return {
        "tls_version": ssl_object.version(),

        "cipher": cipher[0] if cipher else None,

        "certificate_verified": bool(certificate),

        "subject": certificate.get("subject"),

        "issuer": certificate.get("issuer"),

        "not_before": certificate.get("notBefore"),

        "not_after": certificate.get("notAfter"),

        "serial_number": certificate.get("serialNumber"),
    }


# ============================================================
# HTTP FINGERPRINTING
# ============================================================

async def inspect_http(reader, writer, host):

    request = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: NETKIT/{VERSION}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    writer.write(request.encode("ascii", errors="ignore"))

    await writer.drain()

    response = await reader.read(MAX_BANNER_SIZE)

    text = response.decode(
        "utf-8",
        errors="replace"
    )

    lines = text.splitlines()

    status_line = lines[0] if lines else ""

    headers = {}

    for line in lines[1:]:

        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        headers[key.strip()] = value.strip()

    return {
        "status_line": status_line,
        "headers": headers,
        "server": headers.get("Server"),
        "content_type": headers.get("Content-Type"),
        "response_sample": text[:1000],
    }


# ============================================================
# SERVICE BANNER COLLECTION
# ============================================================

async def read_service_banner(reader):

    try:

        data = await asyncio.wait_for(
            reader.readline(),
            timeout=1.0
        )

        return data[:MAX_BANNER_SIZE].decode(
            "utf-8",
            errors="replace"
        ).strip()

    except asyncio.TimeoutError:

        return ""

    except Exception:

        return ""


# ============================================================
# SINGLE PORT PROBE
# ============================================================

async def probe_port(
    host,
    port,
    service,
    timeout,
    semaphore
):

    async with semaphore:

        result = {
            "port": port,
            "service": service,
            "state": "closed",
            "banner": "",
            "tls": None,
            "http": None,
            "error": None,
        }

        reader = None
        writer = None

        try:

            use_tls = port in TLS_PORTS

            connection = asyncio.open_connection(
                host,
                port,
                ssl=SSL_CONTEXT if use_tls else None,
                server_hostname=host if use_tls else None,
            )

            reader, writer = await asyncio.wait_for(
                connection,
                timeout=timeout
            )

            result["state"] = "open"

            # ------------------------------------------------
            # TLS INFORMATION
            # ------------------------------------------------

            if use_tls:

                result["tls"] = extract_certificate(writer)

            # ------------------------------------------------
            # HTTP INFORMATION
            # ------------------------------------------------

            if port in HTTP_PORTS:

                result["http"] = await asyncio.wait_for(
                    inspect_http(reader, writer, host),
                    timeout=timeout
                )

                result["banner"] = (
                    result["http"]["status_line"]
                )

            # ------------------------------------------------
            # OTHER SERVICE BANNERS
            # ------------------------------------------------

            else:

                result["banner"] = await read_service_banner(
                    reader
                )

        except ssl.SSLCertVerificationError as exc:

            result["state"] = "tls_verification_failed"

            result["error"] = str(exc)

        except asyncio.TimeoutError:

            result["state"] = "timeout"

        except ConnectionRefusedError:

            result["state"] = "closed"

        except OSError as exc:

            result["state"] = "error"

            result["error"] = str(exc)

        except Exception as exc:

            result["state"] = "error"

            result["error"] = (
                f"{type(exc).__name__}: {exc}"
            )

        finally:

            if writer is not None:

                writer.close()

                try:

                    await asyncio.wait_for(
                        writer.wait_closed(),
                        timeout=1.0
                    )

                except Exception:
                    pass

        return result


# ============================================================
# NETWORK DISCOVERY
# ============================================================

async def discover_services(
    host,
    ports,
    timeout=DEFAULT_TIMEOUT,
    concurrency=DEFAULT_CONCURRENCY
):

    semaphore = asyncio.Semaphore(concurrency)

    log(
        f"\n[*] Starting network discovery: {host}",
        Colors.MAGENTA
    )

    tasks = [

        probe_port(
            host,
            port,
            DEFAULT_PORTS.get(port, "UNKNOWN"),
            timeout,
            semaphore
        )

        for port in ports

    ]

    results = await asyncio.gather(*tasks)

    open_services = []

    for item in results:

        if item["state"] == "open":

            open_services.append(item)

            log(
                f"[+] OPEN {item['port']:5} "
                f"| {item['service']:18} "
                f"| {item['banner'][:60]}",
                Colors.GREEN
            )

        elif item["state"] == "tls_verification_failed":

            log(
                f"[!] TLS verification failed on "
                f"{item['port']}",
                Colors.YELLOW
            )

        elif item["state"] == "error":

            log(
                f"[!] Port {item['port']}: "
                f"{item['error']}",
                Colors.YELLOW
            )

    return results, open_services


# ============================================================
# JSON REPORTING
# ============================================================

def save_report(report):

    REPORT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    report_path = (
        REPORT_DIRECTORY /
        f"netkit_report_{timestamp}.json"
    )

    fd, temporary_path = tempfile.mkstemp(
        prefix=".netkit_",
        suffix=".tmp",
        dir=str(REPORT_DIRECTORY)
    )

    try:

        os.fchmod(fd, 0o600)

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

            file.flush()

            os.fsync(file.fileno())

        os.replace(
            temporary_path,
            report_path
        )

        log(
            f"\n[+] Report saved: {report_path}",
            Colors.GREEN
        )

        return report_path

    except Exception:

        try:
            os.close(fd)
        except OSError:
            pass

        try:
            os.unlink(temporary_path)
        except OSError:
            pass

        raise


# ============================================================
# SCAN ENGINE
# ============================================================

async def run_engine(
    target,
    ports,
    timeout,
    concurrency
):

    start_time = time.monotonic()

    try:

        addresses = await resolve_host(target)

    except RuntimeError as exc:

        log(
            f"[!] {exc}",
            Colors.RED
        )

        return None

    log(
        f"\n[+] Target: {target}",
        Colors.CYAN
    )

    log(
        f"[+] Resolved addresses: {', '.join(addresses)}",
        Colors.CYAN
    )

    results, open_services = await discover_services(
        target,
        ports,
        timeout,
        concurrency
    )

    duration = round(
        time.monotonic() - start_time,
        3
    )

    report = {

        "tool": "NETKIT",

        "version": VERSION,

        "target": target,

        "resolved_addresses": addresses,

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "duration_seconds": duration,

        "statistics": {

            "ports_scanned": len(ports),

            "open_ports": len(open_services),

            "closed_ports": sum(
                1 for item in results
                if item["state"] == "closed"
            ),

            "timeouts": sum(
                1 for item in results
                if item["state"] == "timeout"
            ),

            "errors": sum(
                1 for item in results
                if item["state"] in (
                    "error",
                    "tls_verification_failed"
                )
            ),

        },

        "services": results,

    }

    save_report(report)

    log(
        "\n========== SCAN SUMMARY ==========",
        Colors.CYAN
    )

    log(
        f"Target: {target}"
    )

    log(
        f"Ports scanned: {len(ports)}"
    )

    log(
        f"Open services: {len(open_services)}",
        Colors.GREEN
    )

    log(
        f"Duration: {duration}s"
    )

    log(
        "==================================",
        Colors.CYAN
    )

    return report


# ============================================================
# PORT PARSING
# ============================================================

def parse_ports(value):

    ports = set()

    try:

        for item in value.split(","):

            item = item.strip()

            if "-" in item:

                start, end = map(
                    int,
                    item.split("-", 1)
                )

                if start < 1 or end > 65535 or start > end:
                    raise ValueError

                if end - start > 1000:
                    raise ValueError(
                        "Port ranges are limited to 1000 ports."
                    )

                ports.update(
                    range(start, end + 1)
                )

            else:

                port = int(item)

                if not 1 <= port <= 65535:
                    raise ValueError

                ports.add(port)

        if not ports:
            raise ValueError

        return sorted(ports)

    except ValueError as exc:

        raise argparse.ArgumentTypeError(
            f"Invalid port specification: {exc}"
        )


# ============================================================
# COMMAND LINE INTERFACE
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "NETKIT v3.0 - Network Reconnaissance Engine"
        )
    )

    parser.add_argument(
        "target",
        help="Target hostname or IP address"
    )

    parser.add_argument(
        "--ports",
        type=parse_ports,
        default=sorted(DEFAULT_PORTS),
        help="Ports, e.g. 80,443,22 or 1-100"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY
    )

    args = parser.parse_args()

    if not 0.2 <= args.timeout <= 30:
        parser.error("Timeout must be between 0.2 and 30 seconds.")

    if not 1 <= args.concurrency <= 100:
        parser.error("Concurrency must be between 1 and 100.")

    print_banner()

    try:

        asyncio.run(
            run_engine(
                args.target,
                args.ports,
                args.timeout,
                args.concurrency
            )
        )

    except KeyboardInterrupt:

        log(
            "\n[!] Scan interrupted by user.",
            Colors.YELLOW
        )

    except Exception as exc:

        log(
            f"\n[!] Fatal error: {exc}",
            Colors.RED
        )

        sys.exit(1)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()