import subprocess
import re
from inform.core.models import CredentialProfile


def get_device_info(ip: str, profile: CredentialProfile):
    """
    Get basic device information using system snmpget (SNMPv3).
    Returns a clean dict with sysName, sysLocation, sysDescr.
    """
    auth_map = {"sha": "SHA", "md5": "MD5"}
    priv_map = {"aes": "AES", "des": "DES"}

    auth_proto = auth_map.get(profile.auth_protocol.lower(), "SHA")
    priv_proto = priv_map.get(profile.priv_protocol.lower(), "AES")

    cmd = [
        "snmpget",
        "-v3",
        "-u", profile.username,
        "-l", "authPriv",
        "-a", auth_proto,
        "-A", profile.auth_key,
        "-x", priv_proto,
        "-X", profile.priv_key,
        "-Ovq",                    # Only show value (quiet mode)
        f"{ip}",
        "1.3.6.1.2.1.1.5.0",       # sysName
        "1.3.6.1.2.1.1.6.0",       # sysLocation
        "1.3.6.1.2.1.1.1.0",       # sysDescr
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return {"error": result.stderr.strip() or "SNMP request failed"}

        lines = result.stdout.strip().splitlines()

        # Map order of OIDs we requested
        oid_order = ["sysName", "sysLocation", "sysDescr"]
        response = {}

        for i, line in enumerate(lines):
            if i < len(oid_order):
                # Clean up the value (remove quotes and extra whitespace)
                value = line.strip().strip('"')
                response[oid_order[i]] = value

        return response

    except FileNotFoundError:
        return {"error": "snmpget command not found. Install net-snmp-utils."}
    except subprocess.TimeoutExpired:
        return {"error": "SNMP request timed out"}
    except Exception as e:
        return {"error": str(e)}
