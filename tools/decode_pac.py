#!/usr/bin/env python3
"""Decode MS-PAC from a Kerberos ticket and display Extra SIDs including trust-level."""

import struct
import sys
import subprocess
import argparse
import tempfile
import os


def run_cmd(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"Error running {' '.join(cmd)}: {r.stderr}", file=sys.stderr)
        sys.exit(1)
    return r.stdout.strip()


def get_ticket_pac(realm, principal, keytab=None, ccache=None):
    kvno_cmd = ['kvno', principal]
    if keytab:
        kvno_cmd = ['kinit', '-k', '-t', keytab, principal] + kvno_cmd
    if ccache:
        os.environ['KRB5CCNAME'] = ccache

    run_cmd(kvno_cmd)

    with tempfile.NamedTemporaryFile(suffix='.keytab', delete=False) as kf:
        keytab_out = kf.name
    try:
        run_cmd(['ktutil', '-k', keytab_out, 'get', principal])

        decode_cmd = ['klist', '-e', keytab_out]
        output = run_cmd(decode_cmd)
        print("Ticket info:")
        print(output)
    finally:
        os.unlink(keytab_out)

    return None


TRUST_LEVEL_RID_BASE = 1000000
TRUST_LEVEL_MAX = 127


def extract_trust_level_from_sid(sid_str):
    parts = sid_str.split('-')
    if len(parts) >= 4:
        try:
            rid = int(parts[-1])
            if TRUST_LEVEL_RID_BASE <= rid <= TRUST_LEVEL_RID_BASE + TRUST_LEVEL_MAX:
                return rid - TRUST_LEVEL_RID_BASE
        except ValueError:
            pass
    return None


def parse_lsb_sid(data, offset):
    revision = data[offset]
    sub_auth_count = data[offset + 1]
    byte_auth = struct.unpack_from('>Q', data, offset + 2)[0]
    byte_auth &= 0xFFFFFFFFFFFF

    sub_authorities = []
    for i in range(sub_auth_count):
        sa = struct.unpack_from('<I', data, offset + 8 + i * 4)[0]
        sub_authorities.append(sa)

    sid_str = f"S-{revision}-{byte_auth}"
    for sa in sub_authorities:
        sid_str += f"-{sa}"

    return sid_str, offset + 8 + sub_auth_count * 4


def decode_pac_logon_info(data):
    print(f"\n{'='*60}")
    print("PAC_LOGON_INFO (Type 1) - KERB_VALIDATION_RESPONSE")
    print(f"{'='*60}")

    try:
        offset = 0

        while offset < len(data) - 8:
            try:
                possible_sid, new_offset = parse_lsb_sid(data, offset)
                if possible_sid.startswith("S-1-") and "-" in possible_sid[4:]:
                    tl = extract_trust_level_from_sid(possible_sid)
                    if tl is not None:
                        print(f"  *** TRUST-LEVEL EXTRA SID: {possible_sid} -> trust-level = {tl}")
                    else:
                        print(f"  SID: {possible_sid}")
            except Exception:
                pass
            offset += 1
    except Exception as e:
        print(f"Error parsing PAC_LOGON_INFO: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Decode MS-PAC from Kerberos ticket and show trust-level Extra SID')
    parser.add_argument('principal', help='Kerberos principal to get ticket for')
    parser.add_argument('--keytab', help='Keytab file for authentication')
    parser.add_argument('--ccache', help='Kerberos credential cache')
    parser.add_argument('--pac-file', help='Raw PAC file to decode (skip ticket fetch)')
    args = parser.parse_args()

    if args.pac_file:
        with open(args.pac_file, 'rb') as f:
            pac_data = f.read()
        print(f"Decoding PAC from file: {args.pac_file} ({len(pac_data)} bytes)")
        decode_pac_logon_info(pac_data)
    else:
        print(f"Fetching ticket for: {args.principal}")
        get_ticket_pac(None, args.principal, args.keytab, args.ccache)

        print("\nTo extract and decode PAC from TGT, use:")
        print(f"  1. kinit {args.principal}")
        print(f"  2. kvno krbtgt/YOUR.REALM@YOUR.REALM")
        print(f"  3. Use 'tshark' or 'ldapsearch' to inspect PAC")
        print(f"  4. Or use the decode_pac.py with --pac-file option")
        print()
        print("Alternative: Use Wireshark to capture Kerberos traffic")
        print("  Filter: kerberos && kerberos.msg_type == 11")
        print("  Look in: Authorization-Data -> PAC -> Logon Info -> Extra SIDs")


if __name__ == '__main__':
    main()
