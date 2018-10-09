#!/usr/bin/env python3
import argparse
import glob
import logging
import os
import re
import requests
import subprocess
import sys

OSS_FUZZ_BUGURL = "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id="
DOWNLOAD_URL = 'https://oss-fuzz.com/download?testcase_id='

testcase_pattern = re.compile(r'https://oss-fuzz\.com/testcase\?key=(\d+)')
proto_pattern = r'\bFuzzer: (?:afl|libFuzzer)_wireshark_fuzzshark_([a-z_-]+)\b'

parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true", help="Enable verbose logging")
parser.add_argument("--cookie-file", "-c", help="File containing cookie value")

# Pass through options
reporter_params = [
    ("report", None),
    ("timeout", int),
    ("memlimit", int),
    ("memleaks", None),
]
for name, arg_type in reporter_params:
    args = ["--" + name]
    kwargs = {}
    if arg_type:
        kwargs["type"] = arg_type
    else:
        kwargs["action"] = "store_true"
    kwargs["default"] = None
    kwargs["help"] = "Option is passed to the reporter"
    parser.add_argument(*args, **kwargs)
parser.add_argument("--reporter-args", "-r", help="Options to pass through")


parser.add_argument("issue_id", type=int)
args = parser.parse_args()

if args.debug:
    logging.basicConfig(level=logging.DEBUG)

def fatal(*args):
    logging.error(*args)
    sys.exit(1)

def parse_cookies(text):
    cookies = {}
    for m in re.finditer(r'(SACSID)\s+(~[0-9a-zA-Z_-]+)\s+([a-z.-]+)(?:\s|$)', text):
        key, value, domain = m.groups()
        cookies[domain] = (key, value)
    # compatibility with Netscape cookie jar
    garbage = r'(?:TRUE|FALSE)\s+/\s+(?:TRUE|FALSE)\s+\d+\s+'
    cj_pattern = r'([a-z.-]+)\s+' + garbage + r'(SACSID)\s+(~[0-9a-zA-Z_-]+)(?:\s+|$)'
    for m in re.finditer(cj_pattern, text):
        domain, key, value = m.groups()
        cookies[domain] = (key, value)
    if any(not d in cookies for d in ["bugs.chromium.org", "oss-fuzz.com"]):
        fatal("Missing domains, got: %s", " ".join(cookies.keys()))
    return cookies

cookie_file = args.cookie_file
if not cookie_file:
    # TODO maybe fallback to a default location?
    parser.error("Missing cookie file")
sid_cookies = parse_cookies(open(cookie_file).read().strip())

session = requests.Session()
for domain, (key, value) in sid_cookies.items():
    session.cookies.set(key, value, domain=domain)

# Fetch bug contents
issue_id = str(args.issue_id)
bugurl = OSS_FUZZ_BUGURL + issue_id
r = session.get(bugurl)
r.raise_for_status()

# Look for ID
pat = re.search(testcase_pattern, r.text)
if not pat:
    fatal('Cannot find testcase ID')
testcase_id = pat.group(1)

# Look for type (IP, etc.)
pat = re.search(proto_pattern, r.text)
if not pat:
    # XXX maybe assume IP?
    fatal('Protocol not found')
protocol = pat.group(1)

attachment_name = None
# Try to locate existing file
for prefix in ["clusterfuzz-testcase-minimized-", "clusterfuzz-testcase-"]:
    for suffix in ['', '.pcap']:
        name = prefix + testcase_id + suffix
        if os.path.exists(name):
            attachment_name = name
            break

# Download the attachment if missing
if attachment_name is None:
    att_url = DOWNLOAD_URL + testcase_id
    r = session.get(att_url, stream=True)
    pat = re.search(r'filename=([a-z0-9_-]+)', r.headers['content-disposition'])
    if not pat:
        fatal('Cannot parse header: %s', r.headers['content-disposition'])
    attachment_name = pat.group(1)
    try:
        # Open without overwriting existing contents.
        with open(attachment_name, 'xb') as f:
            for chunk in r.iter_content(chunk_size=4096):
                f.write(chunk)
        logging.info("Downloaded: %s", attachment_name)
    except FileExistsError:
        # Ignore existing file.
        pass

cmd = [
    "oss-fuzz-report.py",
    "--proto", protocol,
    attachment_name,
    issue_id
]
if args.reporter_args:
    cmd += args.reporter_args.split()
for name, arg_type in reporter_params:
    value = getattr(args, name)
    if value is not None:
        cmd.append("--" + name)
        if arg_type:
            cmd.append(str(value))
print(' '.join(cmd))

os.execvp(cmd[0], cmd)
