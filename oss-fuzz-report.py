#!/usr/bin/env python3
import argparse
import filecmp
import logging
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
BASEDIR = os.path.dirname(os.path.realpath(__file__))
try:
    sys.path.insert(0, os.path.join(BASEDIR, "python-bugzilla"))
    import bugzilla
except ImportError:
    bugzilla = None

OSS_FUZZ_BUGURL = "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id="
BZURL = "https://bugs.wireshark.org/bugzilla/xmlrpc.cgi"
#BZURL = "test.local"
apikey_file = os.path.expanduser("~/.cache/wireshark-bugzilla-apikey.txt")

_logger = logging.getLogger(__name__)

def report_bug(title, description, url, pcap_filename):
    if bugzilla is None:
        _logger.warn("module bugzilla is unavailable, cannot report bug!")
        return

    apikey = open(apikey_file).read().strip()
    # Bugzilla 5 uses tokens for auth, so we can omit the cookie file.
    # Let's see if we can omit cached token given an API key.
    bzapi = bugzilla.Bugzilla(BZURL, cookiefile=None, tokenfile=None, api_key=apikey)
    #if not bzapi.logged_in:
    #    bzapi.interactive_login()

    createinfo = bzapi.build_createbug(
        product="Wireshark",
        #version="unspecified",
        version="Git",
        component="Dissection engine (libwireshark)",
        #op_sys="Ubuntu",
        op_sys="Linux",
        platform="x86-64",
        priority="High",
        url=url,
        status='CONFIRMED',
        summary="[oss-fuzz] %s" % title,
        description=description,
    )
    # Could have added an alias, but it is not much used in WS.
    #bugid_match = re.match(re.escape(OSS_FUZZ_BUGURL) + r'(\d+)', url)
    #if bugid_match:
    #    createinfo['alias'] = 'oss-fuzz-%d' % bugid_match.group(1)
    newbug = bzapi.createbug(createinfo)
    _logger.info("URL: %s", newbug.weburl)
    with open(pcap_filename, 'rb') as pcap_file:
        bzapi.attachfile(newbug.id, pcap_file, "Packet capture file")

def make_pcap(data):
    # Pcap header for linktype = 252
    pcap_data = bytes.fromhex('d4c3b2a1020004000000000000000000ff7f0000fc000000')
    pcap_data += struct.pack('<IIII', 0, 0, len(data), len(data))
    pcap_data += data
    return pcap_data

# Created with scapy and a custom WiresharkUpperPdu class
protocol_headers = {
    'udp_port-bootp': b'\x00\x0e\x00\x08udp.port\x00 \x00\x04\x00\x00\x00C\x00\x00\x00\x00',
    'ip_proto-udp': b'\x00\x0e\x00\x08ip.proto\x00 \x00\x04\x00\x00\x00\x11\x00\x00\x00\x00',
}

ip_proto = {
    'udp': 17,
    'ospf': 89,
}
tcp_port = {
    'bgp': 179,
}
udp_port = {
    'bootp': 67,
    'dns': 53,
}
def make_ip_proto(proto):
    header = b'\x00\x0e\x00\x08ip.proto\x00 \x00\x04'
    header += struct.pack('!I', proto)
    header += b'\x00\x00\x00\x00'
    return header
def make_tcp_proto(proto):
    header = b'\x00\x0e\x00\x08tcp.port\x00 \x00\x04'
    header += struct.pack('!I', proto)
    header += b'\x00\x00\x00\x00'
    return header
def make_udp_proto(proto):
    header = b'\x00\x0e\x00\x08udp.port\x00 \x00\x04'
    header += struct.pack('!I', proto)
    header += b'\x00\x00\x00\x00'
    return header
for name, proto in ip_proto.items():
    protocol_headers['ip_proto-%s' % name] = make_ip_proto(proto)
for name, port in tcp_port.items():
    protocol_headers['tcp_port-%s' % name] = make_tcp_proto(port)
for name, port in udp_port.items():
    protocol_headers['udp_port-%s' % name] = make_udp_proto(port)

def create_pcap(protocol, input_filename, output_filename):
    """
    Convert reproducer to a suitable pcap format.
    """
    with open(output_filename, "wb") as output_file:
        header = protocol_headers.get(protocol)
        if header is not None:
            with open(input_filename, 'rb') as input_file:
                payload = input_file.read()
                output_file.write(make_pcap(header + payload))
            _logger.debug("Wrote header for %s", protocol)
            return
        # Fallback to external program.
        _logger.debug("Invoking: samples_to_pcap %s", protocol)
        subprocess.check_call(
            ["samples_to_pcap", protocol, input_filename],
            stdout=output_file
        )
        # TODO check for "unknown protocol"

def as_str(bytes_or_str):
    if bytes_or_str is None:
        return ""
    if type(bytes_or_str) is bytes:
        return bytes_or_str.decode('utf8', 'backslashreplace')
    return bytes_or_str

def run_tshark(args, homedir, timeout=10, memlimit=0, memleaks=False):
    binpath = os.environ.get('WS_BIN_PATH')
    tshark_exec = os.path.join(binpath or "", "tshark")
    asan_options = [
        'detect_leaks=%d' % (1 if memleaks else 0),
        'detect_odr_violation=0',
        # Will catch strncmp(x, y, strlen(y)) when x is not NUL-terminated
        'strict_string_checks=1',
        # "Enables stack-use-after-return checking at run-time."
        'detect_stack_use_after_return=1',
        # Print nice traces for assertion failures.
        'handle_abort=1',

        # Set memory limit (this is a background thread, polling every 100ms).
        'hard_rss_limit_mb=2048',

        # For debugging
        #'sleep_before_dying=60',
    ]
    if memleaks:
        asan_options += ['fast_unwind_on_malloc=0']
    # Workaround for the 2.0 branch looking in wrong directory
    if '-2.0' in tshark_exec:
        asan_options = [x for x in asan_options if not
                "detect_stack_use_after_return" in x]
    ubsan_options = [
        'print_stacktrace=1',
        'halt_on_error=1',
    ]
    env = {
        'PATH': os.environ['PATH'],
        # Use an empty configuration profile to avoid interference
        'HOME': homedir,
        'WIRESHARK_DEBUG_WMEM_OVERRIDE': 'simple',
        'G_SLICE': 'always-malloc',
        'ASAN_OPTIONS': ':'.join(asan_options),
        'UBSAN_OPTIONS': ':'.join(ubsan_options),
        #'WIRESHARK_ABORT_ON_DISSECTOR_BUG': '1',
    }
    # Timeout library XXX make path and timeout configurable?
    env['TIMEOUT'] = str(timeout)
    env['LD_PRELOAD'] = os.path.join(BASEDIR, "libtimeout.so")
    if memlimit:
        env['MEMLIMIT'] = str(memlimit)
        env['LD_PRELOAD'] += ":%s" % os.path.join(BASEDIR, "libmemlimit.so")

    _logger.debug("Running %r", [tshark_exec] + args)
    _logger.debug("Env: %r", env)
    proc = subprocess.run(
        [tshark_exec] + args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    stderr = as_str(proc.stderr)
    stdout = as_str(proc.stdout)
    return proc.returncode, stderr, stdout


def process_pcap(pcap_filename, homedir, timeout, memlimit, memleaks):
    repro = "tshark -Vxr"
    exitcode, stderr, stdout = run_tshark(["-Vxr", pcap_filename], homedir,
            timeout=timeout, memlimit=memlimit, memleaks=memleaks)
    _logger.info("exit=%d stderr_bytes=%d stdout_bytes=%d",
            exitcode, len(stderr), len(stdout))
    if exitcode == 0 or not stderr:
        repro = "tshark -r"
        _logger.info("Possibly no problem, trying without tree")
        exitcode, stderr, stdout = run_tshark(["-r", pcap_filename], homedir,
                timeout=timeout, memlimit=memlimit)
        _logger.info("-V exit=%d stderr_bytes=%d stdout_bytes=%d",
            exitcode, len(stderr), len(stdout))

    repro += " %s" % os.path.basename(pcap_filename)

    # XXX add an option to control this path
    # Strip source and build directories from paths
    stderr = stderr.replace('/tmp/wireshark/', '')
    stderr = stderr.replace('/tmp/wsbuild/', '')
    # Replace timeout library prefix
    stderr = stderr.replace(BASEDIR + '/', '')

    if stderr:
        _logger.debug("<stderr>\n%s\n</stderr>", stderr.strip())
    if stdout:
        _logger.debug("<stdout>\n%s\n</stdout>", stdout.strip())

    # Exited normally, OK
    if exitcode == 0:
        # Well, but not if a DissectorError happened...
        if 'WARNING **: Dissector bug' in stderr:
            return stderr, repro
        return
    return stderr, repro

def extract_call_info(errmsg, match_dissector=False):
    # Assume an issue is in dissectors
    # "    #8 0x7f9079f8ff5e in expand_dns_name epan/dissectors/packet-dns.c:1158:21"
    re_file = r'^\s+#\d+ 0x[0-9a-f]+ in (\S+) ([a-z][^:\n]+[0-9:]*)$'
    re_dissector = r'^\s+#\d+ 0x[0-9a-f]+ in (\S+) (epan/dissectors/[^:\n]+[0-9:]*)$'
    dissector_match = re.search(re_dissector if match_dissector else re_file,
            errmsg, re.MULTILINE)
    if dissector_match:
        func, filename = dissector_match.groups()
        return "%s in %s" % (filename, func)

def create_summary(errmsg):
    # Try UBSan match
    ubsan_match = re.search(r'^(?:.*/)?(.*?): runtime error: (.*)', errmsg, re.MULTILINE)
    if ubsan_match:
        return "UBSAN: %s in %s" % ubsan_match.groups()[::-1]
    # Try assertion error match
    assert_match = re.search(r'^ERROR:((?:[^ :]+:)+ assertion failed: .+)', errmsg, re.MULTILINE)
    if assert_match:
        return "ABRT: %s" % assert_match.group(1)
    # Try ASAN match
    summary_match = re.search('^SUMMARY: AddressSanitizer: (\S+)(.*)', errmsg, re.MULTILINE)
    if summary_match:
        bug_description, bug_extended_info = summary_match.groups()
        # Try to make reports more useful than just:
        # ASAN: heap-buffer-overflow (run/tshark+0xffbb1) in __interceptor_memcpy.part.40
        if bug_extended_info.strip().startswith('('):
            call_info = extract_call_info(errmsg)
            if call_info:
                bug_extended_info = " %s" % call_info
        return "ASAN: %s%s" % (bug_description, bug_extended_info)
    # Try to detect our timeout
    timeout_match = re.search(r'^ERROR: (timeout after \d+ seconds)$', errmsg, re.MULTILINE)
    if timeout_match:
        dissector_info = extract_call_info(errmsg, match_dissector=True)
        if dissector_info:
            return "timeout: %s" % dissector_info
        return timeout_match.group(1)
    # Try to detect OOM and include faulting dissector.
    oom_msg = "allocator is terminating the process instead of returning 0"
    if oom_msg in errmsg:
        msg = "out-of-memory"
        dissector_info = extract_call_info(errmsg, match_dissector=True)
        if dissector_info:
            msg += " via %s" % dissector_info
        return msg
    # WARNING **: Dissector bug, protocol BGP, in packet 1: More than 1000000 items in the tree -- possible infinite loop
    dbug_match = re.search(r'.*: (Dissector bug(?:, protocol|: ).+)', errmsg, re.MULTILINE)
    if dbug_match:
        return dbug_match.group(1)
    # Should not happen, but in case it happens, return first non-empty line
    _logger.warn("Could not detect sanitizer summary line!")
    for line in errmsg.split("\n"):
        line = line.strip()
        if line and line != "**":
            return line
    return "(unknown error)"

def create_report(pcap, errmsg, url, homedir, repro):
    version_info = run_tshark(['-v'], homedir)[2].strip()
    title = create_summary(errmsg)
    description = """
Build Information:
{build_info}
--
A problem was found by the oss-fuzz project:
{url}

Attached is the sample that triggers this error which can be reproduced with an
ASAN+UBSAN build of Wireshark:
{repro}
--
{stderr}
""".strip().format(
        build_info = version_info,
        stderr = errmsg.strip(),
        url = url,
        repro = repro,
    )
    return title, description

parser = argparse.ArgumentParser(
        epilog="Override path to tshark with env var WS_BIN_PATH."
)
parser.add_argument("--debug", action="store_true",
        help="Enable verbose debug logging")
parser.add_argument("--proto", dest='protocol', default="ip",
        help="Layer that encapsulated the sample (default %(default)s)")
parser.add_argument("--report", action="store_true",
        help="Do not just print the details, report the bug too.")
parser.add_argument("--timeout", type=int, default=25,
        help="Maximum running time limit in seconds (default %(default)d)")
parser.add_argument("--memlimit", type=int, default=2 * 1024**3,
        help="Maximum malloc size (default %(default)d)")
parser.add_argument("--memleaks", action="store_true",
        help="Enable memory leak detection")
parser.add_argument("filename", help="Reproducer Testcase")
parser.add_argument("url", help="URL of the oss-fuzz report")

def main():
    args = parser.parse_args()
    if not os.access(args.filename, os.R_OK):
        parser.error("File not found: %s" % args)

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
            format='%(asctime)s %(name)s:%(levelname)s: %(message)s')

    url = args.url
    # Quick URL from issue ID
    if url.isdigit():
        url = OSS_FUZZ_BUGURL + url

    with tempfile.TemporaryDirectory() as tmpdirname:
        if args.filename.endswith('.pcap'):
            pcap_name = args.filename
        else:
            pcap_name = "%s.pcap" % os.path.basename(args.filename)
        pcap_filename = os.path.join(tmpdirname, pcap_name)
        homedir = os.path.join(tmpdirname, "home")

        _logger.info("pcap=%s protocol=%s", pcap_name, args.protocol)

        if args.filename == pcap_name:
            # Copy file such that tshark can find it.
            shutil.copyfile(args.filename, pcap_filename)
        else:
            # Create pcap from reproducer
            create_pcap(args.protocol, args.filename, pcap_filename)

        # Workaround for crash on textdomain(NULL): the following prevents Lua
        # from triggering an error in g_dir_open which would result in a
        # error message.  https://github.com/google/sanitizers/issues/787
        os.makedirs(os.path.join(homedir, ".config/wireshark/plugins"))
        os.makedirs(os.path.join(homedir, ".local/lib/wireshark/plugins"))

        # Try to reproduce
        error = process_pcap(pcap_filename, homedir, args.timeout,
                args.memlimit, args.memleaks)
        if not error:
            _logger.warn("%s: no error", pcap_name)
        else:
            errmsg, repro = error
            title, description = create_report(pcap_name, errmsg, url, homedir,
                    repro)
            _logger.info("Title: %s", title)
            _logger.info("<description>\n%s\n</description>", description)
            _logger.info("Reproducer: %s", pcap_name)

            # Finally report the bug
            if args.report:
                report_bug(title, description, url, pcap_filename)

        # Try to copy pcap file to current directory if missing or different.
        if not os.path.exists(pcap_name) or \
                not filecmp.cmp(pcap_filename, pcap_name):
                os.rename(pcap_filename, pcap_name)

if __name__ == '__main__':
    main()
