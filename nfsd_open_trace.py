#!/usr/bin/python

from bcc import BPF
# from time import sleep
## import time
from time     import ( localtime, strftime, time as time_time )
from math     import modf
from textwrap import dedent

import os # getpid()
import sys # tests // argv

from socket import ( ntohs, inet_ntoa, inet_ntop
                   , AF_INET, AF_INET6 
                   )

from struct import pack

## import argparse
import optparse



# =========================================================================

parser = optparse.OptionParser()


# logical indentation for options
if 1:
    
    parser.add_option('--maxdirs',    '-N',     action="store",      type="int",  dest='maxdirs',    default=1,     help="max dirs, 0..4" )
    ## parser.add_option('--nfsd-check', '-C',     action="store_true",              dest='nfsd_check', default=False, help="check for nfsd actions only" )
    parser.add_option('--verify',     '-v',     action="store_true",              dest='print_code', default=False, help="print instrumented C code" )

    parser.add_option('--trace-getattr', '--getattr',    action="store_true",       dest='trace_getattr', default=False, help="trace nfsd_dispatch() / vfs_getattr()" )
    ## parser.add_option('--vfs_statx',   '--statx',      action="store_true",       dest='trace_statx',   default=False, help="trace vfs_statx()" )

options, args = parser.parse_args()

N_PATH_COMPS = options.maxdirs
## NFSD_CHECK = options.nfsd_check
NFSD_CHECK = 0 # the whole program is nfsd-only )

# =========================================================================

#
# kernel source path checks // todo: wrap this with a function at some point
#

# shall probably convert this to a list check ...
REQUIRED_HEADER = 'fs/nfsd/nfsfh.h'

def have_kernel_source( required = [REQUIRED_HEADER] ):
    """ checking that we have all required headers etc """
    
    ## have_required = None # False => break, True => return, None => continue checking
    
    #
    # do we already have the sources at some externally specified path ?
    #
    
    BCC_KERNEL_SOURCE_PATH = os.environ.get('BCC_KERNEL_SOURCE', None)
    if BCC_KERNEL_SOURCE_PATH is not None:
        
        checks_passed = True # default assumption
        for pathname in required:
            test_header_path = os.path.join( BCC_KERNEL_SOURCE_PATH, pathname )
            if not os.path.exists( test_header_path ):
                checks_passed = False
                break
        if checks_passed:
            return True

    #
    # did we download the sources to a predefined location?
    #

    with os.popen("uname -r") as p:
        KERNEL_VERSION = p.read()

    KERNEL_VERSION_MAIN = KERNEL_VERSION.split('-')[0]
    LINUX_SOURCE_DIR = 'linux-%s' % ( KERNEL_VERSION_MAIN, )
    LINUX_SOURCE_PATH = os.path.join('/usr/src', LINUX_SOURCE_DIR)
    
    # if the shorter one does not work, try the full version:
    if not os.path.exists( LINUX_SOURCE_PATH ):
        LINUX_SOURCE_DIR = 'linux-%s' % ( KERNEL_VERSION, )
        LINUX_SOURCE_PATH = os.path.join('/usr/src', LINUX_SOURCE_DIR)

    checks_passed = False # until proven so )
    if os.path.exists( LINUX_SOURCE_PATH ):
        checks_passed = True # a temporary default assumption
        for pathname in required:
            test_header_path = os.path.join( LINUX_SOURCE_PATH, pathname )
            if not os.path.exists( test_header_path ):
                checks_passed = False
                break

    if checks_passed:
        os.environ['BCC_KERNEL_SOURCE'] = LINUX_SOURCE_PATH
        print '[info] kernel source path set to "export BCC_KERNEL_SOURCE=%s"' % ( LINUX_SOURCE_PATH, )
        return True

    else:

        message = """
            kernel sources are required.
            please download them using "apt-get source linux-image-unsigned-$(uname -r)"
            ( or "apt-get install linux-source" -- and then untar /usr/src/linux-$(uname -r)/... )

            // then use either of the two to get the .config file:
            // yes '' | make oldconfig                # (i)
            // cp /boot/config-$(uname -r) ./.config  # (ii)
            // and then run 'make prepare' to obtain './include/generated/autoconf.h' :
            // make prepare -> ./include/generated/autoconf.h

            now either specify the source path via "export BCC_KERNEL_SOURCE=$PATH",
            or just put them at /usr/src -- e.g. %s
            ---
        """ % (LINUX_SOURCE_PATH, )

        message = dedent(message)
        print message
        ## sys.exit(1)
    
    # by default
    return False


# full kernel source shall not be needed if we don't trace nfsd_open()
if 0:
    if not have_kernel_source():
        print "install kernel sources for `uname -r` first! [exiting]"
        sys.exit(1)


if 0:
    sys.exit(2)

## BCC_KERNEL_SOURCE
# =========================================================================

first_ts = BPF.monotonic_time()
first_ts_real = time_time()

def get_unix_ts(timestamp_ns):
    
    offset = 1e-9 * (timestamp_ns - first_ts)
    ##      return "%.6f" % (offset + cls.first_ts_real) ##
    ts = offset + first_ts_real

    return ts

def ts_to_str( ts ):
    """ convert unix timestamp to a string """

    main = strftime('%F %T')
    tail = '%.6f' % ( modf(ts)[0] )

    result = main + tail[1:]
    return result


def make_path( event ):

    filename = event.dname0
    path = [filename]
    for i in xrange(1, 1 + N_PATH_COMPS):
        dname = getattr( event, 'dname%s' % (i,), '' )
        if dname and dname != '/' :
            path.append( dname )
        else:
            break

    path.reverse()
    result = '/'.join( path )

    return result


def indent_block( text, tabs=1, step=' '*8 ):

    indent = step * tabs
    lines = text.split('\n')
    text = indent + ('\n' + indent).join( lines )

    return text


# a test
if 0:
    
    text = """
aaa
bbb
ccc
    """.strip()
    
    ## print indent_block( text, 2 )
    print indent_block( text )
    
    sys.exit(2)

# =========================================================================

DSNIPPET = r"""
    if (pD && pD->d_name.name != 0) {
            // void *__tmp = (void *)pD->d_name.name;
            __tmp = (void *)pD->d_name.name;
            bpf_probe_read_kernel(p_data->%(dname)s, sizeof(p_data->%(dname)s), __tmp);

            pD = pD->d_parent;
            /* dentries */
    } else {
            p_data->%(dname)s[0] = '\0';
    }

"""

DSNIPPET = dedent(DSNIPPET)

VSNIPPET = r"""
    char %(dname)s[80];
    /* dnames */
"""

VSNIPPET = dedent( VSNIPPET )

COMMSNIPPET = r"""if (!is_nfsd(__data.comm)) return 0;"""

TGID_CHECK = r"""if (__tgid == %d) { return 0; }"""

with open("nfsd_open_trace.c") as f:
    bpf_code = f.read()


for i in xrange(1, 1 + N_PATH_COMPS):
    ## print i
    dname = 'dname%s' % (i, )

    vsnippet = indent_block( VSNIPPET % locals(), 1 ).lstrip()
    bpf_code = bpf_code.replace( '/* dnames */', vsnippet )

    dsnippet = indent_block( DSNIPPET % locals(), 1+i ).lstrip()
    bpf_code = bpf_code.replace( '/* dentries */', dsnippet )

    tgid_snippet = TGID_CHECK % (os.getpid(), )
    bpf_code = bpf_code.replace( '/* tgid_check */', tgid_snippet )

    if NFSD_CHECK:
        commsnippet = COMMSNIPPET
        bpf_code = bpf_code.replace( '/* comm filter */', commsnippet )

# a test
if 0:

    ## print DSNIPPET
    print bpf_code
    
    ## sys.exit(2)

if options.print_code:

    print bpf_code


# =========================================================================

## b = BPF(src_file="vfs_open_trace.c")

## #define OPCODE_VFS_OPEN     1
## #define OPCODE_VFS_GETATTR  2

OPCODE_NFSD_OPEN     = 1
OPCODE_VFS_GETATTR  = 2
## OPCODE_VFS_STATX    = 3
FUNCNAMES = { OPCODE_NFSD_OPEN    : "nfsd_open"
            , OPCODE_VFS_GETATTR : "vfs_getattr"
            ## , OPCODE_VFS_STATX   : "vfs_statx"
            }


# process event
start = 0
def print_event_default(cpu, data, size):
    global start

    event = b["probe_nfsd_open_events"].event(data)

    # relative time
    if 0:
        if start == 0:
                start = event.timestamp_ns 
        time_s = (float(event.timestamp_ns - start)) / 1000000000

    # unix timestamps
    if 1:
        time_str = ts_to_str( get_unix_ts( event.timestamp_ns ))

    str_path = make_path( event )
    ## str_path = '-'

    func_name = FUNCNAMES.get(event.opcode, '-')

    
    str_ip = '0'
    str_port = '-'
    if event.sin_family == AF_INET:
        n_port = ntohs( event.sin_port )
        str_port = str(n_port)
        
        ## str_ip = inet_ntoa( event.sin_addr.s_addr )
        # [ https://stackoverflow.com/questions/14043886/python-2-3-convert-integer-to-bytes-cleanly/14044431#14044431 ]
        ip_bytes = pack('=I', event.s_addr )
        str_ip = inet_ntoa( ip_bytes )
        
    message = "%s:%s %s" % ( str_ip, str_port, str_path )

    ## print "%-26.22f %-16s %-6d %s" % ( time_s, event.comm, event.pid, str_path )  
    print "%-28s %-6s %-6d %-12s %s" % ( time_str, event.comm, event.pid, func_name, message )  



# ======================================================================================

b = BPF(text=bpf_code)
# nfsd_open()'s 1st arg seems to be a dentry for the (containing) _directory_
if 0:
    b.attach_kprobe(event="nfsd_open", fn_name="probe_nfsd_open")
# new way
if 1:
    # order could be important ?
    b.attach_kretprobe(event="nfsd_dispatch", fn_name="probe_nfsd_dispatch_exit")
    b.attach_kprobe(event="nfsd_dispatch", fn_name="probe_nfsd_dispatch_enter")
    b.attach_kprobe(event="vfs_open", fn_name="probe_vfs_open")

##  if options.trace_getattr:
##      b.attach_kprobe(event="vfs_getattr", fn_name="probe_vfs_getattr")
if options.trace_getattr:
    ## # order could be important ?
    ## b.attach_kretprobe(event="nfsd_dispatch", fn_name="probe_nfsd_dispatch_exit")
    ## b.attach_kprobe(event="nfsd_dispatch", fn_name="probe_nfsd_dispatch_enter")
    b.attach_kprobe(event="vfs_getattr", fn_name="probe_vfs_getattr")


print("%-28s %-6s %-6s %-12s %s" % ("TIME", "COMM", "PID", "FUNC", "MESSAGE"))

# loop with callback to print_event
b["probe_nfsd_open_events"].open_perf_buffer(print_event_default)

##  if options.trace_statx:
##      b["probe_vfs_stat_events"].open_perf_buffer(print_event_default)



while 1:
    b.perf_buffer_poll()


