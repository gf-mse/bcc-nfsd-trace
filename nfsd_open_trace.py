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

    parser.add_option('--trace-getattr', '--getattr',    action="store_true",       dest='trace_getattr',  default=False,  help="trace nfsd_dispatch() / vfs_getattr()"   )
    parser.add_option('--trace-unlunk',  '--unlink',     action="store_true",       dest='trace_unlink',   default=False,  help="trace nfsd_dispatch() / vfs_unlink()"    )
    parser.add_option('--trace-chmod',   '--chmod',      action="store_true",       dest='trace_chmod',    default=False,  help="trace nfsd_dispatch() / notify_change()" )
    parser.add_option('--trace-statfs',  '--stat',       action="store_true",       dest='trace_statfs',   default=False,  help="trace nfsd_dispatch() / vfs_statfs()"    )
    ## parser.add_option('--vfs_statx',   '--statx',      action="store_true",       dest='trace_statx',   default=False, help="trace vfs_statx()" )

    # nfsd_...() stuff -- may require full kernel source ( see USE_KERNEL_SOURCE )
    parser.add_option('--trace-lookup',  '--lookup',     action="store_true",       dest='trace_nfsd_lookup',   default=False,  help="trace nfsd_lookup() // requires kernel source" )

options, args = parser.parse_args()

N_PATH_COMPS = options.maxdirs
## NFSD_CHECK = options.nfsd_check
NFSD_CHECK = 0 # the whole program is nfsd-only )

USE_KERNEL_SOURCE = 0 # for 'fs/nfsd/nfsfh.h' etc -- tracing nfsd_...() functions requires that
if options.trace_nfsd_lookup:
    USE_KERNEL_SOURCE = 1

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
            for some options (tracing some nfsd_...() calls), kernel sources are required.
            if they are in use -- please download the kernel source code
            using "apt-get source linux-image-unsigned-$(uname -r)"
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
if USE_KERNEL_SOURCE:
    print "[info] one of the specified options may require full kernel source .."
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
            // bpf_probe_read_kernel(p_data->%(dname)s, sizeof(p_data->%(dname)s), __tmp);
            bpf_probe_read_kernel(p_data->%(dname)s, sizeof(p_data->%(dname)s) - 1, __tmp);
            p_data->%(dname)s[sizeof(p_data->%(dname)s) - 1] = '\0'; // cut the name if too long

            pD = pD->d_parent;
            /* dentries */
    } else {
            p_data->%(dname)s[0] = '\0';
    }

"""

DSNIPPET = dedent(DSNIPPET)

VSNIPPET = r"""
    char %(dname)s[72];
    /* dnames */
"""

VSNIPPET = dedent( VSNIPPET )

COMMSNIPPET = r"""if (!is_nfsd(__data.comm)) return SKIP_IT;"""

TGID_CHECK = r"""if (__tgid == %d) { return SKIP_IT; }"""

KSOURCE_DEFINE = "#define HAVE_KERNEL_SOURCE 1"

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

    if USE_KERNEL_SOURCE:
        bpf_code = bpf_code.replace( '/* if have kernel source */', KSOURCE_DEFINE )

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

## OPCODE_NFSD_OPEN     = 1
OPCODE_VFS_OPEN        = 1
OPCODE_VFS_GETATTR     = 2
OPCODE_VFS_UNLINK      = 3
OPCODE_NOTIFY_CHANGE   = 4  
OPCODE_VFS_STATFS      = 5 
# let us have a joint list of constants for all probe structures --
# -- makes potential refactoring easier
OPCODE_NFSD_LOOKUP     = 6

FUNCNAMES = { OPCODE_VFS_OPEN       : "vfs_open"
            , OPCODE_VFS_GETATTR    : "vfs_getattr"
            , OPCODE_VFS_UNLINK     : "vfs_unlink"
            , OPCODE_NOTIFY_CHANGE  : "notify_change"
            , OPCODE_VFS_STATFS     : "vfs_statfs"
            , OPCODE_NFSD_LOOKUP    : "nfsd_lookup"
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

    inode = event.i_ino

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
        
    message = "%s:%s %s (%s)" % ( str_ip, str_port, str_path, inode )

    # chmod
    if event.opcode == OPCODE_NOTIFY_CHANGE:
        newmode = '0o%06o' % event.umode
        message = '%s -> %s' % ( message, newmode )

    print "%-28s %-6s %-6d %-14s %s" % ( time_str, event.comm, event.pid, func_name, message )  


# --------------------------------------------------------------------------------------

def print_event_lookup(cpu, data, size):

    event = b["probe_nfsd_lookup_events"].event(data)


    # unix timestamps
    time_str = ts_to_str( get_unix_ts( event.timestamp_ns ))

    ## str_path = '-'
    str_path = event.lookup_name
    if event.dname:
        str_path = '%s/%s' % ( event.dname, str_path )

    inode = event.i_ino
    ## inode_name = event.ino_name

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


    ## message = "%s:%s %s (%s)" % ( str_ip, str_port, str_path, inode, inode_name )
    # omit inode when it's not retrieved
    if inode != 0:
        message = "%s:%s %s (%s)" % ( str_ip, str_port, str_path, inode )
    else:
        message = "%s:%s %s" % ( str_ip, str_port, str_path )

    ## print "%-26.22f %-16s %-6d %s" % ( time_s, event.comm, event.pid, str_path )  
    print "%-28s %-6s %-6d %-14s %s" % ( time_str, event.comm, event.pid, func_name, message )  


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

if options.trace_unlink:
    b.attach_kprobe(event="vfs_unlink", fn_name="probe_vfs_unlink")

if options.trace_chmod:
    b.attach_kprobe(event="notify_change", fn_name="probe_notify_change")

if options.trace_statfs:
    b.attach_kprobe(event="vfs_statfs", fn_name="probe_vfs_statfs")


print("%-28s %-6s %-6s %-14s %s" % ("TIME", "COMM", "PID", "FUNC", "MESSAGE"))

# loop with callback to print_event
b["probe_nfsd_open_events"].open_perf_buffer(print_event_default)


if options.trace_nfsd_lookup:

    b.attach_kprobe(event="nfsd_lookup", fn_name="probe_nfsd_lookup")
    b["probe_nfsd_lookup_events"].open_perf_buffer(print_event_lookup)
    


while 1:
    b.perf_buffer_poll()


