# bcc-nfsd-trace -- howto

Notes on making the script

* [The Goal](#the-goal)
* [Enters BCC](#enters-bcc)
* [the open() syscall](#the-open-syscall)
* [Tracing vfs_open()](#tracing-vfs_open)
* [Tracing nfsd_dispatch()](#tracing-nfsd_dispatch)

## The Goal

Suppose we are debugging some complex NFS access issues on a server.  
( One of my use cases was an OpenVMS client trying to convert between local non-Unix file attributes and remote system. )  

How do we trace what files a remote client is trying to open?  

First answer to that is to try `rpcdebug` -- e.g. `rpcdebug -m nfsd -s fh proc`, but looking at the sources 
( e.g. [(1)](https://github.com/torvalds/linux/blob/v5.8/fs/nfsd/nfsfh.c), [(2)](https://github.com/torvalds/linux/blob/v5.8/fs/nfsd/nfs3proc.c) )
one soon learns that it's not too helpful. 

Next stage could be to use Wireshark (`tshark`, see [README/tshark section](README.md#a-word-on-tshark)), 
and it produces _a lot_ of valuable information, but still has a drawback: apparently, files are identified by some special form of CRC-32.  
This is good because the identifiers are the same every time, 
and not so good because it turns out to be not so easy to find a particular form of CRC-32 that computes the observed values from known filenames.  
( For example, one can't easily do it with Python -- at least not with any obvious initialization. )

One way to obtain these hash sums would be to scan the whole file tree from a known ip address and then capture and decode that traffic, 
but ideally, we'd want to have something better.

## Enters BCC

Going old shool way -- writing a kernel module -- was not an option from the start, since you don't want to load a newly written module on a production server.

Further experimenting -- with tools like `systemtap` or `perf` -- lead to various but ultimately unsatisfactory experience, 
mostly due to the issues with locating and installing proper debugging symbols, and eventually leads us to [BCC](https://github.com/iovisor/bcc).

BCC is an acronym that stands for "BPF Compiler Collection", where BPF is a smart technology named Berkeley Packet Filters, 
mostly because it has little-to-nothing to do with Packets and has a very distant relation to Berkely.
( Filters is also not the first thing that springs to mind here. )

_( Now follows my interpretation, and I wouldn't swear that it is correct. Beware! )_

In short, modern BPF is an in-kernel interpreter, a VM -- like the one we have in Python -- that allows to _safely_ call _and intercept_ kernel functions.  
BCC provides a language to that VM -- a subset of C, where one, in theory, can not use loop statments (so e.g. `strstr()` and `strcmp()` are out of the question ), 
has limited access to `printk()` format expressions, and so on.

Additionally, BCC provides convenient language bindings (Python, Lua, ...) that allow to load this pseudo-C code into the kernel 
( that is, "compile" it to VM instructions and load ) and communicate with it from the userspace.

Here's an example ([hello_world.py](https://github.com/iovisor/bcc/blob/master/examples/hello_world.py)):
```python
#!/usr/bin/python

from bcc import BPF

# This may not work for 4.17 on x64, you need replace kprobe__sys_clone with kprobe____x64_sys_clone
BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()
```

## the open() syscall

Going through the [tools](https://github.com/iovisor/bcc/tree/master/tools) section, we soon find the uber-tools 
[trace](https://github.com/iovisor/bcc/blob/master/tools/trace.py) and 
[tplist](https://github.com/iovisor/bcc/blob/master/tools/tplist.py) 
_( nb: [argdist](https://github.com/iovisor/bcc/blob/master/tools/argdist.py) is also cool, but it's out of the scope now )_, 
and that leads us to a well-known `open()` syscall -- and friends, such as `openat()`:

```
$ sudo ./tplist.py '*open*'
hda_controller:azx_pcm_open
nfsd:read_opened
nfsd:write_opened
fs:do_sys_open
fs:open_exec
syscalls:sys_enter_mq_open
syscalls:sys_exit_mq_open
syscalls:sys_enter_open_by_handle_at
syscalls:sys_exit_open_by_handle_at
syscalls:sys_enter_open
syscalls:sys_exit_open
syscalls:sys_enter_openat
syscalls:sys_exit_openat
syscalls:sys_enter_perf_event_open
syscalls:sys_exit_perf_event_open
```

Sadly, we soon learn that `nfsd` process does not go through the `open()` syscall, and leaves all the hard work to the kernel:

```Shell

#
# here we are trying to use tplist to fetch do_sys_open() arguments ..
#

# ./tplist.py -v fs:do_sys_open
fs:do_sys_open
    __data_loc char[] filename;
    int flags;
    int mode;

#
# and it kinda fails us -- the last column below is empty
#

# ./trace.py 'do_sys_open "%s", arg1'
PID     TID     COMM            FUNC             -
6857    7068    Cache2 I/O      do_sys_open      
6857    7068    Cache2 I/O      do_sys_open      
6857    7068    Cache2 I/O      do_sys_open      
6857    7068    Cache2 I/O      do_sys_open      
6857    7068    Cache2 I/O      do_sys_open      

#
# .. well, may be tplist ain't so accurate after all
# ( or may be we shall add 1 for `struct pt_regs *ctx` -- see the tutorial ; 
#   but no one seems to make this note )
#

#
# anyway, livegrep and LXR (see below) are your friends, so :
#

## use a predefined filename, and create one locally and from an NFS client
# ./trace.py -f 'deleteme' 'do_sys_open "%s", arg2@user'
PID     TID     COMM            FUNC             -
1376    1376    touch           do_sys_open      .deleteme

# ./trace.py -f 'deleteme' 't:syscalls:sys_enter_openat "%s", args->filename' 
PID     TID     COMM            FUNC             -
2337    2337    touch           sys_enter_openat .deleteme

#
# ^^^ you still won't have any sight of nfsd there, though, so .. 
#

```

Well, even the `nfsd` kernel module _shall_ use some standard code to open the files, right?

With a bit of kernel source browsing 
(we could go old school -- download the source and use e.g. GNU Global with it, but now there's [livegrep.com](https://livegrep.com/) and [LXR](https://elixir.bootlin.com) 
-- thanks [Julia Evans](https://youtu.be/0IQlpFWTFbM)! )..  
.. we find out that nfsd-related code 
( e.g. `nfsd_open()` ([1](https://elixir.bootlin.com/linux/latest/source/fs/nfsd/vfs.c#L787)), 
([2]( https://livegrep.com/search/linux?q=nfsd_open(struct%20svc_rqst%20*&fold_case=auto&regex=false&context=true)) )
-- _a trick: search for `.h` files first, then feed the declaration to the search string_ ) invokes `vfs_open()` -- as basically does any filesystem-related kernel code.

Another way to get there is to feed `-UK` flags to `trace.py` utility; stack: 
```
vfs_open+0x1 [kernel]  
nfsd_open+0xd7 [nfsd]  
nfsd_readdir+0x64 [nfsd] 
nfsd3_proc_readdirplus+0x120 [nfsd]     
nfsd_dispatch+0xbb [nfsd]           
svc_process_common+0x380 [sunrpc]   
svc_process+0xfa [sunrpc]  
nfsd+0xe9 [nfsd] 
```

And, indeed, running a quick `vfs_open()` check with `trace.py` we can see that it is triggered by `nfsd` operations:

```Shell

# ./trace.py 'vfs_open(const struct path *pP, struct file * pF)  (pP->dentry) "%s", pP->dentry->d_name.name' | grep nfsd
7549    7549    nfsd            vfs_open         testdir

```


## Tracing vfs_open()

Fortunately, we do not have to write our program from scratch. Our uber-tool from `iovisor/bcc`, [trace.py](https://github.com/iovisor/bcc/blob/master/tools/trace.py) ( written by [Sasha Goldshtein](https://github.com/goldshtn) ), has an option to dump the generated C code :

```Shell
sudo ./trace.py -v 'vfs_open(const struct path *pP, struct file * pF)  (pP->dentry) "%s", pP->dentry->d_name.name' 
```

Sadly, the accompanying Python code does not come for granted -- but we can write it easily using lessons 4-7 from the [Python Developer Tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md) for `bcc`.

Now when we have an example that compiles -- and it makes for a good starting point -- let us add a few enclosing directories to just the filename.  
For that, we would need to traverse the file tree:

```Shell
sudo ./trace.py -v 'vfs_open(const struct path *pP, struct file * pF)  (pP->dentry) "%s | %s", pP->dentry->d_parent->d_name.name,pP->dentry->d_name.name' 
```

Unfortunately, `bcc` does not allow `for` loops ( well, apparently there's [limited support](https://github.com/iovisor/bcc/issues/691) for it in _recent kernels_, but on older kernels and by default we're out of luck ). 

Therefore, we would have to implement something like a "static" loop instead -- see `DSNIPPET` fiddling in [nfsd_open_trace.py](https://github.com/gf-mse/bcc-nfsd-trace/blob/master/nfsd_open_trace.py). However, this "static looping" can't go indefinitely due to BPF stack limitations, and therefore has to be limited to a fairly small number (4 was the maximum in my tests).

Finally, it would be nice to have event timestamps -- so `get_unix_ts()` in [nfsd_open_trace.py](https://github.com/gf-mse/bcc-nfsd-trace/blob/master/nfsd_open_trace.py) is an adjustment of [trace.py](https://github.com/iovisor/bcc/blob/master/tools/trace.py)' `_time_off_str()` for our purpose.


## Tracing nfsd_dispatch()

Listing opened files is already helpful -- but of course we'd like to have at least the IP address as well.  
Examining the stack trace (see e.g. [above](#the-open-syscall)) and browsing the [source code](https://elixir.bootlin.com/linux/latest/source), we can see that one good entry point to check could be `nfsd_dispatch()`( [[1](https://github.com/torvalds/linux/blob/d8a5b80568a9cb66810e75b182018e9edb68e8ff/fs/nfsd/nfssvc.c#L791)], [[2](https://elixir.bootlin.com/linux/latest/C/ident/nfsd_dispatch)], [[3](https://elixir.bootlin.com/linux/latest/source/fs/nfsd/nfssvc.c#L1004)] ).

There would be a tiny problem here -- we would need to store the ip address data from `nfsd_dispatch()` before we eventually get to e.g. `vfs_getattr()` and can inspect `dentry` data.  
And this, of course, is what bpf hashes are for -- again, see lessons 4 and 6 from the `bcc` [tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md); the only thing to remember is to remove the pointer key from the hash when it is not needed anymore.

Another issue is that our Python code would not be able to recognize complex kernel structures like `__kernel_sockaddr_storage`, and we shall help it by reducing the transferred data structure to standard C types.  
Thus, `sin_family` and `sin_port` are converted to `unsigned short` type, and `s_addr` from `struct in_addr` is stored as an `unsigned int`.

Finally, if one would have decided to attach to `nfsd_open()` instead of e.g. `vfs_open()` -- e.g. to have the file (`struct dentry *`) and the IP address (`struct svc_rqst`) at once -- then our code would have required the header `fs/nfsd/nfsfh.h` and wouldn't compile.

The subsection below shows how to install full kernel source and make it compile in that case.

### Install Kernel Sources

 * _This is not needed any more. I am leaving it here as an illustration on how to include other kernel headers if required. _

Sadly, that won't be enough since our code is referring some header files outside of the "stock" kernel header tree which comes with the "linux-headers" package.
One way to go about it would be to download the full source:

```Shell

sudo apt-get build-dep linux linux-image-$(uname -r)

apt-get source linux-image-unsigned-$(uname -r)
# or "apt-get install linux-source" -- and then untar /usr/src/linux-$(uname -r)/... )

cd linux-$(uname -r) # the name may differ
cp /boot/config-$(uname -r) ./.config
# or "yes '' | make oldconfig"
make prepare # makes ./include/generated/autoconf.h

# now move or symlink the code to /usr/src/linux-$(uname -r)
cd ..
sudo ln -s linux-$(uname -r) /usr/src/linux-$(uname -r)
```

