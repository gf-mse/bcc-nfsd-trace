# bcc-nfsd-trace
An `iovisor/bcc` - based demo script which traces (server-side) nfsd opens, etc

* [Quick Glance](#quick-glance)
  - [a word on tshark](#a-word-on-tshark)
* [Installation](#installation)
  - [Install `iovisor-bcc`](#install-iovisor-bcc)
  - [(optional) Install Kernel Sources](#install-kernel-sources) 
* [Run the Tracer](#run-the-tracer)

## Quick Glance

Which NFS clients are opening our files?

```
$ sudo ./nfsd_open_trace.py --getattr -N 4

TIME(s)                     COMM   PID    FUNC         MESSAGE
2020-09-02 20:58:08.5001  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
2020-09-02 20:58:08.5035  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
2020-09-02 20:58:08.5039  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:08.5041  nfsd   7549   vfs_open     192.168.1.31:801 testdir
2020-09-02 20:58:08.5042  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
2020-09-02 20:58:08.5042  nfsd   7549   vfs_getattr  192.168.1.31:801 /
2020-09-02 20:58:08.5042  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:08.5042  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
2020-09-02 20:58:09.9231  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:09.9235  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:09.9466  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:09.9470  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:11.5393  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
2020-09-02 20:58:11.5400  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
2020-09-02 20:58:11.5400  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/.#testfile
2020-09-02 20:58:14.6453  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:14.6460  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:14.6466  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:14.6469  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:14.6471  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:14.6475  nfsd   7549   vfs_open     192.168.1.31:801 testdir/testfile
2020-09-02 20:58:14.6476  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
2020-09-02 20:58:14.6479  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/.#testfile
2020-09-02 20:58:14.6484  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
2020-09-02 20:58:15.1261  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
2020-09-02 20:58:15.1264  nfsd   7549   vfs_open     192.168.1.31:801 testdir
```

### notes

Sadly, this does not list a full path to the file; instead, due to `BCC/eBPF` stack limitations, it prints up to 4 containing directories (see the `-N` option).
( So instead of giving the full path, it sort of prints its tail directories ending with the filename.) Still, this is way better than nothing, and when paired with `tshark` (see below), it can really fill the missing bits of the whole picture )

### a word on tshark

When paired with `tshark`, 

```Shell
tshark -f "port 2049 && host $ip" -i $eth $options -w $savefile -P -t ad

#
# text export with an nfs-related filter
#

dfilter='nfs || nfsacl || nfsauth'

tshark -r $savefile -Y "$dfilter" -V -P -t ad >$savefile.1.text
# these two don't differ much when it comes to simple access calls etc
tshark -r $savefile -Y "$dfilter" -P -t ad >$savefile.1.txt
# tshark -r $savefile -2 -R "$dfilter" -P -t ad >$savefile.2.txt

#
# cut the most interesting part
#

# would miss the first frame number, add a "-e '/^Frame/p'" if needed )
sed -n '/^Remote Procedure Call/,/^Frame/p' <$savefile.1.text >$savefile.excerpts.text 
```

This can help debugging NFS access issues like `uid`/`gid` mismatch, file ownership / group membership, etc etc.

## Installation

Below we shall have brief install instructions, and there also shall be a [HOWTO](HOWTO.md) with a short overview on how one can write this.

 * Both instructions below and the HOWTO are targeting an Ubuntu system, so these could probably be applied to Debian with no much effort ; 
   as for other OS-es (hi RedHat), it may take a bit of extra fiddling (mostly with getting the kernel source, I expect);
   however, I don't think that for most popular distributions it would be too difficult.

 * Also, as most examples at `iovisor-bcc`, this code is Python2 ; again, it shall not be a big issue to either install python2 on your system or port this to Py3, since the Python code is small and simple )

### Install `iovisor-bcc`

Do [as instructed](https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source) ; in particular, I shall note that 18.04 instructions suit to 16.04 as well:

```Shell
sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev

git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make

# instead of `make install` , I would recommend to go with a checkinstall wrapper --
#  -- just in case if you may later decide to remove this from your system

sudo apt-get install checkinstall
cd bcc/build && checkinstall -D --pkgname bcc-local --pkgversion `date +%F` --delspec=no --spec=bcc-local.spec --maintainer='your-name@example.com'

```

### Install Kernel Sources

Sadly, some options may require header files outside of the "stock" kernel header tree which comes with the "linux-headers" package.

 * _nb: however, if they are not in use, full kernel source is <ins>not</ins> required and this section can be skipped._

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


## Run the Tracer

```
Usage: nfsd_open_trace.py [options]

Options:
  -h, --help            show this help message and exit
  -N MAXDIRS, --maxdirs=MAXDIRS
                        max dirs, 0..4
  -v, --verify          print instrumented C code
  --trace-getattr, --getattr
                        trace nfsd_dispatch() / vfs_getattr()
  --trace-unlunk, --unlink
                        trace nfsd_dispatch() / vfs_unlink()
  --trace-chmod, --chmod
                        trace nfsd_dispatch() / notify_change()
  --trace-statfs, --stat
                        trace nfsd_dispatch() / vfs_statfs()

```

An example -- client enters a remote directory and creates a file using a text editor ; `.#.deleteme` is a temporary symlink ( mc stuff ) :

```
# ./nfsd_open_trace.py --chmod --unlink -N 4
TIME                         COMM   PID    FUNC           MESSAGE
2020-09-06 15:11:39.092970   nfsd   7549   vfs_open       192.168.1.31:801 testdir (1336)
2020-09-06 15:11:44.157736   nfsd   7549   notify_change  192.168.1.31:801 testdir/.deleteme (565) -> 0o100644
2020-09-06 15:11:44.158855   nfsd   7549   vfs_open       192.168.1.31:801 testdir/.deleteme (565)
2020-09-06 15:11:44.159177   nfsd   7549   vfs_unlink     192.168.1.31:801 testdir/.#.deleteme (566)
2020-09-06 15:11:44.694515   nfsd   7549   vfs_open       192.168.1.31:801 testdir (1336)

```

Integer numbers after the filenames are the inode numbers.

 * There's also a somewhat older example of the output in the [Overview](#overview) section.

