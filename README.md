# bcc-nfsd-trace
iovisor/bcc - based demo tracing (server-side) nfsd opens, etc

## Overview

 * `sudo ./nfsd_open_trace.py --getattr -N 4` :

    TIME(s)                     COMM   PID    FUNC         MESSAGE
    2020-09-02 20:58:08.0.5001  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
    2020-09-02 20:58:08.0.5035  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
    2020-09-02 20:58:08.0.5039  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:08.0.5041  nfsd   7549   vfs_open     192.168.1.31:801 testdir
    2020-09-02 20:58:08.0.5042  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
    2020-09-02 20:58:08.0.5042  nfsd   7549   vfs_getattr  192.168.1.31:801 /
    2020-09-02 20:58:08.0.5042  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:08.0.5042  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
    2020-09-02 20:58:09.0.9231  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:09.0.9235  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:09.0.9466  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:09.0.9470  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:11.0.5393  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
    2020-09-02 20:58:11.0.5400  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
    2020-09-02 20:58:11.0.5400  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/.#testfile
    2020-09-02 20:58:14.0.6453  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:14.0.6460  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:14.0.6466  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:14.0.6469  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:14.0.6471  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:14.0.6475  nfsd   7549   vfs_open     192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:14.0.6476  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/testfile
    2020-09-02 20:58:14.0.6479  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir/.#testfile
    2020-09-02 20:58:14.0.6484  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
    2020-09-02 20:58:15.0.1261  nfsd   7549   vfs_getattr  192.168.1.31:801 testdir
    2020-09-02 20:58:15.0.1264  nfsd   7549   vfs_open     192.168.1.31:801 testdir

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


