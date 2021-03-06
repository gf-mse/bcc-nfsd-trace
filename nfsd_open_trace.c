
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

#include <linux/fs.h>
#include <linux/sunrpc/svc.h> /* struct svc_rqst */

/* if we do not use nfsd_open(), then "struct svc_fh *fhp" and this header are also not needed */ 
#define PROBE_NFSD_OPEN_OFF 1
#ifndef PROBE_NFSD_OPEN_OFF
    #include <../fs/nfsd/nfsfh.h> /* struct svc_fh */
#endif
// #define HAVE_KERNEL_SOURCE 1 // dev mode
/* if have kernel source */
#ifdef HAVE_KERNEL_SOURCE
    #include <../fs/nfsd/nfsfh.h> /* struct svc_fh */
#endif

#define OPCODE_VFS_OPEN            1
#define OPCODE_VFS_GETATTR         2
#define OPCODE_VFS_UNLINK          3
#define OPCODE_NOTIFY_CHANGE       4
#define OPCODE_VFS_STATFS          5
// let's merge various #define-s for all structures -- easier to join them to one if needed
#define OPCODE_NFSD_LOOKUP         6
#define OPCODE_NFSD_LOOKUP_DENTRY  7

#define MAX_FILENAME_LEN    256

// skipping unrelated probes
#define SKIP_IT (-1)
// #define PROCEED (0)

struct probe_nfsd_open_data_t
{
        u32 opcode;
        u64 timestamp_ns;

        u32 tgid;
        u32 pid;
        char comm[TASK_COMM_LEN];

        /* include/uapi/linux/in.h */
        // __kernel_sa_family_t  sin_family;  /*  Address family    */
        /* for __kernel_sa_family_t -- see include/uapi/linux/socket.h:10 */
        unsigned short      sin_family;    /*  Address family    */
        //      __be16        sin_port;    /*  Port number       */
        /* tools/include/linux/types.h -> include/uapi/asm-generic/int-l64.h */
        unsigned short        sin_port;    /*  Port number       */
    
        // struct in_addr     in_addr;     /*  Internet address  */
        /* 
         * include/uapi/linux/in.h 
         * -> tools/include/linux/types.h 
         * -> include/uapi/asm-generic/int-l64.h
         */
        unsigned int          s_addr;      /*  Internet address  */

        unsigned long         i_ino;       /* from "struct inode" */

        unsigned short        umode; /* for notify_change() */

        // sadly, pointer arithmetic seems to be out of the question  
        char dname0[72];
        /* dnames */
};

BPF_PERF_OUTPUT(probe_nfsd_open_events);

/* tid -> rqstp */
BPF_HASH(hash_getattr, u64, struct svc_rqst * );

/*
#define NFSD "nfsd"

static inline 
int is_nfsd( char* comm ) {
    // return comm && comm[0] == 'n' && comm[1] == 'f' && comm[2] ...
    
    // using branched return statements in attempt to save stack ))
    if (comm) {
        // return __builtin_memcmp(comm, NFSD, sizeof(NFSD)) == 0;
        return comm[0] == 'n' && comm[1] == 'f' && comm[2] == 's' && comm[3] == 'd' && comm[4] == '\0' ;
    } else {
        return 0;
    }
}
*/

static inline 
void load_dentries(struct dentry* pD, struct probe_nfsd_open_data_t* p_data) { 
        void *__tmp = 0;

        if (pD && pD->d_name.name != 0) {            
                __tmp = (void *)pD->d_name.name;
                bpf_probe_read_kernel(p_data->dname0, sizeof(p_data->dname0) - 1, __tmp);
                p_data->dname0[sizeof(p_data->dname0) - 1] = '\0'; // cut the name if too long
            
                pD = pD->d_parent;
                /* dentries */

        } else {
            p_data->dname0[0] = '\0' ;
        }    
}

static inline 
void read_dentry_name(char* p, int size, struct dentry* pD) { 
        void *__tmp = 0;

        if (pD && pD->d_name.name != 0) {            
                __tmp = (void *)pD->d_name.name;
                // bpf_probe_read_kernel(p, size, __tmp);
                bpf_probe_read_kernel(p, size-1, __tmp);
                p[size-1] = '\0';
        } else {
            p[0] = '\0' ;
        }    
}


/* "struct svc_fh *fhp" requires a full kernel source, so -- we temporarily switch this off */ 
#ifndef PROBE_NFSD_OPEN_OFF
int probe_nfsd_open( struct pt_regs *ctx, struct svc_rqst *rqstp, struct svc_fh *fhp
                   , umode_t type, int may_flags, struct file **filp)
{
        u64 __pid_tgid = bpf_get_current_pid_tgid();
        u32 __tgid = __pid_tgid >> 32;
        u32 __pid = __pid_tgid; // implicit cast to u32 for bottom half

        /* tgid_check */

        void *__tmp = 0;
        // if (__tgid == 23356) { return 0; }

        struct probe_nfsd_open_data_t __data = {0};
        __data.opcode = OPCODE_VFS_OPEN;
        __data.tgid = __tgid;
        __data.pid = __pid;

        __data.timestamp_ns = bpf_ktime_get_ns();
        
        bpf_get_current_comm(&__data.comm, sizeof(__data.comm));
        /* comm filter // disabled */

        // __entry->ipv4addr = rqstp->rq_addr.ss_family == AF_INET ? ((struct sockaddr_in *)&rqstp->rq_addr)->sin_addr.s_addr : 0;
        __data.sin_family = rqstp->rq_addr.ss_family ;
        if ( rqstp->rq_addr.ss_family == AF_INET ) {
            struct sockaddr_in *pS = (struct sockaddr_in *) &rqstp->rq_addr ;

            __data.sin_port = pS->sin_port ;
            // __data.sin_addr.s_addr = pS->sin_addr.s_addr ;
            __data.s_addr = pS->sin_addr.s_addr ;
        } else {
            __data.sin_port = 0 ;
            // __data.sin_addr.s_addr = 0 ;
            __data.s_addr = 0 ;
        }

        struct dentry* pD = fhp->fh_dentry; 
        load_dentries(pD, &__data);

        probe_nfsd_open_events.perf_submit(ctx, &__data, sizeof(__data));

        return 0;
}
#endif

// -------------------------------------------------------------------------------
/* nfsd_...() -- based probes; nb: these may require a full kernel source ref to compile */

#ifdef HAVE_KERNEL_SOURCE

// mostly replicating probe_nfsd_open_data_t for two reasons:
//  (1) if we aren't using extra fields, we shall not be paying for that ;
//  (2) using unions is fairly difficult due to limitations of the C-to-Python parser .
struct probe_nfsd_lookup_data_t
{
        u32 opcode;
        u64 timestamp_ns;

        u32 tgid;
        u32 pid;
        char comm[TASK_COMM_LEN];

        /* include/uapi/linux/in.h */
        // __kernel_sa_family_t  sin_family;  /*  Address family    */
        /* for __kernel_sa_family_t -- see include/uapi/linux/socket.h:10 */
        unsigned short      sin_family;    /*  Address family    */
        //      __be16        sin_port;    /*  Port number       */
        /* tools/include/linux/types.h -> include/uapi/asm-generic/int-l64.h */
        unsigned short        sin_port;    /*  Port number       */
    
        // struct in_addr     in_addr;     /*  Internet address  */
        /* 
         * include/uapi/linux/in.h 
         * -> tools/include/linux/types.h 
         * -> include/uapi/asm-generic/int-l64.h
         */
        unsigned int          s_addr;      /*  Internet address  */

        unsigned long         i_ino;       /* from "struct inode" */
        // char ino_name[80]; // a test: the name from inode' dentry

        char  lookup_name[80];
        char  dname[80]; /* dentry name */
};

BPF_PERF_OUTPUT(probe_nfsd_lookup_events);


// -------------------------------------------------------------------------------

static inline 
int get_nfsd_lookup_data( struct pt_regs *ctx, struct probe_nfsd_lookup_data_t* p_data, u32 opcode
                        , struct svc_rqst *rqstp, struct svc_fh *fhp, const char *name )
{

        u64 __pid_tgid = bpf_get_current_pid_tgid();
        u32 __tgid = __pid_tgid >> 32;
        u32 __pid = __pid_tgid; // implicit cast to u32 for bottom half

        // void *__tmp = 0;
        // if (__tgid == 23356) { return SKIP_IT; }

        /* tgid_check */


        // struct probe_nfsd_open_data_t __data = {0};
        p_data->opcode = opcode;
        p_data->tgid = __tgid;
        p_data->pid = __pid;

        p_data->timestamp_ns = bpf_ktime_get_ns();
        
        bpf_get_current_comm(&(p_data->comm), sizeof(p_data->comm));
        /* comm filter // disabled */

        struct svc_rqst** rqstpp = hash_getattr.lookup(&__pid_tgid);
	if (rqstpp != 0) {
            struct svc_rqst* rqstp = *rqstpp;
            // one more check
            if (rqstp == 0) return SKIP_IT;
            
            // else ..
            
            // __entry->ipv4addr = rqstp->rq_addr.ss_family == AF_INET ? ((struct sockaddr_in *)&rqstp->rq_addr)->sin_addr.s_addr : 0;
            p_data->sin_family = rqstp->rq_addr.ss_family ;
            if ( rqstp->rq_addr.ss_family == AF_INET ) {
                struct sockaddr_in *pS = (struct sockaddr_in *) &rqstp->rq_addr ;

                p_data->sin_port = pS->sin_port ;
                // p_data->sin_addr.s_addr = pS->sin_addr.s_addr ;
                p_data->s_addr = pS->sin_addr.s_addr ;
            } else {
                p_data->sin_port = 0 ;
                // p_data->sin_addr.s_addr = 0 ;
                p_data->s_addr = 0 ;
            }
        } else {
            // unknown/unexpected, skip it
            return SKIP_IT;
        }

        // "unsigned int len" probably means that it is not null-terminated
        bpf_probe_read_kernel(p_data->lookup_name, sizeof(p_data->lookup_name) - 1, name);
        p_data->lookup_name[sizeof(p_data->lookup_name)-1] = '\0';

        struct dentry* pD = fhp->fh_dentry; 
        // retrieve the inode number, if set
        if (pD->d_inode) {
            p_data->i_ino = pD->d_inode->i_ino;
        } else {
            p_data->i_ino = 0;
        }
        // load_dentries(pD, &__data);
        read_dentry_name(p_data->dname, sizeof(p_data->dname), pD);

        // probe_nfsd_open_events.perf_submit(ctx, &__data, sizeof(__data));
        
        return 0;
}

#if 0
//  nfsd_lookup(struct svc_rqst *rqstp, struct svc_fh *fhp, const char *name,
//  				unsigned int len, struct svc_fh *resfh)
int probe_nfsd_lookup( struct pt_regs *ctx, struct svc_rqst *rqstp, struct svc_fh *fhp, const char *name    
                     , unsigned int len, struct svc_fh *resfh)
{
        u64 __pid_tgid = bpf_get_current_pid_tgid();
        u32 __tgid = __pid_tgid >> 32;
        u32 __pid = __pid_tgid; // implicit cast to u32 for bottom half

        /* tgid_check */

        void *__tmp = 0;
        // if (__tgid == 23356) { return 0; }

        struct probe_nfsd_lookup_data_t __data = {0};
        __data.opcode = OPCODE_NFSD_LOOKUP;
        __data.tgid = __tgid;
        __data.pid = __pid;

        __data.timestamp_ns = bpf_ktime_get_ns();
        
        bpf_get_current_comm(&__data.comm, sizeof(__data.comm));
        /* comm filter // disabled */

        // __entry->ipv4addr = rqstp->rq_addr.ss_family == AF_INET ? ((struct sockaddr_in *)&rqstp->rq_addr)->sin_addr.s_addr : 0;
        __data.sin_family = rqstp->rq_addr.ss_family ;
        if ( rqstp->rq_addr.ss_family == AF_INET ) {
            struct sockaddr_in *pS = (struct sockaddr_in *) &rqstp->rq_addr ;

            __data.sin_port = pS->sin_port ;
            // __data.sin_addr.s_addr = pS->sin_addr.s_addr ;
            __data.s_addr = pS->sin_addr.s_addr ;
        } else {
            __data.sin_port = 0 ;
            // __data.sin_addr.s_addr = 0 ;
            __data.s_addr = 0 ;
        }

        // "unsigned int len" probably means that it is not null-terminated
        bpf_probe_read_kernel(&__data.lookup_name, sizeof(__data.lookup_name) - 1, name);
        __data.lookup_name[sizeof(__data.lookup_name)-1] = '\0';

        struct dentry* pD = fhp->fh_dentry; 
        // retrieve the inode number, if set
        if (pD->d_inode) {
            __data.i_ino = pD->d_inode->i_ino;
        } else {
            __data.i_ino = 0;
        }
        // load_dentries(pD, &__data);
        read_dentry_name(__data.dname, sizeof(__data.dname), pD);

        probe_nfsd_lookup_events.perf_submit(ctx, &__data, sizeof(__data));

        return 0;
}
#endif


int probe_nfsd_lookup( struct pt_regs *ctx, struct svc_rqst *rqstp, struct svc_fh *fhp, const char *name    
                     , unsigned int len, struct svc_fh *resfh)
{
        struct probe_nfsd_lookup_data_t __data = {0};

        int result = get_nfsd_lookup_data( ctx, &__data, OPCODE_NFSD_LOOKUP, rqstp, fhp, name );
        if ( result != SKIP_IT ) {
            probe_nfsd_lookup_events.perf_submit(ctx, &__data, sizeof(__data));
        }

        return 0;
}

//  nfsd_lookup_dentry(struct svc_rqst *rqstp, struct svc_fh *fhp,
//  		   const char *name, unsigned int len,
//  		   struct svc_export **exp_ret, struct dentry **dentry_ret)
int probe_nfsd_lookup_dentry( struct pt_regs *ctx, struct svc_rqst *rqstp, struct svc_fh *fhp
  		            , const char *name, unsigned int len
  		            , struct svc_export **exp_ret, struct dentry **dentry_ret )
{
        struct probe_nfsd_lookup_data_t __data = {0};

        int result = get_nfsd_lookup_data( ctx, &__data, OPCODE_NFSD_LOOKUP_DENTRY, rqstp, fhp, name );
        if ( result != SKIP_IT ) {
            probe_nfsd_lookup_events.perf_submit(ctx, &__data, sizeof(__data));
        }

        return 0;
}


#endif /* defined(HAVE_KERNEL_SOURCE) */


// -------------------------------------------------------------------------------
/* vfs_open() -- based version */

// https://github.com/torvalds/linux/blob/bcf876870b95592b52519ed4aafcf9d95999bc9c/fs/nfsd/nfssvc.c#L1004
int probe_nfsd_dispatch_enter( struct pt_regs *ctx, struct svc_rqst *rqstp, __be32 *statp )
{
        u64 tid = bpf_get_current_pid_tgid();
    
        struct svc_rqst** rqstpp = hash_getattr.lookup(&tid);
	if (rqstpp != 0) {
                hash_getattr.delete(&tid);
        }

        hash_getattr.update(&tid, &rqstp);

        return 0;
}


int probe_nfsd_dispatch_exit( struct pt_regs *ctx, struct svc_rqst *rqstp, __be32 *statp )
{
        u64 tid = bpf_get_current_pid_tgid();
    
        struct svc_rqst** rqstpp = hash_getattr.lookup(&tid);
	if (rqstpp != 0) {
                hash_getattr.delete(&tid);
        }

        return 0;
}

// -------------------------------------------------------------------------------

static inline 
int retrieve_probe_data(struct pt_regs *ctx, struct probe_nfsd_open_data_t* p_data, u32 opcode, struct dentry* pD) {

        u64 __pid_tgid = bpf_get_current_pid_tgid();
        u32 __tgid = __pid_tgid >> 32;
        u32 __pid = __pid_tgid; // implicit cast to u32 for bottom half

        // if (__pid_tgid == 0) return SKIP_IT; // trying to suppress strange messages from pid 0 and comm ''

        /* tgid_check */

        // void *__tmp = 0;
        // if (__tgid == 23356) { return SKIP_IT; }

        // struct probe_nfsd_open_data_t __data = {0};
        p_data->opcode = opcode;
        p_data->tgid = __tgid;
        p_data->pid = __pid;

        p_data->timestamp_ns = bpf_ktime_get_ns();
        
        bpf_get_current_comm(&(p_data->comm), sizeof(p_data->comm));
        /* comm filter // disabled */

        struct svc_rqst** rqstpp = hash_getattr.lookup(&__pid_tgid);
	if (rqstpp != 0) {
            struct svc_rqst* rqstp = *rqstpp;
            // one more check
            if (rqstp == 0) return SKIP_IT;
            
            // else ..
            
            // __entry->ipv4addr = rqstp->rq_addr.ss_family == AF_INET ? ((struct sockaddr_in *)&rqstp->rq_addr)->sin_addr.s_addr : 0;
            p_data->sin_family = rqstp->rq_addr.ss_family ;
            if ( rqstp->rq_addr.ss_family == AF_INET ) {
                struct sockaddr_in *pS = (struct sockaddr_in *) &rqstp->rq_addr ;

                p_data->sin_port = pS->sin_port ;
                // p_data->sin_addr.s_addr = pS->sin_addr.s_addr ;
                p_data->s_addr = pS->sin_addr.s_addr ;
            } else {
                p_data->sin_port = 0 ;
                // p_data->sin_addr.s_addr = 0 ;
                p_data->s_addr = 0 ;
            }
        } else {
            // unknown/unexpected, skip it
            return SKIP_IT;
        }

        // retrieve the inode number, if set
        if (pD->d_inode) {
            p_data->i_ino = pD->d_inode->i_ino;
            //  if (pD->d_inode->i_sb) {
            //      // bpf_probe_read_kernel(&p_data->ino_name, sizeof(p_data->ino_name), __tmp); 
            //      read_dentry_name((char*)&p_data->ino_name, sizeof(p_data->ino_name), pD->d_inode->i_sb->s_root );
            //  } else {
            //      p_data->ino_name[0] = '\0';
            //  }
        } else {
            p_data->i_ino = 0;
            // p_data->ino_name[0] = '\0';
        }
        
        load_dentries(pD, p_data);

        // probe_nfsd_open_events.perf_submit(ctx, &__data, sizeof(__data));
        
        return 0;
}


// -------------------------------------------------------------------------------

int probe_vfs_open(struct pt_regs *ctx, const struct path *pP, struct file * pF)
{

        struct probe_nfsd_open_data_t __data = {0};

        struct dentry* pD = pP->dentry; 
        if ( pF->f_path.dentry ) { pD = pF->f_path.dentry; }

        int result = retrieve_probe_data(ctx, &__data, OPCODE_VFS_OPEN, pD);
        if ( result != SKIP_IT ) {
            probe_nfsd_open_events.perf_submit(ctx, &__data, sizeof(__data));
        }
            
        return 0;
}



int probe_vfs_getattr( struct pt_regs *ctx, const struct path *pP
                     , struct kstat *stat, u32 request_mask, unsigned int query_flags )
{

        struct probe_nfsd_open_data_t __data = {0};

        struct dentry* pD = pP->dentry; 

        int result = retrieve_probe_data(ctx, &__data, OPCODE_VFS_GETATTR, pD);
        if ( result != SKIP_IT ) {
            probe_nfsd_open_events.perf_submit(ctx, &__data, sizeof(__data));
        }

        return 0;
}


// int vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
int probe_vfs_unlink( struct pt_regs *ctx, struct inode *dir
                    , struct dentry *pD, struct inode **delegated_inode )
{
        struct probe_nfsd_open_data_t __data = {0};

        // struct dentry* pD = pP->dentry; 

        int result = retrieve_probe_data(ctx, &__data, OPCODE_VFS_UNLINK, pD);
        if ( result != SKIP_IT ) {
            probe_nfsd_open_events.perf_submit(ctx, &__data, sizeof(__data));
        }

        return 0;
}


//  int notify_change(struct dentry * dentry, struct iattr * attr, struct inode **delegated_inode)
//  {
//  	struct inode *inode = dentry->d_inode;
//  	umode_t mode = inode->i_mode;
int probe_notify_change( struct pt_regs *ctx, struct dentry * pD, struct iattr * attr, struct inode **delegated_inode)
{
        struct probe_nfsd_open_data_t __data = {0};

        // struct dentry* pD = pP->dentry; 
        // struct inode *inode = pD->d_inode;
        // umode_t nmode = pD->d_inode->i_mode;
        // umode_t new_mode = attr->ia_mode;

        // if ( !( pD->d_inode ) || pD->d_inode->i_mode == attr->ia_mode ) return 0;
        // if ( new_mode == nmode ) return 0;
        // newattrs.ia_valid = ATTR_MODE | ATTR_CTIME
        if (!(attr->ia_valid & ATTR_MODE)) return 0;
        // else ..

        // notify() seems to be happening after chmod() -- see e.g. chmod_common() :  
        // https://github.com/torvalds/linux/blob/bcf876870b95592b52519ed4aafcf9d95999bc9c/fs/open.c#L576
        // __data.umode = pD->d_inode->i_mode ;
        __data.umode = attr->ia_mode ;
        
        int result = retrieve_probe_data(ctx, &__data, OPCODE_NOTIFY_CHANGE, pD);
        if ( result != SKIP_IT ) {
            probe_nfsd_open_events.perf_submit(ctx, &__data, sizeof(__data));
        }

        return 0;
}


// int vfs_statfs(const struct path *path, struct kstatfs *buf)
int probe_vfs_statfs( struct pt_regs *ctx, const struct path *pP, struct kstatfs *buf )
{

        struct probe_nfsd_open_data_t __data = {0};

        struct dentry* pD = pP->dentry; 

        int result = retrieve_probe_data(ctx, &__data, OPCODE_VFS_STATFS, pD);
        if ( result != SKIP_IT ) {
            probe_nfsd_open_events.perf_submit(ctx, &__data, sizeof(__data));
        }

        return 0;
}
