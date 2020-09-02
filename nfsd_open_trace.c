
#include <linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

#include <linux/fs.h>
#include <linux/sunrpc/svc.h> /* struct svc_rqst */
#include <../fs/nfsd/nfsfh.h> /* struct svc_fh */

#define OPCODE_NFSD_OPEN      1
#define OPCODE_NFSD_GETATTR   2
// #define OPCODE_VFS_STAT       3

#define MAX_FILENAME_LEN    256

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
    
        char dname0[80];
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
                bpf_probe_read_kernel(p_data->dname0, sizeof(p_data->dname0), __tmp);

                pD = pD->d_parent;
                /* dentries */

        } else {
            p_data->dname0[0] = '\0' ;
        }    
}


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
        __data.opcode = OPCODE_NFSD_OPEN;
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

// -------------------------------------------------------------------------------

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


int probe_vfs_getattr( struct pt_regs *ctx, const struct path *pP
                     , struct kstat *stat, u32 request_mask, unsigned int query_flags )
{
        u64 __pid_tgid = bpf_get_current_pid_tgid();
        u32 __tgid = __pid_tgid >> 32;
        u32 __pid = __pid_tgid; // implicit cast to u32 for bottom half

        /* tgid_check */

        void *__tmp = 0;
        // if (__tgid == 23356) { return 0; }

        struct probe_nfsd_open_data_t __data = {0};
        __data.opcode = OPCODE_NFSD_GETATTR;
        __data.tgid = __tgid;
        __data.pid = __pid;

        __data.timestamp_ns = bpf_ktime_get_ns();
        
        bpf_get_current_comm(&__data.comm, sizeof(__data.comm));
        /* comm filter // disabled */

        struct svc_rqst** rqstpp = hash_getattr.lookup(&__pid_tgid);
	if (rqstpp != 0) {
            struct svc_rqst* rqstp = *rqstpp;
            // one more check
            if (rqstp == 0) return 0;
            
            // else ..
            
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
        } else {
            // unknown/unexpected, skip it
            return 0;
        }
        

        struct dentry* pD = pP->dentry; 
        load_dentries(pD, &__data);

        probe_nfsd_open_events.perf_submit(ctx, &__data, sizeof(__data));

        return 0;
}
