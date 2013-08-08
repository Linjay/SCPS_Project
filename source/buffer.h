#ifndef buffer_h
#define buffer_h

/********************************************************
 * 
 *                             NOTICE
 *  
 * "This software was produced for the U.S. Government under
 * Contract No's. DAAB07-97-C-E601, F19628-94-C-0001,
 * NAS5-32607, and JPL contract 752939 and is subject 
 * to the Rights in Noncommercial Computer Software and 
 * Noncommercial Computer Software Documentation Clause 
 * at (DFARS) 252.227-7014 (JUN 95), and the Rights in 
 * Technical Data and Computer Software Clause at (DFARS) 
 * 252.227-7013 (OCT 88) with Alternate II (APR 93),  
 * FAR 52.227-14 Rights in Data General, and Article GP-51,
 * Rights in Data - General, respectively.
 *
 *        (c) 1999 The MITRE Corporation
 *
 * MITRE PROVIDES THIS SOFTWARE "AS IS" AND MAKES NO 
 * WARRANTY, EXPRESS OR IMPLIED, AS TO THE ACCURACY, 
 * CAPABILITY, EFFICIENCY, OR FUNCTIONING OF THE PRODUCT. 
 * IN NO EVENT WILL MITRE BE LIABLE FOR ANY GENERAL, 
 * CONSEQUENTIAL, INDIRECT, INCIDENTAL, EXEMPLARY, OR 
 * SPECIAL DAMAGES, EVEN IF MITRE HAS BEEN ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGES.
 *
 * You accept this software on the condition that you 
 * indemnify and hold harmless MITRE, its Board of 
 * Trustees, officers, agents and employees, from any and 
 * all liability or damages to third parties, including 
 * attorneys' fees, court costs, and other related costs 
 * and expenses, arising our of your use of the Product 
 * irrespective of the cause of said liability, except 
 * for liability arising from claims of US patent 
 * infringements.
 *
 * The export from the United States or the subsequent 
 * reexport of this software is subject to compliance 
 * with United States export control and munitions 
 * control restrictions.  You agree that in the event you 
 * seek to export this software you assume full 
 * responsibility for obtaining all necessary export 
 * licenses and approvals and for assuring compliance 
 * with applicable reexport restrictions.
 *
 ********************************************************/

#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>

#define SEQ_GEQ(a,b)    ((int)((a)-(b)) >= 0)
#define SEQ_LEQ(a,b)   ((int)((a)-(b)) <= 0)
#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif /* max */
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif /* min */

/*
 * These Mbuffs are a re-engineered version of the BSD mbuf structure
 * Mbuffs are a single size, MBSIZE currently set to handle 90 octets 
 * of data plus the mbuff header overhead. This will allow for a single
 * STRV1 segment to fit into a single mbuffer.
 * We fix the MBLEN at the desired payload size and then calculate the
 * overall mbuff size required. 
 */

#define MBLEN                      88
#ifndef NULL
#define NULL                        0
#endif /* NULL */

#define MAX_MBUFFS               26200000
#define SMCLBYTES                 32768
#define TOTAL_SYSTEM_BUFFERS     (SYS_MEMORY)

#define MHLEN                  MBLEN
#define MBSIZE                 (MBLEN + (sizeof(struct m_hdr)) + \
				sizeof(struct pkthdr) +\
				sizeof(struct m_ext))

/* Header for the start of each mbuff */
struct m_hdr
  {
    struct mbuff *mh_next,	/* next buffer in chain     */
     *mh_prev,			/* previous buffer in chain */
     *mh_nextpkt;		/* next packet in queue     */
    int mh_len;			/* amount of data in mbuff  */
    caddr_t mh_data;		/* pointer to the data      */
    short mh_type;		/* type of data             */
    short mh_flags;		/* associated flags         */
    /* M_EOR, M_EXT, M_PKTHDR   */
  };

/* Packet header for the first mbuff in chain;           */
struct pkthdr
  {
    int len;			/* total packet length      */
    uint32_t seq;		/* sequence number assoc.   */
    /* exploited for SACK proc. */
    uint32_t ts;		/* timestamp for vegas rtt  */
    uint32_t rt;		/* retransmit time for vegas fast rexmit */
    uint32_t rexmits;	/* Bytes from this mbuff RExmitted */
    unsigned short mfx_count;	/* Number of MFX transmissions this round */
    short offset;		/* pointer to start of data */
    /* in the mbuff, if it is   */
    /* all header, this is 0    */
  };


struct m_ext
  {
    caddr_t ext_buf;		/* pointer to buffer start       */
    u_int offset;		/* offset to data of interest    */
    u_int len;			/* length of data of interest    */
    unsigned short checksum;	/* internet checksum of the data */
    u_int ext_size;		/* size of buffer                */
  };

/* external storage mapped into an mbuff, valid if M_EXT is set */
struct mbuff
  {
    struct _buffer *parent;
    struct m_hdr m_hdr;
    union
      {
	struct
	  {
	    struct pkthdr MH_pkthdr;	/* M_PKTHDR set */
	    struct m_ext MH_ext;	/* M_EXT set */
	    char MH_databuff[MHLEN];
	  }
	MH;
	char M_databuff[MHLEN];	/* !M_PKTHDR, !M_EXT */
      }
    M_dat;
  };


struct mbcluster
  {
    char c_data[SMCLBYTES];	/* Actual data space of cluster */
    struct mbcluster *c_next,	/* Pointer to next cluster in chain */
     *c_prev;			/* Pointer to previous cluster in chain */
    struct _cl_chain *parent;	/* Pointer to owning chain */
    u_int tail;			/* Offset to last byte of *data* */
    int c_count;		/* Reference count for cluster */
    int mbuffs;			/* Temp for debugging */
    int de_queued;		/* Temp for debugging */
    int was_outseq;		/* Temp for debugging */
    int cluster_id;
  };

#define HOLE_EMBARGO 0x1

struct _hole_element
  {
    struct mbuff *mbptr;
    struct mbuff *hole_start;
    struct mbuff *hole_end;
    struct mbuff *next_to_send;
    int flags;
    unsigned int hole_start_seq;
    unsigned int hole_end_seq;
    uint32_t length;
    unsigned int data_start_seq;
    unsigned int data_end_seq;
    uint32_t data_length;
    uint32_t Embargo_Time;
    uint32_t rx_ctr;
    uint32_t rxmit_ctr;
    struct _hole_element *prev;
    struct _hole_element *next;
  };

/* _buffer structure: generic buffer structure */
struct _buffer
  {
    int32_t max_size;		/* upper bound on buffer size */
    int32_t b_size;		/* instantaneous buffer size */
    int num_elements;		/* Number of elements currently enqueued */
    int max_elements;		/* Maximum ever allowed to be enqueued */
    int biggest;		/* Largest number of elements ever seen */
    int32_t data_size;		/* Primarily for Out_Seq debugging */
    int biggest_elements;	/* Biggest # of elements seen so far */
    int flags;			/* Buffer specific flags             */
    struct mbuff *start,	/* pointer to first mbuff of chain */
     *last,			/* pointer to last mbuff of chain */
     *snd_una,			/* pointer to oldest sent but 
				   unacknowledged data  */
     *send;			/* pointer to oldest data pushed to 
				   transmission interface, but not
				   necessarily sent (think link outage */
    struct _hole_element *holes;
    void *parent;		/* Generic pointer socket owning buffer */
  };


/* _cl_chain structure: generic cluster chain structure */
struct _cl_chain
  {
    int32_t max_size;		/* upper bound on chain size */
    int32_t size;			/* instantaneous chain size  */
    int32_t biggest;		/* Biggest size we've seen so far */
    int32_t Out_Seq_size;		/* Occupied bytes in Out-of-Sequence space */
    int num_elements;		/* Number of clusters on chain */
    int max_elements;		/* Max number of elements allowed in chain */
    int biggest_elements;	/* Bigest # of elements seem so far */
    int32_t bytes_beyond;		/* The amount of "write-ahead space in the
				 * buffer (number of bytes in clusters past
				 * the current write-head */
    int run_length;		/* Max-Data Length for a segment */
    struct mbcluster *start,	/* head cluster in chain     */
     *last,			/* final cluster in chain    */
     *read_head,		/* Where to start reading data out */
     *write_head;		/* Where to start writing more new data in */
    int32_t write_off, read_off;	/* Offsets for reading/writing */
    struct record_boundary *RB;	/* Pointer to first Record Boundary of chain */
  };

struct _clust_list {
    struct mbcluster *clust;
    int sock_id;
    int used;
    int where;
};

#define MAX_CLUST	5000

struct _clust_mem_map {
    struct _clust_list clust_list [MAX_CLUST];
};

struct _sys_memory
  {
    uint32_t tot_buff_size;	/* The total space available for buffers   */
    uint32_t mbuff_in_use;		/* The amount of space in use now          */
    uint32_t mbuff_created;	/* The number of buffers currently in use  */
    uint32_t clust_in_use;		/* The amount of clusters currently in use */
    uint32_t clust_promised;	/* The amount of clusters promised         */
    uint32_t clust_created;	/* Number of clusters actually malloc'd    */
    struct _buffer fblist;		/* The mbuff freelist */
    struct _cl_chain fclist;		/* The mcluster freelist */
    struct _hole_element *hole_list;
  };

extern struct _sys_memory sys_memory;

struct record_boundary
  {
    uint32_t offset;	/* Absolute offset from previous RB 
				 * (used for read) */
    uint32_t seq_num;	/* Sequence Number associated with 
				 * start of record (used for write) */
    struct record_boundary *prev, *next;
  };

struct scps_iovec
  {
    char *iov_base;		/* Base Address */
    size_t iov_len;		/* Length */
  };

struct scps_msghdr
  {
    caddr_t msg_name;		/* Optional address */
    int msg_namelen;		/* Size of address    */
    struct scps_iovec *msg_iov;	/* scatter/gather array */
    int msg_iovlen;		/* # elements in msg_iov */
    caddr_t msg_accrights;	/* access rights sent/recvd */
    int msg_accrightslen;
  };

/*
 * mbuff allocation/deallocation macros;
 *
 *       MBALLOC(struct mbuff *m, int type)
 * 
 *       MGET(struct mbuff *m, int type)
 * allocated an mbuff and initializes it to contain data.
 *
 *       MGETHDR(struct mbuff *m, int type)
 * allocates an mbuff and initializes it to contain a 
 * packet header and internal data.
 */


/* Mbuf cluster macros.
 * MCALLOC(caddr_t p) allocates an mbuff cluster.
 * MCLGET adds a cluster to a normal mbuff;
 * the flag M_EXT is set upon success.
 * MCLFREE releases a reference to a cluster allocated by MCALLOC,
 * freeing the cluster if the reference count has reached 0.
 */

#define m_next            m_hdr.mh_next
#define m_prev            m_hdr.mh_prev
#define m_len             m_hdr.mh_len
#define m_data            m_hdr.mh_data
#define m_type            m_hdr.mh_type
#define m_flags           m_hdr.mh_flags
#define m_nextpkt         m_hdr.mh_nextpkt
#define m_act             m_nextpkt

/* MACROS of convienence for accessing packet-header info 
 * mbuff packet-header, packet-header offset to data,
 * starting sequence number for data in chain
 * length of data associated with this packet
 */
#define m_pkthdr          M_dat.MH.MH_pkthdr
#define m_offset          M_dat.MH.MH_pkthdr.offset
#define m_seq             M_dat.MH.MH_pkthdr.seq
#define m_rx              M_dat.MH.MH_pkthdr.rexmits
#define m_ts              M_dat.MH.MH_pkthdr.ts
#define m_rt              M_dat.MH.MH_pkthdr.rt
#define m_mfx_count	  M_dat.MH.MH_pkthdr.mfx_count
#define m_plen            M_dat.MH.MH_pkthdr.len

#define m_pktdat          M_dat.MH.MH_databuff
#define m_dat             M_dat.M_databuf

/* MACROS for accessing the cluster data
 * m_edat points to the begining of data of interest for this cluster
 */

#define m_ext             M_dat.MH.MH_ext

/* mbuff flags */
#define M_EXT             0x0001	/* has associated external storage */
#define M_PKTHDR          0x0002	/* start of record                 */
#define M_EOR             0x0004	/* end of record                   */
#define M_RUNT		  0x0008	/* A runt segment (less < maxdata) */
/* mbuff pkthdr flags, also in m_flags  */
#define M_ACKED           0x0010	/* Data in this packet was ACKED   */
#define M_SEND            0x0020	/* Data in this packet transmitted */

/* mbuff types */
#define MT_FREE           0	/* should be on free list      */
#define MT_DATA           1	/* dynamic (data) allocation   */
#define MT_HEADER         2	/* packet header               */
#define MT_CONTROL        14	/* extra-data protocol message */
#define MT_OOBDATA        15	/* expedited data              */

int enq_mbuff (struct mbuff *buf, struct _buffer *q);

struct mbuff *deq_mbuff (struct _buffer *q);

void kill_bchain (struct mbuff *buff_head);

void free_mbuff (struct mbuff *buf);

struct mbuff *alloc_mbuff (int type);

int enq_mbclus (struct mbcluster *cluster, struct _cl_chain *q);

void free_mclus (struct mbcluster *cluster);

struct mbcluster *deq_mclus (struct _cl_chain *q);

void free_mbclus (struct mbcluster *cluster);

struct mbcluster *alloc_mbclus (int reserve_pool);

int mclget (struct mbuff *m);

int mcput (struct mbuff *m, struct mbcluster *clust,
	   int offset, int len, int force);

int cb_cpdatin (struct _cl_chain *chain, caddr_t dp,
		int len, int offset, int maxseg);

int cb_cpdatout (struct _cl_chain *chain, caddr_t dp,
		 unsigned int len);

struct _buffer *buff_init (uint32_t max_size, void *parent);

struct _cl_chain *chain_init (uint32_t max_size);

uint32_t mb_trim (struct _buffer *buffer, uint32_t limit,
		       uint32_t *tsp, uint32_t *rxm);

void mb_rtrim (struct _buffer *buffer, uint32_t limit);

int clust_copy (struct mbcluster *cluster, caddr_t cp, int togo, int offset);

void read_align (struct _cl_chain *buffer, int increment, int strict);

void write_align (struct _cl_chain *buffer, int increment, int strict);

int cb_outseqin (struct mbuff *mbuff, caddr_t dp, int len, int offset);

int grow_chain (struct _cl_chain *chain, int clusters_needed);

int buff_vec (struct mbuff *mbuf, struct msghdr *msg, int open_slots);

void copy_mbuff (struct mbuff *duplicate, struct mbuff *orig);

struct mbcluster *
  clone_cluster (struct mbcluster *cluster, int original_offset, int length);

struct mbuff *clone_mbuff (struct mbuff *orig);

struct mbuff *
  mb_attach (struct mbuff *mbuffer, char *linear_space, int space_len);

struct _hole_element *alloc_hole_element (void);

void
  free_hole_element (struct _hole_element *hole);

struct _hole_element *
  insert_hole (struct _hole_element *list, struct _hole_element *hole,
	       uint32_t tp_now, uint32_t snack_delay);

struct _hole_element *
  add_hole (struct _hole_element *list, struct mbuff *hole_start,
	    uint32_t len, uint32_t tp_now, uint32_t seq_num,
	    uint32_t seqsent, uint32_t snack_delay);

struct _hole_element *
  remove_hole (struct _hole_element *list, struct _hole_element *hole);

struct _hole_element *
  remove_hole (struct _hole_element *list, struct _hole_element *hole);

struct _hole_element *
  find_hole (struct _hole_element *list, uint32_t seqnum);

int
  trim_chain (struct _cl_chain *chain);

int
  mb_merge (struct mbuff *first, struct mbuff *second);

int
  mb_insert (struct _buffer *buffer, struct mbuff *before, struct mbuff *new);


#endif /* buffer_h */
