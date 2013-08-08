#ifndef scpstp_h
#define scpstp_h

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

#include "scps.h"
#include "buffer.h"
#include "thread.h"
#include "net_types.h"		/* network protocol related structures */
#include <netinet/in.h>
#include <netdb.h>		/* For scps_getprotobyname */
#include <stdio.h>
#include "icmp.h"
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>


#ifdef SCPSSP
#include "scps_sp.h"
#endif	/* SCPSSP */

#include "tp_debug.h"

#define SEQ_LT(a,b)	((int)((a)-(b)) < 0)
#define SEQ_LEQ(a,b)	((int)((a)-(b)) <= 0)
#define SEQ_GT(a,b)	((int)((a)-(b)) > 0)
#define SEQ_GEQ(a,b)	((int)((a)-(b)) >= 0)


/* Useful type definitions */
typedef int (*procref) ();

extern int ls;			/* socket id of lower-layer raw ip socket */

/* protocol address definitions */
typedef uint32_t spanner_ip_addr;

typedef struct
  {
  }
sp_Header;			/* placeholder for now */

/* The Internet Header: */
struct ipv4_s  {
                        u_short vht;            /* version, hdrlen, tos */
                        short length;
                        u_short identification;
                        short frag;
                        u_short ttlProtocol;
                        u_short checksum;
                        scps_np_addr source;
                        scps_np_addr destination;
};

struct ipv6_s {
                        u_int   flow;
                        u_short plen;
                        u_char  nxt;
                        u_char  hlim;
                        struct ipv6_addr src;
                        struct ipv6_addr dst;
};

/* The Internet Header: */
typedef struct inh
  {
        union nl_tag {
                struct ipv4_s ipv4;
                struct ipv6_s ipv6;
        } nl_head;
        int     protocol_fam;
  } in_Header ;

typedef in_Header ip_template;

/*
 *    Security protocol requirements
 */

typedef struct _scps_sp_template
  {
    ip_template ip_templ;		/* Network layer header template */
    scps_np_template np_templ;	/* Network layer header template */
#ifdef XXX
    path_template pa_templ;	/* Network layer header template */
#endif				/* XXX */
    u_char sp_rqts;
    u_char tpid;
    scps_np_rqts np_rqts;
#ifdef  SECURE_GATEWAY
    int secure_gateway_templ;
#endif /* SECURE_GATEWAY */

  }
sp_template;

#define MAX_SP_PAD 8		/* PDF XXX this is equal to max crypt_blksize */

#define inv4_GetVersion(ip) ((ntohs((ip)->nl_head.ipv4.vht) >> 12) & 0xf)
#define inv4_GetHdrlen(ip)  ((ntohs((ip)->nl_head.ipv4.vht) >> 8) & 0xf)
#define inv4_GetHdrlenBytes(ip)  ((ntohs((ip)->nl_head.ipv4.vht) >> 6) & 0x3c)
#define inv4_GetTos(ip)      ((ip)->nl_head.ipv4.vht & 0xff)

#define inv4_GetTTL(ip)      (ntohs((ip)->nl_head.ipv4.ttlProtocol) >> 8)
#define inv4_GetProtocol(ip) (ntohs((ip)->nl_head.ipv4.ttlProtocol) & 0xff)

#define inv6_GetVersion(ip)  ((((ip)->nl_head.ipv6.flow) >> 28) & 0x0000000f)
//#define inv6_GetHdrlen(ip)  ((ntohs((ip)->nl_head.ipv6.) >> 8) & 0xf)
#define inv6_GetHdrlenBytes(ip)  (40)
//#define inv6_GetHdrlenBytes(ip)  ((ntohs((ip)->nl_head.ipv6.vht) >> 6) & 0x3c)
#define inv6_GetTos(ip)      (((ip)->nl_head.ipv6.flow >> 20) & 0x000000ff)

#define inv6_Gethlim(ip)      ((ip)->nl_head.ipv6.hlim)
#define inv6_GetProtocol(ip)  ((ip)->nl_head.ipv6.nxt)

#define MoveW(a,b,l) (bcopy(a,b,l))

#define TP_MAX_HDR	60	/* max length of TP header */

typedef struct
  {
    u_short srcPort;
    u_short dstPort;
    uint32_t seqnum;
    uint32_t acknum;
#ifdef I386
    u_char th_x2:4, th_off:4;
#endif	/* I386 */
#ifndef I386
    u_char th_off:4, th_x2:4;
#endif	/* I386 */
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urgentPointer;
  }
tp_Header;

#define tp_FlagFIN     0x0001
#define tp_FlagSYN     0x0002
#define tp_FlagRST     0x0004
#define tp_FlagPUSH    0x0008
#define tp_FlagACK     0x0010
#define tp_FlagURG     0x0020
#define tp_FlagEOR     0x0040	/* Never gets put over the wire! */
#define tp_FlagDO      0xF000
#define tp_GetDataOffset(tp) ((tp)->th_off)

/* The TP/UDP Pseudo Header */

struct ipv4_ph {
    scps_np_addr src;
    scps_np_addr dst;
    octet mbz;
    octet protocol;
    word length;
    word checksum;
    word upper_seq_num;		/* for compression */
};

struct ipv6_ph {
    struct ipv6_addr src;
    struct ipv6_addr dst;
    longword length;
    octet mbz1;
    octet mbz2;
    octet mbz3;
    octet protocol;
    word checksum;
    word upper_seq_num;		/* for compression */
};

typedef struct {
	union {
		struct ipv4_ph ipv4;
		struct ipv6_ph ipv6;
 	} nl_head;
	int	protocol_fam;
} tp_PseudoHeader;

/*
 * TP states, from tp manual.
 * Note: close-wait state is bypassed by automatically closing a connection
 *       when a FIN is received.  This is easy to undo.
 */
#define tp_StateNASCENT      0	/* socket just created */
#define tp_StateLISTEN       1	/* listening for connection */
#define tp_StateSYNSENT      2	/* syn sent, active open */
#define tp_StateSYNREC       3	/* syn received, synack+syn sent. */
#define tp_StateESTAB        4	/* established */
#define tp_StateCLOSEWT      5	/* received FIN waiting for close */
#define tp_StateWANTTOCLOSE  6	/* sleazy intermediate state :( */
#define tp_StateWANTTOLAST   7	/* yet another sleazy intermediate state :( */
#define tp_StateFINWT1PEND   8	/* enqueued FIN, not yet sent */
#define tp_StateFINWTDETOUR  9	/* Got a FIN while trying to enqueue ours */
#define tp_StateLASTACKPEND  10	/* fin received, finack + fin enqueued but not yet sent */
#define tp_StateFINWT1       11	/* sent FIN */
#define tp_StateFINWT2       12	/* sent FIN, received FINACK */
#define tp_StateCLOSING      13	/* sent FIN, received FIN (waiting for FINACK) */
#define tp_StateLASTACK      14	/* fin received, finack+fin sent */
#define tp_StateTIMEWT       15	/* dally after sending final FINACK */
#define tp_StateCLOSED       16	/* finack received */

/*
 * TP Socket definition
 */
#define tp_MaxData 32		/* maximum bytes to buffer on output */

/*
 * sockFlags values: 
 */
#define SOCK_NDELAY      0x0001	/* flag to indicate whether to delay before coalese */
#define SOCK_ATOMIC      0x0002	/* flag to indicate writes are atomic rcds */
#define SOCK_BL		 0x0008	/* flag to indicate that socket blocks */
#define SOCK_DELACK	 0x0010	/* flag to indicate that delayed ack is used */
#define TF_RCVD_SCALE	 0x0020	/* flag to indicate that we received window scale */
#define TF_RCVD_TSTMP	 0x0040	/* flag to indicate that we received timestamp */
#define TF_REQ_SCALE	 0x0080	/* have/will request window scaling */
#define TF_REQ_TSTMP	 0x0100	/* have/will request timestamps */
#define TF_SNACK1_PERMIT 0x0200	/* other side said I could SACK */
#define TF_REQ_SNACK1	 0x0400	/* I will say other side can SACK */
#define TF_CC_LINEAR	 0x0800	/* 1 = linear cong. ctl, 0 = exponential */
#define TF_REQ_COMPRESS  0x1000	/* 1 = tp compression requested by us */
#define TF_RCVD_COMPRESS 0x2000	/* 1 = tp compression requested by them */
#define TF_COMPRESSING   0x3000	/* TF_REQ_COMPRESS | TF_RCVD_COMPRESS */
#define TF_TSTMPING      0x0140L	/* TF_REQ_TSTMP | TF_RCFD_TSTMP */
#define TF_VEGAS_FAST_REXMIT 0x4000	/* 1 = rexmit from Vegas logic, not timeout */
#define TF_VEGAS_INCREASE 0x8000	/* 1 = last change to cwnd was increase */
#define SOCK_ACKNOW      0x10000	/* 1 = ACK immediately */
#define SOCK_CANACK	 0x20000	/* 1 = ACK if input queue has been drained */
#define TF_HASRUNT       0x40000	/* 1 = Runt segment is outstanding */
#define TF_USERATECNTRL  0x80000	/* 1 = Use rate control for this socket */

#define TP_MAX_WINSHIFT	14	/* maximum window scale value */
#define TP_MAXWIN    65535	/* maximum unscaled window value */

#define RESNACK_THRESH 3	/* The number of times that
				   the hole at snd_una is snacked. */

#ifdef GATEWAY_MANY
#define RATE_BUCKET_FACTOR 2    /* How big our rate bucket size really is */
#else /* GATEWAY_MANY */
#define RATE_BUCKET_FACTOR 5    /* How big our rate bucket size really is */
#endif /* GATEWAY_MANY */

/* Option numbers */
#define TPOPT_EOL	        0
#define TPOPT_NOP	        1
#define TPOPT_MAXSEG	        2
#define	TPOPT_WINDOW	        3
#define TPOPT_SACK_PERMITTED    4
#define TPOPT_SACK	        5
#define TPOPT_TIMESTAMP         8
#define TPOPT_COMPRESS         10
#define TPOPT_SNACK1_PERMITTED 14
#define TPOPT_BETS_PERMITTED   16
#define TPOPT_BETS             16
#define TPOPT_SCPS             20	/* SCPS Capabilities */
#define TPOPT_SNACK1           21	
#define TPOPT_EOR              22
#define TPOPT_CORRUPTION_EXP   23

/* Option lengths */
#define TPOLEN_SCPS	        4
#define TPOLEN_MAXSEG	        4
#define TPOLEN_WINDOW	        3
#define TPOLEN_SNACK1_PERMITTED 2

#define TPOLEN_TIMESTAMP       10
#define TPOLEN_TSTAMP_APPA TPOLEN_TIMESTAMP+2
#define TPOLEN_EOR              2
#define TPOLEN_EOR_PAD          4
#define TPOLEN_SNACK1           6
#define TPOLEN_SNACK1_PAD       8
#define TPOLEN_COMPRESS         3
#define TPOLEN_COMPRESS_PAD     4
#define TPOLEN_BETS_PERMITTED   2
#define TPOLEN_CORRUPTION_EXP   2

#define TPOPT_TSTAMP_HDR       \
    (TPOPT_NOP<<24|TPOPT_NOP<<16|TPOPT_TIMESTAMP<<8|TPOLEN_TIMESTAMP)
#define TPOPT_EOR_HDR    \
    (TPOPT_NOP<<24|TPOPT_NOP<<16|TPOPT_EOR<<8|TPOLEN_EOR)
#define TPOPT_COMPRESS_HDR \
    (TPOPT_NOP << 24 | TPOPT_COMPRESS << 16 | TPOLEN_COMPRESS << 8)
#define TPOPT_BETS_HDR    \
    (TPOPT_NOP<<24|TPOPT_NOP<<16|TPOPT_BETS_PERMITTED<<8|TPOLEN_BETS_PERMITTED)
/*
 *  Macro to compute the header length of a data packet at run-time.
 *  Note that this assumes that the only option accompanying a data packet
 *  is a timestamp, and that a timestamp will accompany ALL data packets.
 *  If this does not hold, tp_Write must be changed.
 */
#define TP_HDR_LEN (((s->sockFlags & TF_COMPRESSING) == (TF_COMPRESSING)) \
               ? (((s->sockFlags & (TF_TSTMPING))  == (TF_TSTMPING))? (-4) : (-12)) \
               : (((s->sockFlags & (TF_TSTMPING)) == (TF_TSTMPING))? (12) : (0)))

typedef enum
  {
    Rexmit,
    Del_Ack,
    Persist,
    Vegas,
    BE_Xmit,
    BE_Recv,			/* BETS Receive Timer, started when tp_read() hits a hole */
    Select,			/* Wierd way of providing a timeout on a select */
    Keep,
    FW2,
    TW,
    KA
  }
_tp_timers;

#define TIMER_COUNT  11

#define TP_MAX_PERSIST_SHIFT    7

#include "scps_np.h"

/* The broken, but global routing socket for this implementation */
int route_sock;
int route_sock2;


/* Route Related Flags */
#define RT_LINK_AVAIL	   0x1	/* Link outage flag 1=link avail, 0 = out */
#define RT_LINK_TRANSITION 0x2	/* Link availability transition */
#define RT_COMPRESS	   0x4	/* Use compression on this route */
#define RT_CONGESTED	   0x8	/* Received indication of congestion */
#define RT_CORRUPTED	  0x10	/* Received indication of corruption */
#define RT_ASSUME_CONGEST 0x20	/* Assume congestion is source of loss */
#define RT_ASSUME_CORRUPT 0x40	/* Assume corruption is source of loss */


/* BETS Related Flags */
#define BF_REQUEST_BETS   0x1	/* Send a BETS request to peer */
#define BF_BETS_PERMITTED 0x2	/* Received a BETS request from peer */
#define BF_BETS_OK        0x3	/* BF_REQUEST_BETS + BF_REQUEST_BETS */
#define BF_BETS_RECEIVE   0x4	/* Currently in BETS mode for receive */
#define BF_BETS_SEND      0x8	/* Currently in BETS mode for send */

struct _BETS
  {
    int Flags;			/* BETS specific flags */
    /* Receiving Side BETS Parameters */

    uint32_t InRecSeq;		/* Seq Number of the 1st octet of RECEIVED data */
    uint32_t Hole_Size;		/* Size of the current receive hole */
    uint32_t Reported_Hole;	/* Hole size to report on the next getsockopt() */
    struct _Hole Receive_Hole;	/* Boundary of current BETS Receive Hole */
    uint32_t Threshold;		/* Currently unused, a receive buffer threshold for amount of outseq data */
    uint32_t Receive_Timeout;	/* Timeout before an Outseq Hole becomes a BETS hole */
    /* Sending Side BETS Parameters */
    uint32_t InSndSeq;		/* Sequence Number of the 1st octet of data SENT */

    /* This is just a temporary hack, ultimately I'd like the Send-Hole to be a 
     * dynamically allocated chunk of memory sized by the number of holes 
     * that the application desires (upto some sane limit) */

    int max_send_holes;		/* The most send holes we can keep around */
    int num_send_holes;		/* The current number of send-holes we've got */

/* This default will soon have a sockopt to set it to something else.  */

/* keep the 50 most recent send-side holes */
#define BETS_MAX_SEND_HOLES 50
    struct _Hole Send_Holes[BETS_MAX_SEND_HOLES];
  };

/* Socket SCPS Protocol Capabilities */
#define  CAP_TIMESTAMP 1
#define  CAP_COMPRESS  2
#define  CAP_SNACK     4
#define  CAP_BETS      8
#define  CAP_CONGEST  16
#define  CAP_MFX      32
#define  CAP_JUMBO    64

typedef struct _tp_socket
  {
    /* --- Don't modify anything here, as it must mirror the tp structure --- */
    struct _tp_socket *prev;
    struct _tp_socket *next;
    struct threads *thread;	/* address of socket owner's thread */
    int nl_protocol_id;		/* NP, IPV4, IPV6 */
    int Initialized;		/* Indication as to whether or not this socket is "clean" */
    unsigned int sockid;	/* Socket's logical "file-descriptor" */
    uint32_t sockFlags;		/* blocking info (see above) */
    scps_np_addr my_ipv4_addr, his_ipv4_addr;	/* internet address of peer */
    struct ipv6_addr my_ipv6_addr, his_ipv6_addr;  /* internet address of peer */
    u_short myport, hisport;	/* tp ports for this connection */
    int np_size;		/* Size of np header for this connection */
    int sp_size;		/* Size of sp header for this connection */
    short nh_off;		/* Offset of the start of the np header 
				   in an mbuff */
    short sh_off;		/* Offset of the start of the sp header 
				   in an mbuff */
    short th_off;		/* Ditto for transport header */
    route *rt_route;		/* pointer to route structure for
				 * connection */
    route *rt_route_def;	/* Default routing structure */
    int s_errno;		/* Error indication consumed by app */
    scps_np_rqts np_rqts;	/* Network layer requirements structure */
    scps_sp_rqts sp_rqts;	/* Securtity layer requirements structure */
#ifdef GATEWAY_SELECT
    struct _tp_socket *read_parent;	/* Thread's socket queue owning this socket */
    struct _tp_socket *read_prev;	/* Previous socket in chain */
    struct _tp_socket *read_next;	/* Next socket in chain */
    unsigned int read;		/* Amount needed to unblock read */
    struct _tp_socket *write_parent;	/* Thread's socket queue owning this socket */
    struct _tp_socket *write_prev;	/* Previous socket in chain */
    struct _tp_socket *write_next;	/* Next socket in chain */
    unsigned int write;		/* Amount needed to unblock write */
#endif				/* GATEWAY_SELECT */

    /*
       * This is a little busted, but the template type is determined
       * at compile time right now. The way to fix this is to declare
       * a pointer to a generic template that is setup at socket 
       * creation time.
     */
    int display_now;
    ip_template ip_templ;		/* Network layer header template */
    scps_np_template np_templ;	/* Network layer header template */
#ifdef XXX
    path_template pa_templ;	/* Network layer header template */
#endif				/* XXX */

#ifdef SCPSSP
    sp_template sp_templ;
#endif	/* SCPSSP */
    struct _buffer *send_buff;	/* Send-Buffer (Holds only the mbuffs */
    struct _buffer *receive_buff;	/* Receive Buffer (Holds only the mbuffs */
    struct _cl_chain *app_sbuff;	/* Application Send-buffer space */
    struct _cl_chain *app_rbuff;	/* Application Receive-buffer space */
    struct _buffer *Out_Seq;	/* Out-of-Sequence reassembly buffer */
#ifdef GATEWAY
    struct _tp_socket *peer_socket;	/* Pointer for the peer socket */
    int gateway_flags;		/* What should the peer do */
    uint32_t fin_seqnum;
    int32_t divert_port;
    int32_t gateway_lan_or_wan;
    unsigned rel_seq_num_urg_ptr;  /* offet from init_seq_num of urg data */
    int gateway_runt_ctr;
    int gateway_runt_ack_ctr;
    int gateway_fairness_ctr;
    int gateway_next_hop; /* USED WITH DIVERT_B_RAWIP ONLY */
#ifdef GATEWAY_DUAL_INTERFACE
    int gateway_layering;
    int special_udp_port;
    uint32_t special_ip_addr;
#endif /* GATEWAY_DUAL_INTERFACE */
#endif				/* GATEWAY */
    /* ------------------------- Safe to modify below here -------- */

    unsigned char DSCP;
    unsigned char strict_DSCP;
    unsigned short protocol_id;
    short state;		/* connection state */
    short state_prev;		/* connection state prior to above */
    short capabilities;		/* SCPS capabilities of this socket */
    struct _tp_socket *q0;	/* Queue of partially connected sockets */
    struct _tp_socket *q;	/* Queue of connected sockets for accept */
    struct _tp_socket *qhead;	/* Listening socket owning q0 or q       */
    uint32_t initial_seqnum;    /* For passing urgent ptrs in the gateway */
    uint32_t initial_seqnum_rec;/* For passing urgent ptrs in the gateway */
    uint32_t acknum, seqnum;	/* data ack'd and sequence num */
    uint32_t snduna;		/* first octet of data sent, but unacked */
    uint32_t seqsent;
    uint32_t max_seqsent;	/* Max sequence number sent excluding RTOs */
    uint32_t high_hole_seq;	/* Sequence number of the highest SNACKed byte
				   during a congestion epoch. */
    uint32_t high_seq;		/* Highest sequence number sent when we transition
				 * into fast retransmit.  NewReno. */
    uint32_t high_congestion_seq;	/* The highest sequence number sent during a congestion
					 * epoch.  On leaving a congestion epoch we don't get 
					 * snd_cwnd credit for acks from packets sent during the
					 * epoch. */
    uint32_t pkts_ack_in_epoch; /* This is the number of packets that were acked during
                                   a congestion epoch */
    unsigned int funct_flags;
    uint32_t old_seqsent;	/* Previous value of seqsent - for hash print */
    uint32_t sndwin, rcvwin;	/* Connections send and receive windows */
    uint32_t lastack;		/* Last ack sent from this socket */
    uint32_t lastuwe;		/* Last upper window edge sent */
    uint32_t lastuwein;		/* Last upper window edge received */
    tp_PseudoHeader ph;		/* This socket's pseudo-header storage */
    tp_Header old_th;		/* Last header sent on this connection */
    tp_Header in_th;		/* Inbound tp header from decompression */
    u_char in_opts[TP_MAX_HDR - sizeof (tp_Header)];	/* must be contig with in_th */
    int timeout;		/* timeout, in milliseconds */
    int maxpersist_ctr;
    uint32_t timers[TIMER_COUNT];	/* timers for this connection */
    struct _timer *otimers[TIMER_COUNT];
    int persist_shift;		/* Shift counter for exponential values */
    u_char flags;		/* tp flags word for last packet sent */
    short ack_delay;		/* # segments since last ack sent */
    short ack_delay_thresh;	/* # segments rcvd before ack sent */
    short ack_freq;		/* 0 = delayed only; 1 = every segment; */
    /* 2 = every 2nd segment */
    short int advance_hole;	/* Used to re-snack the hole at snd_una multiple
				   times. */
    short int mfx_snd_una;	/* used to mfx the packet at send_una
				   0 = Dont use this feature
				   # = number of times to mfx the pkt at snd_una */
    short vegas_ack_check;	/* TP Vegas's fast retransmit */
    short requested_s_scale;	/* remote requested window scale */
    short request_r_scale;	/* pending window scaling */
    short snd_scale;		/* window scaling for send window */
    short rcv_scale;		/* window scaling for receive window */
    short local_conn_id;	/* Our side's connection id */
    short remote_conn_id;	/* Their side's connection id */
    short maxseg;		/* Maximum segment size to send */
    short maxseg_perm;		/* Unmodified version of mss */
    short maxdata;		/* maxseg - TP_HDR_LEN */
    short mss_offer;		/* MSS offered by other side */
    short my_mss_offer;		/* MSS offered to other side */
    uint32_t snd_awnd;		/* Window other side advertised to us */
    uint32_t snd_cwnd;		/* Send side congestion window */
    uint32_t snd_prevcwnd;
    uint32_t snd_ssthresh;	/* Send side slow start threshold */
    uint32_t rttbest;		/* Best rtt we've seen on this connection */
    uint32_t rttcur;		/* Current rtt on this connection */
    int rttcnt;			/* Count down until stable rtt */
    int rtt;			/* Is there a segment being timed? */
    uint32_t rtseq;		/* Segment we are timing */
    uint32_t rt_prev_ts_val;	/* Timestamp of immediately prior segment */
    uint32_t ts_recent;		/* Recent timestamp */
    uint32_t ts_recent_age;	/* Time when ts_recent was written */
    uint32_t ts_now;		/* Timestamp that just came in */
    int t_srtt;			/* smoothed round trip timer (int for signed compare) */
    uint32_t t_rxtcur;		/* current retransmission timer value */
    int  t_rttvar;		/* smoothed mean difference in rtt (int for signed compare) */
    uint32_t t_rxtshift;	/* shift value for rtt if  congested */
    uint32_t user_data;		/* bytes of user_data sent on connection */
    uint32_t total_data;	/* bytes of user data + headers sent on 
				 * this connection */
    uint32_t last_total_data;	/* total data as of last time TFVegas 
				 * was called */
    int cong_algorithm;		/* Vegas, VJ or ??? */
    int dup_ack_cnt;		/* count of duplicate acks, 3 = rexmit now! */
    uint32_t rxmit_last;	/* Time of last retransmission - use for Fast-Retransmit */
    int link_outage;		/* boolean - true if link is out 
				   (move to route struct) */
    int unacked_segs;		/* processed but unacked segments */
    uint32_t ecbs1;
    char ecbs1_value [MAX_ECBS_VALUE];
    uint32_t ecbs1_len;

    uint32_t ecbs1_req;         /* This is what was requested from the remote side */
    char ecbs1_req_value [MAX_ECBS_VALUE];
    uint32_t ecbs1_req_len;
 
    uint32_t ecbs2;
    char ecbs2_value [MAX_ECBS_VALUE];
    uint32_t ecbs2_len;

    uint32_t ecbs2_req;         /* This is what was requested from the remote side */
    char ecbs2_req_value [MAX_ECBS_VALUE];
    uint32_t ecbs2_req_len;
 
    byte data[tp_MaxData];	/* data to send */
    uint32_t snack_delay;  /* Delay in before processing a snack */
    uint32_t ACKDELAY;
    uint32_t ACKFLOOR;
    uint32_t RTOMIN;
    uint32_t RTOMAX;
    uint32_t RETRANSMITTIME;
    uint32_t PERSISTTIME;
    uint32_t TIMEOUT;
    uint32_t LONGTIMEOUT;
    uint32_t MAXPERSIST_CTR;
    uint32_t RTOPERSIST_MAX;
    uint32_t RTO_TO_PERSIST_CTR;
    uint32_t  EMBARGO_FAST_RXMIT_CTR;
    uint32_t TWOMSLTIMEOUT;
    uint32_t KATIMEOUT;
    unsigned int VEGAS_ALPHA;
    unsigned int VEGAS_BETA;
    unsigned int VEGAS_GAMMA;
    unsigned int VEGAS_SS;
    uint32_t BETS_RECEIVE_TIMEOUT;
    unsigned short MFX_SETTING;
    struct timeval start_time;	/* for throughput calculation:  
				 * beginning of data transfer phase */
    short SNACK1_Flags;		/* SNACK related flags */
    uint32_t SNACK1_Receive_Hole;	/* Sequence Number of end of hole 
					   in receive buffer  */
    int SNACK1_Send_Hole;	/* Size of hole in MSSs (as seen by receiver of SNACK) */
    int SNACK1_Send_Offset;	/* Offset from acknum of hole (as seen by receiver of SNACK) */
    uint32_t hole_start, hole_end;
    struct mbuff *hole_ptr;
    int mbuff_fails;
    uint32_t mbuff_overage;
    int cb_datin_fails;
#ifdef TAP_INTERFACE
    unsigned char src_mac_addr [6];
    unsigned char dst_mac_addr [6];
    unsigned short frame_type;
    int recv_tap_if;
#endif /* TAP_INTERFACE */

    struct _BETS BETS;		/* BETS flags and other values */
    struct mbuff *scratch_buff;
  }
tp_Socket;

#define hton16(d,s)({int i,j; for (i = 0; i< 16; i++) {j=15-i;(d)[i]=(s)[i];}})
#define ntoh16(d,s)({int i,j; for (i = 0; i< 16; i++) {j=15-i;(d)[i]=(s)[i];}})

typedef struct _reset_Socket {
    tp_Socket *s;
    struct _reset_Socket *next;
} reset_Socket;

#define SNACK1_RECEIVED           1
#define SEND_SNACK1               2

#define BETS_OK                   0xF	/* Both sides requested BETS */
#define BETS_REQUESTED            0x8	/* Local side is requesting BETS */
#define BETS_Receive              0x4	/* Currently in BETS mode: receive */
#define BETS_Transmit             0x2	/* Currently in BETS mode: transmit */


#define FUNCT_HIGH_CONGESTION_SEQ	0x0001
#define FUNCT_HIGH_SEQ			0x0002
#define FUNCT_REL_SEQ_NUM_URG_PTR	0x0004
#define FUNCT_RTSEQ			0x0008

/*
 * The smoothed round-trip time and estimated variance
 * are stored as fixed point numbers scaled by the values below.
 * For convenience, these scales are also used in smoothing the average
 * (smoothed = (1/scale)sample + ((scale-1)/scale)smoothed).
 * With these scales, srtt has 3 bits to the right of the binary point,
 * and thus an "ALPHA" of 0.875.  rttvar has 2 bits to the right of the
 * binary point, and is smoothed with an ALPHA of 0.75.
 */
#define TP_RTT_SCALE           8	/* multiplier for srtt; 3 bits frac. */
#define TP_RTT_SHIFT           3	/* shift for srtt; 3 bits frac. */
#define TP_RTTVAR_SCALE        4	/* multiplier for rttvar; 2 bits */
#define TP_RTTVAR_SHIFT        2	/* multiplier for rttvar; 2 bits */

/*
 * The initial retransmission should happen at rtt + 4 * rttvar.
 * Because of the way we do the smoothing, srtt and rttvar
 * will each average +1/2 tick of bias.  When we compute
 * the retransmit timer, we want 1/2 tick of rounding and
 * 1 extra tick because of +-1/2 tick uncertainty in the
 * firing of the timer.  The bias will give us exactly the
 * 1.5 tick we need.  But, because the bias is
 * statistical, we have to test that we don't drop below
 * the minimum feasible timer (which is 2 ticks).
 * This macro assumes that the value of TP_RTTVAR_SCALE
 * is the same as the multiplier for rttvar.
 */
#define TP_REXMTVAL(tp) \
        (((tp)->t_srtt >> TP_RTT_SHIFT) + (tp)->t_rttvar)

/* Specify maximum value of exponential retransmission backoff */
#define TP_MAXRXTSHIFT 12

/* TP VJ congestion control constants. */
#define DUPACK_THRESH	3

/* TP Vegas congestion control constants */
#define ALPHA	3 /* 5 */	/* Bigger = more likely to increase congestion window */
#define BETA	5 /* 7 */	/* Bigger = less likely to decrease congestion window */
#define GAMMA	4		/* Bigger = come out of exponential mode later */

#ifndef min
#define min(a,b) ((((int) (a-b))<0) ? (a) : (b))
#endif	/* min */
#ifndef max
#define max(a,b) ((((int) (a-b))>0) ? (a) : (b))
#endif	/* max */

/* For tp_Send */
#define  MBUFFER_OK   128
#define  RETRANS_OK    64
#define  NEW_DATA_OK   32
#define  NEW_ACK        2
#define  TP_SENT       1

extern struct _ll_queue_element *in_data;	/* incoming data */
extern byte out_data[];		/* outgoing data */

extern scps_np_addr local_addr;

#define SCPS_SOCKET 0xff
#define PROTO_SCPSTP 0xfe
#define PROTO_SCPSUDP 0xfd
#define SCPS_ROUTE 0xfc
#define NP_PROTO_NP 0xfb
#define NP_PROTO_SP 0xfa

/* 
 * SCPS_SOCKET options
 */
#define SCPS_SO_SNDBUF       0x1001	/* send buffer size */
#define SCPS_SO_RCVBUF       0x1002	/* receive buffer size */
#define SCPS_SO_SNDLOWAT     0x1003	/* send low-water mark */
#define SCPS_SO_RCVLOWAT     0x1004	/* receive low-water mark */
#define SCPS_SO_SNDTIMEO     0x1005	/* send timeout */
#define SCPS_SO_RCVTIMEO     0x1006	/* receive timeout */
#define SCPS_SO_ERROR        0x1007	/* get error status and clear */
#define SCPS_SO_TYPE         0x1008	/* get socket type */
#define SCPS_SO_BETS_RHOLE_SIZE   0x1009	/* size of BETS Receive Hole */
#define SCPS_SO_BETS_RHOLE_START  0x100A	/* relative octet sequence of BETS Receive Hole */
#define SCPS_SO_BETS_NUM_SEND_HOLES 0x100B	/* Number of BETS Send-holes to report */
#define SCPS_SO_BETS_SEND_HOLES 0x100C	/* Get the locations of the send-holes */
				     /* while Socket types get sorted out... */
#define SCPS_SO_BLOCK 0x100D
#define SCPS_SO_NBLOCK 0x100E
#define SCPS_SO_NDELAY 0x100F
#define SCPS_SO_ATOMIC 0x1010
#define SCPS_SO_NLDEFAULT 0x1011

/* IPPROTO_SCPSTP Options */
#define SCPSTP_MAXSEG  	       0x01
#define SCPSTP_NODELAY         0x02
#define SCPSTP_ACKDELAY        0x03
#define SCPSTP_ACKFLOOR        0x04
#define SCPSTP_ACKBEHAVE       0x05
#define SCPSTP_RTOMIN          0x06
#define SCPSTP_RETRANSMITTIME  0x07
#define SCPSTP_PERSISTTIME     0x08
#define SCPSTP_TIMEOUT         0x09
#define SCPSTP_LONGTIMEOUT     0x0A
#define SCPSTP_2MSLTIMEOUT     0x0B
#define SCPSTP_BETS_RTIMEOUT   0x0C
#define SCPSTP_TIMESTAMP       0x0D
#define SCPSTP_COMPRESS        0x0E
#define SCPSTP_SNACK           0x0F
#define SCPSTP_BETS            0x10
#define SCPSTP_CONGEST         0x11
#define SCPSTP_VEGAS_CONGEST   0x12
#define SCPSTP_VJ_CONGEST      0x13
#define SCPSTP_VEGAS_ALPHA	0x14
#define SCPSTP_VEGAS_BETA	0x15
#define SCPSTP_VEGAS_GAMMA	0x16
#define SCPSTP_SNACK_DELAY	0x17
#define SCPSTP_VEGAS_SS		0x18
#define SCPSTP_FLOW_CONTROL_CONGEST      0x19
#define SCPSTP_MAXPERSIST_CTR 0x01A
#define SCPSTP_RTOPERSIST_MAX 0x01B
#define SCPSTP_RTO_TO_PERSIST_CTR 0x01C
#define SCPSTP_EMBARGO_FAST_RXMIT_CTR  0x01D
#define SCPSTP_RTOMAX          0x01E

/* SCPS_ROUTE Options */
#define SCPS_RATE 0x1
#define SCPS_MTU  0x2
#define SCPS_RTT   0x3
#define SCPS_SMTU  0x4
#define SCPS_MSS_FF  0x5
#define SCPS_TCPONLY  0x6
#define SCPS_IRTO   0x7
#define SCPS_DIV_ADDR   0x8
#define SCPS_DIV_PORT   0x9
#define SCPS_IFNAME   0xa
#define SCPS_SP_RQTS   0xb
#define SCPS_MIN_RATE 0xc
#define SCPS_FLOW_CONTROL 0xd
#define SCPS_FLOW_CONTROL_CAP 0xe
#define SCPS_ENCRYPT_IPSEC		0x2f
#define SCPS_ENCRYPT_PRE_OVERHEAD	0x30
#define SCPS_ENCRYPT_BLOCK_SIZE		0x31
#define SCPS_ENCRYPT_POST_OVERHEAD	0x32

#define SCPS_SOCKET 0xff
#define PROTO_SCPSTP 0xfe
#define PROTO_SCPSUDP 0xfd
#define SCPS_ROUTE 0xfc

/* NP_PROTO_NP Options */
#define SCPS_SO_NPTIMESTAMP		0x01
#define SCPS_SO_CHECKSUM		0x02
#define SCPS_SO_PRECEDENCE		0x03

/* NP_PROTO_SP OPTIONS */
#define SCPS_SO_CONFIDENTIALITY	0x01
#define SCPS_SO_AUTHENTICATION	0x02
#define SCPS_SO_SECURITY_LABEL	0x04
#define SCPS_SO_INTEGRITY		0x08

extern const uint32_t tp_TICK;
extern const uint32_t tp_ACKDELAY;
extern const uint32_t tp_ACKFLOOR;
extern const uint32_t tp_RTOMIN;
extern const uint32_t tp_RTOMAX;
extern const uint32_t tp_RETRANSMITTIME;
extern const uint32_t tp_PERSISTTIME;
extern const uint32_t tp_TIMEOUT;
extern const uint32_t tp_LONGTIMEOUT;
extern const uint32_t tp_MAXPERSIST_CTR;
extern const uint32_t tp_RTOPERSIST_MAX;
extern const uint32_t tp_RTO_TO_PERSIST_CTR;
extern const uint32_t tp_2MSLTIMEOUT;
extern const uint32_t tp_KATIMEOUT;
extern const unsigned int DEFAULT_ACK_FREQ;
extern const uint32_t tp_BIGTIME;
extern const uint32_t BETS_RECEIVE_TIMEOUT;
extern const uint32_t HASH_SIZE;
extern const uint32_t BUFFER_SIZE;

#define SCPSROUTE 101		/* busted routing sockets */
#define SCMP    1		/* protocol id for SCPS Control Message Protocol */

#define ICMP	1
#ifdef ENCAP_DIVERT
#define SCPSTP  6		/* protocol id for uncompressed TP */
#ifndef SOCK_STREAM
#define SOCK_STREAM 6
#endif /* SOCK_STREAM */
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 17
#endif /* SOCK_DGRAM */
#else /* ENCAP_DIVERT */
#define SCPSTP  106		/* protocol id for uncompressed TP */
#ifndef SOCK_STREAM
#define SOCK_STREAM 106
#endif	/* SOCK_STREAM */
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 117
#endif /* SOCK_DGRAM */
#endif /* ENCAP_DIVERT */

#ifndef SOCK_ROUTE
#define SOCK_ROUTE 101
#endif	/* SOCK_ROUTE */

#define NO_CONGESTION_CONTROL    0
#define VJ_CONGESTION_CONTROL    1
#define VEGAS_CONGESTION_CONTROL 2
#define FLOW_CONTROL_CONGESTION_CONTROL	3

/* User-visible function prototypes */
void scps_Init (void);
int scps_accept (int sockid, void *peer, int *addrlen);
int scps_bind (int sockid, void *ina, int addrlen);
int scps_close (int sockid);
int scps_connect (int sockid, void *ina, int addrlen);
int scps_getpeername (int sockid, void *ina, int *addrlen);
struct protoent *scps_getprotobyname (char *name);
int scps_getsockname (int sockid, void *ina, int *addrlen);
int scps_getsockopt (int sockid, int level, int optname, void *optval, int *optlen);
int scps_listen (int sockid, int backlog);
int scps_read (int sockid, void *data, int size);
int scps_recvfrom (int sockid, void *data, int size, void *ina, int *ina_len);
int scps_select (int sockid, scps_fd_set * readset, scps_fd_set * writeset,
		 scps_fd_set * nullval, struct timeval *time);
int scps_sendto (int sockid, void *data, int size, int flags, void *to, int addrlen);
int scps_setsockopt (int sockid, int level, int optname, void *optval, int optlen);
int scps_shutdown (int sockid, int how);
int scps_socket (int family, int type, int flags);
int scps_write (int sockid, void *dp, int len);

/* Since I don't support the MSG_OOB, MSG_PEEK and MSG_DONTROUTE flags yet... */
#define scps_send(a, b, c, flags)     scps_write(a, b, c)
#define scps_recv(a, b, c, flags)     scps_read(a, b, c)

int tp_Connect (int sockid, void *ina, int addrlen);
int tp_Abort (int sockid);
int tp_Close (int sockid);
int tp_Write (int sockid, void *dp, int len, int push);
int tp_Read (int sockid, void *data, int size);
void tp_buffer_report (int sockid);

int nl_ind (scps_np_rqts *rqts_in, int max_mtu, int *offset);

/*deprecated */
int tp_connect (int sockid);
int tp_accept (int sockid);
int tp_closed (int sockid);

#ifdef GATEWAY_SELECT
#define SCPS_FD_ZERO(a)     memset((int32_t *)a, 0, sizeof(scps_fd_set))
#define SCPS_FD_SET(a, b)\
      (((int32_t *)b)[(a)/(sizeof(int32_t)*8)]) |= (1 << ((a)%(sizeof(int32_t)*8)))

#define SCPS_FD_CLR(a, b) \
      (((int32_t *)b)[(a)/sizeof(int32_t)*8)]) &= ~(1 << ((a)%(sizeof(int32_t)*8)))

#define SCPS_FD_ISSET(a, b)\
      ((int32_t *)b)[(a)/(sizeof(int32_t)*8)] & (1 << ((a)%(sizeof(int32_t)*8)))

#else /* GATEWAY_SELECT */

#define SCPS_FD_ZERO(a)     memset(a, 0, sizeof(scps_fd_set))
#define SCPS_FD_SET(a, b)   *(int *)b |= (1 << a)
#define SCPS_FD_CLR(a, b)   *(int *)b &= ~(1 << a)
#define SCPS_FD_ISSET(a, b) *(int *)b & (1 << a)

#endif /* GATEWAY_SELECT */

/* Internal use function prototypes */
/* From tp_socket.c */
tp_Socket *clone_socket (tp_Socket * socket);

/* From tp_utility.c */
int np_hdr_size (scps_np_rqts np_rqts);
#ifdef SCPSSP
int sp_hdr_size (scps_sp_rqts sp_rqts);
#else /* SCPSSP */
int sp_hdr_size (void);
#endif	/* SCPSSP */
int tp_hdr_size (void);
int tp_Common (tp_Socket * s);
void tp_Unthread (tp_Socket * ds);
int tp_Flush (tp_Socket * s);
void tp_WinAck (tp_Socket * s, tp_Header * th);
void tp_mss (tp_Socket * s, unsigned int offer);
void tp_dooptions (tp_Socket * s, int cnt, tp_Header * tp,
		   int *ts_present, uint32_t * ts_val, uint32_t * ts_ecr);
void Validate_Thread (void);
void tp_quench (tp_Socket * s);
void tp_notify (int type, scps_np_rqts * rqts, tp_Header * tp);

/* From tp_timers.c */
void tp_Timers (void);
void tp_CancelTimers (tp_Socket * s);
void tp_TFDelayedAck (tp_Socket * s);
void tp_TFRetransmit (tp_Socket * s);
void tp_TFPersist (tp_Socket * s);
void tp_TFVegas (tp_Socket * s);
void tp_TFRate (route *r);
void tp_TFBERecv (tp_Socket * s);
void tp_TFSelect (tp_Socket * s);
void tp_TFTimeWT (tp_Socket * s);
void tp_TFKeepAlive (tp_Socket * s);

void tp (void);
uint32_t tp_Compress (tp_Socket * socket, struct mbuff *m, u_char * chp);
int tp_Uncompress (tp_Socket * s, char *cp);

int tp_CompressedHandler (scps_np_rqts * rqts, int len, tp_Header * tp);
void tp_Handler (scps_np_rqts * rqts, int len, tp_Header * tp);
void scmp_Handler (scps_np_rqts * rqts, int len, tp_Header * tp);
int tp_CommonHandler (tp_Socket * s, scps_np_rqts * rqts,
		      tp_Header * tp, byte * data, int len);

void tp_ProcessAck (tp_Socket * s, tp_Header * tp, int data_len);
void tp_ProcessData (tp_Socket * s, tp_Header * tp, byte * data, int len);
int tp_OutSeq (tp_Socket * s, tp_Header * tp, int tp_len,
	       byte * dp, int dp_len);
void Process_EOR (tp_Socket * s, struct mbuff *mbuffer, int OutSeq);
uint32_t checksum (word * dp, int length);
uint32_t data_checksum (struct mbcluster *cluster, int length, int offset);

void tp_DumpHeader (in_Header * ip, tp_Header * tpp, char *mesg);
void Move (byte * src, byte * dest, int numbytes);
struct mbuff *tp_BuildHdr (tp_Socket * s, struct mbuff *mbuffer, int push);
void fix_tp_header (void *socket, struct mbuff *mbuffer);
void tp_FinalCksum (tp_Socket * s, struct mbuff *m, tp_Header * th, uint32_t thl);
uint32_t tp_NewSend (tp_Socket * s, struct mbuff *mbuffer, BOOL force);
void tp_xmit_timer (tp_Socket * s, uint32_t rttrto, uint32_t rttvegas);
void ddump (byte * dp, int len);
void udp_Handler (scps_np_rqts * rqts, int len, tp_Header * tp);
uint32_t tp_iovCoalesce (tp_Socket * s, struct mbuff *m, uint32_t * bytes_sent);
struct mbuff *tp_next_to_send (tp_Socket * s, struct _hole_element **hole);

void tp_BuildHdr_add_ecbs_header (unsigned char opt[], unsigned short *opt_len, unsigned short *tpopt_len_location);
void tp_BuildHdr_add_ecbs_header_len (unsigned char opt[], unsigned short *opt_len, unsigned short *tpopt_len_location);
void tp_BuildHdr_add_ecbs_pad (unsigned char opt[], unsigned short *opt_len, unsigned short *tpopt_len_location);
int tp_BuildHdr_add_ecbs1_req (tp_Socket *s, unsigned char opt[], unsigned short *opt_len);
int tp_BuildHdr_add_ecbs1_reply (tp_Socket *s, unsigned char opt[], unsigned short *opt_len);
int tp_BuildHdr_add_ecbs2_req (tp_Socket *s, unsigned char opt[], unsigned short *opt_len);
int tp_BuildHdr_add_ecbs2_reply (tp_Socket *s, unsigned char opt[], unsigned short *opt_len);

#ifdef GATEWAY
void gateway_reset (int s1, scps_np_rqts * rqts, tp_Header * tp);
void gateway_move_data (tp_Socket * from, tp_Socket * to);
void gateway_set_options (int sockid, int divert_port, int other);
void gateway_double_check_parameters (tp_Socket* s);

#endif /* GATEWAY */

#ifdef IP_ICMP
void icmp_Handler (scps_np_rqts *rqts_in, int ip_pkt_len, ip_template *ip_hdr,
                  int offset);
int scps_icmp_output ();
int icmp_unreachable (icmp_Header *i_hdr);
#endif /* IP_ICMP */

/* lower layer support routine prototypes */

#include "ll.h"

#define NL_PROTOCOL_IPV4                0x01
#define NL_PROTOCOL_NP                  0x02
#define NL_PROTOCOL_PATH                0x04
#define NL_PROTOCOL_IPV6                0x08

#define NL_TRY_NP                       -2
#define NL_TRY_IPV6                     -3
#define NL_TRY_IPV4                     -4

#ifdef GATEWAY
#define GATEWAY_SEND_SYN                1
#define GATEWAY_PEER_WIN_NOT_OPENED     2
#define GATEWAY_SCPS_TP_SESSION         4
#define GATEWAY_SEND_FIN                8
#define GATEWAY_MORE_TO_WRITE           16
#define GATEWAY_HAS_RUNT		32
#define GATEWAY_ABORT_NOW               64

#define GATEWAY_MAX_BURST		5

#ifdef GATEWAY_DUAL_INTERFACE
#define GATEWAY_LAYERING_NORMAL		0
#define GATEWAY_LAYERING_UDP		1

#endif /* GATEWAY_DUAL_INTERFACE */

#endif /* GATEWAY */

#define DEFAULT_ENCRYPT_PRE_OVERHEAD     8
#define DEFAULT_ENCRYPT_BLOCK_SIZE       8
#define DEFAULT_ENCRYPT_POST_OVERHEAD    44

#endif	/* _scpstp_h */
