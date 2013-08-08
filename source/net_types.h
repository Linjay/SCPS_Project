#ifndef net_types_h
#define net_types_h

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

/* #include "scps.h"  */
/* ##include "scps_defines.h" */

#define LOW_RATE_THRESH		20000
#define LOW_RATE_SCALE_FACTOR	8

#define MAX_MPF_ADDRS		4

struct ipv6_addr {
	u_char addr [16];
};

typedef uint32_t scps_np_addr;

struct addrs {
	union {
		uint32_t ipv4_addr;
		struct ipv6_addr ipv6_addr;
	} nl_head;
	int nl_protocol;
};

/* move this route struct from scpstp.h to here (net_types.h) */
typedef struct _route
  {
    struct _route *next;
    unsigned char IFNAME [16];
    uint32_t bytes_per_interval;
    uint32_t current_credit;
    uint32_t shifted_bytes_per_interval;
    uint32_t shifted_rate_bucket;
#ifdef MIN_RATE_THRESH
    uint32_t min_bytes_per_interval;
    uint32_t min_current_credit;
    uint32_t min_shifted_bytes_per_interval;
    uint32_t min_shifted_rate_bucket;
#endif /* MIN_RATE_THRESH */
    uint32_t  attrib_list;
    int min_rate;
    uint32_t max_credit;
    uint32_t max_burst_bytes;
    uint32_t interval;
    uint32_t time;
    uint32_t prev_time;
    unsigned int MTU;
    unsigned int SMTU;
    unsigned int MSS_FF;
    unsigned int TCPONLY;
    unsigned int DIV_ADDR;
    unsigned int DIV_PORT;
    uint32_t flags;
    uint32_t rtt;
    uint32_t rtt_var;
    uint32_t initial_RTO;
    uint32_t sendpipe;
    int cong_control;
    int rate;
    int encrypt_ipsec;
    int encrypt_pre_overhead;
    int encrypt_block_size;
    int encrypt_post_overhead;
#ifdef SECURE_GATEWAY
    int secure_gateway_rqts;
#endif /* SECURE_GATEWAY */

    uint32_t new_params_flag;
#ifdef GATEWAY_ROUTER
    uint32_t dst_ipaddr;
    uint32_t dst_netmask;
    uint32_t src_ipaddr;
    uint32_t src_netmask;
    unsigned short dst_higport; 
    unsigned short dst_lowport;
    unsigned short src_higport;
    unsigned short src_lowport;
    uint32_t protocol_id;
    int dscp;
    int lan_wan;
#endif /* GATEWAY_ROUTER */

    unsigned int route_sock_id;
#ifdef MPF
    int mpf;
    uint32_t mpf_src [MAX_MPF_ADDRS];
    uint32_t mpf_dst [MAX_MPF_ADDRS]; 
    int mpf_src_cnt;
    int mpf_dst_cnt;
#endif /* MPF */
    int mpf_xmit_delay;

#ifdef GLOBAL_VEGAS
    uint32_t rttbest;		/* Best rtt we've seen on this connection */
    uint32_t rttcur;		/* Current rtt on this connection */
#endif /* GLOBAL_VEGAS */

    int flow_control;
    int flow_control_cap;

  }
route;

#ifdef FAIRER_GATEWAY
#define GW_LOST_RATE			0
#define GW_USING_RATE			1
#define GW_LOST_AND_REGAINED_RATE	2
#endif /* FAIRER_GATEWAY */

#define RESET_USING_RATE		1
#define RESET_LOST_AND_REGAINED_RATE	2

#define MIN_IP_HDR			20
#ifdef UNDEFINED
/* don't use about defines; use enumerated type instead: */
typedef enum
  {
    TBD0,
    SCMP,			/* SCPS Control Message Protocol */
    TBD2,
    TBD3,
    SCPSCTCP,			/* SCPS Compressed Transport Protocol */
/* SCPSUDP, *//* SCPS User Datagram Protocol */
    SCPSTCP = 6,		/* SCPS Transport Protocol (=6 to match TCP) */
    TBD7,
    SP,				/* SCPS Security Protocol */
    SP3,			/* Secure Data Network Systems Security Protocol 3 */
    IPV6AUTH,			/* Speculative IPv6 authorization exchange */
    IPV6ESP,			/* Speculative IPv6 telepathic exchange */
    TBD12,
    TBD13,
    TBD14,
    TBD15,
    SCPSCTP = 105,
    SCPSTP = 106,
    SCPSUDP = 117,
    SCPSNP = 118,
  }
scps_tpid;
#endif /* UNDEFINED */

/** WARNING! IF THESE VALUES ARE CHANGED, THE CODE
*** IN SCPS_NP.C: scps_np_get_template MUST ALSO BE
*** CHANGED, SINCE THE TS HDR MASKING DEPENDS ON
*** THESE VALUES.
**/
typedef enum
  {
    None,
    ISO24,
    TBD24,
    SCPS32
  }
ts_fmt;

typedef struct _scps_np_ts
  {
    ts_fmt format;
    short ts_val[2];
  }
scps_ts;

typedef struct _scps_np_bqos
  {
    u_short precedence;
    u_short routing;
    u_short pro_specific;
  }
scps_np_bqos;

typedef struct _scps_np_eqos
  {
    u_short ip_precedence;
    u_short ip_tos;
  }
scps_np_eqos;

/* NOTE: int_del & cksum are new fields here;
         also, dst & src addrs are now 'ip' not np
*/

typedef struct _scps_np_rqts
  {
    scps_tpid tpid;
    int nl_protocol;
    uint32_t ipv4_dst_addr;
    uint32_t ipv4_src_addr;
    struct ipv6_addr ipv6_dst_addr;
    struct ipv6_addr ipv6_src_addr;
    scps_ts timestamp;
    scps_np_bqos bqos;
    scps_np_eqos eqos;
    BOOL cksum;
    BOOL int_del;
    unsigned char DSCP;
    void *interface;
#ifdef ENCAP_DIVERT
    int32_t divert_port_number;
#endif				/* ENCAP_DIVERT */
#ifdef SECURE_GATEWAY
     int secure_gateway_rqts;
#endif /* SECURE_GATEWAY */
#ifdef TAP_INTERFACE
    unsigned char src_mac_addr [6];
    unsigned char dst_mac_addr [6];
    unsigned short frame_type;
    int recv_tap_if;
    int peer_tap_if;
#endif /* TAP_INTERFACE */
  }
scps_np_rqts;

/* since there was no set use for the bitmask and pointers
** fields, I'm using the pointers to 'point' to input
** fields in the header that can change between _get_template 
** and _trequest. So far, the only dynamic fields are the
** timestamp and the secondary header. I've picked pointers[0]
** to hold the pointer (header octet number) to the timestamp,
** and pointers[1] to hold ptr to the secondary hdr.
*/
typedef struct
  {
    short hdr_len;
    uint32_t bitmask;
    short pointers[10];
    byte header[84];
    uint32_t dst_npaddr;
    uint32_t src_npaddr;

  }
scps_np_template;

typedef struct _scps_sp_rqts
  {
    scps_np_rqts np_rqts;
    short tpid;
    short sprqts;
#ifdef SECURE_GATEWAY
    int secure_gateway_rqts;
#endif /* SECURE_GATEWAY */
  }
scps_sp_rqts;

#endif /* net_types_h */
