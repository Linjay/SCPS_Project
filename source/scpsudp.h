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

/*
 * scpsup.h - header file for SCPS UDP
 *
 */

#ifndef scpsudp_h
#define scpsudp_h

#define MAX_NP_LEN (MAX_MTU + 14)	/* this doesn't belong here! */
#define UDP_HDR_LEN 8
#define MAX_UDP_PAYLOAD (MAX_NP_LEN - UDP_HDR_LEN)

typedef struct _udphdr
  {
    word srcPort;		/* source port */
    word dstPort;		/* destination port */
    short len;			/* udp length */
    word checksum;		/* udp checksum */
  }
udp_Header;


typedef struct _udp_socket
  {
    /* --- Don't modify anything here, as it must mirror the tp structure --- */
    struct _udp_socket *prev;
    struct _udp_socket *next;
    struct threads *thread;	/* address of this socket's owner's 
				 * thread structure */
    int Initialized;		/* Indication as to whether or not this socket is "clean" */
    unsigned int sockid;	/* Socket's "logical" file-descriptor */
    uint32_t sockFlags;		/* blocking info (see above) */
    scps_np_addr my_ipv4_addr, his_ipv4_addr;	/* address of current peer */
    struct ipv6_addr my_ipv6_addr, his_ipv6_addr;	/* address of current peer */
    u_short myport, hisport;	/* udp ports for this "connection" */
    int np_size;		/* Size of np header for this "connection" */
    int sp_size;		/* Size of sp header for this "connection" */
    short nh_off;		/* Offset of the start of the np header in an mbuff */
    short sh_off;		/* Offset of the start of the sp header in an mbuff */
    short th_off;		/* Ditto for udp header */
    route *rt_route;		/* pointer to route structure for "connection" */
    route *rt_route_def;	/* Default routing structure */
    int s_errno;		/* Error indication consumed by app */
    scps_np_rqts np_rqts;	/* Network layer requirements structure */
    scps_sp_rqts sp_rqts;	/* Securtity layer requirements structure */
#ifdef GATEWAY_SELECT
    caddr_t *read_parent;	/* Thread's socket queue owning this socket */
    struct _udp_socket *read_prev;	/* Previous socket in chain */
    struct _udp_socket *read_next;	/* Next socket in chain */
    unsigned int read;		/* Amount needed to unblock read */
    caddr_t *write_parent;	/* Thread's socket queue owning this socket */
    struct _udp_socket *write_prev;	/* Previous socket in chain */
    struct _udp_socket *write_next;	/* Next socket in chain */
    unsigned int write;		/* Amount needed to unblock write */
#endif /*  GATEWAY_SELECT */

    /*
     * This is a little busted, but the template type is determined
     * at compile time right now. The way to fix this is to declare
     * a pointer to a generic template that is setup at socket 
     * creation time.
     */
    int display_now;
    ip_template ip_templ;		/* Network layer header template */
    scps_np_template np_templ;	/* Network layer header template */

#ifdef XXXX
    path_template pa_templ;	/* Network layer header template */
#endif				/* XXXX */

#ifdef SCPSSP
    sp_template sp_templ;
#endif				/* SCPSSP */

    struct _buffer *send_buff;	/* Send Buffer (Holds only ONE static mbuff) */
    struct _buffer *receive_buff;	/* Receive Buffer (Holds only the mbuffs) */
    struct _cl_chain *app_sbuff;	/* Application Send-buffer space for 1 pckt */
    struct _cl_chain *app_rbuff;	/* Application Receive-buffer space */
    /* ------------------------- Safe to modify below here -------- */

#ifdef UDP_GATEWAY
    int gw_udp_port_from;
    int gw_udp_port_to;
#endif /* UDP_GATEWAY */
    word buff_full;		/* send buffer is occupied */
    uint32_t select_timer;	/* This is an ugly hack to have a select-timer */
    tp_PseudoHeader ph;		/* This socket's pseudo-header storage */
    udp_Header old_th;		/* Last header sent on this "connection" */
    uint32_t user_data;		/* bytes of user_data sent on "connection" */
    uint32_t total_data;	/* bytes of user data + headers sent on 
				 * this "connection" */
    struct timeval start_time;	/* for throughput calculation:  
				 * beginning of data transfer phase */
  }
udp_Socket;

/* User-visible function prototypes */
int udp_Open (int sockid, word lport);
int udp_Close (int sockid);
int udp_WriteTo (int sockid, byte * dp, int len, scps_np_addr ina, word port);
int udp_Read (int sockid, caddr_t data, int size);
int udp_Recvfrom (int sockid, caddr_t data, int size, void *ina, int *ina_len);
void udp_buffer_report (int sockid);

/* Internal use function prototypes */
int udp_Common (udp_Socket * s);
void udp_Unthread (udp_Socket * ds);
void udp_Handler (scps_np_rqts * rqts, int len, tp_Header * tp);
void udp_DumpHeader (in_Header * ip, udp_Header * upp, char *mesg);
int udp_BuildHdr (udp_Socket * s, struct mbuff *mbuffer);
void udp_FinalCksum (udp_Socket * s, struct mbuff *m, udp_Header * uh);
uint32_t udp_Coalesce (udp_Socket * s, uint32_t * bytes_sent);

/* For handling of blocking and non-blocking sockets */
#ifndef SOCK_BL
#define SOCK_BL		 0x0008	/* flag to indicate that socket blocks */
#endif /* SOCK_BL */
#endif /* !scpsudp_h */
