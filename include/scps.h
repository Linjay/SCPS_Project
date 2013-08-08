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

#ifndef scps_h
#define scps_h

#include <stdint.h>
#include "./scpserrno.h"
#include "thread.h"
#include "scps_defines.h"

/* Canonically-sized data */
typedef unsigned int longword;
typedef unsigned short word;
typedef unsigned char byte;
typedef byte octet;		/*  8 bits, for TP */
typedef short BOOL;		/* boolean type */
#ifdef GATEWAY_SELECT
#ifdef GATEWAY_LARGER
typedef int32_t scps_fd_set[16];	/* Assumes int32_t = 4 bytes = 32 bits */
#else /* GATEWAY_LARGER */
typedef int32_t scps_fd_set[8];	/* Assumes int32_t = 4 bytes = 32 bits */
#endif /* GATEWAY_LARGER */
#else /* GATEWAY_SELECT */
typedef int scps_fd_set;
#endif /* GATEWAY_SELECT */

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

void tp (void);

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

/* Temporary thread macros */
#define GET_ERR() ((scheduler.current)?scheduler.current->SCPS_errno:0)
#ifdef DEBUG_ERRORS
#define SET_ERR(n) SET_ERR_FUNCTION(n, __FILE__, __LINE__)
#else /* DEBUG_ERRORS */
#define SET_ERR(n) ((scheduler.current)?scheduler.current->SCPS_errno = (n):0)
#endif /* DEBUG_ERRORS */

/* Socket SCPS Protocol Capabilities */
#define  CAP_TIMESTAMP 1
#define  CAP_COMPRESS  2
#define  CAP_SNACK     4
#define  CAP_BETS      8
#define  CAP_CONGEST  16

#define SCPS_SOCKET 0xff
#define PROTO_SCPSTP 0xfe
#define PROTO_SCPSUDP 0xfd
#define SCPS_ROUTE 0xfc
#define NP_PROTO_NP 0xfb
#define SP_PROTO_SP 0xfa

/* 
 * SCPS_SOCKET options
 */
#define SCPS_SO_SNDBUF       0x1001          /* send buffer size */
#define SCPS_SO_RCVBUF       0x1002          /* receive buffer size */
#define SCPS_SO_SNDLOWAT     0x1003          /* send low-water mark */
#define SCPS_SO_RCVLOWAT     0x1004          /* receive low-water mark */
#define SCPS_SO_SNDTIMEO     0x1005          /* send timeout */
#define SCPS_SO_RCVTIMEO     0x1006          /* receive timeout */
#define SCPS_SO_ERROR        0x1007          /* get error status and clear */  
#define SCPS_SO_TYPE         0x1008          /* get socket type */ 
#define SCPS_SO_BETS_RHOLE_SIZE   0x1009     /* size of BETS Receive Hole */         
#define SCPS_SO_BETS_RHOLE_START  0x100A   /* relative octet sequence of BETS Receive Hole */
#define SCPS_SO_BETS_NUM_SEND_HOLES 0x100B /* Number of BETS Send-holes to report */
#define SCPS_SO_BETS_SEND_HOLES 0x100C     /* Get the locations of the send-holes */
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
#define SCPSTP_VEGAS_ALPHA     0x14
#define SCPSTP_VEGAS_BETA      0x15
#define SCPSTP_VEGAS_GAMMA     0x16
#define SCPSTP_SNACK_DELAY     0x17
#define SCPSTP_VEGAS_SS        0x18
#define SCPSTP_FLOW_CONTROL_CONGEST      0x19

/* SCPS_ROUTE Options */
#define SCPS_RATE 0x1
#define SCPS_MTU  0x2
#define SCPS_RTT   0x3
#define SCPS_SMTU  0x4       
#define SCPS_MSS_FF	0x5
#define SCPS_TCPONLY	0x6
#define SCPS_IRTO   0x7
#define SCPS_DIV_ADDR   0x8
#define SCPS_DIV_PORT   0x9
#define SCPS_IFNAME   0xa
#define SCPS_SP_RQTS   0xb
#define SCPS_MIN_RATE 0xc
#define SCPS_FLOW_CONTROL 0xd
#define SCPS_ENCRYPT_IPSEC              0x2f
#define SCPS_ENCRYPT_PRE_OVERHEAD       0x30
#define SCPS_ENCRYPT_BLOCK_SIZE         0x31
#define SCPS_ENCRYPT_POST_OVERHEAD      0x32

#define SCPS_SOCKET 0xff
#define PROTO_SCPSTP 0xfe
#define PROTO_SCPSUDP 0xfd
#define SCPS_ROUTE 0xfc

/* NP_PROTO_NP Options */
#define SCPS_SO_NPTIMESTAMP		0x01
#define SCPS_SO_CHECKSUM		0x02
#define SCPS_SO_PRECEDENCE		0x03

/* NP_PROTO_SP OPTIONS */
#define SCPS_SO_CONFIDENTIALITY      0x01
#define SCPS_SO_AUTHENTICATION       0x02
#define SCPS_SO_SECURITY_LABEL       0x04
#define SCPS_SO_INTEGRITY            0x08

extern int route_sock;

struct _Hole
  {
    uint32_t Start;		/* Sequence # of first octet of hole */
    uint32_t Finish;		/* Sequence # of last octet of hole */
  };

#define MAX_MTU 1500
#define MAX_LL_DATA 2000      /* There must be a difference between
                                 MAX_LL_DATA and MAX_MTU... extra
                                 encapsulations methods for example */
#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8

#define MAX_ECBS_VALUE 20

/* Determine how int32_t the encapsulating headers
 * are.  This value must be subtracted from the MTU to 
 * determine the usable area of the packet.  There
 * are three possibilities:
 *   packets are encapsulated in UDP/IP, (28 byte overhead)
 *   packets are encapsulated in IP (20 byte overhead)
 *   packets are not encapsulated (0 byte overhead)  
 */
#ifdef USESCPSNP
#ifdef ENCAP_UDP
#define ENCAP_HDR_LEN (IP_HDR_LEN + UDP_HDR_LEN)
#else /* ENCAP_UDP */
#define ENCAP_HDR_LEN (IP_HDR_LEN)
#endif /* ENCAP_UDP */
#else /* USESCPSNP */
#ifdef ENCAP_UDP
#define ENCAP_HDR_LEN (IP_HDR_LEN + UDP_HDR_LEN)
#elif ENCAP_RAW
#define ENCAP_HDR_LEN (IP_HDR_LEN)
#else /* ENCAP_UDP */
#define ENCAP_HDR_LEN (0)
#endif /* ENCAP_UDP */
#endif /* USESCPSNP */

#endif /* scps_h */
