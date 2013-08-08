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
#ifndef _ll_include_h
#define _ll_include_h

#include "scps.h"
#include "scpstp.h"

#ifdef LINUX
#ifndef IPPROTO_DIVERT
#define IPPROTO_DIVERT	254
#endif /* IPPROTO_DIVERT */
#endif /* LINUX */

#define MAX_LL_QUEUE_ELEMENTS 1000
#define SCPS_UDP_PORT  7168
#define Other_SCPS_UDP_PORT 7167        /* Added for loopback testing */
#define SCPS_SPANNER_PORT 7169

#define MAC_ADDR_SIZE 6
#define START_OF_FRAME_TYPE 12
#define SIZE_OF_ETHER_PART 14

struct timeval lltimeout;
fd_set llfd_set;
int ll_max_socket;

struct _ll_queue_element
  {
    struct _ll_queue_element *next;
    int size;
    int offset;
    unsigned char data[MAX_LL_DATA];
    struct _interface *interface;
#ifdef ENCAP_DIVERT
    int32_t divert_port_number;
#endif				/* ENCAP_DIVERT */

#ifdef GATEWAY_DUAL_INTERFACE
    int layering;
    int special_udp_port;
    uint32_t special_ip_addr;
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef TAP_INTERFACE
    unsigned char src_mac_addr [MAC_ADDR_SIZE];
    unsigned char dst_mac_addr [MAC_ADDR_SIZE];
    unsigned short frame_type;
    int recv_tap_if;
    int frame_size;
#endif /* TAP_INTERFACE */

  };

struct _ll_queue
  {
    struct _ll_queue_element *head;
    struct _ll_queue_element *tail;
    int size;
  };

struct _interface
  {
    struct _ll_queue incoming;
    struct _ll_queue outgoing;
    struct _ll_queue available;
    struct _interface *next;
    int MTU;
    uint32_t address;
    uint32_t next_hop; /* USED only for DIVERT_N_RAWIP */
    uint32_t local_ipaddr;  /* user for gateway udp encap only */
    uint32_t remote_ipaddr;  /* user for gateway udp encap only */
    int tp_socket, ctp_socket, udp_socket, sp_socket, np_socket, raw_socket, et_socket;
    int div_socket;
    int div_a_socket;
    int div_b_socket;
    int tun_a_fd;
    int tun_b_fd;
    int tun_c_fd;
    int tap_a_fd;
    int tap_b_fd;
    int32_t div_port;
    int32_t div_a_port;
    int32_t div_b_port;
    int is_free, service_now;
    int overhead;
    int mss_ff;
  };

/* Function prototypes for lower layer stuff */
int get_local_internet_addr (char *storage);
int32_t get_remote_internet_addr (char *host);
uint32_t clock_ValueRough (void);
int setup_lower (spanner_ip_addr span_addr);
void initialize_interface (struct _interface *interface, uint32_t local_addr);
struct _ll_queue_element *alloc_llbuff (struct _interface *interface);
void move_ll_queue_element (struct _ll_queue from, struct _ll_queue to);
void service_interface (struct _interface *interface);
int ll_iovsend (struct _interface *interface, struct addrs addr,
	    int protocol, int data_len, struct msghdr *my_msg,
	    route *a_route, scps_np_rqts *rqts);
int ll_send (uint32_t remote_internet_addr, byte * data, int data_len);
void free_ll_queue_element (struct _interface *interface,
			    struct _ll_queue_element *buffer);
int ll_nbreceive (struct _interface *interface, struct
		  _ll_queue_element **buffer, int max_len,
		  int *offset);
struct _interface *create_interface (spanner_ip_addr local_addr,
				     spanner_ip_addr span_addr);

#ifdef ENCAP_DIVERT
void
  create_divert_interface (spanner_ip_addr local_addr, int32_t port_number1);
#endif /* ENCAP_DIVERT */

void toggle_iostatus (int status);

#define ET_MAGIC        100	/* MAGIC NUMBER FOR et_socket */
#endif /* _ll_include_h */
