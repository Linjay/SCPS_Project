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

#include <signal.h>
#include <fcntl.h>
#include <string.h>  /* for bzero */
#include "scps.h"
#include "scpstp.h"
#include "scpsudp.h"
#include "np_scmp.h"
#include "gateway.h"
#include "route.h"
#ifdef SCPSSP
#include "scps_sp.h"
#include "scps_sadb.h"
int get_SAinfo (scps_np_rqts * np_rqts, SA_data * SAinfo);
#endif /* SCPSSP */

#ifdef TAP_INTERFACE
#include "tap.h"
#include "other_proto_handler.h"
#endif /* TAP_INTERFACE */

int scps_np_get_template (scps_np_rqts * rqts, scps_np_template * templ);

#ifdef GATEWAY
#include "rs_config.h"
#include <stdlib.h>
extern GW_ifs gw_ifs;
extern int init_port_number_offset;
#endif /* GATEWAY */

#ifdef SECURE_GATEWAY
#include "scps_sp.h"
#endif /* SECURE_GATEWAY */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_utility.c,v $ -- $Revision: 1.61 $\n";
#endif

#ifdef FAIRER_GATEWAY
  extern tp_Socket *start_s;
  extern tp_Socket *init_s;
#endif /* FAIRER_GATEWAY */

extern void free (void *ptr);
extern void *malloc (size_t size);
//extern void *memset (void *s, int c, size_t n);


extern route *route_list_head;
extern route *def_route;
extern route *other_route;
extern uint32_t tp_now;
extern tp_Socket *tp_allsocs;
extern udp_Socket *udp_allsocs;
extern struct _timer rate_timer;
extern struct msghdr out_msg;
extern struct iovec out_iov[8];
extern char config_span_name[];
extern char config_local_name[];
extern int write_count;
extern int send_count;
extern int udp_write_count;
extern int udp_send_count;
extern procref timer_fn[];
extern unsigned short tp_id;
extern unsigned short udp_id;
extern short global_conn_ID;
extern int ll_read_avail;
extern fd_set llfd_set;
extern int ll_max_socket;
extern struct _times
  {
    struct timeval t;
    uint32_t rtt;
  }
ts_array[1];
extern int tp_is_running;

extern int nl_default;

#include "ll.h"

extern struct _interface *divert_interface;

int
np_hdr_size (scps_np_rqts np_rqts)
{
  switch (np_rqts.nl_protocol) {
        case NL_PROTOCOL_IPV4:
                return (20);
                break;
    
        case NL_PROTOCOL_NP: {
                scps_np_template np_templ;
                return (scps_np_get_template (&np_rqts, &np_templ));
                break;
                }

        case NL_PROTOCOL_IPV6:
                return (40);
                break;

        default:
                printf ("WARNING %s %d protocol = %d\n", __FILE__, __LINE__, np_rqts.nl_protocol);
                return (20);
                break;
        
  }
}

int
tp_hdr_size ()
{
  return (20);
}

#ifdef SCPSSP
int
sp_hdr_size (scps_sp_rqts sp_rqts)
{
  SA_data SAinfo;
  int len = 2;

#ifdef SECURE_GATEWAY
  if (sp_rqts.secure_gateway_rqts == SECURE_GATEWAY_NO_SECURITY) {
      return (0);
  }
#endif /* SECURE_GATEWAY */

  if ((get_SAinfo (&(sp_rqts.np_rqts), &SAinfo)) == -1)
    {
      return (0);
    }

  if (SAinfo.QOS & SECURITY_LABEL)
    len += SAinfo.sec_label_len;

  if (SAinfo.QOS & AUTHENTICATION)
    len += 8;			/* XXX PDF size of 2 addresses */

  if (SAinfo.QOS & INTEGRITY)
    len += SAinfo.ICVsize;

  if (SAinfo.QOS & CONFIDENTIALITY)
    len += MAX_SP_PAD;

  return (len);
}
#else /* SCPSSP */
int
sp_hdr_size ()
{
  return (0);
}
#endif /* SCPSSP */

/*
 * Initialize the tp implementation
 */
void
scps_Init ()
{

  int i;
  char *spanner_name;
  char *local_name;
  struct mbcluster *mbcluster;
  struct timeval mytime;

  spanner_ip_addr spanner_addr = 0;
  ll_max_socket = 0;
  FD_ZERO (&llfd_set);

  out_msg.msg_iov = out_iov;

  spanner_name = (char *) config_span_name;
  if (*spanner_name) {
    spanner_addr = get_remote_internet_addr (spanner_name);
  } 
    
  local_name = (char *) config_local_name;
  if (*local_name) {
    local_addr = get_remote_internet_addr (local_name);
  } else {
    get_local_internet_addr ((char *) &local_addr);
  }

  /* interface = create_interface (0, spanner_addr); */

#ifdef GATEWAY
  rs_init ();
#endif /* GATEWAY */

#ifdef TAP_INTERFACE
	other_proto_init ();
#endif /* TAP_INTERFACE */

#ifdef ENCAP_DIVERT
  create_divert_interface (0, (short) 0);

#ifdef GATEWAY_DUAL_INTERFACE
  if (gw_ifs.aif_local_ipaddr) {
	 create_interface (htonl (gw_ifs.aif_local_ipaddr),
                           htonl (gw_ifs.aif_remote_ipaddr));
  } else if (gw_ifs.bif_local_ipaddr) {
	 create_interface (htonl (gw_ifs.bif_local_ipaddr),
                           htonl (gw_ifs.bif_remote_ipaddr));
  } else  {
	printf ("Error in gateway resource file.\n");
	printf ("UDP encapsulated specified without specifing\n");
	printf ("The local and remote addresses\n");
  }

#endif /* GATEWAY_DUAL_INTERFACE */

#else /* ENCAP_DIVERT */
  create_interface (local_addr, spanner_addr);
#endif /* ENCAP_DIVERT */

#ifdef DIVERT_N_RAWIP
  create_interface (local_addr, spanner_addr);
#endif /* DIVERT_N_RAWIP */

#ifdef TUN_INTERFACE
#ifdef GATEWAY
  gateway_tun_rules ();
#endif /* GATEWAY */
#endif /* TUN_INTERFACE */

#ifdef TAP_INTERFACE
#ifdef GATEWAY
  gateway_tap_rules ();
#endif /* GATEWAY */
#endif /* TAP_INTERFACE */

#ifndef SOLARIS
#ifdef ASYNC_IO
  if (!(scheduler.service_interface_now))
    {
      toggle_iostatus (1);
    }
#endif /* ASYNC_IO */
#endif /* SOLARIS */


  memset (ts_array, 0, sizeof (ts_array));

  tp_allsocs = NIL;
  udp_allsocs = NIL;

  route_initialize ();
  init_default_routes ();
  
  mytime.tv_sec = 0;
  mytime.tv_usec = 100000;

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);           
  create_timer (&tp_TFRate, route_list_head, 1, &mytime, &rate_timer, -1);
  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);           

  tp_id = 0;
  udp_id = 0;

  global_conn_ID = (short) clock_ValueRough ();

  write_count = send_count = 0;
  udp_write_count = udp_send_count = 0;

  /* 
   * Initialize the timer function pointer array.
   */

  for (i = 0; i < TIMER_COUNT; i++)
    timer_fn[i] = 0;
  timer_fn[Del_Ack] = (procref) tp_TFDelayedAck;
  timer_fn[Rexmit] = (procref) tp_TFRetransmit;
  timer_fn[Persist] = (procref) tp_TFPersist;
#ifdef CONGEST
  timer_fn[Vegas] = (procref) tp_TFVegas;
#endif /* CONGEST */
#ifdef OPT_BETS
  timer_fn[BE_Recv] = (procref) tp_TFBERecv;
#endif /* OPT_BETS */
  timer_fn[Select] = (procref) tp_TFSelect;
  timer_fn[TW] = (procref) tp_TFTimeWT;
  timer_fn[KA] = (procref) tp_TFKeepAlive;

  route_list_head->time = clock_ValueRough ();		/* turn on timer */
  /*
   * Do it here rather than in 
   * tp_mss() to make UDP happy 
   */
#define PRELOAD 0
  for (i = 0; i < PRELOAD; i++)
    {
      mbcluster = alloc_mbclus (1);
      mbcluster->c_count = 1;
      free_mclus (mbcluster);
    }

  /* Get the busted routing socket */
  route_sock = def_route -> route_sock_id;
#ifdef GATEWAY
  {
    extern GW_ifs gw_ifs;
    int rate_control;
    int mtu;
    int mss_ff;
    int irto;
    int cc;
    uint32_t addr;
    int		  port;
    int32_t rand_number;
    int one = 1;
    void *s1;
    void *s2;
    int rc;

    route_sock2 = other_route -> route_sock_id;
    s1 = scheduler.sockets[route_sock].ptr;
    s2 = scheduler.sockets[route_sock2].ptr;

    ((tp_Socket *) s2)->rt_route = other_route;

printf ("%s %d route_sock = %d rouet_sock2 %d\n", __FILE__, __LINE__, route_sock, route_sock2);
    if (gw_ifs.aif_mtu) {
	mtu = gw_ifs.aif_mtu ;
	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_MTU, &mtu, sizeof (mtu));
    }

    if (gw_ifs.aif_smtu) {
        mtu = gw_ifs.aif_smtu ; 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_SMTU, &mtu, sizeof (mtu));
    }  

    if (gw_ifs.aif_cc)  {
        cc = gw_ifs.aif_cc ; 

	if (cc == NO_CONGESTION_CONTROL) {
		int zero = 0;
        	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPSTP_CONGEST, &zero, sizeof (zero));
	}

	if (cc == VJ_CONGESTION_CONTROL) {
		int one = 1;
        	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPSTP_VJ_CONGEST, &one, sizeof (one));
	}

	if (cc == VEGAS_CONGESTION_CONTROL) {
		int one = 1;
        	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPSTP_VEGAS_CONGEST, &one, sizeof (one));
	}

	if (cc == FLOW_CONTROL_CONGESTION_CONTROL) {
		int one = 1;
        	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPSTP_FLOW_CONTROL_CONGEST, &one, sizeof (one));
	}
    }  

    if (gw_ifs.aif_mss_ff) {
        mss_ff = gw_ifs.aif_mss_ff; 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_MSS_FF, &mss_ff, sizeof (mss_ff));
    }  

    if (gw_ifs.aif_irto) {
        irto = gw_ifs.aif_irto; 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_IRTO, &irto, sizeof (irto));
    }  

    if (gw_ifs.aif_tcponly) {
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_TCPONLY, &one, sizeof (one));
    }  

    if (gw_ifs.aif_div_addr) {
        addr = gw_ifs.aif_div_addr; 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_DIV_ADDR, &addr, sizeof (addr));
    }  

    if (gw_ifs.aif_div_port) {
        port = gw_ifs.aif_div_port; 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_DIV_PORT, &port, sizeof (port));
    }  

    if (gw_ifs.aif_name) {
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_IFNAME, &gw_ifs.aif_name, strlen (gw_ifs.aif_name));
    }  

    if (gw_ifs.aif_scps_security) {
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_SP_RQTS, &gw_ifs.aif_scps_security, sizeof (gw_ifs.aif_scps_security));
    }  

    if (gw_ifs.aif_rate) {
	rate_control = gw_ifs.aif_rate;
	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_RATE, &rate_control,
			 sizeof (rate_control));
    } else {
	rate_control = GATEWAY_DEFAULT_RATE;
	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_RATE, &rate_control,
			 sizeof (rate_control));
    }
#ifdef MIN_RATE_THRESH
    if (gw_ifs.aif_min_rate) {
	rate_control = gw_ifs.aif_min_rate;
	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_MIN_RATE, &rate_control,
			 sizeof (rate_control));
    } else {
	rate_control = GATEWAY_DEFAULT_RATE;
	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_MIN_RATE, &rate_control,
			 sizeof (rate_control));
    }
#endif /* MIN_RATE_THRESH */

#ifdef FLOW_CONTROL_THRESH 
    if (gw_ifs.aif_flow_control_cap) {
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_FLOW_CONTROL_CAP, &gw_ifs.aif_flow_control_cap, sizeof (gw_ifs.aif_flow_control_cap));
    }  
#endif /*  FLOW_CONTROL_THRESH  */

#ifdef MPF
    if (gw_ifs.aif_mpf) {
         ((tp_Socket *) s1)->rt_route->mpf = 1;
         {
            int i;
	
            ((tp_Socket *) s1)->rt_route->mpf_src_cnt = gw_ifs.aif_mpf_src_cnt;
            for (i = 0; i < gw_ifs.aif_mpf_src_cnt; i++) {
                ((tp_Socket *) s1)->rt_route->mpf_src [i] = gw_ifs.aif_mpf_src[i];
            }

            ((tp_Socket *) s1)->rt_route->mpf_src_cnt = gw_ifs.aif_mpf_src_cnt;
            for (i = 0; i < gw_ifs.aif_mpf_dst_cnt; i++) {
                ((tp_Socket *) s1)->rt_route->mpf_dst [i] = gw_ifs.aif_mpf_dst[i];
            }
	}
    }
    ((tp_Socket *) s1)->rt_route->mpf_xmit_delay = gw_ifs.aif_mpf_xmit_delay;
#endif /* MPF */

    if (gw_ifs.aif_encrypt_ipsec_downstream) {
	int value;
        value = gw_ifs.aif_encrypt_ipsec_downstream; 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE,
 	                      SCPS_ENCRYPT_IPSEC,
		     	      &value, sizeof (value));
    }  

    if (gw_ifs.aif_encrypt_pre_overhead) {
	int value;
        value = gw_ifs.aif_encrypt_pre_overhead; 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE,
 	                      SCPS_ENCRYPT_PRE_OVERHEAD,
			      &value, sizeof (value));
    }  

    if (gw_ifs.aif_encrypt_block_size) {
	int value;
        value = gw_ifs.aif_encrypt_block_size; 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE,
 	                      SCPS_ENCRYPT_BLOCK_SIZE,
			      &value, sizeof (value));
    }  

    if (gw_ifs.aif_encrypt_post_overhead) {
	int value;
        value = gw_ifs.aif_encrypt_post_overhead; 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE,
 	                      SCPS_ENCRYPT_POST_OVERHEAD,
			      &value, sizeof (value));
    }  
    if (gw_ifs.bif_mtu) {
	mtu = gw_ifs.bif_mtu;
	rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_MTU, &mtu, sizeof (mtu));
    }

    if (gw_ifs.bif_smtu) {
        mtu = gw_ifs.bif_smtu ;
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_SMTU, &mtu, sizeof (mtu));
    }
    
    if (gw_ifs.bif_cc)  {
        cc = gw_ifs.bif_cc ; 

	if (cc == NO_CONGESTION_CONTROL) {
		int zero = 0;
        	rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPSTP_CONGEST, &zero, sizeof (zero));
	}

	if (cc == VJ_CONGESTION_CONTROL) {
		int one = 1;
        	rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPSTP_VJ_CONGEST, &one, sizeof (one));
	}

	if (cc == VEGAS_CONGESTION_CONTROL) {
		int one = 1;
        	rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPSTP_VEGAS_CONGEST, &one, sizeof (one));
	}

	if (cc == FLOW_CONTROL_CONGESTION_CONTROL) {
		int one = 1;
        	rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPSTP_FLOW_CONTROL_CONGEST, &one, sizeof (one));
	}
    }  

    if (gw_ifs.bif_mss_ff) {
        mss_ff = gw_ifs.bif_mss_ff ; 
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_MSS_FF, &mss_ff, sizeof (mss_ff));
    }  

    if (gw_ifs.bif_irto) {
        irto = gw_ifs.bif_irto; 
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_IRTO, &irto, sizeof (irto));
    }  

    if (gw_ifs.bif_tcponly) {
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_TCPONLY, &one, sizeof (one));
    }  

    if (gw_ifs.bif_div_addr) {
        addr = gw_ifs.bif_div_addr; 
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_DIV_ADDR, &addr, sizeof (addr));
    }  

    if (gw_ifs.bif_div_port) {
        port = gw_ifs.bif_div_port; 
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_DIV_PORT, &port, sizeof (port));
    }  

    if (gw_ifs.bif_name) {
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_IFNAME, &gw_ifs.bif_name, strlen (gw_ifs.bif_name));
    }  

    if (gw_ifs.bif_scps_security) {
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_SP_RQTS, &gw_ifs.bif_scps_security, sizeof (gw_ifs.bif_scps_security));
    }  

    if (gw_ifs.bif_rate) {
	rate_control = gw_ifs.bif_rate;
	rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_RATE, &rate_control,
			 sizeof (rate_control));
    } else {
	rate_control = GATEWAY_DEFAULT_RATE;
	rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_RATE, &rate_control,
			 sizeof (rate_control));
    }

#ifdef MIN_RATE_THRESH
    if (gw_ifs.bif_min_rate) {
	rate_control = gw_ifs.bif_min_rate;
	rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_MIN_RATE, &rate_control,
			 sizeof (rate_control));
    } else {
	rate_control = GATEWAY_DEFAULT_RATE;
	rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_MIN_RATE, &rate_control,
			 sizeof (rate_control));
    }
#endif /* MIN_RATE_THRESH */

#ifdef FLOW_CONTROL_THRESH 
    if (gw_ifs.bif_flow_control_cap) {
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE, SCPS_FLOW_CONTROL_CAP, &gw_ifs.bif_flow_control_cap, sizeof (gw_ifs.bif_flow_control_cap));
    }  
#endif /*  FLOW_CONTROL_THRESH  */

#ifdef MPF
    if (gw_ifs.bif_mpf) {
         ((tp_Socket *) s2)->rt_route->mpf = 1;
         {
            int i;
	
            ((tp_Socket *) s2)->rt_route->mpf_src_cnt = gw_ifs.bif_mpf_src_cnt;
            for (i = 0; i < gw_ifs.bif_mpf_src_cnt; i++) {
                ((tp_Socket *) s2)->rt_route->mpf_src [i] = gw_ifs.bif_mpf_src[i];
            }

            ((tp_Socket *) s2)->rt_route->mpf_src_cnt = gw_ifs.bif_mpf_src_cnt;
            for (i = 0; i < gw_ifs.bif_mpf_dst_cnt; i++) {
                ((tp_Socket *) s2)->rt_route->mpf_dst [i] = gw_ifs.bif_mpf_dst[i];
            }
	}
    }
    ((tp_Socket *) s2)->rt_route->mpf_xmit_delay = gw_ifs.bif_mpf_xmit_delay;
#endif /* MPF */

    if (gw_ifs.bif_encrypt_ipsec_downstream) {
	int value;
        value = gw_ifs.bif_encrypt_ipsec_downstream; 
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE,
 	                      SCPS_ENCRYPT_IPSEC,
		     	      &value, sizeof (value));
    }  

    if (gw_ifs.bif_encrypt_pre_overhead) {
	int value;
        value = gw_ifs.bif_encrypt_pre_overhead; 
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE,
 	                      SCPS_ENCRYPT_PRE_OVERHEAD,
			      &value, sizeof (value));
    }  

    if (gw_ifs.bif_encrypt_block_size) {
	int value;
        value = gw_ifs.bif_encrypt_block_size; 
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE,
 	                      SCPS_ENCRYPT_BLOCK_SIZE,
			      &value, sizeof (value));
    }  

    if (gw_ifs.bif_encrypt_post_overhead) {
	int value;
        value = gw_ifs.bif_encrypt_post_overhead; 
        rc = scps_setsockopt (route_sock2, SCPS_ROUTE,
 	                      SCPS_ENCRYPT_POST_OVERHEAD,
			      &value, sizeof (value));
    }  

    rand_number = clock_ValueRough ();
    srandom (rand_number);
    rand_number = random ();
    rand_number = rand_number % 5000;
    rand_number += 5000;
    init_port_number_offset = rand_number;
  }
#endif /* GATEWAY */
  mbcluster =
    deq_mclus (((tp_Socket *) (scheduler.sockets[route_sock].ptr))->app_sbuff);
  free_mclus (mbcluster);
  mbcluster =
    deq_mclus (((tp_Socket *) (scheduler.sockets[route_sock].ptr))->app_rbuff);
  free_mclus (mbcluster);

  /* Kick in rate control timers here */
  route_list_head->prev_time = 1;

  /* 
   * We created a socket, keep running until we've 
   * closed out all the protocol sockets
   */

  tp_is_running = 1;

  scps_np_init ();

}
#ifdef GATEWAY

#ifndef GATEWAY_SINGLE_THREAD
void
gateway ()
{
  int fd;
  int nfd;
  struct sockaddr_in sinme;
  int fromlen;
  struct sockaddr_in frominet;

  fd = scps_socket (AF_INET, SOCK_STREAM, 0);
  scps_bind (fd, (struct sockaddr *) &sinme, sizeof (sinme));
  scps_listen (fd, 0);          /* allow a queue of 0 */
  fromlen = sizeof (frominet);

  nfd = scps_accept (fd, &frominet, &fromlen);

  scps_close (fd);
  scps_close (nfd);
  threadExit ();
}
#endif /* GATEWAY_SINGLE_THREAD */

void
init_gateway ()
   
{
  
  init_scheduler ();
  scheduler.run_queue[1] = create_thread (tp);
#ifndef GATEWAY_SINGLE_THREAD
  scheduler.run_queue[0] = create_thread (gateway);
#endif /* GATEWAY_SINGLE_THREAD */
  (void) scps_Init ();
  start_threads ();
#ifdef GATEWAY_SINGLE_THREAD
  tp ();
#endif /* GATEWAY_SINGLE_THREAD */
  exit (0);
}
#else /* GATEWAY */
void
init_gateway () {}
#endif /* GATEWAY */




int
tp_Common (tp_Socket * s)
{
  int temp;
  struct threads *tpthread;
  struct timeval mytime;
  tp_Socket *sp;
  struct mbcluster *mbcluster;
  int i;

  if (!((s->state == tp_StateNASCENT) || (s->state == tp_StateCLOSED)))
    {
      SET_ERR (SCPS_ESOCKOUTSTATE);
      return (-1);
    }

  /* We're clean, skip the rest */
  if (s->Initialized)
    {
      if (!(s->scratch_buff))
	{
	  s->scratch_buff = alloc_mbuff (MT_HEADER);
	}
      return (0);
    }

  for (sp = tp_allsocs; sp != NULL; sp = sp->next)
    {
      if (s == sp)
	{
	  SET_ERR (SCPS_ESOCKINUSE);
	  return (-1);
	}
    }

  /* Get a pseudo-file descriptor for our socket */
  for (temp = 0; temp < MAX_SCPS_SOCKET; temp++)
    {
      if (scheduler.sockets[temp].ptr == NULL)
	{
	  scheduler.sockets[temp].ptr = (caddr_t) s;
	  s->sockid = temp;
	  break;
	}
    }

  if (temp == MAX_SCPS_SOCKET)
    {
      SET_ERR (SCPS_ENOBUFS);
printf ("We are temporary out of sockets\n");
      return (-1);
    }

  /* Initialize blocking related parameters */
#ifdef GATEWAY_SELECT
  s->read = s->write = 0;
  s->read_prev = s->read_next = 0x0;
  s->write_prev = s->write_next = 0x0;
  s->read_parent = s->write_parent = 0x0;
#endif /* GATEWAY_SELECT */

  s->display_now = 0x00;

  s->snack_delay = 0;	/* The default is to not delay the response to a SNACK */
  /* Copy local copies of the settable constants */
  s->ACKDELAY = tp_ACKDELAY;
  s->ACKFLOOR = tp_ACKFLOOR;
  s->RTOMIN = tp_RTOMIN;
  s->RTOMAX = tp_RTOMAX;
  s->MAXPERSIST_CTR = tp_MAXPERSIST_CTR;
  s->RTOPERSIST_MAX = tp_RTOPERSIST_MAX;
  s->RETRANSMITTIME = tp_RETRANSMITTIME;
  s->PERSISTTIME = tp_PERSISTTIME;
  s->TIMEOUT = tp_TIMEOUT;
  s->LONGTIMEOUT = tp_LONGTIMEOUT;
  s->TWOMSLTIMEOUT = tp_2MSLTIMEOUT;
  s->KATIMEOUT = tp_KATIMEOUT;
  s->BETS_RECEIVE_TIMEOUT = BETS_RECEIVE_TIMEOUT;
  s->scratch_buff = alloc_mbuff (MT_HEADER);
  s->ack_freq = DEFAULT_ACK_FREQ;	/* set default ack behavior */
  s->cong_algorithm = VEGAS_CONGESTION_CONTROL;		/* set default cong-contr */
#ifdef MFX_TRANS
  s->MFX_SETTING = 3;
#else /* MFX_TRANS */
  s->MFX_SETTING = 0;
#endif /* MFX_TRANS */
  s->mfx_snd_una = 8;

  s->rt_route = NIL;
#ifdef GATEWAY
  s->rel_seq_num_urg_ptr = 0;
  s->gateway_runt_ack_ctr = 0;
  s->gateway_runt_ctr = 0;
#ifdef GATEWAY_DUAL_INTERFACE
//  s->gateway_layering = GATEWAY_LAYERING_NORMAL;
#endif /* GATEWAY_DUAL_INTERFACE */
#endif /* GATEWAY */

  /* Congestion epoch control variables. */
  s->high_seq = 0;
  s->high_congestion_seq = 0;

  /* Use for persist expontential time out values */
  s->persist_shift = 0;
  s->maxpersist_ctr = 0;

  /* TCP-Vegas related parameters */
  s->VEGAS_ALPHA = ALPHA;
  s->VEGAS_BETA = BETA;
  s->VEGAS_GAMMA = GAMMA;
  s->VEGAS_SS	 = 0;

  mytime.tv_sec = mytime.tv_usec = 0;

  s->capabilities = 0;		/* Defaults to just Window-Scaling */

  /* default to running with Timestamps and SNACK1 */


  s->ecbs1 = s->ecbs1_req = 0;
  s->ecbs2 = s->ecbs2_req = 0;
  s->ecbs1_len = s->ecbs1_req_len = 0;
  s->ecbs2_len = s->ecbs2_req_len = 0;
  { int iii;
  	for (iii = 0; iii < MAX_ECBS_VALUE; iii++) {
		s->ecbs1_value [iii] = s->ecbs1_req_value [iii] = 0;
		s->ecbs2_value [iii] = s->ecbs2_req_value [iii] = 0;
 	 }
  }
  
#ifdef OPT_SCPS
  s->capabilities |= CAP_JUMBO;
#endif /* OPT_SCPS */

#ifdef OPT_TSTMP
  s->capabilities |= CAP_TIMESTAMP;
  s->sockFlags |= TF_REQ_TSTMP;
#endif /* OPT_TSTMP */

#ifdef OPT_SNACK1
  s->capabilities |= CAP_SNACK;
  s->sockFlags |= TF_REQ_SNACK1;
#endif /* OPT_SNACK1 */

#ifdef CONGEST
  s->capabilities |= CAP_CONGEST;
#endif /* CONGEST */

#ifdef MFX_TRANS
  s->capabilities |= CAP_MFX;
#endif /* MFX_TRANS */

  s->thread = scheduler.current;	/* process id of this thread */
  s->timeout = tp_LONGTIMEOUT;	/* max retransmissions */
  tp_now = clock_ValueRough ();

  s->total_data = s->last_total_data = 0;
#ifndef GATEWAY
  s->sockFlags |= SOCK_BL;	/* Sockets block by default */
#endif /* GATEWAY */

  s->funct_flags = 0x0;

/*
 * Note:  initializing lastuwein to seqnum results 
 * in a window size of 0 on the initial SYN. This 
 * should be at least 1 to allow the SYN out, but 
 * in our tests, we use SEQ_LEQ rather than SEQ_LT, 
 * which is correct.  When/if we support transaction
 * TP, in which data can accompany the SYN, we must 
 * set lastuwein to seqnum + the default window size, 
 * which should be at least 1 mss.
 */
#ifdef DEBUG_SEQNUM
  s->seqnum = s->snduna = s->seqsent = s->max_seqsent =
    s->old_seqsent = s->lastuwein = 0;
  s->lastuwein = 2;
#else /* DEBUG_SEQNUM */
  s->seqnum = s->snduna = s->seqsent = s->max_seqsent =
    s->old_seqsent = s->lastuwein = tp_now;
  /* s->lastuwein = s->seqnum++; */
#endif /* DEBUG_SEQNUM */
  s->initial_seqnum = s->seqnum;
  s->high_hole_seq = s->seqnum;
#ifdef DEBUG_MEMORY
//  printf ("%s Initial seqnum is %u\n", stringNow (), s->initial_seqnum);
  fflush (stdout);
#endif /* DEBUG_MEMORY */

#ifdef OPT_BETS
  if (s->capabilities & CAP_BETS)
    s->BETS.InSndSeq = s->seqnum + 1;
#endif /* OPT_BETS */

  s->ack_delay = 0;
  s->rttcnt = -1;
  s->rtt = 0;
  /* s->t_rxtcur = 0; */
  s->flags = tp_FlagSYN;
  s->th_off = temp = MBLEN - TP_MAX_HDR;

  /* Set some default network layer parameters */
  s->np_rqts.tpid = SCPSTP;
  s->np_rqts.ipv4_dst_addr = 0;
#ifdef GATEWAY
  s->np_rqts.ipv4_src_addr = 0;
#endif /* GATEWAY */
  s->np_rqts.timestamp.format = 0;
  s->np_rqts.timestamp.ts_val[0] = s->np_rqts.timestamp.ts_val[1] = 0;
  s->np_rqts.bqos.precedence = 0;
  s->np_rqts.bqos.routing = 0;
  s->np_rqts.bqos.pro_specific = 0;
  s->np_rqts.eqos.ip_precedence = 0;
  s->np_rqts.eqos.ip_tos = 0;
  s->np_rqts.cksum = 1;
  s->np_rqts.int_del = 0;

  if (!s->np_rqts.nl_protocol) {
      s->np_rqts.nl_protocol =  nl_default;
  }

#ifdef SCPSSP
  s->sp_rqts.np_rqts.tpid = SP;
  s->sp_rqts.np_rqts.ipv4_dst_addr = 0;
#ifdef GATEWAY
  s->sp_rqts.np_rqts.ipv4_src_addr = 0;
#endif /* GATEWAY */
  s->sp_rqts.np_rqts.timestamp.format = 0;
  s->sp_rqts.np_rqts.timestamp.ts_val[0] =
    s->sp_rqts.np_rqts.timestamp.ts_val[1] = 0;
  s->sp_rqts.np_rqts.bqos.precedence = s->np_rqts.bqos.precedence;
  s->sp_rqts.np_rqts.bqos.routing = 0;
  s->sp_rqts.np_rqts.bqos.pro_specific = 0;
  s->sp_rqts.np_rqts.eqos.ip_precedence = 0;
  s->sp_rqts.np_rqts.eqos.ip_tos = 0;
  s->sp_rqts.np_rqts.cksum = 1;
  s->sp_rqts.np_rqts.int_del = 0;

  if (!s->sp_rqts.np_rqts.nl_protocol) {
      s->sp_rqts.np_rqts.nl_protocol =  nl_default;
  }

  s->sp_rqts.tpid = SCPSTP;
  s->sp_rqts.sprqts = 0x00;
  s->np_rqts.tpid = SP;
#ifdef SECURE_GATEWAY
  s->sp_rqts.secure_gateway_rqts = SECURE_GATEWAY_STRICT_SECURITY;
#endif /* SECURE_GATEWAY */

#ifdef GATEWAY_DUAL_INTERFACE
  s->special_udp_port = 0;
  s->special_ip_addr = 0;
#endif /*  GATEWAY_DUAL_INTERFACE */

  s->sp_size = sp_hdr_size (s->sp_rqts);
  temp = s->sp_size + (s->sp_size % sizeof (uint32_t));
  s->sh_off = s->th_off - temp;
  temp = s->sh_off;
#endif /* SCPSSP */

#ifdef USESCPSNPXXX
  s->np_size = np_hdr_size (s->np_rqts);
  s->nh_off = temp - s->np_size - (s->np_size % sizeof (uint32_t));
#endif /* USESCPSNPPXXX */

  if ( (s->np_rqts.nl_protocol == NL_PROTOCOL_IPV4) ||
       (s->np_rqts.nl_protocol == NL_PROTOCOL_NP) ) {
        s->ph.nl_head.ipv4.src = local_addr;
          s->ph.nl_head.ipv4.mbz = 0;
          s->ph.nl_head.ipv4.protocol = SCPSTP;
  }

  if (s->np_rqts.nl_protocol == NL_PROTOCOL_IPV6) {
//      s->ph.nl_head.ipv4.src = local_addr;
          s->ph.nl_head.ipv6.protocol = SCPSTP;
  }

  if (!(s->receive_buff))
    {
      s->receive_buff = buff_init (MAX_MBUFFS, s);
      s->Out_Seq = buff_init (MAX_MBUFFS, s);
    }
  if (!(s->send_buff))
    s->send_buff = buff_init (MAX_MBUFFS, s);

  if ((!(s->receive_buff)) || (!(s->Out_Seq)) || (!(s->send_buff)))
    goto SockAlloc_Failure;

  /* 
   * With the addition of socket options, it is possible to
   * setup your send and receive buffers prior to doing a
   * tp_Connect() or tp_Listen(); We can (and probably should)
   * think about implementing a socket() call to a globally 
   * managed pool of sockets - the application then just has
   * to deal with a file-descriptor, rather than a socket.
   */

  if (!(s->app_rbuff))
    {
      if (!(s->app_rbuff = chain_init (BUFFER_SIZE)))
	goto SockAlloc_Failure;
    }

  if (!(s->app_sbuff))
    {
      if (!(s->app_sbuff = chain_init (BUFFER_SIZE)))
	goto SockAlloc_Failure;
    }


  /* Create our timers */
  sigprocmask (SIG_BLOCK, &alarmset, 0x0);           
  for (i = 0; i < TIMER_COUNT; i++)
    {
      if (!(s->otimers[i] = create_timer ((void *) timer_fn[i], s, 0, NULL,
					  NULL, i)))
	{
  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);           
	  SET_ERR (SCPS_ENOBUFS);
	  return (-1);
	}
    }
  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);           

  s->rcvwin = s->app_rbuff->max_size - 1;

  s->rttbest = 0;

#ifdef OPT_SCALE
  s->sockFlags |= TF_REQ_SCALE;	/* say we'll scale our windows */
  s->request_r_scale = 0;
  while ((s->request_r_scale < TP_MAX_WINSHIFT) &&
	 ((TP_MAXWIN << s->request_r_scale) < s->app_rbuff->max_size))
    s->request_r_scale++;
#endif /* OPT_SCALE */

  s->mbuff_fails = 0;
  s->cb_datin_fails = 0;

#ifndef GATEWAY_SINGLE_THREAD
  tpthread = get_thread (tp);
  if (tpthread->status > Ready)
    {
      tpthread->status = Ready;
      /* scheduler.num_runable++; */
    }
#endif /* GATEWAY_SINGLE_THREAD */
  s->thread = scheduler.current;

  s->Initialized = SCPSTP;
  s->next = tp_allsocs;
  if (s->next)
    s->next->prev = s;
  s->prev = NULL;

  tp_allsocs = s;
  return (s->sockid);

SockAlloc_Failure:
  /*
   * Give back any dynamic memory we grabbed so far...
   */

  if (s->scratch_buff)
    free_mbuff (s->scratch_buff);
  if (s->receive_buff)
    free (s->receive_buff);
  if (s->Out_Seq)
    free (s->Out_Seq);
  if (s->send_buff)
    free (s->send_buff);
  if (s->app_sbuff) {
    while ((mbcluster = deq_mclus (s->app_sbuff))) {
	mbcluster->c_count = 1;
	free_mclus (mbcluster);
    }
    free (s->app_sbuff);
  }
  if (s->app_rbuff) {
    while ((mbcluster = deq_mclus (s->app_rbuff)))
	mbcluster->c_count = 1;
        free_mclus (mbcluster);
    free (s->app_rbuff);
  }

  scheduler.sockets[s->sockid].ptr = 0x0;
//  printf ("Not enough memory to establish a new socket %d.\n", s->sockid);
  SET_ERR (SCPS_ENOMEM);
  return (-1);
}

/*
 * Unthread a TP socket from the socket list, if it's there
 */
void
tp_Unthread (tp_Socket * ds)
{
  int i;
  tp_Socket *s, **sp;
  struct mbcluster *mbcluster;

  ds->Initialized = 0;
  sp = &tp_allsocs;

  scheduler.sockets[ds->sockid].ptr = NULL;

  for (;;)
    {
      s = *sp;
      if (s == ds)
	{

	  /*
	   * We deallocate any mbuffs & clusters still owned by
	   * the socket prior to unthreading the socket from
	   * tp_allsocs. Note: At this point if we are closing
	   * normally, There should not be anything left there
	   * anyway!
	   */

	  kill_bchain (ds->send_buff->start);
	  kill_bchain (ds->receive_buff->start);
	  kill_bchain (ds->Out_Seq->start); 

	  s->state = tp_StateCLOSED;
          sigprocmask (SIG_BLOCK, &alarmset, 0x0);
	  /* Delete all our timers */
	  for (i = 0; i < TIMER_COUNT; i++) {
	    delete_timer (s->otimers[i], 0);
 	  }
          sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);

	  /*
	   * Any data still in clusters should either be freed
	   * by the kill_bchain() calls, are it is being
	   * retained by the application (through the reference
	   * counts)
	   *
	   * Except for the cases where the initial cluster provided
	   * by chain_init is never used!
	   */

  if (ds->app_rbuff) {
    while ((mbcluster = deq_mclus (ds->app_sbuff))) {
      mbcluster->c_count = 1;
      free_mclus (mbcluster);
    }
  }

  if (ds->app_rbuff) {
    while ((mbcluster = deq_mclus (ds->app_rbuff))) {
      mbcluster->c_count = 1;
      free_mclus (mbcluster);
    }
  }

	  /* Remove our buffer structures */
	  free (ds->receive_buff);
	  free (ds->send_buff);
	  free (ds->app_sbuff);
	  free (ds->app_rbuff);
	  free (ds->Out_Seq);
	  free_mbuff (ds->scratch_buff);

	  if (ds->hole_ptr)
	    free_mbuff (ds->hole_ptr);

	  /* Prevent use from trying to free a phantom cluster */
	  if (ds->scratch_buff)
         	  ds->scratch_buff->m_ext.offset = ds->scratch_buff->m_ext.len = 0;
	  /* free_mbuff(ds->scratch_buff); */
	  ds->scratch_buff = 0x0;
	  *sp = s->next;
	  /* Maintain the integrity of the prev pointer. */
	  if ( *sp && (*sp)->next ) (*sp)->next->prev = *sp;

	  if (*sp) {
		  if (s->prev) {
			s->prev->next = *sp;
		  }
          } else {
		  if (s->prev) {
			s->prev->next = NIL;
		  }
	  }

	  if (*sp) {
		  if (s->prev) {
		  	(*sp) ->prev = s->prev;
		  } else {
		  	(*sp) -> prev = NIL;
		  }
	  }

#ifdef FAIRER_GATEWAY
	  /* 
	   * When using the fair gateway, make sure that we don't leave a dangling
	   * pointer to a freed socket!
	   */
	  if ( start_s==ds ) {
	    start_s = ds->next?ds->next:tp_allsocs;
	  }
	  if ( init_s==ds ) {
	    init_s = ds->next?ds->next:tp_allsocs;
	  }
#endif /* FAIRER_GATEWAY */

#ifdef GATEWAY_SELECT
	  /*
	   * If gateway_select is on, we'd better get ourselves out of the
	   * readable/writable lists.  The important cases handled by these
	   * macros is when ds is the head of the read or write queue.
	   */
	  REMOVE_READ(ds);
	  REMOVE_WRITE(ds);
#endif /* GATEWAY_SELECT */

	  /*
	   * If this socket is unlucky enough to be on the queue of partially connected
	   * sockets or the queue of connected sockets listening for accept, we have
	   * to get him off.
	   */
	  if ( ds->qhead ) {
	    /*
	     * Unlink myself from the partially connected and fully connected
	     * lists of my qhead.  Note that q0 is the forward pointer for the
	     * partially connected list and q is the forward pointer for the
	     * fully connected list.
	     */
	    if ( ds->q0 ) ds->q0->q = ds->q;
	    if ( ds->q ) ds->q->q0 = ds->q0;
	    if ( ds->qhead->q0 == ds ) {
	      ds->qhead->q0 = ds->q0;
	    }
	    if ( ds->qhead->q == ds ) {
	      ds->qhead->q = ds->q;
	    }
#ifdef GATEWAY
	    tp_Abort(ds->qhead->sockid);
#endif /* GATEWAY */
	  } else {
	    /*
	     * When freeing a listening socket, kill off everything related to it.
	     */
	    if ( ds->state == tp_StateLISTEN ) {
	      while ( ds->q0 ) tp_Abort(ds->q0->sockid);
	      while (ds->q ) tp_Abort(ds->q->sockid);
	    } else {
              if (ds->q0) {
		printf ("q0 is set to something\n");
              }
              if (ds->q) {
		printf ("q is set to something\n");
              }
            }
	  }

#ifdef GATEWAY
          if ( (ds->peer_socket) && (ds->peer_socket->peer_socket == ds)) {
	      ds->peer_socket->peer_socket = 0x0;
         }
#endif /*  GATEWAY */

	  free (ds);
	  ds = NIL;

	  break;
	}
      if (s == NIL)
	break;
      sp = &s->next;
    }
  Validate_Thread ();
}

/*
 * Send pending TP data
 */
int
tp_Flush (tp_Socket * s)
{
  struct mbuff *mbuffer = NULL;
  int len;

  /*
   * Note: this is a dumb thing, check to see whether 
   * we check the send_buff.start, send_buff.snd_una 
   * or send_buff.send as the test...
   */

  /* if there is pending data, send it... but don't 
   * bother to even allocate an mbuffer if the read_head 
   * is NULL (no data to send)
   */

  /* if (((s->send_buff->start) && (s->app_sbuff->read_head) &&  */
  if (((s->app_sbuff->read_head) &&
       (s->send_buff->b_size < s->send_buff->max_size)) ||
      (s->state == tp_StateWANTTOLAST) ||
      (s->state == tp_StateWANTTOCLOSE))
    {
      /* We can enqueue data to go out, give it  a shot */

      if (s->app_sbuff->size > 0)
	{

	  s->flags |= tp_FlagPUSH;

	  /* While we can enqueue another mbuff, allocate 
	   * another mbuff AND we can attach data to an 
	   * mbuff, build a header and enqueue it to go 
	   * out. Continue until we fail. 
	   */

	  while ((s->send_buff->b_size < s->send_buff->max_size) &&
		 (mbuffer = alloc_mbuff (MT_HEADER)) &&
		 ((len = mcput (mbuffer, s->app_sbuff->read_head,
				s->app_sbuff->read_off,
				s->maxdata, 1)) > 0))
	    {
	      if (len < s->maxdata)
		{
		  write_align (s->app_sbuff, 0, 1);
		  mbuffer->m_flags |= M_RUNT;
		}

	      tp_BuildHdr (s, mbuffer, 1);
	      enq_mbuff (mbuffer, s->send_buff);
	      read_align (s->app_sbuff, len, 1);
	      s->app_sbuff->size -= len;
	      s->app_sbuff->run_length -= len;
	      if (!(s->send_buff->send))
		s->send_buff->send = s->send_buff->last;
	    }
	}

      else
	mbuffer = alloc_mbuff (MT_HEADER);

      /* If we failed because we couldn't grab an mbuff, 
       * there is no point in even considering whether 
       * or not a FIN needs to go out.
       */

      if (!(mbuffer))
	{
	  SET_ERR (SCPS_ENOBUFS);
	  return (-1);
	}

      /* If we're here, we've got an mbuffer so we we've 
       * managed to enqueue all our data to send. Build 
       * a FIN if necessary.
       */
      if ((s->state == tp_StateWANTTOCLOSE) ||
	  (s->state == tp_StateWANTTOLAST))
	{

	  if (s->send_buff->b_size >= s->send_buff->max_size)
	    {
	      free_mbuff (mbuffer);
	      SET_ERR (SCPS_ENOMEM);
	      return (-1);
	    }

	  /*
	   * Must allocate mbuffer before calling tp_BuildHdr 
	   * and pass it in.  This is a hack to say that this 
	   * segment will be queued for transmission, not sent 
	   * immediately.  As a result, the maximum sequence 
	   * number BUILT, not SENT should be used.  (If this 
	   * were an ACK, we would allow tp_BuildHdr to allocate 
	   * the mbuffer, and use the sequence number most 
	   * recently SENT in the header.)
	   */

	  s->flags = tp_FlagACK | tp_FlagFIN;
	  s->lastack = s->acknum;

	  s->lastuwe = s->acknum + s->rcvwin;
	  /* s->sockFlags &= ~SOCK_DELACK; */

	  (void) tp_BuildHdr (s, mbuffer, 0);
	  enq_mbuff (mbuffer, s->send_buff);
	  if (!(s->send_buff->send))
	    s->send_buff->send = s->send_buff->last;
	  if (s->state == tp_StateWANTTOCLOSE)
	    {
	      s->state_prev = s->state;
	      s->state = tp_StateFINWT1PEND;
	      PRINT_STATE (s->state, s);
	    }
	  else
	    {
	      s->state_prev = s->state;
	      s->state = tp_StateLASTACKPEND;
	      PRINT_STATE (s->state, s);
	    }
	}
      else
	free_mbuff (mbuffer);

      tp_NewSend (s, NULL, false);
    }
  return (0);
}

void
tp_WinAck (tp_Socket * s, tp_Header * th)
{
  uint32_t long_temp;

  th->acknum = htonl (s->acknum);
  long_temp = s->rcvwin;

  if ((long_temp < (uint32_t) (s->app_rbuff->max_size / 4)) &&
      (long_temp < (uint32_t) (s->maxseg)))
    long_temp = 0;
  if (long_temp > (uint32_t) (TP_MAXWIN << s->rcv_scale))
    long_temp = (uint32_t) (TP_MAXWIN << s->rcv_scale);
  if (long_temp < (uint32_t) (s->lastuwe - s->acknum))
    long_temp = (uint32_t) (s->lastuwe - s->acknum);

#ifdef GATEWAY
#ifdef GATEWAY_DEBUG
  printf ("In tp_WinAck Peer socket = %x\n", (s->peer_socket));
#endif /* GATEWAY_DEBUG */
  if ((s) &&
      (s->gateway_flags & GATEWAY_PEER_WIN_NOT_OPENED))
    {
      long_temp = 0;
    }
#endif /* GATEWAY */

  /*
   * This is to prevent being bitten by Little Endian 
   * machines when we want to advertise a window greater 
   * than 65535, but we don't have window-scaling option 
   * available 
   */
  if ((long_temp > 0xFFFF) && (!(s->rcv_scale)))
    {
      th->window = 0xFFFF;
    }
  else
    {
      th->window = htons ((u_short) (long_temp >> s->rcv_scale));
    }
}

void
Validate_Thread (void)
{
  tp_Socket *s;

  /*
   * If the only sockets on allsocs are now Routing sockets, 
   * and we want to terminate if tp_is_running = 1;
   */

  for (s = tp_allsocs; s; s = s->next)
    {
      if (s->Initialized == SCPSTP)
	return;
    }

  for (s = (tp_Socket *) udp_allsocs; s; s = s->next)
    {
      if (s->Initialized == SCPSUDP)
	return;
    }

  tp_is_running = 0;
  return;
}

void
tp_quench (tp_Socket * s)
{
  s->snd_cwnd = s->maxseg;
  s->snd_prevcwnd = s->maxseg;
  s->snd_ssthresh = 2 * s->maxseg;
  s->sockFlags &= ~TF_CC_LINEAR;
}

void
tp_notify (int type, scps_np_rqts * rqts, tp_Header * tp)
{
  tp_Socket *s;
  int source = 0;
  int dest = 0;

  /* Walk the socket list to see which socket this message applies */
  for (s = tp_allsocs; ((s) && (!(source)) && (!(dest))); s = s->next)
    {
      if ((s->np_rqts.ipv4_dst_addr == rqts->ipv4_dst_addr) &&
	  (s->np_rqts.ipv4_src_addr == rqts->ipv4_src_addr) &&
	  (s->myport == tp->srcPort) && (s->hisport == tp->dstPort))
	source = 1;
      else if ((s->np_rqts.ipv4_dst_addr == rqts->ipv4_src_addr) &&
	       (s->np_rqts.ipv4_src_addr == rqts->ipv4_dst_addr) &&
	       (s->myport == tp->dstPort) && (s->hisport == tp->srcPort))
	dest = 1;
    }

  if (!(source || dest))
    return;

  switch (type)
    {

    case SCMP_SOURCEQUENCH:
      tp_quench (s);
      break;

    case SCMP_CORRUPT:
      break;

    default:
      break;
    }
}
