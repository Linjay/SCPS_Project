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
#include "scpstp.h"
#include "scpserrno.h"
#include "tp_debug.h"
#include "gateway.h"
#include <stdio.h>
#include <math.h>
#include "../include/route.h"


#ifdef SCPSSP
#include "scps_sp.h"
#endif /* SCPSSP */

#ifdef GATEWAY_ROUTER
#include "rt_alloc.h"
#endif /* GATEWAY_ROUTER */

#include "scps_ip.h"
#include "scps_np.h"
int scps_np_get_template (scps_np_rqts * rqts,
			  scps_np_template * templ);

#ifdef GATEWAY
extern void *memset (void *s, int c, size_t n);
#include "rs_config.h"
extern GW_ifs gw_ifs;
int init_port_number_offset;
extern route *def_route;
extern route *other_route;
#endif /* GATEWAY */

#ifdef Sparc
#ifndef SOLARIS
extern int gettimeofday (struct timeval *tp, struct timezone *tzp);
#endif /* SOLARIS */
#endif /* Sparc */

extern struct _interface *sock_interface;
extern struct _interface *divert_interface;

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_handler.c,v $ -- $Revision: 1.75 $\n";
#endif

extern tp_Socket *tp_allsocs;	/* Pointer to first TP socket */
extern uint32_t tp_now;
extern struct timeval end_time;
extern float elapsed_time;
extern int delayed_requested;
int delayed_sent;
extern short tp_id;
extern int cluster_check;

struct _ll_queue_element *in_data;      /* packet buffer */

int abs (int i);		/* test function prototype */

int
tp_CompressedHandler (scps_np_rqts * rqts, int len, tp_Header * tp)
{
#ifdef OPT_COMPRESS
  tp_Socket *s;
  tp_PseudoHeader ph;
  byte *cp;
  word cks;
  byte remote_conn_id;
  short tp_hdr_len;
  int chl;
  int rc;

  cp = (byte *) tp;
  remote_conn_id = *cp++;

  /* demux to active sockets */
  for (s = tp_allsocs; s; s = s->next)
    {
      if (((s->nl_protocol_id == NL_PROTOCOL_IPV4) &&
          ((htonl (rqts->ipv4_src_addr) == s->his_ipv4_addr))) ||

          ((s->nl_protocol_id == NL_PROTOCOL_NP) &&
          ((htonl (rqts->ipv4_src_addr) == s->his_ipv4_addr))) ||

          ((s->nl_protocol_id == NL_PROTOCOL_IPV6) &&
          (memcmp (&(rqts->ipv6_src_addr), &(s->his_ipv6_addr), sizeof (struct ipv6_addr))))) {

                break;
      }
    }
  if (s == NIL)
    {
      return (0);
    }

  if (rqts->nl_protocol == NL_PROTOCOL_IPV4) {
        ph.nl_head.ipv4.src = htonl (rqts->ipv4_src_addr);
        ph.nl_head.ipv4.dst = htonl (rqts->ipv4_dst_addr);
        ph.nl_head.ipv4.mbz = 0;
                /* pseudo header checksum still assumes TP */
        ph.nl_head.ipv4.protocol = SCPSTP;
        ph.nl_head.ipv4.length = htons (len);
        ph.nl_head.ipv4.checksum = checksum ((word *) tp, ntohs (ph.nl_head.ipv4.length));
         cks = checksum ((word *) & ph.nl_head.ipv4, 14);
  if (cks != 0xffff)
    {
        /* Cksum failed with protocol SCPSTP - Let's try SCPSCTP */
         ph.nl_head.ipv4.protocol = SCPSCTP;
         cks = checksum ((word *) & ph, 14);
         if (cks != 0xffff) {
             printf ("%s %d Checkum failure \n",__FILE__, __LINE__);
             return (0);                /* Disregard on checksum failure */
         }
    }
  }
  if (rqts->nl_protocol == NL_PROTOCOL_IPV6) {
        ntoh16 (ph.nl_head.ipv6.src.addr, rqts->ipv6_src_addr.addr);
        ntoh16 (ph.nl_head.ipv6.dst.addr, rqts->ipv6_dst_addr.addr);
        ph.nl_head.ipv6.mbz1 = 0;
        ph.nl_head.ipv6.mbz2 = 0;
        ph.nl_head.ipv6.mbz3 = 0;
                /* pseudo header checksum still assumes TP */
        ph.nl_head.ipv6.protocol = SCPSTP;
        ph.nl_head.ipv6.length = htonl (((long) len));
        ph.nl_head.ipv6.checksum = checksum ((word *) tp, len);
        cks = checksum ((word *) & ph.nl_head.ipv6, 42);
  if (cks != 0xffff)
    {
        /* Cksum failed with protocol SCPSTP - Let's try SCPSCTP */
         ph.nl_head.ipv6.protocol = SCPSCTP;
         cks = checksum ((word *) & ph, 42);
         if (cks != 0xffff) {
             printf ("%s %d Checkum failure \n",__FILE__, __LINE__);
             return (0);                /* Disregard on checksum failure */
         }
    }
  }


  chl = tp_Uncompress (s, cp);
  tp_hdr_len = s->in_th.th_off << 2;
  len -= chl;			/* Don't want the compressed header with data */

  rc = tp_CommonHandler (s, rqts, &(s->in_th), (((byte *) tp) + chl), len);
#else /* OPT_COMPRESS */
  /* Empty body */
#endif /* OPT_COMPRESS */
  return (0);
}

/*
 * Handler for incoming TP packets.
 */
void
tp_Handler (scps_np_rqts * rqts, int len, tp_Header * tp)
{
  tp_PseudoHeader ph;
  tp_Socket *s;
  int tp_header_len = 0;
  int odd_aligned = 0;
  char ugly[60];
  byte *data = NULL;
  int rc;

#ifdef GATEWAY
  int s1 = -1;
  int s2 = -1;
  struct sockaddr_in dst;
  struct sockaddr_in src;
  struct sockaddr_in6 dst6;
  struct sockaddr_in6 src6;
  tp_Socket *active_s = NULL;
  int reset_now = 0;
  int close_s1 = 0;

#endif /* GATEWAY */

  if (rqts->nl_protocol == NL_PROTOCOL_NP) {
        ph.nl_head.ipv4.src = htonl (rqts->ipv4_src_addr);
        ph.nl_head.ipv4.dst = htonl (rqts->ipv4_dst_addr);
        ph.nl_head.ipv4.mbz = 0;
                /* pseudo header checksum still assumes TP */
        ph.nl_head.ipv4.protocol = SCPSTP;
        ph.nl_head.ipv4.length = htons (len);
        ph.nl_head.ipv4.checksum = checksum ((word *) tp, ntohs (ph.nl_head.ipv4.length));
  if (checksum ((word *) & ph, 14) != 0xffff)
    {
      for (s = tp_allsocs; s; s = s->next)
        if (s->hisport != 0 &&
            tp->dstPort == s->myport &&
            tp->srcPort == s->hisport &&
            htonl (rqts->ipv4_src_addr) == s->his_ipv4_addr)
          {
            break;
          }
      syslog (LOG_ERR,"gateway: %s BAD CHECKSUM on seq num abs(%u) rel(%lu) %u %x %x \n",
#ifdef DEBUG_GATEWAY
              (s) ? printPorts (s) : "????",
#else /* DEBUG_GATEWAY */
              "m(?) h(?)",
#endif /* DEBUG_GATEWAY */
              (unsigned int) (htonl (tp->seqnum)),
              (unsigned int) (htonl (tp->seqnum)) - ((s) ? s->initial_seqnum
                                                     : 0),
              len,
              (unsigned int) rqts->ipv4_src_addr, (unsigned int) rqts->ipv4_dst_addr);
      return;
    }
  }
  if (rqts->nl_protocol == NL_PROTOCOL_IPV4) {
        ph.nl_head.ipv4.src = htonl (rqts->ipv4_src_addr);
        ph.nl_head.ipv4.dst = htonl (rqts->ipv4_dst_addr);
        ph.nl_head.ipv4.mbz = 0;
                /* pseudo header checksum still assumes TP */
        ph.nl_head.ipv4.protocol = SCPSTP;
        ph.nl_head.ipv4.length = htons (len);
        ph.nl_head.ipv4.checksum = checksum ((word *) tp, ntohs (ph.nl_head.ipv4.length));
  if (checksum ((word *) & ph, 14) != 0xffff)
    {
      for (s = tp_allsocs; s; s = s->next)
        if (s->hisport != 0 &&
            tp->dstPort == s->myport &&
            tp->srcPort == s->hisport &&
            htonl (rqts->ipv4_src_addr) == s->his_ipv4_addr)
          {
            break;
          }
      syslog (LOG_ERR,"gateway: %s BAD CHECKSUM on seq num abs(%u) rel(%lu) %u %x %x \n",
#ifdef DEBUG_GATEWAY
              (s) ? printPorts (s) : "????",
#else /* DEBUG_GATEWAY */
              "m(?) h(?)",
#endif /* DEBUG_GATEWAY */
              (unsigned int) (htonl (tp->seqnum)),
              (unsigned int) (htonl (tp->seqnum)) - ((s) ? s->initial_seqnum
                                                     : 0),
              len,
              (unsigned int) rqts->ipv4_src_addr, (unsigned int) rqts->ipv4_dst_addr);
      return;
    }

  }

  if (rqts->nl_protocol == NL_PROTOCOL_IPV6) {
        hton16 (ph.nl_head.ipv6.src.addr, rqts->ipv6_src_addr.addr);
        hton16 (ph.nl_head.ipv6.dst.addr, rqts->ipv6_dst_addr.addr);

        memcpy (ph.nl_head.ipv6.src.addr, rqts->ipv6_src_addr.addr, 16);
        memcpy (ph.nl_head.ipv6.dst.addr, rqts->ipv6_dst_addr.addr, 16);

        ph.nl_head.ipv6.mbz1 = 0;
        ph.nl_head.ipv6.mbz2 = 0;
        ph.nl_head.ipv6.mbz3 = 0;
                /* pseudo header checksum still assumes TP */
        ph.nl_head.ipv6.protocol = SCPSTP;
        ph.nl_head.ipv6.length = htonl (((longword) len));
        ph.nl_head.ipv6.checksum = checksum ((word *) tp, len);
  if (checksum ((word *) & ph, 42) != 0xffff)
    {
      for (s = tp_allsocs; s; s = s->next)
        if (s->hisport != 0 &&
            tp->dstPort == s->myport &&
            tp->srcPort == s->hisport &&
            memcmp (&(rqts->ipv6_src_addr.addr), &(s->his_ipv6_addr.addr) , sizeof (struct ipv6_addr)))
          {
            break;
          }
      syslog (LOG_ERR,"gateway: %s BAD CHECKSUM on seq num abs(%u) rel(%lu) %u %x %x \n",
#ifdef DEBUG_GATEWAY
              (s) ? printPorts (s) : "????",
#else /* DEBUG_GATEWAY */
              "m(?) h(?)",
#endif /* DEBUG_GATEWAY */
              (unsigned int) (htonl (tp->seqnum)),
              (unsigned int) (htonl (tp->seqnum)) - ((s) ? s->initial_seqnum
                                                     : 0),
              len,
              (unsigned int) rqts->ipv4_src_addr, (unsigned int) rqts->ipv4_dst_addr);
      return;
    }

  }

  if ((int) tp & (sizeof (int) - 1))	/* must align xport hdr */
    {
      odd_aligned = 1;
      /* Reach in and get tp header length */
      tp_header_len = ((u_char) (*(((char *) tp) + 12)) & 0xF0) >> 2;
      memcpy (ugly, (char *) tp, tp_header_len);
      data = ((char *) tp + tp_header_len);
      tp = (tp_Header *) ugly;
    }
  /* demux to active sockets */

  for (s = tp_allsocs; s; s = s->next) {

   if ( ((rqts->nl_protocol == NL_PROTOCOL_NP) &&
         (s->nl_protocol_id == NL_PROTOCOL_NP)) ||
        ((rqts->nl_protocol == NL_PROTOCOL_IPV4) &&
         (s->nl_protocol_id == NL_PROTOCOL_IPV4))) {

    if (s->hisport != 0 &&
	tp->dstPort == s->myport &&
	tp->srcPort == s->hisport &&
	(htonl (rqts->ipv4_src_addr) == s->his_ipv4_addr))
      {
	break;
      }
  } 

   if ((rqts->nl_protocol == NL_PROTOCOL_IPV6) &&
       (s->nl_protocol_id == NL_PROTOCOL_IPV6)) {
    if (s->hisport != 0 &&
        tp->dstPort == s->myport &&
        tp->srcPort == s->hisport &&
        (!memcmp (&(rqts->ipv6_src_addr.addr),
                &(s->his_ipv6_addr.addr),
                 sizeof (struct ipv6_addr))))
      {
        break;
      }


   }
  }

  if (s == NIL)
    {

      /* demux to passive sockets */

      for (s = tp_allsocs; s; s = s->next)
        {
          if (((s->hisport == 0) && (tp->dstPort == s->myport))
#ifdef GATEWAY
        && (!memcmp (&(rqts->ipv6_dst_addr),
                &(s->my_ipv6_addr.addr),
                 sizeof (struct ipv6_addr)))
#endif /* GATEWAY */
            )
            {
              break;
            }
        }
    }

  if (s == NIL)
    {

      /* demux to passive sockets */

      for (s = tp_allsocs; s; s = s->next)
	{
	  if (((s->hisport == 0) && (tp->dstPort == s->myport))
#ifdef GATEWAY
	      && (htonl (rqts->ipv4_dst_addr) == s->my_ipv4_addr)
#endif /* GATEWAY */
	    )
	    {
	      break;
	    }
	}
    }

  if ((s) && (s->Initialized == 0))
    {
      printf ("Demuxed to an initialized socket %p %d\n", s, s->state);
      fflush (stdout);
    }


  if (s == NIL)
    {
#ifdef GATEWAY

#ifdef DEBUG_GATEWAY
      printf ("Failed demuxing, must do it myself\n");
#endif /* DEBUG_GATEWAY */
      if (tp->flags & tp_FlagRST)
	{
	  return;
	}

      if ((!(tp->flags & tp_FlagSYN)) ||
	  (tp->flags & tp_FlagACK))
	{

	  reset_now = 1;
	}

#ifdef GATEWAY_STRICT
      {
	int total_needed = 0;

	total_needed += (ceil (BUFFER_SIZE / SMCLBYTES)) * 2;
	total_needed += (ceil (size / SMCLBYTES)) * 4;

	if (total_needed + sys_memory.clust_promised >
	    sys_memory.fclist.max_size)
	  {
	    syslog (LOG_ERR, "Gateway: out of system resources %d %d %ld\n",
		    total_needed, sys_memory.clust_promised, sys_memory.fclist.max_size);
#ifdef DEBUG_MEMORY2
	    printf ("OUT OF SYSTEM RESOURCES %d %ld %ld\n",
		    total_needed, sys_memory.clust_promised, sys_memory.fclist.max_size);
#endif /* DEBUG_MEMORY2 */
            cluster_check = 0;
            if ((s1 = scps_socket (AF_INET, SOCK_STREAM, 0)) == -1) {
             cluster_check = 1;
	     return;
	    }

            s = (tp_Socket *) scheduler.sockets[s1].ptr;
            s->ph.src = htonl (rqts->dst_addr);

      	    memset ((char *) &dst, 0, sizeof (dst));
#ifndef LINUX
	    dst.sin_len = sizeof (dst);
#endif /* LINUX */
	    dst.sin_family = AF_INET;
	    dst.sin_addr.s_addr = htonl (rqts->dst_addr);
	    dst.sin_port = tp->dstPort;

            if ((rc = scps_bind (s1, (struct sockaddr *) &dst,
                              sizeof (dst))) == -1) {
	     scps_close (s1);
             cluster_check = 1;
	     return;
    	    }

	    memcpy (&(s->hisaddr), &(rqts->src_addr), sizeof (uint32_t));
	    memcpy (&(s->hisport), &(tp->srcPort), sizeof (u_short));
	    gateway_reset (s1, rqts, tp);
            cluster_check = 1;
	    return;
	  }
      }
#endif /* GATEWAY_STRICT */

#ifdef GATEWAY
	if ((gw_ifs.c_clust_thresh) &&
            (sys_memory.clust_in_use > gw_ifs.c_clust_thresh)) {
        	struct stat sb;

	        if ((stat (gw_ifs.c_clust_filename, &sb)) < 0) {
       		} else {
	                syslog (LOG_ERR, "Gateway: not allowing any more connection\n");
       	        	reset_now = 1;
	        }    
	}
#endif /* GATEWAY */

      if ((sys_memory.clust_in_use  + 20  >
            sys_memory.fclist.max_size) || (reset_now) )
          {
	    syslog (LOG_ERR, "Gateway: Connection being reset %d %d %d\n",
		    20, sys_memory.clust_promised, sys_memory.fclist.max_size);
#ifdef DEBUG_MEMORY2
            printf ("OUT OF SYSTEM RESOURCES %d %ld %ld\n",
                    20, sys_memory.clust_in_use, sys_memory.fclist.max_size);
#endif /* DEBUG_MEMORY2 */
            cluster_check = 0;
            if ((s1 = scps_socket (AF_INET, SOCK_STREAM, 0)) == -1) {
             cluster_check = 1;
	     return;
	    }

            s = (tp_Socket *) scheduler.sockets[s1].ptr;
            s->ph.nl_head.ipv4.src = htonl (rqts->ipv4_dst_addr);
            s->ph.nl_head.ipv4.dst = htonl (rqts->ipv4_src_addr);

      	    memset ((char *) &dst, 0, sizeof (dst));
#ifndef LINUX
	    dst.sin_len = sizeof (dst);
#endif /* LINUX */
	    dst.sin_family = AF_INET;
	    dst.sin_addr.s_addr = htonl (rqts->ipv4_dst_addr);
	    dst.sin_port = tp->dstPort;

            if ((rc = scps_bind (s1, (struct sockaddr *) &dst,
                              sizeof (dst))) == -1) {
	     scps_close (s1);
             cluster_check = 1;
	     return;
    	    }

	    memcpy (&(s->his_ipv4_addr), &(rqts->ipv4_src_addr), sizeof (u_long));
	    memcpy (&(s->hisport), &(tp->srcPort), sizeof (u_short));

#ifdef TAP_INTERFACE
      memcpy (&(s->src_mac_addr [0]), &(rqts->dst_mac_addr [0]),6);
      memcpy (&(s->dst_mac_addr [0]), &(rqts->src_mac_addr [0]),6);

      s->frame_type = rqts->frame_type;
      s->recv_tap_if = rqts->recv_tap_if;
#endif /* TAP_INTERFACE */

	    gateway_reset (s1, rqts, tp);
            cluster_check = 1;
            return;
          }

/* First Create passive socket */
#ifndef IPV6
      memset ((char *) &dst, 0, sizeof (dst));
#ifndef LINUX
      dst.sin_len = sizeof (dst);
#endif /* LINUX */
      dst.sin_family = AF_INET;
      dst.sin_addr.s_addr = htonl (rqts->ipv4_dst_addr);
      dst.sin_port = tp->dstPort;

      if ((s1 = scps_socket (AF_INET, SOCK_STREAM, 0)) == -1)
	{
          syslog (LOG_ERR, "Gateway: not allowing any more connection ss1\n");
	  return;
	}

      s = (tp_Socket *) scheduler.sockets[s1].ptr;
      s->ph.nl_head.ipv4.src = htonl (rqts->ipv4_dst_addr);

      if ((rc = scps_bind (s1, (struct sockaddr *) &dst, sizeof (dst))) ==
	  -1)
	{
          syslog (LOG_ERR, "Gateway: not allowing any more connection sb1\n");
	  scps_close (s1);
	  return;
	}
#else /* IPV6 */
        if (rqts->nl_protocol == NL_PROTOCOL_IPV4) {
      memset ((char *) &dst, 0, sizeof (dst));
#ifndef LINUX
      dst.sin_len = sizeof (dst);
#endif /* LINUX */
      dst.sin_family = AF_INET;
      dst.sin_addr.s_addr = htonl (rqts->ipv4_dst_addr);
      dst.sin_port = tp->dstPort;

      if ((s1 = scps_socket (AF_INET, SOCK_STREAM, 0)) == -1)
        {
          syslog (LOG_ERR, "Gateway: not allowing any more connection ss1\n");
          return;
        }

      s = (tp_Socket *) scheduler.sockets[s1].ptr;
      s->ph.nl_head.ipv4.src = htonl (rqts->ipv4_dst_addr);

      if ((rc = scps_bind (s1, (struct sockaddr *) &dst, sizeof (dst))) ==
          -1)
        {
          syslog (LOG_ERR, "Gateway: not allowing any more connection sb1\n");
          scps_close (s1);
          return;
        }

      }
        if (rqts->nl_protocol == NL_PROTOCOL_IPV6) {
      memset ((char *) &dst6, 0, sizeof (dst6));
#ifndef LINUX
      dst6.sin6_len = sizeof (dst6);
#endif /* LINUX */
      dst6.sin6_family = AF_INET;
      hton16 (dst6.sin6_addr.s6_addr, rqts->ipv6_dst_addr.addr);
      dst6.sin6_port = tp->dstPort;

      if ((s1 = scps_socket (AF_INET6, SOCK_STREAM, 0)) == -1)
        {
          syslog (LOG_ERR, "Gateway: not allowing any more connection (ipv6) ss1\n");
          return;
        }

      s = (tp_Socket *) scheduler.sockets[s1].ptr;
      hton16 (s->ph.nl_head.ipv6.src.addr, rqts->ipv6_dst_addr.addr);

      if ((rc = scps_bind (s1, (struct sockaddr *) &dst6, sizeof (dst6))) ==
          -1)
        {
          syslog (LOG_ERR, "Gateway: not allowing any more connection (ipv6) sb1\n");
          scps_close (s1);
          return;
        }

      }
#endif /* IPV6 */

#ifdef GATEWAY_DUAL_INTERFACE 
      s->gateway_layering = in_data->layering;
      s->special_udp_port = in_data->special_udp_port;
      s->special_ip_addr = in_data->special_ip_addr;
#endif /* GATEWAY_DUAL_INTERFACE  */

#ifdef TAP_INTERFACE
      memcpy (&(s->src_mac_addr [0]), &(rqts->dst_mac_addr [0]),6);
      memcpy (&(s->dst_mac_addr [0]), &(rqts->src_mac_addr [0]),6);

      s->frame_type = rqts->frame_type;
      s->recv_tap_if = rqts->recv_tap_if;
#endif /* TAP_INTERFACE */

#ifdef GATEWAY
        s->DSCP = rqts->DSCP; 
	s->np_rqts.DSCP = rqts->DSCP;
#endif /* GATEWAY */

      tp_mss (s, 0);		/* provisional mss setup */
      gateway_set_options (s->sockid, rqts->divert_port_number, 0);
      s->state_prev = tp_StateCLOSED;	/* Might have been tp_StateNASCENT */
      s->state = tp_StateLISTEN;

      s->timeout = 0x7ffffff;	/* forever... */

//      clear_timer (s->otimers[Rexmit], 1); PDF XXX WHY IS THIS HERE
      s->hisport = 0;
#ifndef IPV6 /* XXXXX */
      s->ph.nl_head.ipv4.dst = 0;
#endif /* IPV6 */
      s->link_outage = 0;	/* forced for now */

/* Now create active socket */
      if (!reset_now)
#ifndef IPV6
	{

	  int initial_port;
	  int port_ok = 0;
	  tp_Socket *temp_socket;

	  memset ((char *) &src, 0, sizeof (src));
#ifndef LINUX
	  src.sin_len = sizeof (src);
#endif /* LINUX */
	  src.sin_family = AF_INET;
	  src.sin_addr.s_addr = htonl (rqts->ipv4_src_addr);

	  initial_port = tp->srcPort;
#ifdef CHANGE_SRC_PORT
	  initial_port = tp->srcPort + init_port_number_offset;

/* Make sure src port is ok to use */
	  while (!port_ok)
	    {
	      port_ok = 1;
	      if (tp_allsocs)
		{
		  for (temp_socket = tp_allsocs; temp_socket != NIL;
		       temp_socket = temp_socket->next)
		    {
		      if (initial_port == temp_socket->myport)
			{
			  port_ok = 0;
			}
		    }
		  if (!port_ok)
		    {
		      initial_port++;
		      if (initial_port > 64000)
			initial_port = init_port_number_offset;

		      if (initial_port == tp->srcPort +
			  init_port_number_offset)
			{
			  port_ok = 1;
			  close_s1 = 1;
			}
		    }
		}
	    }

#endif /* CHANGE_SRC_PORT */

	  src.sin_port = initial_port;
	  if ((s2 = scps_socket (AF_INET, SOCK_STREAM, 0)) == -1)
	    {
              syslog (LOG_ERR, "Gateway: not allowing any more connection ss2\n");
	      reset_now = 1;
	    }
	  else
	    {
	      active_s = (tp_Socket *) scheduler.sockets[s2].ptr;
	      active_s->ph.nl_head.ipv4.src = htonl (rqts->ipv4_src_addr);

	      if ((rc = scps_bind (s2, (struct sockaddr *) &src, sizeof
				   (src))) == -1)
		{
                  syslog (LOG_ERR, "Gateway: not allowing any more connection sb2\n");
		  close_s1 = 1;
		  scps_close (active_s->sockid);
		}
	      active_s->np_rqts.ipv4_src_addr = htonl (rqts->ipv4_src_addr);
	      gateway_set_options (active_s->sockid,
				   rqts->divert_port_number, 1);
#ifdef GATEWAY_DUAL_INTERFACE 
      active_s->special_udp_port = in_data->special_udp_port;
      active_s->special_ip_addr = in_data->special_ip_addr;
#endif /* GATEWAY_DUAL_INTERFACE  */
#ifdef TAP_INTERFACE
      memcpy (&(active_s->src_mac_addr [0]), &(rqts->src_mac_addr [0]),6);
      memcpy (&(active_s->dst_mac_addr [0]), &(rqts->dst_mac_addr [0]),6);
      active_s->frame_type = rqts->frame_type;
      active_s->recv_tap_if = rqts->peer_tap_if;
#endif /* TAP_INTERFACE */

#ifdef GATEWAY
        s->DSCP = rqts->DSCP; 
	active_s->DSCP = rqts->DSCP;
	active_s->np_rqts.DSCP = rqts->DSCP;
#endif /* GATEWAY */

	    }
	}

#else /* IPV6 */
        {
        if (rqts->nl_protocol == NL_PROTOCOL_IPV4) {
          int initial_port;
          int port_ok = 0;
          tp_Socket *temp_socket;

          memset ((char *) &src, 0, sizeof (src));
#ifndef LINUX
          src.sin_len = sizeof (src);
#endif /* LINUX */
          src.sin_family = AF_INET;
          src.sin_addr.s_addr = htonl (rqts->ipv4_src_addr);
          initial_port = tp->srcPort + init_port_number_offset;

/* Make sure src port is ok to use */
          while (!port_ok)
            {
              port_ok = 1;
              if (tp_allsocs)
                {
                  for (temp_socket = tp_allsocs; temp_socket != NIL;
                       temp_socket = temp_socket->next)
                    {
                      if (initial_port == temp_socket->myport)
                        {
                          port_ok = 0;
                        }
                    }
                  if (!port_ok)
                    {
                      initial_port++;
                      if (initial_port > 64000)
                        initial_port = init_port_number_offset;

                      if (initial_port == tp->srcPort +
                          init_port_number_offset)
                        {
                          port_ok = 1;
                          close_s1 = 1;
                        }
                    }
                }
            }

          src.sin_port = initial_port;
          if ((s2 = scps_socket (AF_INET, SOCK_STREAM, 0)) == -1)
            {
              syslog (LOG_ERR, "Gateway: not allowing any more connection ss2\n");
              reset_now = 1;
            }
          else
            {
              active_s = (tp_Socket *) scheduler.sockets[s2].ptr;
              active_s->ph.nl_head.ipv4.src = htonl (rqts->ipv4_src_addr);

              if ((rc = scps_bind (s2, (struct sockaddr *) &src, sizeof
                                   (src))) == -1)
                {
                  syslog (LOG_ERR, "Gateway: not allowing any more connection sb2\n");
                  close_s1 = 1;
                  scps_close (active_s->sockid);
                }
              active_s->np_rqts.ipv4_src_addr = htonl (rqts->ipv4_src_addr);
              gateway_set_options (active_s->sockid,
                                   rqts->divert_port_number, 1);
#ifdef GATEWAY_DUAL_INTERFACE
      active_s->special_udp_port = in_data->special_udp_port;
      active_s->special_ip_addr = in_data->special_ip_addr;
#endif /* GATEWAY_DUAL_INTERFACE  */
#ifdef TAP_INTERFACE
      memcpy (&(active_s->src_mac_addr [0]), &(rqts->src_mac_addr [0]),6);
      memcpy (&(active_s->dst_mac_addr [0]), &(rqts->dst_mac_addr [0]),6);
      active_s->frame_type = rqts->frame_type;
      active_s->recv_tap_if = rqts->peer_tap_if;
#endif /* TAP_INTERFACE */

#ifdef GATEWAY
        s->DSCP = rqts->DSCP;
        active_s->DSCP = rqts->DSCP;
        active_s->np_rqts.DSCP = rqts->DSCP;
#endif /* GATEWAY */

            }
        }

        if (rqts->nl_protocol == NL_PROTOCOL_IPV6) {
          int initial_port;
          int port_ok = 0;
          tp_Socket *temp_socket;

          memset ((char *) &src6, 0, sizeof (src6));
#ifndef LINUX
          src6.sin6_len = sizeof (src6);
#endif /* LINUX */
          src6.sin6_family = AF_INET;
          hton16 (src6.sin6_addr.s6_addr, rqts->ipv6_src_addr.addr);
          initial_port = tp->srcPort + init_port_number_offset;

/* Make sure src port is ok to use */
          while (!port_ok)
            {
              port_ok = 1;
              if (tp_allsocs)
                {
                  for (temp_socket = tp_allsocs; temp_socket != NIL;
                       temp_socket = temp_socket->next)
                    {
                      if (initial_port == temp_socket->myport)
                        {
                          port_ok = 0;
                        }
                    }
                  if (!port_ok)
                     {
                       initial_port++;
                       if (initial_port > 64000)
                         initial_port = init_port_number_offset;
 
                       if (initial_port == tp->srcPort +
                           init_port_number_offset)
                         {
                           port_ok = 1;
                           close_s1 = 1;
                         }
                     }
                 }       
             }

          src6.sin6_port = initial_port;
          if ((s2 = scps_socket (AF_INET6, SOCK_STREAM, 0)) == -1)
            {
              syslog (LOG_ERR, "Gateway: not allowing any more connection ss2\n");
              reset_now = 1;
            }
          else
            {
              active_s = (tp_Socket *) scheduler.sockets[s2].ptr;
              hton16 (active_s->ph.nl_head.ipv6.src.addr, rqts->ipv6_src_addr.addr);

              if ((rc = scps_bind (s2, (struct sockaddr *) &src6, sizeof
                                   (src6))) == -1)
                {
                  syslog (LOG_ERR, "Gateway: not allowing any more connection sb2\n");
                  close_s1 = 1;
                  scps_close (active_s->sockid);
                }
              hton16 (active_s->np_rqts.ipv6_src_addr.addr, rqts->ipv6_src_addr.addr);
              gateway_set_options (active_s->sockid,
                                   rqts->divert_port_number, 1);
#ifdef GATEWAY_DUAL_INTERFACE
      active_s->special_udp_port = in_data->special_udp_port;
      active_s->special_ip_addr = in_data->special_ip_addr;
#endif /* GATEWAY_DUAL_INTERFACE  */
#ifdef TAP_INTERFACE
      memcpy (&(active_s->src_mac_addr [0]), &(rqts->src_mac_addr [0]),6);
      memcpy (&(active_s->dst_mac_addr [0]), &(rqts->dst_mac_addr [0]),6);
      active_s->frame_type = rqts->frame_type;
      active_s->recv_tap_if = rqts->peer_tap_if;
#endif /* TAP_INTERFACE */

#ifdef GATEWAY
        s->DSCP = rqts->DSCP;
        active_s->DSCP = rqts->DSCP;
        active_s->np_rqts.DSCP = rqts->DSCP;
#endif /* GATEWAY */


            }
        }

        }
#endif /* IPV6 */

/* Now connect the two sockets */
      if ((!reset_now) && (!close_s1))
	{
	  s->peer_socket = (tp_Socket *) active_s;
	  s->gateway_flags |= GATEWAY_PEER_WIN_NOT_OPENED;
	  active_s->peer_socket = (tp_Socket *) s;

	  s->gateway_flags |= GATEWAY_SEND_SYN;
	}
      else
	{
	  if (close_s1)
	    {
              syslog (LOG_ERR, "Gateway: closing s1 - not enough resoures\n");
	      scps_close (s1);
	    }
	  if (reset_now)
	    {
              syslog (LOG_ERR, "Gateway: Reseting s1 - not enough resources\n");
	      gateway_reset (s1, rqts, tp);
	    }
	  return;
	}

/* Now do the accept which should just come naturally */
       gateway_double_check_parameters (s);
       gateway_double_check_parameters (active_s);

/* The end */

#else /* GATEWAY */
      return;
#endif /* GATEWAY */
    } else {
#ifdef TAP_INTERFACE
      memcpy (&(s->np_rqts.src_mac_addr [0]), &(rqts->dst_mac_addr [0]),6);
      memcpy (&(s->np_rqts.dst_mac_addr [0]), &(rqts->src_mac_addr [0]),6);
#endif /* TAP_INTERFACE */
}

  if (odd_aligned)
    {
      memcpy (&(s->in_th), ugly, tp_header_len);
      tp = (tp_Header *) & (s->in_th);
    }
  else
    {
      tp_header_len = tp->th_off << 2;
      data = ((byte *) tp + tp_header_len);
    }

#ifdef OPT_COMPRESS
  if (s->capabilities & CAP_COMPRESS)
    memcpy ((tp_Header *) & s->in_th, tp, ((tp->flags & tp_FlagDO) >> 10));
#endif /* OPT_COMPRESS */

  len -= tp_header_len;

/*
 * If you receive packets from a partcular route, the make sure the
 * interface is set to AVAILABLE.  This may cause problems when the
 * forward and return link are independent of each other.  - PDF
 */
  if (s->rt_route) s->rt_route->flags |= RT_LINK_AVAIL;

#ifdef GATEWAY
  if (s->state == tp_StateCLOSED)
    {
      gateway_reset (s->sockid, rqts, tp);
      return;
    }
#endif /* GATEWAY */

#ifdef GATEWAY
#ifndef STRICT_DSCP
    if (s->DSCP != rqts ->DSCP) {
        s->DSCP = rqts->DSCP; 
    }

    if ((s->peer_socket) && (s->peer_socket->DSCP != rqts ->DSCP)) {
        s->peer_socket->DSCP = rqts->DSCP; 
    }
#endif /* STRICT_DSCP */
#endif /* GATEWAY */

  rc = tp_CommonHandler (s, rqts, tp, data, len);

#ifdef GATEWAY
{
	struct stat sb;
	if (gw_ifs.c_pkt_io_filename[0] != '\0') {
		if ((stat (gw_ifs.c_pkt_io_filename, &sb)) < 0) {
		} else {
			syslog (LOG_ERR,"Gateway: return from CommonHandler %d %d\n",len, rc);
		}		
	}
}
#endif /* GATEWAY */

#ifdef GATEWAY
  switch (rc)
    {
    case 0:
      scps_close (s1);
      scps_close (s2);
      break;

    case -2:
      tp_Abort (s1);
      tp_Abort (s2);
      break;

    case -1:
      break;

    default:
      if ((s->gateway_flags & GATEWAY_SEND_SYN)  && (s2 > 0))
	{
	  s->gateway_flags &= (~GATEWAY_SEND_SYN);
          SET_ERR (0);
#ifndef IPV6
          rc = tp_Connect (s2, (void *) &dst, sizeof (dst));
#else /* IPV6 */
        if (rqts->nl_protocol == NL_PROTOCOL_IPV4) {
          rc = tp_Connect (s2, (void *) &dst, sizeof (dst));
        }
        if (rqts->nl_protocol == NL_PROTOCOL_NP) {
          rc = tp_Connect (s2, (void *) &dst, sizeof (dst));
        }
        if (rqts->nl_protocol == NL_PROTOCOL_IPV6) {
          rc = tp_Connect (s2, (void *) &dst6, sizeof (dst6));
        }
#endif /* IPV6 */
          if ((rc == -1) && (GET_ERR () != SCPS_EINPROGRESS)) {
            /* If you can complete the connection you must abort */
            tp_Abort (s1);
            tp_Abort (s2);
    
            return;
          }

        if ((s) && (active_s)) {
#ifdef GATEWAY_ROUTER
          route *tmp = active_s->peer_socket->rt_route;
 
#ifndef STRICT_DSCP
          if (active_s->peer_socket->DSCP != rqts ->DSCP) {
              active_s->peer_socket->DSCP = rqts->DSCP; 
  	  }
#endif /* STRICT_DSCP */

          if (!(active_s->peer_socket->rt_route = route_rt_lookup_s (active_s->
peer_socket))) {
                active_s->peer_socket->rt_route = tmp;
          }
 
          tmp = active_s->rt_route;
 
#ifndef STRICT_DSCP
          if (active_s->DSCP != rqts ->DSCP) {
              active_s->DSCP = rqts->DSCP; 
  	  }
#endif /* STRICT_DSCP */

          if (!(active_s->rt_route = route_rt_lookup_s (active_s))) {
                active_s->rt_route = tmp;
          }
#endif  /* GATEWAY_ROUTER */
        }
#ifdef DEBUG_GATEWAY
	  if ((s) && (active_s))
	    {
	      printf ("%s active side %d %d passive side %d %d\n",
		      stringNow (),
		      htons (active_s->myport),
		      htons (active_s->hisport),
		      htons (s->myport),
		      htons (s->hisport));
	    }
#endif /* DEBUG_GATEWAY */
	}
      break;
    }
#endif /* GATEWAY */
}


int
tp_CommonHandler (tp_Socket * s, scps_np_rqts * rqts, tp_Header * tp,
                  byte * data, int len)

{
  word flags;
  struct mbuff *mbuffer;
  short option_len;
  int ts_present;
  uint32_t ts_val, ts_ecr, temp, temp1;
  uint32_t tempseq;
  tp_Socket *new_socket = NULL;
  tp_Socket *iterative_socket = NULL;
  unsigned int mss;
  struct timeval mytime;
  volatile uint32_t flippedwindow = ntohs (tp->window);
  volatile uint32_t flippedack = ntohl (tp->acknum);
  volatile uint32_t flippedseq = ntohl (tp->seqnum);

#ifndef LINUX_STYLE_FIRST_DATA_RTO
  uint32_t temp2;
#endif /* LINUX_STYLE_FIRST_DATA_RTO */
#ifdef GATEWAY
  int does_a_peer_exist = (int) (s->peer_socket);
  tp_Socket *listening_s = NULL;
#endif /* GATEWAY */
  mytime.tv_sec = mytime.tv_usec = 0;

  if ((len != 0) && (sys_memory.clust_in_use + 10 >= sys_memory.fclist.max_size)) {
     return (-1);
  }

  flags = tp->flags;
  if (flags & tp_FlagRST)
    {
#ifdef GATEWAY
      tp_Socket *peer_s;
      peer_s = s->peer_socket;
#endif /* GATEWAY */
#ifdef DEBUG_GATEWAY
      printf ("Got a reset\n");
      fflush (stdout);
#endif /* DEBUG_GATEWAY */

      if ((s->state == tp_StateCLOSED) /* || (s->state == tp_StateTIMEWT) */ )
	{
	  return (0);
	}

      s->state_prev = s->state;
      s->state = tp_StateCLOSED;
      PRINT_STATE (s->state, s);
      clear_timer (s->otimers[Rexmit], 1);
      SET_ERR (SCPS_ECONNRESET);
#ifdef GATEWAY_SELECT
      if ((s->thread->status == Blocked) &&
	  ((s->read) || (s->write)))
	{
	  s->thread->status = Ready;
	  scheduler.num_runable++;
	  s->read = s->write = 0;
	}
#else /* GATEWAY_SELECT */
      if ((s->thread->status == Blocked) &&
	  ((scheduler.sockets[s->sockid].read) ||
	   (scheduler.sockets[s->sockid].write)))
	{
	  s->thread->status = Ready;
	  scheduler.num_runable++;
	  scheduler.sockets[s->sockid].read = 0;
	  scheduler.sockets[s->sockid].write = 0;
	}
#endif /* GATEWAY_SELECT */

      /* Write connection data to routing structure */
#ifdef GATEWAY
      if ( (peer_s) && (peer_s->peer_socket->peer_socket == peer_s) )
	{
	  tp_Abort (peer_s->sockid);
	}
#endif /* GATEWAY */
      tp_Unthread (s);
      return (-1);
    }

  if ((flags & tp_FlagSYN) == 0)
    s->snd_awnd = flippedwindow << s->snd_scale;
  else
    s->snd_awnd = flippedwindow;

  if (!(s->capabilities & CAP_CONGEST))
    s->snd_cwnd = s->snd_awnd;

  s->sndwin = min (s->snd_cwnd, s->snd_awnd + s->snduna - s->max_seqsent);

  ts_present = 0;

  option_len = (tp->th_off << 2) - 20;

#ifdef GATEWAY
  if ((len) && (!s->peer_socket) ) {
	gateway_reset (s->sockid, rqts, tp);
  }
#endif /* GATEWAY */

  if (option_len && (s->state != tp_StateLISTEN))
    tp_dooptions (s, option_len, tp, &ts_present, &ts_val, &ts_ecr);

  tp_now = clock_ValueRough ();

#ifdef OPT_TSTMP
  if (s->capabilities & CAP_TIMESTAMP)
    {
      /* Revert to Braden code */
      if (ts_present && SEQ_GEQ (ts_val, s->ts_recent) &&
	  SEQ_LEQ (flippedseq, s->lastack))
	{
	  s->ts_recent_age = tp_now;
	  s->ts_recent = ts_val;
	  s->ts_now = ts_val;
	}
      else
	{
	  if (ts_present && SEQ_GEQ (ts_val, s->ts_now)) {
	    s->ts_now = ts_val;
	  }
	}
      if (ts_present && ts_ecr)
	{
	  temp = (uint32_t) ((abs) (tp_now - ts_ecr));
	  /* tp_xmit_timer (s, temp, temp); */
          if (SEQ_GT (flippedack, s->snduna)) {
		/* PDF -- only update rtt if acknum moves forward */
	  	tp_xmit_timer (s, temp, 0);
	  }
	}
    }
#endif /* OPT_TSTMP */

#ifdef GATEWAY
#ifdef THIS_CODE_SHOULD_BE_DELETED
        if ((flags & tp_FlagSYN) && (s->state > tp_StateESTAB)) {
                tp_Socket *peer_s = s->peer_socket;
                gateway_reset (s->sockid, rqts, tp);
                if (peer_s) {
                        tp_Abort (peer_s->sockid);
                }
        }
#endif /* THIS_CODE_SHOULD_BE_DELETED */
#endif /* GATEWAY */

  s->flags = tp_FlagACK;

#ifndef STRICT_DSCP
#ifndef IPV6
  if (s->DSCP != rqts ->DSCP) {
         s->DSCP = rqts->DSCP; 
  }
#endif /* IPV6 */
#endif /* STRICT_DSCP */

#ifdef GATEWAY_ROUTER
         s->rt_route = route_rt_lookup_s (s);
#endif /* GATEWAY_ROUTER */

#ifndef IPV6
#ifndef STRICT_DSCP
  s->np_rqts.DSCP = rqts->DSCP;
  s->ip_templ.nl_head.ipv4.vht = htons (0x4500 | rqts->DSCP);
  s->DSCP = rqts->DSCP; 
  s->protocol_id = rqts->tpid; 
#endif /* STRICT_DSCP */
#endif /* IPV6 */

#ifdef GATEWAY
#ifndef IPV6
#ifndef STRICT_DSCP
  if (s->peer_socket) {
      s->peer_socket->ip_templ.nl_head.ipv4.vht = htons (0x4500 | rqts->DSCP);
  }
#endif /* STRICT_DSCP */
#endif /* IPV6 */
#endif /* GATEWAY  */

  switch (s->state)
    {				/* Switch */

    case tp_StateLISTEN:
      {
	if (flags & tp_FlagSYN)
	  {
	  NewConnect:
	    if (!(new_socket = clone_socket (s)))
	      {
#ifdef GATEWAY
                tp_Socket *peer_s = s->peer_socket;
	        gateway_reset (s->sockid, rqts, tp);
		if (peer_s) {
			tp_Abort (peer_s->sockid);
		}
#endif /* GATEWAY */
		return (-2);
	      }

#ifdef GATEWAY
            s->hisport = ntohs (tp->srcPort);
#endif /* GATEWAY */

#ifdef GATEWAY
	    if (does_a_peer_exist)
	      {
		s->peer_socket->peer_socket = new_socket;
		new_socket->peer_socket = s->peer_socket;
	      }
#endif /* GATEWAY */
	    /* This doesn't check for ports already in use, Danger! */
	    new_socket->initial_seqnum_rec = flippedseq;
	    new_socket->acknum = flippedseq + 1;
	    new_socket->lastuwein = new_socket->seqnum + flippedwindow;
	    new_socket->hisport = tp->srcPort;
            switch (new_socket->np_rqts.nl_protocol) {
                case NL_PROTOCOL_IPV4: 
                        new_socket->his_ipv4_addr = htonl (rqts->ipv4_src_addr); // PDF XXX PDF XXX 
                        break;  
                case NL_PROTOCOL_NP:
                        new_socket->his_ipv4_addr = htonl (rqts->ipv4_src_addr); // PDF XXX PDF XXX 
                        break;  
                case NL_PROTOCOL_IPV6:
                        hton16 (new_socket->his_ipv6_addr.addr, rqts->ipv6_src_addr.addr);
                        break;  
           }  
#ifdef GATEWAY
	    new_socket->my_ipv4_addr = htonl (rqts->ipv4_dst_addr);

            switch (new_socket->np_rqts.nl_protocol) {
                case NL_PROTOCOL_IPV4: 
                        new_socket->ip_templ.nl_head.ipv4.source = htonl (rqts->ipv4_dst_addr);
                        new_socket->my_ipv4_addr = htonl (rqts->ipv4_dst_addr);
                        break;  
                case NL_PROTOCOL_NP:
                        new_socket->np_templ.src_npaddr = htonl (rqts->ipv4_dst_addr); 
                        new_socket->my_ipv4_addr = htonl (rqts->ipv4_dst_addr);
                        break;
                case NL_PROTOCOL_IPV6:
                        hton16 (new_socket->ip_templ.nl_head.ipv6.src.addr, rqts->ipv6_dst_addr.addr);
                        hton16 (new_socket->my_ipv6_addr.addr, rqts->ipv6_dst_addr.addr);
                        break;
            }

#endif /* GATEWAY */
            switch (new_socket->np_rqts.nl_protocol) {
                case NL_PROTOCOL_IPV4:
                case NL_PROTOCOL_NP:
                        new_socket->ph.nl_head.ipv4.dst = new_socket->his_ipv4_addr;
                        break;
                case NL_PROTOCOL_IPV6:
                        memcpy (&(new_socket->ph.nl_head.ipv6.dst), &(new_socket->his_ipv6_addr),16);
                        break;
            }

#ifdef OPT_BETS
	    if (new_socket->capabilities & CAP_BETS)
	      new_socket->BETS.InRecSeq = new_socket->acknum - 1;
#endif /* OPT_BETS */

	    /* Add checks to make sure that the mbuffer isn't underrun */
	    new_socket->sh_off = new_socket->th_off -
	      new_socket->sp_size - (new_socket->sp_size % sizeof (uint32_t));
	    new_socket->nh_off = new_socket->sh_off -
	      new_socket->np_size - (new_socket->np_size % sizeof (uint32_t));

	    new_socket->flags = tp_FlagSYN | tp_FlagACK;
	    new_socket->lastack = new_socket->acknum;

	    new_socket->lastuwe = new_socket->acknum + new_socket->rcvwin;

#ifdef NONONO
#ifdef OLD_CODE
	    /* new_socket->timers[Rexmit] = tp_now + new_socket->t_rxtcur; */
	    mytime.tv_usec = ((new_socket->t_srtt >> TP_RTT_SHIFT) << 1);
#else /* OLD_CODE */
	    mytime.tv_usec = s->rt_route->initial_RTO;
#endif /* OLD_CODE */
            mytime.tv_usec = max (mytime.tv_usec, s->RTOMIN);
            mytime.tv_usec = min (mytime.tv_usec, s->RTOMAX);
	    set_timer (&mytime, new_socket->otimers[Rexmit], 1);
	    /* The commented-out code above, oddly enough,
	     * would work better now.  Why were we clearing
	     * the timer? 
	     */
#ifdef OLD_CODE
	    clear_timer (s->otimers[Rexmit], 1);
#endif /* OLD_CODE */
#undef OLD_CODE 
#endif /* NONONO */
	    new_socket->np_rqts.tpid = SCPSTP;
            switch (new_socket->np_rqts.nl_protocol) {
                case NL_PROTOCOL_IPV4:
                case NL_PROTOCOL_NP:
                        new_socket->np_rqts.ipv4_dst_addr = rqts->ipv4_src_addr;
                        break;
                case NL_PROTOCOL_IPV6:
                        memcpy (&(new_socket->np_rqts.ipv6_dst_addr.addr), &(rqts->ipv6_src_addr.addr), 16);
                        break;
            }
#ifdef GATEWAY
            switch (new_socket->np_rqts.nl_protocol) {
                case NL_PROTOCOL_IPV4:
                case NL_PROTOCOL_NP:
                        new_socket->np_rqts.ipv4_src_addr = rqts->ipv4_dst_addr;
                        break;
                case NL_PROTOCOL_IPV6:
                        memcpy (&(new_socket->np_rqts.ipv6_src_addr.addr), &(rqts->ipv6_dst_addr.addr), 16);
                        break;
            }
#else /* GATEWAY */
            new_socket->np_rqts.ipv4_src_addr = ntohl (local_addr); /* PDF XXX  */
#endif /* GATEWAY */
	    new_socket->np_rqts.timestamp.format = 0;
	    new_socket->np_rqts.timestamp.ts_val[0] =
	      new_socket->np_rqts.timestamp.ts_val[1] = 0;
	    new_socket->np_rqts.bqos.precedence = rqts->bqos.precedence;
	    new_socket->np_rqts.bqos.routing = 0;
	    new_socket->np_rqts.bqos.pro_specific = 0;
	    new_socket->np_rqts.eqos.ip_precedence = 0;
	    new_socket->np_rqts.eqos.ip_tos = 0;
	    new_socket->np_rqts.cksum = 1;	/* rqts->cksum; */
	    new_socket->np_rqts.int_del = 0;
#ifdef SCPSSP
	    /* Fill in the SP requirements structure */
	    new_socket->sp_rqts.np_rqts.tpid = SP;
	    new_socket->sp_rqts.np_rqts.ipv4_dst_addr = rqts->ipv4_src_addr;
#ifdef GATEWAY
	    new_socket->sp_rqts.np_rqts.ipv4_src_addr = rqts->ipv4_dst_addr;
#else /* GATEWAY */
	    new_socket->sp_rqts.np_rqts.ipv4_src_addr = ntohl (local_addr);
#endif /* GATEWAY */
	    new_socket->sp_rqts.np_rqts.timestamp.format = 0;
	    new_socket->sp_rqts.np_rqts.timestamp.ts_val[0] =
	      new_socket->sp_rqts.np_rqts.timestamp.ts_val[1] = 0;
	    new_socket->sp_rqts.np_rqts.bqos.precedence =
	      rqts->bqos.precedence;
	    new_socket->sp_rqts.np_rqts.bqos.routing = 0;
	    new_socket->sp_rqts.np_rqts.bqos.pro_specific = 0;
	    new_socket->sp_rqts.np_rqts.eqos.ip_precedence = 0;
	    new_socket->sp_rqts.np_rqts.eqos.ip_tos = 0;
	    new_socket->sp_rqts.np_rqts.cksum = 1;	/* rqts->cksum; */
	    new_socket->sp_rqts.np_rqts.int_del = 0;
	    new_socket->sp_rqts.tpid = SCPSTP;
	    new_socket->np_rqts.tpid = SP;
#endif /* SCPSSP */

            if ((rqts->nl_protocol == NL_PROTOCOL_IPV4) ||
                (rqts->nl_protocol == NL_PROTOCOL_IPV6) ||
                (rqts->nl_protocol == NL_PROTOCOL_NP)) {
                new_socket->np_rqts.nl_protocol = rqts->nl_protocol;
#ifdef SCPSSP
                new_socket->sp_rqts.np_rqts.nl_protocol = rqts->nl_protocol;
#endif /* SCPSSP */
            }  

#ifdef SCPSSP
	    new_socket->sp_size = sp_hdr_size (new_socket->sp_rqts);	/* fill in security req */
#else /* SCPSSSP */
	    new_socket->sp_size = 0;
#endif /* SCPSSP */
	    new_socket->np_size = np_hdr_size (new_socket->np_rqts);

            tp_dooptions (new_socket, option_len, tp, &ts_present, &ts_val,
                          &ts_ecr);
            
            switch (new_socket->np_rqts.nl_protocol) {
                case NL_PROTOCOL_IPV4:
                        new_socket->np_size = ip_get_template (&(new_socket->np_rqts), &(new_socket->ip_templ));
                        break;
#ifdef IPV6
                case NL_PROTOCOL_IPV6:
                        new_socket->np_size = ipv6_get_template (&(new_socket->np_rqts), &(new_socket->ip_templ));
                        break;
#endif /* IPV6 */
                case NL_PROTOCOL_NP:
                        new_socket->np_size = scps_np_get_template (&(new_socket->np_rqts),&(new_socket->np_templ));
                        break;
            }

#ifdef GATEWAY_DUAL_INTERFACE  
	if (new_socket->gateway_layering == GATEWAY_LAYERING_NORMAL) {
		new_socket->np_rqts.interface = divert_interface;
	} else {
		new_socket->np_rqts.interface = sock_interface;  
	}
#endif /* GATEWAY_DUAL_INTERFACE */

	    if ((mbuffer = tp_BuildHdr (new_socket, NULL, 0)))
	      enq_mbuff (mbuffer, new_socket->send_buff);

	    if (!(new_socket->send_buff->send))
	      new_socket->send_buff->send = new_socket->send_buff->last;

	    if (new_socket->send_buff->send)
	      {
		tp_NewSend (new_socket, NULL, false);
	      }

	    new_socket->state_prev = new_socket->state;
	    new_socket->state = tp_StateSYNREC;
	    PRINT_STATE (s->state, s);
	    new_socket->timeout = s->LONGTIMEOUT;

	    /* Now, attach new_socket to s->q0 */
	    new_socket->qhead = s;
	    new_socket->q0 = (s->q0);

	    if (s->q0)
	      s->q0->q = new_socket;

	    s->q0 = new_socket;
	    new_socket->q = NULL;

#ifdef GATEWAY
	    if (new_socket->capabilities & CAP_JUMBO)
	      {
		new_socket->gateway_flags |= (GATEWAY_SCPS_TP_SESSION);
	      } else {
                new_socket->capabilities |= CAP_CONGEST;
                new_socket->cong_algorithm = VJ_CONGESTION_CONTROL;
              }

/* The listening socket should be closed after the connection has been fully
 * established */

#endif /* GATEWAY */
	  }
      }
      break;

    case tp_StateSYNSENT:
      {
	if (flags & tp_FlagSYN)
	  {
	    s->acknum++;
	    s->timeout = s->TIMEOUT;

	    if ((s->state_prev == tp_StateCLOSED) && (flags & tp_FlagACK)
		&& (flippedack == (s->snduna + 1)))
	      {
		/* Cool, this is a SYN,ACK in response to our active open... */
		clear_timer (s->otimers[Rexmit], 1);

                mytime.tv_usec = 0;
                mytime.tv_sec = 1;  /* Initially I want to send an ACK fairly soon
 				       incase the ACK that opens up the window gets
 				       lost -- PDF */
					
                set_timer (&mytime, s->otimers[KA], 1);

	        s->initial_seqnum_rec = flippedseq;
		s->state_prev = s->state;
		s->state = tp_StateESTAB;
		PRINT_STATE (s->state, s);
		s->sockFlags &= ~SOCK_ACKNOW;
		/* We have an open connection, make the socket as writeable */
#ifdef GATEWAY_SELECT
		ADD_WRITE (s);
#else /* GATEWAY_SELECT */
		s->thread->write_socks |= (1 << s->sockid);
#endif /* GATEWAY_SELECT */
#ifdef GATEWAY_SELECT
		if ((s->thread->status == Blocked) && (s->write))
		  {
		    /*
		     * If this socket is not currently on the list
		     * of *writeable* sockets, place it there.
		     */
		    ADD_WRITE (s);
		    s->write = 0;


		    /*
		     * Remove this socket from the list of readable
		     * sockets if it is there.
		     */

		    if (s->read_parent)
		      {
			if (s->read_prev)
			  s->read_prev->read_next = s->read_next;
			else if ((tp_Socket *) (s->thread->read_socks) ==
				 (tp_Socket *) s)
			  ((tp_Socket *) s)->thread->read_socks = ((tp_Socket *) s->read_next);
			else
			  printf ("Uh oh! tp_handler.c:Common_Handler\n");

			if (s->read_next)
			  s->read_next->read_prev = s->read_prev;
		      }

		    /* s->thread->read_socks &= ~(1 << s->sockid); */

		    s->thread->status = Ready;
		    scheduler.num_runable++;
		  }
#else /* GATEWAY_SELECT */
		if ((s->thread->status == Blocked) && (
							(scheduler.sockets[s->sockid].write) ||
							(scheduler.sockets[s->sockid].read)))
		  {
		    s->thread->write_socks |= (1 << s->sockid);
		    s->thread->read_socks |= (1 << s->sockid);
		    scheduler.sockets[s->sockid].write = 0;
		    s->thread->status = Ready;
		    scheduler.num_runable++;
		  }
#endif /* GATEWAY_SELECT */

		s->snduna++;
		s->ack_delay = 0;
		s->acknum = flippedseq + 1;
		s->lastack = s->acknum;

		s->lastuwe = s->acknum + s->rcvwin;
		/* free the SYN's mbuffer */
		ts_val = mb_trim (s->send_buff, (s->snduna) - 1,
				  &temp1, (uint32_t *) NULL);
		/*
		 * If we are acked up, we can optionally reset the retransmission timer
		 * values to their initial values (a la linux 2.0.32 kernel).  We
		 * don't care if s->rtt is set or not (retransmitted SYN?)
		 */
#ifndef LINUX_STYLE_FIRST_DATA_RTO
		if ((s->rtt) && (SEQ_GEQ (flippedack, s->rtseq)))
		  {
		    temp1 = (temp1) ? (uint32_t) ((abs) (tp_now - temp1)) : 0;
		    temp2 = (ts_val) ? (uint32_t) ((abs) (tp_now -
							  ts_val)) : 0;
		    tp_xmit_timer (s, temp1, temp2);  /*SYN */
		    s->rtt = 0;
		  }
#else /* LINUX_STYLE_FIRST_DATA_RTO */
		if ( SEQ_GEQ (flippedack, s->rtseq) )
		  {
		    s->t_srtt = s->rt_route->rtt << (TP_RTT_SHIFT);
		    s->t_rttvar = s->rt_route->rtt_var << TP_RTTVAR_SHIFT;
		    s->t_rxtcur = s->rt_route->initial_RTO << TP_RTT_SHIFT;
		    s->rtt = 0;
		  }
#endif /* LINUX_STYLE_FIRST_DATA_RTO */

#ifdef DEBUG_TIMING
		    logEventv(s, timing, TIMING_FORMAT,
			      stringNow (),
			      "SYNACK",
			      flippedack,
			      s->lastuwein,
			      s->snd_cwnd,
			      s->snd_prevcwnd,
			      s->snd_ssthresh,
			      s->rtt,
			      s->rtseq,
			      s->snduna,
			      s->seqsent);
#endif	/* DEBUG_TIMING */

#ifdef GATEWAY
		if (s->capabilities & CAP_JUMBO)
		  {
		    s->gateway_flags |= (GATEWAY_SCPS_TP_SESSION);
		  } else {
                    s->capabilities |= CAP_CONGEST;
                    s->cong_algorithm = VJ_CONGESTION_CONTROL;
                  }

		if ((ntohs (tp->window)) && (does_a_peer_exist))
		  {
                    if (s->peer_socket) {
		      s->peer_socket->gateway_flags &= (~GATEWAY_PEER_WIN_NOT_OPENED);
		      s->peer_socket->sockFlags |= SOCK_ACKNOW;
                    }
		  }
#endif /* GATEWAY */

#ifdef GATEWAY_SELECT
		if ((s->thread->status == Blocked) &&
		    (((s->write) &&
		      ((s->send_buff->max_size - (s->seqnum - s->snduna)) >=
		       s->write))))
		  {
		    s->thread->status = Ready;
		    scheduler.num_runable++;
		    s->write = 0;
		  }
#else /* GATEWAY_SELECT */
		if ((s->thread->status == Blocked) &&
		    (((scheduler.sockets[s->sockid].write) &&
		      ((s->send_buff->max_size - (s->seqnum - s->snduna)) >=
		       scheduler.sockets[s->sockid].write))))
		  {
		    s->thread->status = Ready;
		    scheduler.num_runable++;
		    scheduler.sockets[s->sockid].write = 0;
		  }
#endif /* GATEWAY_SELECT */

#ifdef OPT_SCALE
		if ((s->sockFlags & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
		    (TF_RCVD_SCALE | TF_REQ_SCALE))
		  {
		    s->snd_scale = s->requested_s_scale;
		    s->rcv_scale = s->request_r_scale;
		  }
#else /* OPT_SCALE */
		s->snd_scale = s->rcv_scale = 0;
#endif /* OPT_SCALE */
		s->snd_awnd = flippedwindow << s->snd_scale;

		s->lastuwein = flippedack + s->snd_awnd;

		if (!(s->capabilities & CAP_CONGEST))
		  s->snd_cwnd = s->snd_awnd;

		s->sndwin =
		  min (s->snd_cwnd, s->snd_awnd + s->snduna - s->max_seqsent);

		/* build an ACK in an mbuffer and send it.
		 * This logic is not quite right, since we
		 * declare the connection open possibly
		 * without having sent this ACK
		 */

		if (s->capabilities & CAP_COMPRESS)
		  {
		    s->sockFlags |= SOCK_ACKNOW;
		    gettimeofday (&(s->start_time), NULL);
		  }
		if ((mbuffer = tp_BuildHdr (s, NULL, 0)))
		  {
		    if (s->capabilities & CAP_COMPRESS)
		      {
			tp_NewSend (s, mbuffer, true);
		      }
		    else
		      {
			tp_NewSend (s, mbuffer, false);
		      }
		    free_mbuff (mbuffer);
		    gettimeofday (&(s->start_time), NULL);
		  }
	      }

	    /*
	     *  Not quite correct protection against old duplicate SYNs:
	     * We have sent a SYN, To get to this point, we have sent a 
	     * SYN and received a SYN but the acknum on the incoming SYN 
	     * is wrong... Neglecting simultaneous opens, we should be 
	     * sending a RST here and remaining in the SYNSENT state.
	     *
	     * We need to check our state prior to this, if it was CLOSED:
	     *     If this packet is a pure SYN we have a simultaneous open. 
	     *         Handle it.
	     *     If this packet is a SYN,ACK but has an ACK < seqsent, 
	     *         it is a old duplicate, send a reset and kill it!
	     */

	    else
	      {
		/* Figure out why we are here... */
		if ((s->state_prev == tp_StateCLOSED))
		  {
		    if (!(flags & tp_FlagACK))
		      {
			/* Simultaneous open... handle it; */
		      }
		    else if (SEQ_LT (flippedack, (s->snduna + 1)))
		      {
			/* Old duplicate SYN,ACK - send a RST */
			s->flags = tp_FlagRST | tp_FlagACK;
			if ((mbuffer = tp_BuildHdr (s, NULL, 0)))
			  {
			    /* 
			     * Need to doctor the sequence number of 
			     * the packet in the mbuffer to be that 
			     * in the incoming acknumber...
			     */
			    tempseq = s->max_seqsent;
			    s->max_seqsent = flippedack;
			    tp_NewSend (s, mbuffer, true);
			    s->max_seqsent = tempseq;
			    free_mbuff (mbuffer);
			  }
		      }
		    else
		      {
			/* 
			 * What could this be... a SYN,ACK with an 
			 * acknum > s->max_seqsent... 
			 *
			 * Roll into above by sending a RST (but if this 
			 * case is valid, someone is very broken on 
			 * the other-side! 
			 */
		      }
		  }
		else
		  {
		    /* This was a passive open to begin with...  */
		  }
	      }

	    s->maxdata = s->maxseg - TP_HDR_LEN;

            if (s->rt_route->SMTU) {
                s->maxdata = min (s->maxdata, s->rt_route->SMTU - tp_hdr_size () - s->np_size - s->sp_size - TP_HDR_LEN);
            }

#ifdef GATEWAY_DUAL_INTERFACE
            s->maxdata += ENCAP_HDR_LEN;
            if ((struct _interface *)(s->np_rqts.interface) == sock_interface ) {
              s->maxdata -= ((struct _interface *)(s->np_rqts.interface))->mss_ff;
            }
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef MPF
//           s->maxdata -= s->rt_route->MSS_FF;
#endif /* MPF */

#ifdef INIT_CWND_INCR
	    s->snd_cwnd = s->snd_prevcwnd =
	      min (4 * s->maxdata, max (2 * s->maxdata, 4380));
#else /* INIT_CWND_INCR */
	    s->snd_cwnd = s->snd_prevcwnd = s->maxdata;
#endif /* INIT_CWND_INCR */

#if SET_INITIAL_CWND
	   s->snd_cwnd = s->snd_prevcwnd = SET_INITIAL_CWND;
#endif /* SET_INITIAL_CWND */

	    s->sndwin =
	      min (s->snd_cwnd, s->snd_awnd + s->snduna - s->max_seqsent);
	  }
	if (flags & tp_FlagFIN)
	  {
		return (-2);
	  }
#ifdef GATEWAY
	if ( (s) && (s->peer_socket) )
	  {
	    gateway_move_data (s->peer_socket, s);
	  }
#endif /* GATEWAY */
	return (1);
      }
      break;

    case tp_StateSYNREC:
      {
	if (flags & tp_FlagSYN)
	  {
	    s->flags = tp_FlagSYN | tp_FlagACK;
	    /* Just retransmit the original syn off the retransmission queue */
	    tp_NewSend (s, s->send_buff->snd_una, true);
	  }

	if ((flags & tp_FlagACK) && (flippedack == s->seqnum))
	  {
#ifdef OPT_COMPRESS
	    if ((s->sockFlags & TF_COMPRESSING) == TF_COMPRESSING)
	      {
#ifdef SCPSSP
		s->sp_rqts.tpid = SCPSCTP;
#else /* SCPSSP */
		s->np_rqts.tpid = SCPSCTP;
#endif /* SCPSSP */

                switch (s->np_rqts.nl_protocol) {
                        case NL_PROTOCOL_IPV4:
                                ip_get_template (&(s->np_rqts), &(s->ip_templ));
                                break;
#ifdef IPV6
                        case NL_PROTOCOL_IPV6:
                                ipv6_get_template (&(s->np_rqts), &(s->ip_templ));
                                break;
#endif /* IPV6 */
                        case NL_PROTOCOL_NP:
                                s->np_size = scps_np_get_template (&(s->np_rqts), &(s->np_templ));
                                break;  
                }

	      }
#endif /* OPT_COMPRESS */
            s->maxdata = s->maxseg - TP_HDR_LEN;

            if (s->rt_route->SMTU) {
                s->maxdata = min (s->maxdata, s->rt_route->SMTU - tp_hdr_size () - s->np_size - s->sp_size - TP_HDR_LEN);
            }

#ifdef GATEWAY_DUAL_INTERFACE
            s->maxdata += ENCAP_HDR_LEN;
            if ((struct _interface *)(s->np_rqts.interface) == sock_interface ) {
              s->maxdata -= ((struct _interface *)(s->np_rqts.interface))->mss_ff;
            }
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef MPF
           s->maxdata -= s->rt_route->MSS_FF;
#endif /* MPF */

	    s->snd_cwnd = s->snd_prevcwnd = s->maxdata =
	      s->maxseg - TP_HDR_LEN;

	    mss = s->maxseg - TP_HDR_LEN;

#ifdef INIT_CWND_INCR
/* 
 * This is the Sally Floyd proposal for optionally increasing initial cwnd:
 *
 */
	    s->snd_cwnd = s->snd_prevcwnd = min (4 * mss, max (2 * mss, 4380));
#else /* INIT_CWND_INCR */
	    s->snd_cwnd = s->snd_prevcwnd = mss;
#endif /* INIT_CWND_INCR */

#if SET_INITIAL_CWND
	   s->snd_cwnd = s->snd_prevcwnd = SET_INITIAL_CWND;
#endif /* SET_INITIAL_CWND */

	    s->sndwin =
	      min (s->snd_cwnd, s->snd_awnd + s->snduna - s->max_seqsent);

	    s->state_prev = s->state;
	    s->state = tp_StateESTAB;

            mytime.tv_usec = 0;
            mytime.tv_sec = 1;  /* Initially I want to send an ACK fairly soon
 				   incase the ACK that opens up the window gets
 				   lost -- PDF */
					
            set_timer (&mytime, s->otimers[KA], 1);

	    PRINT_STATE (s->state, s);
#ifndef GATEWAY
            /* Curious problem here, in a gateway environment, a zero
               window is always offerred until the other side offers a
               window, this tries to ensure that data does now flow
               through the network until an end-to-end connection has
               been established.  When a window is received on one side
               of a gatewayed connection, a flag is set on the peer
               connection to indicates that the window can be openned,
               and the ACK NOW flag is set to force and ACK out to 
               advertise this new window.  Unfotunately, if the peer
               connection is not yet in the ESTAB state, the ACK can't
               be sent until the connection is established.  In this
               case, the connection is established when the SYN-ACK is
               ACKED (located in this code block) This code block also
               clears ACK NOW, to supress spurrious ACKs.  This also
               caused the new adverstised window not be sent.  The fix
               is to not clear this flag in the gateway mode. -- PDF
            */
            s->sockFlags &= ~SOCK_ACKNOW;
#endif /* GATEWAY */
	    s->snduna++;

	    /* 
	     * We now want to move this socket from the "connecting" to
	     * the tail of the connected queue of the listening socket.
	     */

	    /* Disconnect from s->qhead->q0 */

#ifdef GATEWAY
            listening_s = (s->qhead);
#endif /* GATEWAY */
	    if (s->qhead->q0 == s)
	      s->qhead->q0 = s->q0;

	    /* Cut forward link */
	    if (s->q0)
	      s->q0->q = s->q;

	    /* Cut reverse link */
	    if (s->q)
	      s->q->q0 = s->q0;

	    s->q0 = s->q = NULL;

	    /* Walk to the "end" of the connected queue */

	    /* What the heck is this **really** doing??? */

	    /*
	     * If there is no current queue head, then
	     * this newly connected socket becomes it.
	     */

	    if (!(s->qhead->q))
	      {
		s->qhead->q = s;
		iterative_socket = s->qhead;
	      }
	    else
	      /*
	       * Otherwise, we want to add this socket to
	       * chain of "child" sockets;
	       *
	       * Start at the parent's first entry (s->qhead->q)
	       * and walk to the last socket in the "child" list;
	       * When we hit the end of the list, we add the new
	       * socket to the tail (iterative_socket->q = s)
	       */
	      {
		for (iterative_socket = s->qhead->q;
		     ((iterative_socket) && (iterative_socket->q));
		     iterative_socket = iterative_socket->q);
		/* Set previous list end's forward pointer to me. */
		iterative_socket->q = s;
		/* Set my reverse link to the previous list end (my
		 * forward poitner (q) was nulled out above.
		 */
		s->q0 = iterative_socket;
	      }
#ifdef GATEWAY
	    /*
	     * This replaces the call to accept but doesn't commit suicide.
	     */
	    iterative_socket->q = NULL;
	    if (s->qhead) {
	      s->qhead = NULL;
	      s->q = NULL;
	      s->q0 = NULL;
	    }

           if (listening_s) {
	     scps_close (listening_s->sockid); 
           }

#endif /* GATEWAY */

	    /*
	     * We have an open connection, make the socket as writable,
	     * and unblock the listening socket if it is blocked
	     */
	    /*    
	     * If this socket is not currently on the list of
	     * writable sockets, place it there.
	     */
#ifdef GATEWAY_SELECT
	    ADD_WRITE (s);
#ifndef GATEWAY
	    ADD_WRITE (s->qhead);
#endif /* GATEWAY */
#else /* GATEWAY_SELECT */
	    s->thread->write_socks |= (1 << s->sockid);
	    s->qhead->thread->write_socks |= (1 << s->qhead->sockid);
#endif /* GATEWAY_SELECT */

	    /* 
	     * If this socket is not currently on the
	     * list of readable sockets, place it there.
	     */
#ifdef GATEWAY_SELECT
	    ADD_READ (s);
#ifndef GATEWAY
	    ADD_READ (s->qhead);
#endif /* GATEWAY */
#else /* GATEWAY_SELECT */
	    s->thread->read_socks |= (1 << s->sockid);
	    s->qhead->thread->read_socks |= (1 << s->qhead->sockid);
#endif /* GATEWAY_SELECT */

#ifdef GATEWAY_SELECT
	    if ((s->thread->status == Blocked) &&
		((s->qhead->write) || (s->qhead->read)))
	      {
		s->write = 0;
		s->thread->status = Ready;
		scheduler.num_runable++;
	      }
#else /* GATEWAY_SELECT */
	    if ((s->thread->status == Blocked) &&
		((scheduler.sockets[s->qhead->sockid].write) ||
		 (scheduler.sockets[s->qhead->sockid].read)))
	      {
		scheduler.sockets[s->sockid].write = 0;
		s->thread->status = Ready;
		scheduler.num_runable++;
	      }
#endif /* GATEWAY_SELECT */
	    /* Free the mbuff associated with the SYN */
	    ts_val = mb_trim (s->send_buff, (s->snduna), &temp1,
			      (uint32_t *) NULL);

#ifndef LINUX_STYLE_FIRST_DATA_RTO
	    if (((s->rtt) && (SEQ_GEQ (flippedack, s->rtseq))))
	      {
		temp1 = (temp1) ? (uint32_t) ((abs) (tp_now - temp1)) : 0;
		temp2 = (ts_val) ? (uint32_t) ((abs) (tp_now - ts_val)) : 0;
		tp_xmit_timer (s, temp1, temp2); /* SYN */
		s->rtt = 0;
	      }
#else /* LINUX_STYLE_FIRST_DATA_RTO */
	    if ( SEQ_GEQ (flippedack, s->rtseq) )
	      {
		s->t_srtt = s->rt_route->rtt << (TP_RTT_SHIFT);
		s->t_rttvar = s->rt_route->rtt_var << TP_RTTVAR_SHIFT;
		s->t_rxtcur = s->rt_route->initial_RTO << TP_RTT_SHIFT;
		s->rtt = 0;
	      }
#endif /* LINUX_STYLE_FIRST_DATA_RTO */

#ifdef DEBUG_TIMING
		logEventv(s, timing, TIMING_FORMAT,
			  stringNow (),
			  "SYNREC",
			  flippedack,
			  s->lastuwein,
			  s->snd_cwnd,
			  s->snd_prevcwnd,
			  s->snd_ssthresh,
			  s->rtt,
			  s->rtseq,
			  s->snduna,
			  s->seqsent);
#endif	/* DEBUG_TIMING */

#ifdef OPT_SCALE
	    if ((s->sockFlags & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
		(TF_RCVD_SCALE | TF_REQ_SCALE))
	      {
		s->snd_scale = s->requested_s_scale;
		s->rcv_scale = s->request_r_scale;
	      }
#else /* OPT_SCALE */
	    s->snd_scale = s->rcv_scale = 0;
#endif /* OPT_SCALE */

	    s->snd_awnd = flippedwindow << s->snd_scale;

	    if (!(s->capabilities & CAP_CONGEST))
	      s->snd_cwnd = s->snd_awnd;

	    s->sndwin =
	      min (s->snd_cwnd, (s->snd_awnd - (s->max_seqsent - s->snduna)));
	    tp_ProcessData (s, tp, data, len);
	    s->timeout = s->TIMEOUT;
	    clear_timer (s->otimers[Rexmit], 1);

	    gettimeofday (&(s->start_time), NULL);

	    /* 
	     * If there is any OutSeq data that was really in-order, bring
	     * it into the fold now...
	     */
	    if ((s->Out_Seq->start) &&
		(s->Out_Seq->start->m_seq <= s->acknum))
	      {

		mbuffer = deq_mbuff (s->Out_Seq);

		s->acknum += mbuffer->m_plen;

		/*
		 * We've filled a hole, if there is another,
		 * set the socket parameters accordingly.
		 */

#ifdef OPT_SNACK1
		if (s->capabilities & CAP_SNACK)
		  {
		    if (s->Out_Seq->start)
		      s->SNACK1_Flags |= SEND_SNACK1;
		  }
#endif /* OPT_SNACK1 */

		s->app_rbuff->write_off += mbuffer->m_plen;

		/* Advance the write_head and offset properly */
		while (s->app_rbuff->write_off >= SMCLBYTES)
		  {
		    s->app_rbuff->write_off -= SMCLBYTES;
		    s->app_rbuff->write_head->tail = SMCLBYTES;
		    s->app_rbuff->write_head = s->app_rbuff->write_head->c_next;
		    if (s->app_rbuff->bytes_beyond)
		      s->app_rbuff->bytes_beyond -= SMCLBYTES;
		  }
		if (s->app_rbuff->write_head)
		  s->app_rbuff->write_head->tail = s->app_rbuff->write_off;

		s->app_rbuff->size += mbuffer->m_plen;

		if (s->app_rbuff->size > s->app_rbuff->biggest)
		  s->app_rbuff->biggest = s->app_rbuff->size;

		s->app_rbuff->Out_Seq_size -= mbuffer->m_plen;

		enq_mbuff (mbuffer, s->receive_buff);
	      }
#ifdef GATEWAY
	    if ( (s) && (s->peer_socket) )
	      {
		gateway_move_data (s->peer_socket, s);
	      }
#endif /* GATEWAY */
	  }
	else
	  /* Allow data to queue on a connecting connection... */
	  {
	    tp_ProcessData (s, tp, data, len);
	  }
	return (1);
      }
      break;

    case tp_StateESTAB:
    case tp_StateCLOSEWT:	/* Eric is trying this 7/2/98 */
    case tp_StateFINWT1PEND:
    case tp_StateFINWTDETOUR:
    case tp_StateLASTACKPEND:
      {
	if ((flags & tp_FlagACK) == 0)
	  {
	    return (1);
	  }

#ifdef GATEWAY
        if (s->peer_socket) {
          if ((flags & tp_FlagURG) && (ntohs (tp->urgentPointer))) {
            s->peer_socket->rel_seq_num_urg_ptr =
               flippedseq + ntohs (tp->urgentPointer) - s->initial_seqnum_rec;
            s->peer_socket->funct_flags =
               s->peer_socket->funct_flags | FUNCT_REL_SEQ_NUM_URG_PTR;
          }
     
          if ((s->peer_socket->funct_flags & FUNCT_REL_SEQ_NUM_URG_PTR) &&
              SEQ_GT (flippedseq,
                   s->peer_socket->rel_seq_num_urg_ptr+s->initial_seqnum_rec)) {
            s->peer_socket->rel_seq_num_urg_ptr = 0;
            s->peer_socket->funct_flags =
               s->peer_socket->funct_flags & (~FUNCT_REL_SEQ_NUM_URG_PTR);
          }
        }
#endif /* GATEWAY */

	if (flags & tp_FlagSYN)	{
	  /* Probably lost the ACK of the SYNACK */
	  s->sockFlags |= SOCK_ACKNOW;
	}
	tp_ProcessAck (s, tp, len);
	if ((tp->flags & ~tp_FlagACK) || (len > 0))
	  {
	    /* if ((tp->flags & ~tp_FlagACK) || (len > (tp->th_off << 2))) */
	    tp_ProcessData (s, tp, data, len);
	  }
      }
      break;

    case tp_StateFINWT1:
      {
	if ((flags & tp_FlagACK) == 0)
	  {
	    return (-1);
	  }

	tp_ProcessAck (s, tp, len);

	/* If other side acked our fin, move to FINWT2 */
	if (flippedack == s->seqnum)
	  {
	    s->state_prev = s->state;
	    s->state = tp_StateFINWT2;
	    PRINT_STATE (s->state, s);
	    clear_timer (s->otimers[Rexmit], 1);
	    s->timeout = 0x7ffffff;
	    (void) mb_trim (s->send_buff, s->seqnum, (uint32_t *) NULL,
			    (uint32_t *) NULL);
#ifdef GATEWAY_SELECT
	    if ((s->thread->status == Blocked) &&
		((s->read) || (s->write)))
	      {
		s->thread->status = Ready;
		scheduler.num_runable++;
		s->read = s->write = 0;
	      }
#else /* GATEWAY_SELECT */
	    if ((s->thread->status == Blocked) &&
		((scheduler.sockets[s->sockid].read) ||
		 (scheduler.sockets[s->sockid].write)))
	      {
		s->thread->status = Ready;
		scheduler.num_runable++;
		scheduler.sockets[s->sockid].write = 0;
		scheduler.sockets[s->sockid].read = 0;
	      }
#endif /* GATEWAY_SELECT */

	    clear_timer (s->otimers[Del_Ack], 1);
	    s->sockFlags &= ~SOCK_DELACK;
            s->persist_shift = 0;
	    s->maxpersist_ctr = 0;
	    clear_timer (s->otimers[Persist], 1);
	  }
	tp_ProcessData (s, tp, data, len);
      }
      break;

    case tp_StateFINWT2:
      {
	clear_timer (s->otimers[Del_Ack], 1);
	s->sockFlags &= ~SOCK_DELACK;
        s->persist_shift = 0;
	s->maxpersist_ctr = 0;
	clear_timer (s->otimers[Persist], 1);
	tp_ProcessAck (s, tp, len);
	tp_ProcessData (s, tp, data, len);
      }
      break;

    case tp_StateCLOSING:
      {
	if (flippedack == (s->seqnum))
	  {
	    s->state_prev = s->state;
	    s->state = tp_StateTIMEWT;
            if (s->send_buff->holes) {
	        s->send_buff->holes = 0x0;
            }
	    PRINT_STATE (s->state, s);
	    s->timeout = s->TWOMSLTIMEOUT;
	    mytime.tv_sec = s->TWOMSLTIMEOUT;
	    mytime.tv_usec = 0;
	    set_timer (&mytime, s->otimers[TW], 1);
	    clear_timer (s->otimers[Rexmit], 1);
	    tp_ProcessAck (s, tp, len);
	  }
      }
      break;

    case tp_StateLASTACK:
      {
	clear_timer (s->otimers[Del_Ack], 1);
	s->sockFlags &= ~SOCK_DELACK;
        s->persist_shift = 0;
	s->maxpersist_ctr = 0;
	clear_timer (s->otimers[Persist], 1);

	if (flippedack == (s->seqnum))
	  {
	    s->state_prev = 0;
	    s->state = tp_StateCLOSED;
	    PRINT_STATE (s->state, s);
	    clear_timer (s->otimers[Rexmit], 1);
#ifdef GATEWAY_SELECT
	    if ((s->thread->status == Blocked) &&
		((s->read) || (s->write)))
	      {
		s->thread->status = Ready;
		scheduler.num_runable++;
		s->read = s->write = 0;
	      }
#else /* GATEWAY_SELECT */
	    if ((s->thread->status == Blocked) &&
		((scheduler.sockets[s->sockid].read) ||
		 (scheduler.sockets[s->sockid].write)))
	      {
		s->thread->status = Ready;
		scheduler.num_runable++;
		scheduler.sockets[s->sockid].read = 0;
		scheduler.sockets[s->sockid].write = 0;
	      }
#endif /* GATEWAY_SELECT */
	    SET_ERR (SCPS_ENOTCONN);
 
	    tp_Unthread (s);
	    return (-1); /* PDF ADDED */
	  }
      }
      break;

    case tp_StateTIMEWT:
      {
	/* 
	 * If this is a SYN and the starting sequence number is greater 
	 * than the final we've seen here, we are allowed to reincarnate 
	 * this connection... See Stevens Vol2 fig 28.28; When listen forks
	 * new sockets, this goto will go away... 
	 */
	if ((flags & tp_FlagSYN) && (flippedseq > s->acknum))
	  goto NewConnect;

	/* Otherwise, build a pure ack in an mbuffer and send it */
	s->lastack = s->acknum;

	s->lastuwe = s->acknum + s->rcvwin;

	if ((mbuffer = tp_BuildHdr (s, NULL, 0)))
	  {
	    tp_NewSend (s, mbuffer, false);
	    free_mbuff (mbuffer);
	  }
      }
      break;
    }

  /* see if any changes to window size have allowed us to send */
  /* 
   * We should ONLY do this if we know we have data to push out,
   * Otherwise this is expensive!
   */
  /* tp_NewSend (s, NULL, false); */
  return (1);
}

#ifdef GATEWAY
void
gateway_reset (s1, rqts, tp)
     int s1;
     scps_np_rqts *rqts;
     tp_Header *tp;

{
  tp_Socket *s;

  s = (tp_Socket *) scheduler.sockets[s1].ptr;

  s->ph.nl_head.ipv4.dst = htonl (rqts->ipv4_src_addr);
  s->np_rqts.ipv4_dst_addr = (rqts->ipv4_src_addr);
  s->np_rqts.ipv4_src_addr = (rqts->ipv4_dst_addr);
  s->hisport = tp->srcPort;
  s->myport = tp->dstPort;
  s->np_rqts.tpid = SCPSTP;

#ifdef SCPSSP
    memset ((void *) (&s->sp_rqts), 0x00, sizeof (s->sp_rqts));
#ifdef SECURE_GATEWAY
  if (rqts-> secure_gateway_rqts != SECURE_GATEWAY_NO_SECURITY) {
    /* Fill in the SP requirements structure */
    s->sp_rqts.np_rqts.tpid = SP;
    s->sp_rqts.np_rqts.dst_addr = rqts->src_addr;
    s->sp_rqts.np_rqts.src_addr = rqts->dst_addr;  
    s->sp_rqts.np_rqts.timestamp.format = 0;
    s->sp_rqts.np_rqts.timestamp.ts_val[0] =
    s->sp_rqts.np_rqts.timestamp.ts_val[1] = 0;
    s->sp_rqts.np_rqts.bqos.precedence = rqts->bqos.precedence;
    s->sp_rqts.np_rqts.bqos.routing = 0;
    s->sp_rqts.np_rqts.bqos.pro_specific = 0;
    s->sp_rqts.np_rqts.eqos.ip_precedence = 0;
    s->sp_rqts.np_rqts.eqos.ip_tos = 0;
    s->sp_rqts.np_rqts.cksum = 1;      /* rqts->cksum; */ 
    s->sp_rqts.np_rqts.int_del = 0;
    s->sp_rqts.tpid = SCPSTP;
    s->np_rqts.tpid = SP; 
    if (rqts-> secure_gateway_rqts) {
      s->sp_rqts.secure_gateway_rqts = rqts->secure_gateway_rqts;
    } 
  }
#else  /* SECURE_GATEWAY */
  /* Fill in the SP requirements structure */
  s->sp_rqts.np_rqts.tpid = SP;
  s->sp_rqts.np_rqts.dst_addr = rqts->src_addr;
  s->sp_rqts.np_rqts.src_addr = rqts->dst_addr;  
  s->sp_rqts.np_rqts.timestamp.format = 0;
  s->sp_rqts.np_rqts.timestamp.ts_val[0] =
  s->sp_rqts.np_rqts.timestamp.ts_val[1] = 0;
  s->sp_rqts.np_rqts.bqos.precedence = rqts->bqos.precedence;
  s->sp_rqts.np_rqts.bqos.routing = 0;
  s->sp_rqts.np_rqts.bqos.pro_specific = 0;
  s->sp_rqts.np_rqts.eqos.ip_precedence = 0;
  s->sp_rqts.np_rqts.eqos.ip_tos = 0;
  s->sp_rqts.np_rqts.cksum = 1;      /* rqts->cksum; */ 
  s->sp_rqts.np_rqts.int_del = 0;
  s->sp_rqts.tpid = SCPSTP;
  s->np_rqts.tpid = SP; 
#endif /* SECURE_GATEWAY */

#endif /* SCPSSP */

  switch (s->np_rqts.nl_protocol) {
    case NL_PROTOCOL_IPV4:
      s->np_size = ip_get_template (&(s->np_rqts), &(s->ip_templ));
      break;
#ifdef IPV6
    case NL_PROTOCOL_IPV6:
      s->np_size = ipv6_get_template (&(s->np_rqts), &(s->ip_templ));
      break;
#endif /* IPV6 */
    case NL_PROTOCOL_NP:
      s->np_size = scps_np_get_template (&(s->np_rqts),&(s->np_templ));
      break; 
  }

/* if Ack is set , set ack to 0, seq = seq num */

#ifdef GATEWAY_DUAL_INTERFACE
  if (s->gateway_layering == GATEWAY_LAYERING_NORMAL) {
      s->np_rqts.interface = divert_interface;
      if (gw_ifs.bif_layering == s->gateway_layering) {
          divert_interface->overhead = gw_ifs.aif_overhead;
	  divert_interface->mss_ff = gw_ifs.aif_mss_ff;
      }
      if (gw_ifs.bif_layering == s->gateway_layering) {
          divert_interface->overhead = gw_ifs.bif_overhead;
	  divert_interface->mss_ff = gw_ifs.bif_mss_ff;
      }
  } else {
      s->np_rqts.interface = sock_interface;
      if (gw_ifs.aif_layering == s->gateway_layering) {
          sock_interface->overhead = gw_ifs.aif_overhead;
	  sock_interface->mss_ff = gw_ifs.aif_mss_ff;
      }
      if (gw_ifs.bif_layering == s->gateway_layering) {
          sock_interface->overhead = gw_ifs.bif_overhead;
	  sock_interface->mss_ff = gw_ifs.bif_mss_ff;
      }
   }
#endif /* GATEWAY_DUAL_INTERFACE */


  if (tp->flags & tp_FlagACK)
    {
      s->acknum = ntohl (tp->seqnum) + 0;
      s->seqsent = ntohl (tp->acknum) + 0;
      s->max_seqsent = ntohl (tp->acknum) + 0;
      s->seqnum = ntohl (tp->acknum) + 0;
    }
  else
    {
      s->acknum = ntohl (tp->seqnum) + 0;
      s->seqsent = 0;
      s->max_seqsent = 0;
      s->seqnum = 0;
    }

  {

    s->state = tp_StateESTAB;
    fflush (stdout);
    s->rt_route = def_route;
    tp_Abort (s1);
  }
}

void
gateway_move_data (from, to)
     tp_Socket *from;
     tp_Socket *to;

{
  int can_be_read, can_be_written, to_be_moved, clusters;
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined(__NetBSD__)
#define BUFFER_SIZ 32000
#endif /*  __FreeBSD__ || __OpenBSD__ || __NetBSD__ */
#ifdef LINUX 
#define BUFFER_SIZ 8192
#endif /*  LINUX  */
  unsigned char temp_buff[BUFFER_SIZ];
  int tmp = 0;
  int bytes_read;
  int temp = 0;

  from->gateway_flags &= ~GATEWAY_MORE_TO_WRITE;
  clusters = 0;

  if ((from ->peer_socket->peer_socket != from) || (to->peer_socket->peer_socket !=to)) {
#ifdef DEBUG_GATEWAY
	printf ("Warning %x %x %x %x\n",from, from->peer_socket->peer_socket, to, to->peer_socket->peer_socket);
#endif /* DEBUG_GATEWAY */
	return;
  }

  BUG_HUNT (from);
  BUG_HUNT (to);
  if (sys_memory.clust_in_use + 10 >= sys_memory.fclist.max_size)
    {
      from->gateway_flags |= GATEWAY_MORE_TO_WRITE;
      return;
    }

  if ((from && ((from->state == tp_StateESTAB) ||
       (from->state == tp_StateFINWT2) ||
       (from->state == tp_StateFINWT1PEND) ||
       (from->state == tp_StateCLOSEWT) ||
  /*       (from->state == tp_StateSYNREC) ||   */
       (from->state == tp_StateFINWT1))) &&
      (to && ((to->state == tp_StateESTAB) ||
       (to->state == tp_StateFINWT2) ||
       (to->state == tp_StateFINWT1PEND) ||
       (to->state == tp_StateCLOSEWT) ||
  /*      (to->state == tp_StateSYNREC) ||   */
       (to->state == tp_StateFINWT1))) &&
      (from->app_rbuff->size != 0))
    {

#ifdef DEBUG_MEMORY
      {
	static int nowinStatus = 0;
	if (fileExists ("nowin"))
	  {
	    if (nowinStatus == 0)

	      {
		printf ("%s Window inhibited by presence of file `nowin'.\n",
			stringNow ());
		fflush (stdout);
	      }
	    nowinStatus = 1;
	    from->gateway_flags |= GATEWAY_MORE_TO_WRITE;
	    return;
	  }
	else if (nowinStatus == 1)
	  {
	    printf ("%s Window enabled by removal of file `nowin'.\n",
		    stringNow ());
	    nowinStatus = 2;
	  }
	else
	  {
	    nowinStatus = 0;
	  }
      }
#endif /* DEBUG_MEMORY */

#define ORIG_CODE
#ifdef ORIG_CODE
      can_be_read = from->app_rbuff->size;
      can_be_written = to->app_sbuff->max_size -
	(to->app_sbuff->size + to->send_buff->data_size);
      to_be_moved = min (can_be_read, can_be_written);
      to_be_moved = min (to_be_moved, BUFFER_SIZ);

#ifdef GATEWAY
{
	struct stat sb;
	if (gw_ifs.c_pkt_io_filename[0] != '\0') {
		if ((stat (gw_ifs.c_pkt_io_filename, &sb)) < 0) {
		} else {
			syslog (LOG_ERR,"Gateway: move_data %d %d %d\n",can_be_read, can_be_written, to_be_moved);
		}		
	}
}
#endif /* GATEWAY */

#ifdef DEBUG_GATEWAY 
      printf ("%s %d %s %s Moving data %d\n", __FILE__, __LINE__, 
              stringNow (),
              (to) ? printPorts (to) : "????",
	      to_be_moved);
#endif /* DEBUG_GATEWAY */

      if (to_be_moved < 1)
	{
	  from->gateway_flags |= GATEWAY_MORE_TO_WRITE;
	  return;
	}

      if (to_be_moved < can_be_read)
        {
          from->gateway_flags |= GATEWAY_MORE_TO_WRITE;
        }

#ifdef DEBUG_GATEWAY
      logEventv(to, gateway, "to_be_moved = %d %d %d %d %d\n",
		from->app_rbuff->size, to->app_sbuff->max_size,
		to->app_sbuff->size, to->send_buff->data_size, to_be_moved);
#endif /* DEBUG_GATEWAY */

      if (to->app_sbuff->write_head == NULL)
	{
	  printf ("Write head = 0\n");
	  clusters++;

	  if (to->app_sbuff->start == NULL)
	    {
	      printf ("Chain Start = 0\n");
	      clusters++;
	    }
	}

      if (to->maxseg)
	temp = (to_be_moved / to->maxseg) + 1;

      while (((SMCLBYTES - to->app_sbuff->write_off) + to->app_sbuff->bytes_beyond)
	     < (0 + to_be_moved + temp))
	{
	  if (!((to->app_sbuff->num_elements <
		 to->app_sbuff->max_elements)))
	    {
	      if (grow_chain (to->app_sbuff, 1))
		{
		  from->gateway_flags |= GATEWAY_MORE_TO_WRITE;
		  return;
		}
	    }
#ifdef ORIG_CODE
	  if (!((to->app_sbuff->num_elements < to->app_sbuff->max_elements) &&
		(grow_chain (to->app_sbuff, 1))))
	    {
	      printf ("error in growing chain in big while loop %d %d\n",
                       to->app_sbuff->num_elements, to->app_sbuff->max_elements);
	      from->gateway_flags |= GATEWAY_MORE_TO_WRITE;
	      return;
	    }
#endif /* ORIG_CODE */
	}


      if (grow_chain (to->app_sbuff, clusters))
	{
	  if (to_be_moved)
	    {
	      bytes_read = scps_read (from->sockid, temp_buff, to_be_moved);
	      if (bytes_read != to_be_moved)
		{
		  printf ("READ FAILED err(%d) to_be_moved(%d) bytes_read(%d) tmp(%d) from->state(%d)\n",
			  GET_ERR (),
			  to_be_moved,
			  bytes_read,
			  tmp,
			  from->state);
		  printf ("  can_be_read(%d) can_be_written(%d) BUFFER_SIZE(%d)\n",
			  can_be_read, can_be_written, BUFFER_SIZ);
	
		  tmp = bytes_read;
		  from->gateway_flags |= GATEWAY_MORE_TO_WRITE;
		}
	      else
		{
		  tmp = scps_write (to->sockid, temp_buff, bytes_read);
		  if (tmp != bytes_read)
		    {
		      printf ("WRITE FAILED err(%d) bytes_read(%d) tmp(%d)\n", GET_ERR (),
			      bytes_read, tmp);
		    }
		}
#ifdef DEBUG_GATEWAY
	      logEventv (to, gateway, "In gateway_move_data %d bytes %d\n", to_be_moved, tmp);
#endif /* DEBUG_GATEWAY */
	    }
	  else
	    {
	      from->gateway_flags |= GATEWAY_MORE_TO_WRITE;
#ifdef DEBUG_GATEWAY
	      logEventv(from, gateway, "In gateway_move_data CAN'T WRITE DATA!\n");
#endif /* DEBUG_GATEWAY */
	    }

	}
      else
	{
	  printf ("Could not grow chain %d \n", to->app_sbuff->max_elements);
	}
#endif /* ORIG_CODE */

    }
  if ( ((!from) || (from && ( ((from->state == tp_StateNASCENT ) || (from->state == tp_StateCLOSED) )
      || (!from->app_rbuff->size)))) && (to->gateway_flags & GATEWAY_SEND_FIN))
    {
      to->gateway_flags &= (~GATEWAY_SEND_FIN);
      tp_Close (to->sockid);
    }
  else
    {
    }
}


void
gateway_set_options (sockid, divert_port, other)
     int sockid;
     int divert_port;
     int other;
{
  int buffer_size = GATEWAY_DEFAULT_BUFFER;
  int one = 1;
  int zero = 0;
  tp_Socket *s;

  s = (tp_Socket *) scheduler.sockets[sockid].ptr;

#ifdef DEBUG_GATEWAY
  logEventv(s, gateway, "gateway_set_options sockid(%d) divert_port(%d) other(%d)\n",
	    sockid, divert_port, other);
  printf("%s %s gateway_set_options sockid(%d) divert_port(%d) other(%d)\n",
	 stringNow(), printPorts(s),
	 sockid, divert_port, other);
#endif /* DEBUG_GATEWAY */

  switch (other)
    {
    case 0:			/* This means the divert port corresponds to
				 * the interface this was received on
				 */

      s->divert_port = divert_port;
      if (divert_port == gw_ifs.aif_divport)
	{
	  s->gateway_lan_or_wan = gw_ifs.aif_gateway_lan_or_wan;
	  /* PDF SET the BUFFERS PROPERLY FIRST */
	  if (gw_ifs.aif_buf)
	    {
	      buffer_size = gw_ifs.aif_buf;
	    }
#ifdef DEBUG_GATEWAY
	  logEventv(s, gateway, "Case 0:\n");
	  logEventv(s, gateway, "  divert_port(%d) = gw_ifs.aif_divport (%d)", divert_port);
	  logEventv(s, gateway, "  buffer_size        = %u\n", buffer_size);
	  logEventv(s, gateway, "  congestion control = %d\n", gw_ifs.aif_cc);
#endif /* DEBUG_GATEWAY */

	  scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_SNDBUF, &buffer_size,
			   sizeof buffer_size);

	  if (gw_ifs.aif_rbuf) {
	      buffer_size = gw_ifs.aif_rbuf;
	  }

	  scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_RCVBUF, &buffer_size,
			   sizeof buffer_size);

	  /* SET THE CC NEXT */
	  switch (gw_ifs.aif_cc)
	    {
	    case NO_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_CONGEST,
			       &zero, sizeof (zero));
	      break;
	    case VJ_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VJ_CONGEST,
			       &one, sizeof (one));
	      break;
	    case VEGAS_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_CONGEST,
			       &one, sizeof (one));
              if (gw_ifs.aif_vegas_alpha)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_ALPHA,
		    	           &gw_ifs.aif_vegas_alpha, sizeof (gw_ifs.aif_vegas_alpha));
              if (gw_ifs.aif_vegas_beta)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_BETA,
		    	           &gw_ifs.aif_vegas_beta, sizeof (gw_ifs.aif_vegas_beta));
              if (gw_ifs.aif_vegas_gamma)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_GAMMA,
		    	           &gw_ifs.aif_vegas_gamma, sizeof (gw_ifs.aif_vegas_gamma));
              scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_SS,
	             &gw_ifs.aif_vegas_ss, sizeof (gw_ifs.aif_vegas_ss));
	      break;
	    case FLOW_CONTROL_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_FLOW_CONTROL_CONGEST,
			       &one, sizeof (one));
	      break;
	    }

#ifdef SECURE_GATEWAY
            s->sp_rqts.secure_gateway_rqts=gw_ifs.aif_scps_security;
#endif /* SECURE_GATEWAY */

#ifdef GATEWAY_DUAL_INTERFACE
	   s->gateway_layering=gw_ifs.aif_layering;
	   if (s->gateway_layering == GATEWAY_LAYERING_NORMAL) {
	       s->np_rqts.interface = divert_interface;
               divert_interface->overhead = gw_ifs.aif_overhead;
               divert_interface->mss_ff = gw_ifs.aif_mss_ff;
           } else {
	       s->np_rqts.interface = sock_interface;
               sock_interface->overhead = gw_ifs.aif_overhead;
               sock_interface->mss_ff = gw_ifs.aif_mss_ff;
	   }
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef DIVERT_N_RAWIP
           s->gateway_next_hop = gw_ifs.aif_next_hop;
#endif /* DIVERT_N_RAWIP */

           s->RTOMIN = gw_ifs.aif_minrto;
           s->RTOMAX = gw_ifs.aif_maxrto;
           s->TIMEOUT = gw_ifs.aif_maxrto_ctr;
           s->LONGTIMEOUT = gw_ifs.aif_maxrto_ctr;
           s->MAXPERSIST_CTR = gw_ifs.aif_maxpersist_ctr;
           s->RTOPERSIST_MAX = gw_ifs.aif_rtopersist_max;
           s->RTO_TO_PERSIST_CTR = gw_ifs.aif_rto_to_persist_ctr;
	   s->EMBARGO_FAST_RXMIT_CTR = gw_ifs.aif_embargo_fast_rxmit_ctr;
      
           if (gw_ifs.aif_ecbs1_len > 0 && gw_ifs.aif_ecbs1_len < 20) {
	      s->ecbs1 = gw_ifs.aif_ecbs1;
	      s->ecbs1_len = gw_ifs.aif_ecbs1_len;
              memcpy (s->ecbs1_value, gw_ifs.aif_ecbs1_value, s->ecbs1_len * 2);
           }

           if (gw_ifs.aif_ecbs2_len > 0 && gw_ifs.aif_ecbs2_len < 20) {
	      s->ecbs2 = gw_ifs.aif_ecbs2;
	      s->ecbs2_len = gw_ifs.aif_ecbs2_len;
              memcpy (s->ecbs2_value, gw_ifs.aif_ecbs2_value, s->ecbs2_len * 2);
           }

           if (gw_ifs.aif_2msltimeout != 0) {
           	scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_2MSLTIMEOUT,
                            &gw_ifs.aif_2msltimeout, sizeof (gw_ifs.aif_2msltimeout));
	   }

           scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_NLDEFAULT,
                            &gw_ifs.aif_nl, sizeof (gw_ifs.aif_nl));

            if (gw_ifs.aif_ack_behave != -1) {
	       short behave = gw_ifs.aif_ack_behave;

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKBEHAVE,
	           &behave, sizeof (behave));
	    }

            if (gw_ifs.aif_ack_delay != 0x0) {
	       int ack_delay = gw_ifs.aif_ack_delay;

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKDELAY,
	           &ack_delay, sizeof (ack_delay));

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKFLOOR,
	           &ack_delay, sizeof (ack_delay));
	    }

	    if (gw_ifs.aif_ts == 0)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_TIMESTAMP,
	           &zero, sizeof (zero));

	    if (gw_ifs.aif_snack == 0)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_SNACK,
	           &zero, sizeof (zero));

	    if (gw_ifs.aif_nodelay == 1)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_NODELAY,
	           &one, sizeof (one));

	    if (gw_ifs.aif_snack_delay != 0) {
	       uint32_t snack_delay = gw_ifs.aif_snack_delay;
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_SNACK_DELAY,
	           &snack_delay, sizeof (snack_delay));
	    }

	    if (gw_ifs.aif_tp_compress == 1)  
		scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_COMPRESS,
		   &one, sizeof (one));

	    if (gw_ifs.aif_tcponly == 1)  
		s->capabilities &= (~CAP_JUMBO);

/* Assign the routed properly now */
          s->rt_route = def_route;
          s->rt_route_def = def_route;
	}
      else if (divert_port == gw_ifs.bif_divport)
	{
	  s->gateway_lan_or_wan = gw_ifs.bif_gateway_lan_or_wan;
	  if (gw_ifs.bif_buf)
	    {
	      buffer_size = gw_ifs.bif_buf;
	    }
#ifdef DEBUG_GATEWAY
	  logEventv(s, gateway, "Case 0:\n");
	  logEventv(s, gateway, "  divert_port = gw_ifs.bif_divport");
	  logEventv(s, gateway, "  buffer_size        = %u\n", buffer_size);
	  logEventv(s, gateway, "  congestion control = %d\n", gw_ifs.bif_cc);
#endif /* DEBUG_GATEWAY */

	  scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_SNDBUF, &buffer_size,
			   sizeof buffer_size);

	  if (gw_ifs.bif_rbuf) {
	      buffer_size = gw_ifs.bif_rbuf;
	  }

	  scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_RCVBUF, &buffer_size,
			   sizeof buffer_size);

	  /* SET THE CC NEXT */
	  switch (gw_ifs.bif_cc)
	    {
	    case NO_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_CONGEST,
			       &zero, sizeof (zero));
	      break;
	    case VJ_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VJ_CONGEST,
			       &one, sizeof (one));
	      break;
	    case VEGAS_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_CONGEST,
			       &one, sizeof (one));
              if (gw_ifs.bif_vegas_alpha)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_ALPHA,
		    	           &gw_ifs.bif_vegas_alpha, sizeof (gw_ifs.bif_vegas_alpha));
              if (gw_ifs.bif_vegas_beta)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_BETA,
		    	           &gw_ifs.bif_vegas_beta, sizeof (gw_ifs.bif_vegas_beta));
              if (gw_ifs.bif_vegas_gamma)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_GAMMA,
		    	           &gw_ifs.bif_vegas_gamma, sizeof (gw_ifs.bif_vegas_gamma));
              scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_SS,
	             &gw_ifs.bif_vegas_ss, sizeof (gw_ifs.bif_vegas_ss));
	      break;
	    case FLOW_CONTROL_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_FLOW_CONTROL_CONGEST,
			       &one, sizeof (one));
	      break;
	    }

#ifdef SECURE_GATEWAY
            s->sp_rqts.secure_gateway_rqts=gw_ifs.bif_scps_security;
#endif /* SECURE_GATEWAY */

#ifdef GATEWAY_DUAL_INTERFACE
	   s->gateway_layering=gw_ifs.bif_layering;
	   if (s->gateway_layering == GATEWAY_LAYERING_NORMAL) {
	       s->np_rqts.interface = divert_interface;
               divert_interface->overhead = gw_ifs.bif_overhead;
               divert_interface->mss_ff = gw_ifs.bif_mss_ff;
           } else {
	       s->np_rqts.interface = sock_interface;
               sock_interface->overhead = gw_ifs.bif_overhead;
               sock_interface->mss_ff = gw_ifs.bif_mss_ff;
	   }
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef DIVERT_N_RAWIP
           s->gateway_next_hop = gw_ifs.bif_next_hop;
#endif /* DIVERT_N_RAWIP */

           s->RTOMIN = gw_ifs.bif_minrto; 
           s->RTOMAX = gw_ifs.bif_maxrto;
           s->TIMEOUT = gw_ifs.bif_maxrto_ctr;
           s->LONGTIMEOUT = gw_ifs.bif_maxrto_ctr;
           s->MAXPERSIST_CTR = gw_ifs.bif_maxpersist_ctr;
           s->RTOPERSIST_MAX = gw_ifs.bif_rtopersist_max;
           s->RTO_TO_PERSIST_CTR = gw_ifs.bif_rto_to_persist_ctr;
	   s->EMBARGO_FAST_RXMIT_CTR = gw_ifs.bif_embargo_fast_rxmit_ctr;
 
           if (gw_ifs.bif_ecbs1_len > 0 && gw_ifs.bif_ecbs1_len < 20) {
	      s->ecbs1 = gw_ifs.bif_ecbs1;
	      s->ecbs1_len = gw_ifs.bif_ecbs1_len;
              memcpy (s->ecbs1_value, gw_ifs.bif_ecbs1_value, s->ecbs1_len * 2);
           }

           if (gw_ifs.bif_ecbs2_len > 0 && gw_ifs.bif_ecbs2_len < 20) {
	      s->ecbs2 = gw_ifs.bif_ecbs2;
	      s->ecbs2_len = gw_ifs.bif_ecbs2_len;
              memcpy (s->ecbs2_value, gw_ifs.bif_ecbs2_value, s->ecbs2_len * 2);
           }

           if (gw_ifs.bif_2msltimeout != 0) {
           	scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_2MSLTIMEOUT,
                            &gw_ifs.bif_2msltimeout, sizeof (gw_ifs.bif_2msltimeout));
	   }

           scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_NLDEFAULT,
                            &gw_ifs.bif_nl, sizeof (gw_ifs.bif_nl));

            if (gw_ifs.bif_ack_behave != -1) {
	       short behave = gw_ifs.bif_ack_behave;

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKBEHAVE,
	           &behave, sizeof (behave));
	    }

            if (gw_ifs.bif_ack_delay != 0x0) {
	       int ack_delay = gw_ifs.bif_ack_delay;

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKDELAY,
	           &ack_delay, sizeof (ack_delay));

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKFLOOR,
	           &ack_delay, sizeof (ack_delay));
	    }

	    if (gw_ifs.bif_tp_compress == 1)  
		scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_COMPRESS,
		   &one, sizeof (one));

	    if (gw_ifs.bif_ts == 0)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_TIMESTAMP,
	           &zero, sizeof (zero));

	    if (gw_ifs.bif_snack == 0)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_SNACK,
	           &zero, sizeof (zero));

	    if (gw_ifs.bif_nodelay == 1)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_NODELAY,
	           &one, sizeof (one));

	    if (gw_ifs.bif_snack_delay != 0) {
	       uint32_t snack_delay = gw_ifs.bif_snack_delay;
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_SNACK_DELAY,
	           &snack_delay, sizeof (snack_delay));
	    }

	    if (gw_ifs.bif_tcponly == 1)  
		s->capabilities &= (~CAP_JUMBO);

/* Assign the routed properly now */
          s->rt_route = other_route;
          s->rt_route_def = other_route;
	}
      break;

    case 1:			/* This means the divert port corresponds to
				 * the other interface this was received on
				 */

      if (divert_port == gw_ifs.bif_divport)
	{

	  s->gateway_lan_or_wan = gw_ifs.aif_gateway_lan_or_wan;
	  s->divert_port = gw_ifs.aif_divport;
	  if (gw_ifs.aif_buf)
	    {
	      buffer_size = gw_ifs.aif_buf;
	    }
#ifdef DEBUG_GATEWAY
	  logEventv(s, gateway, "Case 1:\n");
	  logEventv(s, gateway, "  divert_port = gw_ifs.bif_divport");
	  logEventv(s, gateway, "  buffer_size        = %u\n", buffer_size);
	  logEventv(s, gateway, "  congestion control = %d\n", gw_ifs.aif_cc);
#endif /* DEBUG_GATEWAY */

	  scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_SNDBUF, &buffer_size,
			   sizeof buffer_size);

	  if (gw_ifs.aif_rbuf) {
	      buffer_size = gw_ifs.aif_rbuf;
	  }

	  scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_RCVBUF, &buffer_size,
			   sizeof buffer_size);

	  /* SET THE CC NEXT */
	  switch (gw_ifs.aif_cc)
	    {
	    case NO_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_CONGEST,
			       &zero, sizeof (zero));
	      break;
	    case VJ_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VJ_CONGEST,
			       &one, sizeof (one));
	      break;
	    case VEGAS_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_CONGEST,
			       &one, sizeof (one));
              if (gw_ifs.aif_vegas_alpha)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_ALPHA,
		    	           &gw_ifs.aif_vegas_alpha, sizeof (gw_ifs.aif_vegas_alpha));
              if (gw_ifs.aif_vegas_beta)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_BETA,
		    	           &gw_ifs.aif_vegas_beta, sizeof (gw_ifs.aif_vegas_beta));
              if (gw_ifs.aif_vegas_gamma)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_GAMMA,
		    	           &gw_ifs.aif_vegas_gamma, sizeof (gw_ifs.aif_vegas_gamma));
              scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_SS,
	             &gw_ifs.aif_vegas_ss, sizeof (gw_ifs.aif_vegas_ss));
	      break;
	    case FLOW_CONTROL_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_FLOW_CONTROL_CONGEST,
			       &one, sizeof (one));
	      break;
	    }

#ifdef SECURE_GATEWAY
            s->sp_rqts.secure_gateway_rqts=gw_ifs.aif_scps_security;
#endif /* SECURE_GATEWAY */

#ifdef GATEWAY_DUAL_INTERFACE
	   s->gateway_layering=gw_ifs.aif_layering;
	   if (s->gateway_layering == GATEWAY_LAYERING_NORMAL) {
	       s->np_rqts.interface = divert_interface;
               divert_interface->overhead = gw_ifs.aif_overhead;
               divert_interface->mss_ff = gw_ifs.aif_mss_ff;
           } else {
	       s->np_rqts.interface = sock_interface;
               sock_interface->overhead = gw_ifs.aif_overhead;
               sock_interface->mss_ff = gw_ifs.aif_mss_ff;
	   }
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef DIVERT_N_RAWIP
           s->gateway_next_hop = gw_ifs.aif_next_hop;
#endif /* DIVERT_N_RAWIP */

           s->RTOMIN = gw_ifs.aif_minrto; 
           s->RTOMAX = gw_ifs.aif_maxrto;
           s->TIMEOUT = gw_ifs.aif_maxrto_ctr;
           s->LONGTIMEOUT = gw_ifs.aif_maxrto_ctr;
           s->MAXPERSIST_CTR = gw_ifs.aif_maxpersist_ctr;
           s->RTOPERSIST_MAX = gw_ifs.aif_rtopersist_max;
           s->RTO_TO_PERSIST_CTR = gw_ifs.aif_rto_to_persist_ctr;
	   s->EMBARGO_FAST_RXMIT_CTR = gw_ifs.aif_embargo_fast_rxmit_ctr;
               
           if (gw_ifs.aif_ecbs1_len > 0 && gw_ifs.aif_ecbs1_len < 20) {
	      s->ecbs1 = gw_ifs.aif_ecbs1;
	      s->ecbs1_len = gw_ifs.aif_ecbs1_len;
              memcpy (s->ecbs1_value, gw_ifs.aif_ecbs1_value, s->ecbs1_len * 2);
           }

           if (gw_ifs.aif_ecbs2_len > 0 && gw_ifs.aif_ecbs2_len < 20) {
	      s->ecbs2 = gw_ifs.aif_ecbs2;
	      s->ecbs2_len = gw_ifs.aif_ecbs2_len;
              memcpy (s->ecbs2_value, gw_ifs.aif_ecbs2_value, s->ecbs2_len * 2);
           }

           if (gw_ifs.aif_2msltimeout != 0) {
           	scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_2MSLTIMEOUT,
                            &gw_ifs.aif_2msltimeout, sizeof (gw_ifs.aif_2msltimeout));
	   }

           scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_NLDEFAULT,
                            &gw_ifs.aif_nl, sizeof (gw_ifs.aif_nl));

            if (gw_ifs.aif_ack_behave != -1) {
	       short behave = gw_ifs.aif_ack_behave;

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKBEHAVE,
	           &behave, sizeof (behave));
	    }

            if (gw_ifs.aif_ack_delay != 0x0) {
	       int ack_delay = gw_ifs.aif_ack_delay;

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKDELAY,
	           &ack_delay, sizeof (ack_delay));

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKFLOOR,
	           &ack_delay, sizeof (ack_delay));
	    }

	    if (gw_ifs.aif_tp_compress == 1)  
		scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_COMPRESS,
		   &one, sizeof (one));

	    if (gw_ifs.aif_ts == 0)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_TIMESTAMP,
	           &zero, sizeof (zero));

	    if (gw_ifs.aif_snack == 0)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_SNACK,
	           &zero, sizeof (zero));

	    if (gw_ifs.aif_nodelay == 1)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_NODELAY,
	           &one, sizeof (one));

	    if (gw_ifs.aif_snack_delay != 0) {
	       uint32_t snack_delay = gw_ifs.aif_snack_delay;
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_SNACK_DELAY,
	           &snack_delay, sizeof (snack_delay));
	    }

	    if (gw_ifs.aif_tcponly == 1)  
		s->capabilities &= (~CAP_JUMBO);

/* Assign the routed properly now */
          s->rt_route = def_route;
          s->rt_route_def = def_route;
	}
      else if (divert_port == gw_ifs.aif_divport)
	{

	  s->gateway_lan_or_wan = gw_ifs.bif_gateway_lan_or_wan;
	  s->divert_port = gw_ifs.bif_divport;
	  if (gw_ifs.bif_buf)
	    {
	      buffer_size = gw_ifs.bif_buf;
	    }
#ifdef DEBUG_GATEWAY
	  logEventv(s, gateway, "Case 1:\n");
	  logEventv(s, gateway, "  divert_port = gw_ifs.aif_divport");
	  logEventv(s, gateway, "  buffer_size        = %u\n", buffer_size);
	  logEventv(s, gateway, "  congestion control = %d\n", gw_ifs.bif_cc);
#endif /* DEBUG_GATEWAY */

	  scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_SNDBUF, &buffer_size,
			   sizeof buffer_size);

	  if (gw_ifs.bif_rbuf) {
	      buffer_size = gw_ifs.bif_rbuf;
	  }

	  scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_RCVBUF, &buffer_size,
			   sizeof buffer_size);

	  /* SET THE CC NEXT */
	  switch (gw_ifs.bif_cc)
	    {
	    case NO_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_CONGEST,
			       &zero, sizeof (zero));
	      break;
	    case VJ_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VJ_CONGEST,
			       &one, sizeof (one));
	      break;
	    case VEGAS_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_CONGEST,
			       &one, sizeof (one));
              if (gw_ifs.bif_vegas_alpha)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_ALPHA,
		    	           &gw_ifs.bif_vegas_alpha, sizeof (gw_ifs.bif_vegas_alpha));
              if (gw_ifs.bif_vegas_beta)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_BETA,
		    	           &gw_ifs.bif_vegas_beta, sizeof (gw_ifs.bif_vegas_beta));
              if (gw_ifs.bif_vegas_gamma)  
	          scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_GAMMA,
		    	           &gw_ifs.bif_vegas_gamma, sizeof (gw_ifs.bif_vegas_gamma));
              scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_VEGAS_SS,
	             &gw_ifs.bif_vegas_ss, sizeof (gw_ifs.bif_vegas_ss));
	      break;
	    case FLOW_CONTROL_CONGESTION_CONTROL:
	      scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_FLOW_CONTROL_CONGEST,
			       &one, sizeof (one));
	      break;
	    }

#ifdef SECURE_GATEWAY
            s->sp_rqts.secure_gateway_rqts=gw_ifs.bif_scps_security;
#endif /* SECURE_GATEWAY */

#ifdef GATEWAY_DUAL_INTERFACE
	   s->gateway_layering=gw_ifs.bif_layering;
	   if (s->gateway_layering == GATEWAY_LAYERING_NORMAL) {
	       s->np_rqts.interface = divert_interface;
               divert_interface->overhead = gw_ifs.bif_overhead;
               divert_interface->mss_ff = gw_ifs.bif_mss_ff;
           } else {
	       s->np_rqts.interface = sock_interface;
               sock_interface->overhead = gw_ifs.bif_overhead;
               sock_interface->mss_ff = gw_ifs.bif_mss_ff;
	   }
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef DIVERT_N_RAWIP
           s->gateway_next_hop = gw_ifs.bif_next_hop;
#endif /* DIVERT_N_RAWIP */

           s->RTOMIN = gw_ifs.bif_minrto; 
           s->RTOMAX = gw_ifs.bif_maxrto;
           s->TIMEOUT = gw_ifs.bif_maxrto_ctr;
           s->LONGTIMEOUT = gw_ifs.bif_maxrto_ctr;
           s->MAXPERSIST_CTR = gw_ifs.bif_maxpersist_ctr;
           s->RTOPERSIST_MAX = gw_ifs.bif_rtopersist_max;
           s->RTO_TO_PERSIST_CTR = gw_ifs.bif_rto_to_persist_ctr;
	   s->EMBARGO_FAST_RXMIT_CTR = gw_ifs.bif_embargo_fast_rxmit_ctr;
               
           if (gw_ifs.bif_ecbs1_len > 0 && gw_ifs.bif_ecbs1_len < 20) {
	      s->ecbs1 = gw_ifs.bif_ecbs1;
	      s->ecbs1_len = gw_ifs.bif_ecbs1_len;
              memcpy (s->ecbs1_value, gw_ifs.bif_ecbs1_value, s->ecbs1_len * 2);
           }

           if (gw_ifs.bif_ecbs2_len > 0 && gw_ifs.bif_ecbs2_len < 20) {
	      s->ecbs2 = gw_ifs.bif_ecbs2;
	      s->ecbs2_len = gw_ifs.bif_ecbs2_len;
              memcpy (s->ecbs2_value, gw_ifs.bif_ecbs2_value, s->ecbs2_len * 2);
           }

           if (gw_ifs.bif_2msltimeout != 0) {
           	scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_2MSLTIMEOUT,
                            &gw_ifs.bif_2msltimeout, sizeof (gw_ifs.bif_2msltimeout));
	   }

           scps_setsockopt (sockid, SCPS_SOCKET, SCPS_SO_NLDEFAULT,
                            &gw_ifs.bif_nl, sizeof (gw_ifs.bif_nl));

            if (gw_ifs.bif_ack_behave != -1) {
	       short behave = gw_ifs.bif_ack_behave;

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKBEHAVE,
	           &behave, sizeof (behave));
	    }

            if (gw_ifs.bif_ack_delay != 0x0) {
	       int ack_delay = gw_ifs.bif_ack_delay;

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKDELAY,
	           &ack_delay, sizeof (ack_delay));

	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_ACKFLOOR,
	           &ack_delay, sizeof (ack_delay));
	    }

	    if (gw_ifs.bif_tp_compress == 1)  
		scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_COMPRESS,
		   &one, sizeof (one));

	    if (gw_ifs.bif_ts == 0)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_TIMESTAMP,
	           &zero, sizeof (zero));

	    if (gw_ifs.bif_snack == 0)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_SNACK,
	           &zero, sizeof (zero));

	    if (gw_ifs.bif_nodelay == 1)  
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_NODELAY,
	           &one, sizeof (one));

	    if (gw_ifs.bif_snack_delay != 0) {
	       uint32_t snack_delay = gw_ifs.bif_snack_delay;
	       scps_setsockopt (sockid, PROTO_SCPSTP, SCPSTP_SNACK_DELAY,
	           &snack_delay, sizeof (snack_delay));
	    }

	    if (gw_ifs.bif_tcponly == 1)  
		s->capabilities &= (~CAP_JUMBO);

/* Assign the routed properly now */
          s->rt_route = other_route;
          s->rt_route_def = other_route;
	}

      break;
    }
}
#endif /* GATEWAY */

#ifdef GATEWAY 
void
gateway_double_check_parameters (s)
tp_Socket *s;

{
	tp_Socket *rt_socket;
	int route_sock_id;
	int s_id;
	route *rt;
	int value;
	int value_size;
	int rc;

	rt = s->rt_route;
        route_sock_id = rt->route_sock_id;
	rt_socket = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
	s_id = s->sockid;

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_RATE) {
		rc = scps_getsockopt (route_sock_id, SCPS_ROUTE, SCPS_RATE, &value, &value_size);
		printf ("IN RATE getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, SCPS_ROUTE, SCPS_RATE, &value, value_size);
		printf ("IN RATE setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_MTU) {
		rc = scps_getsockopt (route_sock_id, SCPS_ROUTE, SCPS_MTU, &value, &value_size);
		printf ("IN MTU getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, SCPS_ROUTE, SCPS_MTU, &value, value_size);
		printf ("IN MTU setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_SMTU) {
		rc = scps_getsockopt (route_sock_id, SCPS_ROUTE, SCPS_SMTU, &value, &value_size);
		printf ("IN SMTU getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, SCPS_ROUTE, SCPS_SMTU, &value, value_size);
		printf ("IN SMTU setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_MIN_RATE) {
		rc = scps_getsockopt (route_sock_id, SCPS_ROUTE, SCPS_MIN_RATE, &value, &value_size);
		printf ("IN MIN_RATE getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, SCPS_ROUTE, SCPS_MIN_RATE, &value, value_size);
		printf ("IN MIN_RATE setsockopt RC = %d\n", rc);
	}


	if (rt->new_params_flag & GW_ROUTE_ATTRIB_FLOW_CONTROL) {
		rc = scps_getsockopt (route_sock_id, SCPS_ROUTE, SCPS_FLOW_CONTROL, &value, &value_size);
		printf ("IN FLOW_CONTROL getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, SCPS_ROUTE, SCPS_FLOW_CONTROL, &value, value_size);
		printf ("IN FLOW_CONTROL setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_SEND_BUFFER) {
		rc = scps_getsockopt (route_sock_id, SCPS_SOCKET, SCPS_SO_SNDBUF, &value, &value_size);
		printf ("IN SO_SNDBUF getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, SCPS_SOCKET, SCPS_SO_SNDBUF, &value, value_size);
		printf ("IN SO_SNDBUF setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_RECEIVE_BUFFER) {
		rc = scps_getsockopt (route_sock_id, SCPS_SOCKET, SCPS_SO_RCVBUF, &value, &value_size);
		printf ("IN SO_RCVBUF getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, SCPS_SOCKET, SCPS_SO_SNDBUF, &value, value_size);
		printf ("IN SO_RCVBUF setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_MIN_RTO_VALUE) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_RTOMIN, &value, &value_size);
		printf ("IN SCPSTP_RTOMIN getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_RTOMIN, &value, value_size);
		printf ("IN SCPSTP_RTOMIN setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_MAX_RTO_VALUE) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_RTOMAX, &value, &value_size);
		printf ("IN SCPSTP_RTOMAX getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_RTOMAX, &value, value_size);
		printf ("IN SCPSTP_RTOMAX setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_MAX_RTO_CTR) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_TIMEOUT, &value, &value_size);
		printf ("IN SCPSTP_TIMEOUT getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_TIMEOUT, &value, value_size);
		printf ("IN SCPSTP_TIMEOUT setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_MAX_PERSIST_CTR) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_MAXPERSIST_CTR, &value, &value_size);
		printf ("IN MAXPERSIST_CTR getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_MAXPERSIST_CTR, &value, value_size);
		printf ("IN MAXPERSIST_CTR setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_RTO_PERSIST_MAX) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_RTOPERSIST_MAX, &value, &value_size);
		printf ("IN RTOPERSIST_MAX getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_RTOPERSIST_MAX, &value, value_size);
		printf ("IN RTOPERSIST_MAX setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_RTO_PERSIST_CTR) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_RTOPERSIST_MAX, &value, &value_size);
		printf ("IN RTOPERSIST_CTR getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_RTOPERSIST_MAX, &value, value_size);
		printf ("IN RTOPERSIST_CTR setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_EMBARGO_FAST_RXMIT_CTR) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_EMBARGO_FAST_RXMIT_CTR, &value, &value_size);
		printf ("IN EMBARGO_FAST_RXMIT_CTR getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_EMBARGO_FAST_RXMIT_CTR, &value, value_size);
		printf ("IN EMBARGO_FAST_RXMIT_CTR setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_TWO_MSL_TIMEOUT) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_2MSLTIMEOUT, &value, &value_size);
		printf ("IN TWO_MSL_TIMEOUT getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_2MSLTIMEOUT, &value, value_size);
		printf ("IN TWO_MSL_TIMEOUT setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_ACK_BEHAVE) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_ACKBEHAVE, &value, &value_size);
		printf ("IN ACKBEHAVE getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_ACKBEHAVE, &value, value_size);
		printf ("IN ACKBEHAVE setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_ACK_DELAY) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_ACKDELAY, &value, &value_size);
		printf ("IN ACKDELAY getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_ACKDELAY, &value, value_size);
		printf ("IN ACKDELAY setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_ACK_FLOOR) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_ACKFLOOR, &value, &value_size);
		printf ("IN ACKFLOOR getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_ACKFLOOR, &value, value_size);
		printf ("IN ACKFLOOR setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_TIME_STAMPS) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_TIMESTAMP, &value, &value_size);
		printf ("IN TIMESTAMP getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_TIMESTAMP, &value, value_size);
		printf ("IN TIMESTAMP setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_SNACK) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_SNACK, &value, &value_size);
		printf ("IN SNACK getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_SNACK, &value, value_size);
		printf ("IN SNACK setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_SNACK_DELAY) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_SNACK_DELAY, &value, &value_size);
		printf ("IN SNACK_DELAY getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_SNACK_DELAY, &value, value_size);
		printf ("IN SNACK_DELAY setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_COMPRESS) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_COMPRESS, &value, &value_size);
		printf ("IN COMPRESS getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_COMPRESS, &value, value_size);
		printf ("IN COMPRESS setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_VEGAS_ALPHA) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_VEGAS_ALPHA, &value, &value_size);
		printf ("IN VEGAS_ALPHA getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_VEGAS_ALPHA, &value, value_size);
		printf ("IN VEGAS_ALPHA setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_VEGAS_BETA) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_VEGAS_BETA, &value, &value_size);
		printf ("IN VEGAS_BETA getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_VEGAS_BETA, &value, value_size);
		printf ("IN VEGAS_BETA setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_VEGAS_GAMMA) {
		rc = scps_getsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_VEGAS_GAMMA, &value, &value_size);
		printf ("IN VEGAS_GAMMA getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, PROTO_SCPSTP, SCPSTP_VEGAS_GAMMA, &value, value_size);
		printf ("IN VEGAS_GAMMA setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_NO_DELAY) {
		rc = scps_getsockopt (route_sock_id, SCPS_SOCKET, SCPS_SO_NDELAY, &value, &value_size);
		printf ("IN NO_DELAY getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, SCPS_SOCKET, SCPS_SO_NDELAY, &value, value_size);
		printf ("IN NO_DELAY setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_TCP_ONLY) {
		rc = scps_getsockopt (route_sock_id, SCPS_SOCKET, SCPS_TCPONLY, &value, &value_size);
		printf ("IN TCP_ONLY getsockopt RC = %d\n", rc);
		rc = scps_setsockopt (s_id, SCPS_SOCKET, SCPS_TCPONLY, &value, value_size);
		printf ("IN TCP_ONLY setsockopt RC = %d\n", rc);
	}

	if (rt->new_params_flag & GW_ROUTE_ATTRIB_CONG_CONTROL) { 
		switch (rt->cong_control)  {
			case SCPSTP_CONGEST:
				value = 0;
				rc = scps_setsockopt (s_id, SCPS_ROUTE, SCPSTP_CONGEST, &value, value_size);
				printf ("IN PURE_RATE RC = %d\n", rc);
			break;

			case SCPSTP_VJ_CONGEST:
				value = 1;
				rc = scps_setsockopt (s_id, SCPS_ROUTE, SCPSTP_VJ_CONGEST, &value, value_size);
				printf ("IN VJ RC = %d\n", rc);
			break;

			case SCPSTP_VEGAS_CONGEST:
				value = 1;
				rc = scps_setsockopt (s_id, SCPS_ROUTE, SCPSTP_VEGAS_CONGEST, &value, value_size);
				printf ("IN VEGAS  RC = %d\n", rc);
			break;

			case SCPSTP_FLOW_CONTROL_CONGEST:
				value = 1;
				rc = scps_setsockopt (s_id, SCPS_ROUTE, SCPSTP_FLOW_CONTROL_CONGEST, &value, value_size);
				printf ("IN FLOW_CONTROL RC = %d\n", rc);
			break;


		}



	}
#ifdef XXXX
#define GW_ROUTE_ATTRIB_CONG_CONTROL            0x0000008
#endif /* XXXX */
}

#endif /* GATEWAY */

