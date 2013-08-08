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

#include <string.h>
#include "scps.h"
#include "scpstp.h"
#include "scpsudp.h"
#include <stdio.h>		/* temporary  - for udp_WriteTo() */

#include "scps_ip.h"

int scps_np_get_template (scps_np_rqts * rqts,
			  scps_np_template * templ);

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: udp_socket.c,v $ -- $Revision: 1.16 $\n";
#endif

extern uint32_t tp_now;
extern struct timeval end_time;
extern float elapsed_time;

extern int nl_default;
/*
 * Open a UDP "connection" to a particular destination. 
 * Doesn't do a "connect" yet; only specifies local port 
 * and address.
 */
int
udp_Open (int sockid, word lport)
{
  udp_Socket *s = (udp_Socket *) scheduler.sockets[sockid].ptr;

  if (udp_Common (s) < 0)
    return (-1);

  if (lport == 0)
    lport = (u_short) tp_now;	/* hope nobody else is using this port */
  s->myport = htons ((u_short) lport);
  s->hisport = 0;

  s->ph.nl_head.ipv4.dst = 0;

  gettimeofday (&(s->start_time), NULL);

  return (0);
}

/*
 * Close a UDP socket
 */
int
udp_Close (int sockid)
{
  udp_Socket *s = (udp_Socket *) scheduler.sockets[sockid].ptr;

  if (s->myport == 0)
    {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  udp_Unthread (s);
  return (0);
}

/*
 * Try to send the UDP datagram. Enqueue at most 
 * one UDP datagram if there's room, and then try 
 * to send it. Return the number of bytes queued. 
 * Otherwise, throw away the data, return -1 and 
 * set EWOULDBLOCK for non-blocking, or just block.
 *
 * This will need to be modified to provide a way 
 * for the application to flush the one-datagram 
 * buffer. timer? "system call"? later
 */
int
udp_WriteTo (int sockid, byte * dp, int len, scps_np_addr ina, word port)
{
  uint32_t bytes_sent = 0;
#ifdef SCPSSP
  int temp;
#endif /* SCPSSP */
  int cc = 0;
  struct mbuff *mbuffer;
  struct mbcluster *mbcluster;
  udp_Socket *s = (udp_Socket *) scheduler.sockets[sockid].ptr;

  if (s->myport == 0)		/* minimal error checking */
    {
      SET_ERR (SCPS_EBADF);
      goto cleanup;
      return (-1);
    }

  if (len > MAX_UDP_PAYLOAD)	/* enforce max UDP datagram size ??????? */
    {
      SET_ERR (SCPS_EMSGSIZE);
      goto cleanup;
      return (-1);
    }

  if ((s->rt_route->MTU) &&	/* enforce MTU */
      ((len + UDP_HDR_LEN + s->np_size + s->sp_size) > s->rt_route->MTU))
    {
      SET_ERR (SCPS_EMSGSIZE);
      goto cleanup;
      return (-1);
    }
		
  if ((s->rt_route && s->rt_route->flags & RT_LINK_AVAIL) &&
      (s->rt_route->current_credit >=
       ((int) s->send_buff->start->m_ext.len +
	UDP_HDR_LEN + s->sp_size + 20)))	/* hard-coded for IP! */
    {
      s->buff_full = FALSE;
    }

  if (s->buff_full)
    {
      SET_ERR (SCPS_ENOBUFS);
      goto cleanup;
      return (-1);
    }

  if ((cb_cpdatin (s->app_sbuff, dp, len, 0, 0)) != len)
    {
      SET_ERR (SCPS_ENOBUFS);
      goto cleanup;
      return (-1);
    }
  s->ph.nl_head.ipv4.dst = ina;
  s->hisport = port;
  s->his_ipv4_addr = htonl ((uint32_t) ina);

  /* Build the packet! */

  if ((mcput (s->send_buff->start, s->app_sbuff->start,
	      s->app_sbuff->read_off, len, 1)) != len)
    {
      printf ("\nbigs problems in udp_WriteTo()\n");
      fflush (stdout);
      return (-1);
    }

  /* Fill in the requirements structure */
  s->np_rqts.tpid = SCPSUDP;
  s->np_rqts.ipv4_dst_addr = htonl (ina);
#ifdef UDP_GATEWAY
  s->np_rqts.ipv4_src_addr = s->my_ipv4_addr;
#else /* UDP_GATEWAY */
  s->np_rqts.ipv4_src_addr = ntohl (local_addr);
#endif /* UDP_GATEWAY */
  s->np_rqts.timestamp.format = 0;
  s->np_rqts.timestamp.ts_val[0] =
    s->np_rqts.timestamp.ts_val[1] = 0;
  /* s->np_rqts.bqos.precedence = rqts->bqos.precedence; */
  s->np_rqts.bqos.routing = 0;
  s->np_rqts.bqos.pro_specific = 0;
  s->np_rqts.eqos.ip_precedence = 0;
  s->np_rqts.eqos.ip_tos = 0;
  s->np_rqts.cksum = 0;
  s->np_rqts.int_del = 0;
  s->np_rqts.nl_protocol = nl_default;

#ifdef SCPSSP
  /* Fill in the SP requirements structure */
  s->sp_rqts.np_rqts.tpid = SP;
  s->sp_rqts.np_rqts.ipv4_dst_addr = htonl (ina);
#ifdef UDP_GATEWAY
  s->sp_rqts.np_rqts.ipv4_src_addr = s->myaddr;
#else /* UDP_GATEWAY */
  s->sp_rqts.np_rqts.ipv4_src_addr = ntohl (local_addr);
#endif /* UDP_GATEWAY */
  s->sp_rqts.np_rqts.timestamp.format = 0;
  s->sp_rqts.np_rqts.timestamp.ts_val[0] =
    s->sp_rqts.np_rqts.timestamp.ts_val[1] = 0;
  s->sp_rqts.np_rqts.bqos.precedence = 0;	/* rqts->bqos.precedence; */
  /* s->sp_rqts.np_rqts.bqos.routing = rqts->bqos.precedence; */
  s->sp_rqts.np_rqts.bqos.pro_specific = 0;
  s->sp_rqts.np_rqts.eqos.ip_precedence = 0;
  s->sp_rqts.np_rqts.eqos.ip_tos = 0;
  s->sp_rqts.np_rqts.cksum = 0;	/* rqts->cksum; */
  s->sp_rqts.np_rqts.int_del = 0;
  s->sp_rqts.np_rqts.nl_protocol = nl_default;
  s->sp_rqts.tpid = SCPSUDP;
  s->sp_rqts.sprqts = 0;
  s->np_rqts.tpid = SP;
#ifdef SECURE_GATEWAY
  s->sp_rqts.secure_gateway_rqts = s->rt_route->secure_gateway_rqts;
#endif /* SECURE_GATEWAY */
  s->sp_size = sp_hdr_size (s->sp_rqts);
  temp = s->sp_size + (s->sp_size % sizeof (uint32_t));
  s->sh_off = s->th_off - temp;
#endif /* SCPSSP */

  switch (s->np_rqts.nl_protocol) { 
	case NL_PROTOCOL_IPV4:
		s->np_size = ip_get_template (&(s->np_rqts), &(s->ip_templ));
		break;

	case NL_PROTOCOL_NP:
		s->np_size = scps_np_get_template (&(s->np_rqts), &(s->np_templ));
		break;
  }

  udp_BuildHdr (s, s->send_buff->start);

  s->app_sbuff->size -= len;	/* size should be zero now! */
  s->buff_full = TRUE;

  if ((s->rt_route && s->rt_route->flags & RT_LINK_AVAIL) &&
      (s->rt_route->current_credit >=
       ((int) s->send_buff->start->m_ext.len +
	UDP_HDR_LEN + s->sp_size + 20)))	/* hard-coded for IP! */
    {
      cc = udp_Coalesce (s, &bytes_sent);
      bytes_sent = len;
      s->buff_full = FALSE;
      /* Let them know how much data we actually wrote to the transport */
      if (cc > 0)
	s->user_data += len;
    }

cleanup:

  /*
     * This all looks kind of crusty 
   */
  /* dequeue all clusters */
  for (mbcluster = deq_mclus (s->app_sbuff); mbcluster;
       mbcluster = deq_mclus (s->app_sbuff))
    free_mclus (mbcluster);

  s->app_sbuff->read_head = s->app_sbuff->write_head = NULL;
  s->app_sbuff->write_off = s->app_sbuff->bytes_beyond = 0;
  mbuffer = deq_mbuff (s->send_buff);
  free_mbuff (mbuffer);		/* free mbuff and all clusters */

  if (!(mbuffer = alloc_mbuff (MT_HEADER)))	/* get back our mbuff */
    {
      SET_ERR (SCPS_ENOMEM);
      exit (-1);		/* not the thing to do */
    }
  if (!(enq_mbuff (mbuffer, s->send_buff)))
    printf ("MBUFFER ENQUEUEING ERROR in udp_Coalesce()\n");
  if (cc)
    return (len);
  else
    {
      SET_ERR (SCPS_ENOBUFS);
      return (-1);
    }
}

int
udp_Read (int sockid, caddr_t data, int size)
{
  int read;
  struct mbuff *mbuffer;
  udp_Socket *sock = (udp_Socket *) scheduler.sockets[sockid].ptr;

  if (sock->myport == 0)	/* minimal error checking */
    {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  /* If there is no mbuff and associated data available, then we block */

  if (!(mbuffer = sock->receive_buff->start))
    {
      ((tp_Socket *) scheduler.sockets[sockid].ptr)->thread->status = Blocked;
      scheduler.num_runable--;
      scheduler.sockets[sockid].read = 1;
      sched ();
      mbuffer = sock->receive_buff->start;
    }

  /*
   * Make sure the size request is less than or equal 
   * to the amount of memory we have available to this connection
   */

  if (size > mbuffer->m_ext.len)
    size = mbuffer->m_ext.len;

  /*
   * At this point, it should just be a matter 
   * of doing a cb_cpdatout() into the data pointer...
   */

  read = cb_cpdatout (sock->app_rbuff, data, size);

#ifndef GATEWAY 
  if (!(sock->app_rbuff->size))
    sock->thread->read_socks &= ~(1 << sock->sockid);
#endif /* GATEWAY  */

  if (read == 0)
    {
      printf ("cb_cpdatout returns 0\t");
      printf ("size = %d, app rbuff size = %d\n", size, (int) sock->app_rbuff->size);
      SET_ERR (SCPS_EWOULDBLOCK);
      return (-1);
    }

  /* Trim off the associated mbuff from the receive-buffer.   */

  /*  mb_rtrim (sock->receive_buff, read); */
  mbuffer = deq_mbuff (sock->receive_buff);
  free_mbuff (mbuffer);
  return (read);
}

int
scps_recvfrom (int sockid, void *data, int size, void *ina, int *ina_len)
{
  int read;
  udp_Header *up;
  in_Header *ip;
  udp_Socket *sock = (udp_Socket *) scheduler.sockets[sockid].ptr;

  if ((sock->myport == 0) || (sock->Initialized != SCPSUDP))
    {				/* minimal error checking */
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  /*
   * Make sure the size request is less than or equal 
   * to the amount of memory we have available to this 
   * connection
   */
  if (size > sock->app_rbuff->max_size)
    size = sock->app_rbuff->max_size;
  if (size > MAX_UDP_PAYLOAD)
    size = MAX_UDP_PAYLOAD;

  if (sock->app_rbuff->size)
    {
      /* this is how we enforce segment boundaries on reads */
      if (size > sock->receive_buff->start->m_ext.len)
	size = sock->receive_buff->start->m_ext.len;
    }
  else
    {
      SET_ERR (SCPS_EWOULDBLOCK);	/* nothing here to read now */
      return (-1);
    }

  /*
   * At this point, it should just be a matter of doing a cb_cpdatout()
   * into the data pointer...
   */

  read = cb_cpdatout (sock->app_rbuff, data, size);

  if (read == 0)
    {
      printf ("cb_cpdatout returns 0\t");
      SET_ERR (SCPS_EWOULDBLOCK);
      return (-1);
    }

  /* Grab the sender's address from the mbuff... */

  ip = (in_Header *) (sock->receive_buff->start->m_pktdat);
  up = (udp_Header *) (sock->receive_buff->start->m_pktdat +
		       inv4_GetHdrlenBytes ((in_Header *) (sock->receive_buff->start->m_pktdat)));
  memcpy (&(((struct sockaddr_in *) ina)->sin_port), &(up->srcPort),
	  sizeof (unsigned int));
  memcpy (&(((struct sockaddr_in *) ina)->sin_addr),
	  &(ip->nl_head.ipv4.source), sizeof (uint32_t));

  /* Trim off the associated mbuff from the receive-buffer.   */
  mb_rtrim (sock->receive_buff, read);

  return (read);
}
