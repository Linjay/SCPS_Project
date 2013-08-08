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
#include "scpsudp.h"
#include "rs_config.h"
#include <stdio.h>

#ifdef UDP_GATEWAY
extern int gateway_mega_udp_socket;
extern void *memset (void *s, int c, size_t n);
extern GW_ifs gw_ifs;
extern route *def_route;
extern route *other_route;
#endif /* UDP_GATEWAY */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: udp_handler.c,v $ -- $Revision: 1.12 $\n";
#endif

extern udp_Socket *udp_allsocs;	/* Pointer to first UDP socket */
extern uint32_t tp_now;

#define ADD_READ(z) \
        { \
          if (!(z->read_parent)) \
             { \
                ((tp_Socket *) z)->read_next = ((tp_Socket *) z)->thread->read_socks; \
                if (z->read_next) \
                  ((tp_Socket *) z)->read_next->read_prev = (tp_Socket *)z; \
                ((tp_Socket *) z)->read_prev = (tp_Socket *)(0x0); \
                ((tp_Socket *) z)->thread->read_socks = (tp_Socket *)z; \
                z->read_parent = (caddr_t *)&(z->thread->read_socks); \
             } \
        }

/*
 * Handler for incoming UDP packets.
 */
/* Note: fix udp_handler to use rqts structure */
void
udp_Handler (scps_np_rqts * rqts, int len, tp_Header * tp)
{
  udp_Header *up;
  char ugly[8];
  tp_PseudoHeader ph;
  udp_Socket *s;
  byte *dp;
  struct mbuff *mbuffer;
  struct mbcluster *old_write_head;
  int old_write_off, temp_len;
  char *a;
#ifdef UDP_GATEWAY
  scps_np_addr dst_addr;
  word dst_port;
#endif /* UDP_GATEWAY */

  up = (udp_Header *) ((byte *) tp);

  if ((int) tp & (sizeof (int32_t) - 1))	/* must align xport hdr */
    {
      /* Reach in and get tp header length */
      a = (char *) tp;
      /* You'd think that we could just cast tp to a (char *) in the 
       * memcpy call, but on SunOS 4.1.3 it JUST DOESN'T WORK.  On
       * FreeBSD 2.2.2, it works fine.  
       */
      memcpy (ugly, a, 8);
      up = (udp_Header *) ugly;
    }

  if (len != ntohs (up->len))
    {
      printf ("len = %d, up->len = %d(%d)\n", len, up->len, ntohs (up->len));
      udp_DumpHeader ((in_Header *) 0, up,
		      "Discarding (IP/UDP length mismatch)");
      return;
    }

  /* demux to sockets. Accept UDP segments from 
   * any address and port, i.e., 
   * we're not doing recvfrom(), just receive() 
   */

  for (s = udp_allsocs; s; s = s->next)
    if (up->dstPort == s->myport)
      break;

  if (s == NIL)
#ifndef UDP_GATEWAY
    {
      return;
    }
#else /* UDP_GATEWAY */
    {
      if (gateway_mega_udp_socket == -1)
	{
	  struct sockaddr_in dummy_sin;
	  int rc;

	  memset ((char *) &dummy_sin, 0, sizeof (dummy_sin));
	  dummy_sin.sin_len = sizeof (dummy_sin);
	  dummy_sin.sin_family = AF_INET;
	  dummy_sin.sin_addr.s_addr = htonl (INADDR_ANY);
	  dummy_sin.sin_port = htons (4999);

	  gateway_mega_udp_socket = scps_socket (AF_INET, SOCK_DGRAM, 0);
	  rc = scps_bind (gateway_mega_udp_socket, (struct sockaddr *) &dummy_sin,
			  sizeof (dummy_sin));
	}
      s = (udp_Socket *) scheduler.sockets[gateway_mega_udp_socket].ptr;
      s->gw_udp_port_from = rqts->divert_port_number;
      s->np_rqts.dst_addr = rqts->ipv4_src_addr;
      s->np_rqts.src_addr = rqts->ipv4_dst_addr;
      dst_addr = rqts->dst_addr;
      dst_port = ntohs (up->dstPort);

      memcpy (&(((tp_Socket *) s)->myaddr), &rqts->ipv4_src_addr, sizeof (rqts->ipv4_src_addr));
      ((tp_Socket *) s)->myport = (u_short) (up->srcPort);

    }
#endif /* UDP_GATEWAY */

  if (up->checksum != 0)
    {				/* a zero checksum in the header => checksum disabled */
      ph.nl_head.ipv4.src = htonl (rqts->ipv4_src_addr);	/* don't bother computing it */
      ph.nl_head.ipv4.dst = htonl (rqts->ipv4_dst_addr);
      ph.nl_head.ipv4.mbz = 0;
      ph.nl_head.ipv4.protocol = SCPSUDP;
      ph.nl_head.ipv4.length = htons (len);
      ph.nl_head.ipv4.checksum = checksum ((word *) up, len);
    }

  dp = (byte *) up + UDP_HDR_LEN;
  len -= UDP_HDR_LEN;

  if (len <= 0)
    return;

  /* 
   * Place the data into the receive buffer's cluster chain!
   * First, put the header into an mbuff, then copy the data
   * into a cluster. 
   */
  if ((mbuffer = alloc_mbuff (MT_HEADER)))
    {

      int offset = mbuffer->m_offset;
      mbuffer->m_len = UDP_HDR_LEN;
      memcpy ((&(mbuffer->m_pktdat) + offset), tp, mbuffer->m_len);

      /* Copy the data into the receive_buffer */
      old_write_head = s->app_rbuff->write_head;
      old_write_off = s->app_rbuff->write_off;
      if ((cb_cpdatin (s->app_rbuff, dp, len, 0, 0)) <= 0)
	{
	  /* add counter of trashed UDP segs!!!!! */
	  free_mbuff (mbuffer);
	  return;
	}

      if (old_write_head == NULL)
	{
	  /* We entered cb_cpdatin w/o a write_head, and one
	   * was provided to us. Figure out where it was since
	   * we might have done a write > SMCLBYTES. write_off
	   * will always have started at 0 in this case.
	   * 12/18: cb_cpdatin will NOT provide us with a 
	   * write-head if the write ends on a cluster-boundary :(
	   * This shows up when the writes are exactly one cluster
	   * in length... It's good that Gregs found this!!!
	   * We need to put one in if not...
	   */

	  if (!(old_write_head = s->app_rbuff->write_head))
	    /* We are full... No more for us */
	    old_write_head = s->app_rbuff->last;

	  temp_len = len - s->app_rbuff->write_off;

	  while (temp_len > 0)
	    {
	      old_write_head = old_write_head->c_prev;
	      temp_len -= SMCLBYTES;
	    }
	}

      if ((mcput (mbuffer, old_write_head, old_write_off, len, 0)) == len)
	{
	  /* Place the new segment into the receive queue */
	  enq_mbuff (mbuffer, s->receive_buff);

#ifndef UDP_GATEWAY
#ifdef GATEWAY_SELECT
	  /* Wake up the receiver */
	  if ((!(s->read_parent)) || s->thread->status == Blocked)
	    {
	      s->read = 0;
	      /*
	       * Make sure the socket is on the list of readable sockets
	       */
	      ADD_READ ( ((tp_Socket *) s));

	      if (s->thread->status == Blocked)
		{
		  s->thread->status = Ready;
		  scheduler.num_runable++;
		}
	    }
#else /* GATEWAY_SELECT */
          s->thread->read_socks |= (1 << s->sockid);

          if ((s->thread->status == Blocked) &&
              (((scheduler.sockets[s->sockid].read) &&
                (s->app_rbuff->size >= scheduler.sockets[s->sockid].read))))
            {
              scheduler.sockets[s->sockid].read = 0;
              s->thread->status = Ready;
              scheduler.num_runable++;
            }
#endif /* GATEWAY_SELECT */

#else /* UDP_GATEWAY */
	  {
#define UDP_BUFFER_SIZE 8192
	    int to_be_moved;
	    unsigned char temp_buff[BUFFER_SIZE];
	    int bytes_read;
	    int tmp;

	    to_be_moved = min (len, UDP_BUFFER_SIZE);

            if (gw_ifs.aif_divport == s->gw_udp_port_from) {
                s->rt_route = other_route;
                s->rt_route_def = other_route;
	    } else {
                s->rt_route = def_route;
                s->rt_route_def = def_route;
	    }
            s->sp_rqts.secure_gateway_rqts = s->rt_route->secure_gateway_rqts;
/* get the data and send it on its merry way */
	    if (to_be_moved)
	      {
		bytes_read = scps_read (s->sockid, temp_buff, to_be_moved);
		if (bytes_read != to_be_moved)
		  {
		    printf ("READ FAILED err = %d %d %d\n", GET_ERR (),
			    to_be_moved, bytes_read);
		    tmp = bytes_read;
		  }
		else
		  {
		    tmp = udp_WriteTo (s->sockid, temp_buff, bytes_read,
				       htonl (dst_addr), htons (dst_port));
		    if (tmp != bytes_read)
		      {
			printf ("WRITE FAILED err = %d %d %d\n", GET_ERR (),
				bytes_read, tmp);
		      }
		  }
	      }
	    else
	      {
		printf ("In gateway_move_data CAN'T WRITE DATA!\n");
	      }
	  }
#endif /* UDP_GATEWAY */
	}
      else
	{
	  free_mbuff (mbuffer);
	}
    }
}
