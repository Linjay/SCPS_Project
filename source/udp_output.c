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
#include <stdio.h>
#include <sys/types.h>

#ifdef SCPSSP
#include "scps_sp.h"
int sp_trequest (tp_Socket * s, route * nroute, int *bytes_sent,
		 struct mbuff *m, int th_off);
#endif /* SCPSSP */

#include "scps_ip.h"

int scps_np_trequest (tp_Socket * s, scps_ts * ts, route * nproute, uint32_t
		      length, struct mbuff *m, u_char th_off);

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: udp_output.c,v $ -- $Revision: 1.13 $\n";
#endif

extern unsigned short udp_id;
extern uint32_t tcp_now;
extern struct msghdr out_msg;

int
udp_BuildHdr (s, mbuffer)
     udp_Socket *s;
     struct mbuff *mbuffer;
{
  udp_Header *uh;

#ifdef SCPSSP
  sp_Header *sh;
#endif /* SCPSSP */

  in_Header *nh;

  short offset;

  if (!(mbuffer))
    {
      printf ("\ndisaster in udp_BuildHdr()\n");
      fflush (stdout);
      return (-1);
    }

  offset = (short) (s->th_off);
  uh = (udp_Header *) (mbuffer->m_pktdat + offset);

#ifdef SCPSSP
  offset = (short) (s->sh_off);
  sh = (sp_Header *) (mbuffer->m_pktdat + offset);
#endif /* SCPSSP */

  offset = (short) (s->nh_off);
  nh = (in_Header *) (mbuffer->m_pktdat + offset);

  mbuffer->m_offset = offset;

  uh->srcPort = s->myport;
  uh->dstPort = s->hisport;
  uh->len = ntohs (mbuffer->m_ext.len + UDP_HDR_LEN);	/* data length */
  uh->checksum = 0;
  mbuffer->m_len = UDP_HDR_LEN;

  mbuffer->m_ext.checksum =	/* should we do the whole checksum at once? */
    data_checksum (((struct mbcluster *) mbuffer->m_ext.ext_buf),
		   mbuffer->m_ext.len, mbuffer->m_ext.offset);

  udp_FinalCksum (s, mbuffer, uh);
#ifdef UDP_GATEWAY
  uh->checksum = 0;
#endif /* UDP_GATEWAY */

  if (s->np_rqts.nl_protocol == NL_PROTOCOL_IPV4) { /* PDF WHY NOT NP */
  /* np_build_hdr */
	nh->nl_head.ipv4.vht = htons (0x4500);
	nh->nl_head.ipv4.identification = htons (udp_id++);
	nh->nl_head.ipv4.frag = 0;
	nh->nl_head.ipv4.ttlProtocol = htons ((250 << 8) + SCPSUDP);
	nh->nl_head.ipv4.checksum = 0;
	nh->nl_head.ipv4.source = local_addr;
	nh->nl_head.ipv4.destination = htonl (s->his_ipv4_addr);		/* get rid of htonl everywhere??? */
	nh->nl_head.ipv4.length = s->np_size + s->sp_size + UDP_HDR_LEN + mbuffer->m_ext.len;
	nh->nl_head.ipv4.length = htons (nh->nl_head.ipv4.length);
	nh->nl_head.ipv4.checksum = ~checksum ((word *) nh, sizeof (in_Header));
  }
  return (1);

}

uint32_t
udp_Coalesce (udp_Socket * s, uint32_t * bytes_sent)
{
  uint32_t long_temp;
  int cc = 0;
  struct mbuff *mbuffer;
  struct mbcluster *mbcluster;

  /* 
   * Build the headers in the output buffer, but then keep 
   * the actual data in the clusters - avoid an outbound copy.
   *
   * assume there is a out_msg structure available...
   *
   */

  mbuffer = deq_mbuff (s->send_buff);

  /*
   * Tweak the template length field - everything but network header 
   */

  long_temp = mbuffer->m_len + mbuffer->m_ext.len + s->np_size;

  if (s->np_rqts.nl_protocol == NL_PROTOCOL_IPV4) {
    s->ip_templ.nl_head.ipv4.length = htons (long_temp);
  }

  /*
   * Call ip_trequest() to build the network protocol header
   * and push the packet onto an interface/queue
   */


  if ((s->rt_route->current_credit >= long_temp) &&
      (bytes_sent) && (s->rt_route->max_burst_bytes >= long_temp))
    {
#ifdef SCPSSP
      cc = sp_trequest ((tp_Socket *) s, NULL, (int *) bytes_sent, mbuffer, 8);
#else /* SCPSSP */
	switch (s->np_rqts.nl_protocol) {
		case NL_PROTOCOL_IPV4:
			cc = ip_trequest ((tp_Socket *) s, mbuffer, bytes_sent);
			break;
		case NL_PROTOCOL_NP:
			/* Fix this it's a mess, get rid of the 8 and put the right thing in */
			cc = scps_np_trequest ((tp_Socket *) s, NULL, NULL, *bytes_sent,
			 mbuffer, 8);
			break;
	}
#endif /* SCPSSP */
    }

  else
    {
      cc = 0;
      SET_ERR (SCPS_ENOBUFS);
    }

  if (cc)
    {
      s->rt_route->current_credit -= (int) long_temp;
      *bytes_sent = long_temp;
      s->total_data += long_temp;
    }
  /*
   * This all looks kind of crusty 
   */
  /* dequeue all clusters */
  for (mbcluster = deq_mclus (s->app_sbuff); mbcluster;
       mbcluster = deq_mclus (s->app_sbuff))
    free_mclus (mbcluster);

  s->app_sbuff->read_head = s->app_sbuff->write_head = NULL;
  s->app_sbuff->write_off = s->app_sbuff->bytes_beyond = 0;
  free_mbuff (mbuffer);		/* free mbuff and all clusters */

  if (!(mbuffer = alloc_mbuff (MT_HEADER)))	/* get back our mbuff */
    {
      SET_ERR (SCPS_ENOBUFS);
      exit (-1);		/* not the thing to do */
    }
  if (!(enq_mbuff (mbuffer, s->send_buff)))
    printf ("MBUFFER ENQUEUEING ERROR in udp_Coalesce()\n");

  return (cc);
}
