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

#include <stdio.h>
#include <sys/types.h>
#include "scps.h"
#include "net_types.h"
#include "scps_np.h"
#include "scpserrno.h"
#include "np_scmp.h"
#include "scpsnp_protos.h"
#include "scpstp.h"
#include "mib.h"
#include "string.h"

#ifdef GATEWAY
#include "rs_config.h"
extern GW_ifs gw_ifs;
extern struct _interface *sock_interface;
extern struct _interface *divert_interface;
  
#ifdef GATEWAY_DUAL_INTERFACE
#include "scpsudp.h" 
extern int special_port_number;
extern uint32_t special_ip_addr;
extern int scps_udp_port;
#endif /* GATEWAY_DUAL_INTERFACE */
 
#endif /* GATEWAY */

extern route *def_route;
extern route *other_route;

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: scps_np.c,v $ -- $Revision: 1.22 $\n";
#endif

extern void free (void *ptr);

static short PRINT_HDR;
byte outbuf[0x10000];
extern struct _ll_queue_element *in_data;
#ifndef LINUX
extern void *memset (void *s, int c, size_t n);
#endif /* LINUX */
extern void *malloc (size_t size);
extern int fclose (FILE * stream);
int get_np_template (scps_np_rqts * rqts, short *position);

extern ip_np_entry npAddrConvTable[];
np_Internals np_Int;

extern struct msghdr out_msg;
extern tp_Socket *tp_allsocs;

scps_np_addr np_local_addr;
scps_np_addr mc_local_addrs[MAX_NUM_GROUPS];
np_addr_type nptype2 = none;
npNextHopEntry npNextHopTable[MAX_ADDR];
npMultiNextHopEntry npMultiNextHopTable[MAX_NUM_GROUPS];
npPathEntry npPathTable[MAX_ADDR];

#define npNextHopFile       "npNextHopFile"
#define npIP_NP_File        "npIP_NP_File"
#define npMultiNextHopFile  "npMultiNextHopFile"
#define npPathFile	    "npPathFile"

uint32_t checksum (word * dp, int length);
short MC_mbr (uint32_t dst_addr);

extern uint32_t tp_now;
uint32_t time_last_corrupt_sent = 0;

uint32_t quench_addrs[MAX_ADDR];
uint32_t time_last_quench_sent[MAX_ADDR];


/* this is to test the purge; it assumes the queue will hold 100
 * pkts with congestion at 20%. i.e., 10 pkts. */
#define CONG_LEVEL   100
#define PURGE_AMT    20
#ifndef SET_ERR
#define SET_ERR(n) (scheduler.current->SCPS_errno = (n))
#endif 

extern struct route ipforward_rt;
np_mib npmib;

int
scps_np_get_template (rqts, np_templ)
     scps_np_rqts *rqts;
     scps_np_template *np_templ;
{
  short addrlen = 2, cur_index, mc_addr = FALSE;
  scps_np_addr np_addr;

  if (!rqts | !np_templ)
    return (-1);

  memset (&(np_templ->header), 0, sizeof (np_templ->header));
  memset (&(np_templ->pointers), 0, 10 * sizeof (short));

  np_templ->header[0] |= VPI;

  /* reserve header[1] for 'LENGTH' later.... */
  {
    int convert = 0;

    switch (rqts->tpid)
      {
      case SCMP:
	convert = 1;
	break;
      case SCPSCTP:
	convert = 4;
	break;
      case SCPSUDP:
	convert = 5;
	break;
      case SCPSTP:
	convert = 6;
	break;
      case SP:
	convert = 8;
	break;
      case IPV6AUTH:
	convert = 10;
	break;
      case IPV6ESP:
	convert = 11;
	break;

      default:
	SET_ERR (SCPS_EBADTPID);
	return (-1);

      }

    np_templ->header[2] |= (convert << 4);
  }


  /* do dest & src addr later */

  if (rqts->timestamp.format != None)
    {
      if (SUFF_CL_SYNC)
	np_templ->header[3] |= (rqts->timestamp.format << 3);
      else if (LOOP_CONTROL)
	np_templ->header[3] |= HP_MASK;
    }
  else if (LOOP_CONTROL)
    np_templ->header[3] |= HP_MASK;

  if (rqts->bqos.precedence || rqts->bqos.routing ||
      rqts->bqos.pro_specific)
    {
      np_templ->header[3] |= QOS_MASK;
    }

  /* do ExpAddr below..... */

  if (rqts->int_del)
    np_templ->header[4] |= INT_DEL_MASK;

  if (rqts->eqos.ip_precedence || rqts->eqos.ip_tos)
    np_templ->header[4] |= ExQOS_MASK;

  /* convert to NETWORK BYTE ORDER,  if necessary */
  np_addr = np_templ->dst_npaddr = htonl (Convert_to_np (ntohl
						      (rqts->ipv4_dst_addr), &mc_addr));

  /* if no returned address, problem with format */
  if (!np_addr)
    {
      SET_ERR (SCPS_EINVAL);
      return (-1);
    }
  np_templ->header[2] |= DA_MASK;

  /* check if this is a multicast address; if so, set the mc bit */
  if (mc_addr)
    np_templ->pointers[MC_PTR] = 0x1;

  /* determine the address length */
  if (nptype2 == es_basic || nptype2 == path_basic)
    addrlen = 2;
  else
    {
      addrlen = 4;
      if (mc_addr)
	{
	  SET_ERR (SCPS_EINVAL);
	  return (-1);
	}
    }

  /* set the extended address bit, if necessary */
  if (addrlen == 4)
    {
      np_templ->header[3] |= ExADD_MASK;
    }

  /* if src addr & *not* path, set the proper bit. Path doesn't
   * use source addresses. Ignore it if it's sent to us. */
  if (rqts->ipv4_src_addr &&
      nptype2 != path_basic && nptype2 != path_extended)
    {
      np_templ->header[3] |= SA_MASK;
      np_templ->pointers[SA_PTR] = 0x1;
    }


  /* flag 'bit field conts' & find start for hdr info */
  if (np_templ->header[4])
    {				/* max 4 octets of bit info for now */
      np_templ->header[3] |= BFC_MASK;
      np_templ->header[2] |= BFC1_MASK;
      cur_index = 5;
    }
  else if (np_templ->header[3])
    {
      np_templ->header[2] |= BFC1_MASK;
      cur_index = 4;
    }
  else				/* min 3 octets of bit info */
    cur_index = 3;

  /* can now start putting header info in */
  if (addrlen == 4)
    {
      np_templ->header[cur_index++] = np_addr >> 0x18;
      np_templ->header[cur_index++] = np_addr >> 0x10;
    }
  np_templ->header[cur_index++] = np_addr >> 8;
  np_templ->header[cur_index++] = np_addr;

  /* now step through all the rest of the bit flags... */

  /* See if any bits set in 3rd octet of hdr */
  if (np_templ->header[2] & BFC1_MASK)
    {

      /* SOURCE ADDRESS */
      if (np_templ->header[3] & SA_MASK)
	{
	  np_addr = np_templ->src_npaddr = htonl (Convert_to_np (ntohl
							      (rqts->ipv4_src_addr), NULL));

	  if (addrlen == 4)
	    {
	      np_templ->header[cur_index++] = np_addr >> 0x18;
	      np_templ->header[cur_index++] = np_addr >> 0x10;
	    }
	  np_templ->header[cur_index++] = np_addr >> 8;
	  np_templ->header[cur_index++] = np_addr;
	}

      /* BQoS: move this field from after the Loop Control
       * fields to before them.
       */

      if (np_templ->header[3] & QOS_MASK)
	{
	  if (rqts->bqos.precedence == USE_DEF_PREC)
	    np_templ->header[cur_index] = DEF_PREC;
	  else
	    np_templ->header[cur_index] = rqts->bqos.precedence;
	  np_templ->header[cur_index] = (np_templ->header[cur_index] << 2);
	  np_templ->header[cur_index] |= rqts->bqos.routing;
	  np_templ->header[cur_index] = (np_templ->header[cur_index] << 2);
	  np_templ->header[cur_index] |= rqts->bqos.pro_specific;

	  /* point to the BQoS field for easy Precedence access later */
	  np_templ->pointers[BQOS_PTR] = (short) cur_index;

	  cur_index++;
	}

      /* HOP COUNT  - initialize to default or maximum amt: all 1's */
      if (np_templ->header[3] & HP_MASK)
	{
	  if (npmib.npDefaultHopCount)
	    np_templ->header[cur_index] = npmib.npDefaultHopCount;		/* <--here, too */
	  else
	    np_templ->header[cur_index] = ~(np_templ->header[cur_index]);
	  cur_index++;
	}

      /* TIMESTAMP - just reserve space for this; will fill in with 'real'
         timestamp data when _trequest is called.
       */
      if (np_templ->header[3] & TS_MASK)
	{
	  np_templ->pointers[TS_PTR] = (short) cur_index;
	  cur_index += 3;	/* all timestamps use at least 3 octets */
	  /* only SCPS32 has the 4th octet of timestamp value */
	  if (rqts->timestamp.format == SCPS32)
	    cur_index++;
	}

      /* EXTENDED ADDRS: already taken care of above */

      /* see if any bit fields remain in next octet */
      if (np_templ->header[3] & BFC_MASK)
	{
	  /* IPv6 ADDR: already taken care of above */

	  /* EXPANDED QoS */
	  if (np_templ->header[4] & ExQOS_MASK)
	    {
	      if (rqts->eqos.ip_precedence == USE_DEF_PREC)
		np_templ->header[cur_index] |= DEF_IPPREC;
	      else
		np_templ->header[cur_index] = rqts->eqos.ip_precedence;
	      (np_templ->header[cur_index]) = ((np_templ->header[cur_index]) << 4);
	      np_templ->header[cur_index] |= rqts->eqos.ip_tos;
	      (np_templ->header[cur_index]) = ((np_templ->header[cur_index]) << 1);
	      cur_index++;
	    }
	  /* INTERMEDIATE DELIVERY -- nothing to do here */

	}
    }
  /* hdr_len will let _trequest know where to stick cksum */
  np_templ->hdr_len = cur_index;
  if (rqts->cksum)
    {
      (np_templ->header[2]) |= CKSUM_MASK;		/* flag hdr chsum */
      np_templ->hdr_len += 2;
    }
  np_templ->bitmask = (uint32_t) 0;	/* initialize the bitmask array */

  return (np_templ->hdr_len);
}

/*
 *  fully-connectionless API to the scps_np. The user passes the rqts
    and data to the NP, which puts it into a header and sends it out.
 *
 */
int
scps_np_dg_request (tp_Socket * s, scps_ts * ts, short length,
		    struct mbuff *m, u_char th_off)
{
  scps_np_template np_templ;
  int ret;

  /* create the np_template */
  ret = scps_np_get_template (&(s->np_rqts), &np_templ);

  /* let np_trequest create dg and send out the data; send NULL for
     'route' parameter since this is connectionless
   */
  if (ret > 0)
    ret = scps_np_trequest (s, ts, NULL, length, m, th_off);
  else
    /* else ERROR value from get_template will be returned below */
    ;

  return (ret);
}

int
scps_np_trequest (tp_Socket * s, scps_ts * ts, route * nproute, uint32_t
		  length, struct mbuff *m, u_char th_off)

{
  uint32_t chsum, next_mhop[MAX_ADDR];
  short len, ts_ptr, cur_prec;
  scps_np_addr dstaddr, nexthop = 0;
  int i, mcc = 0, cc = 0;
  scps_np_template *np_templ;
  int32_t te;
  NP_dg *np_dg;
  struct _interface *interface = scheduler.interface;
  struct _interface *interface_tmp;
  int done;
  struct addrs next_hop;

  np_templ = (scps_np_template *) (&(s->np_templ));
/*   inbuf = in_data; */
  npmib.npOutRequests++;

  check_sendqueues (np_templ);
  if ((np_templ->header[2] & BFC1_MASK) && (np_templ->header[3] & TS_MASK))
    {
      if (ts)
	{
	  ts_ptr = np_templ->pointers[TS_PTR];
	  np_templ->header[ts_ptr++] = ts->ts_val[0];
	  np_templ->header[ts_ptr++] = ts->ts_val[1];
	  np_templ->header[ts_ptr++] = ts->ts_val[2];
	  /* only SCPS32 has the 4th octet of timestamp value */
	  if (((ts_fmt) ((np_templ->header[3] & TS_MASK) >> 3)) == SCPS32)
	    np_templ->header[ts_ptr++] = ts->ts_val[3];
	}
      else
	/* insert proper timestamp here; note type 2 is undefined  */
      if (((ts_fmt) ((np_templ->header[3] & TS_MASK) >> 3)) == ISO24)
	;
    }
  if (m)
    {
      out_msg.msg_iovlen = buff_vec (m, &out_msg, 3);
      out_msg.msg_iov[2].iov_base = m->m_pktdat + s->th_off;
      out_msg.msg_iov[2].iov_len = m->m_len;
      /* len = length + np_templ->hdr_len; */
      len = m->m_len + m->m_ext.len + np_templ->hdr_len;
      te = (int32_t) (m->m_ext.len);
    }
  /* m == NULL, we're transmitting a SCMP packet; simple comp. to get len */
  else
    {
      out_msg.msg_iovlen = 2;
      len = length + np_templ->hdr_len;
    }

  np_templ->header[0] = VPI;
  np_templ->header[1] = 0;

  if (len < 0x100)		/* len will fit in 2nd byte of header - 8 bits */
    np_templ->header[1] = len;

  else
    {				/* else have to use all 13 bits */
      np_templ->header[0] |= ((len >> 8) & ~VPI);	/* get rid of 2nd byte of number */
      np_templ->header[1] |= (len & 0xFF);		/* this gets rid of 1st byte of number */

    }

  /* insert cksum if pointer set */
  if ((np_templ->header[2]) & CKSUM_MASK)
    {
      np_templ->header[np_templ->hdr_len - 2] = 0;
      np_templ->header[np_templ->hdr_len - 1] = 0;

      chsum = htons ((uint32_t) checksum ((word *) (np_templ->header),
					  (int) (np_templ->hdr_len - 2)));
      /* space for checksum already accounted for in _get_np_template;
       * therefore, must 'count back' to get to proper offset. */
      np_templ->header[np_templ->hdr_len - 2] = (chsum >> 8);
      np_templ->header[np_templ->hdr_len - 1] = chsum;
    }

  out_msg.msg_iov[1].iov_base = (void *) &(np_templ->header);
  if (m)
    out_msg.msg_iov[1].iov_len = np_templ->hdr_len;
  else
    out_msg.msg_iov[1].iov_len = len;

  s->np_size = np_templ->hdr_len;

  /* since we're routing over IP, want to use the IP addr only as
   * a link-layer address to pass to the lower layer.  */

  /* if multicast address, must check for multiple next hops */
  if (np_templ->pointers[MC_PTR])
    {
      memset (&(next_mhop), 0, MAX_ADDR * sizeof (uint32_t));

      /* if ES address, check that table */
      if (np_templ->pointers[SA_PTR])
	{
	  if (!get_next_mhop (ntohl (np_templ->dst_npaddr), next_mhop))
	    {
	      return (-1);
	    }
	}
      /* else, must be path; check that table */
      else
	{
	  if (!get_path_mhop (ntohl (np_templ->dst_npaddr), next_mhop))
	    {
	      npmib.npOutNoRoutes++;
	      return (-1);
	    }
	}
    }
  else
    {
      /* if path, get the dst from the path definition table */
      if (!(np_templ->header[3] & SA_MASK))
	dstaddr = get_path_dst (ntohl (np_templ->dst_npaddr), NULL);
      else
	dstaddr = ntohl (np_templ->dst_npaddr);

      if (!(nexthop = get_next_hop (dstaddr)))
	{
	  npmib.npOutNoRoutes++;
	  SET_ERR (SCPS_EHOSTUNREACH);
	  return (-1);
	}
    }
  if (np_templ->pointers[MC_PTR])
    {
      for (i = 0; i < MAX_ADDR && next_mhop[i]; i++)
	{
/* Find the correct corresponding interface */

          if (s->np_rqts.interface)
            interface_tmp = s->np_rqts.interface;
          else  
            interface_tmp = scheduler.interface;

	  done = 0;
	  while (!done && interface_tmp)
	    {
	      uint32_t addr = 0x01000000;
	      if ((next_mhop[i] == addr) &&
		  (interface_tmp->et_socket == ET_MAGIC))
		{
		  interface = interface_tmp;
		  done = 1;
		}
	      if ((next_mhop[i] != addr) &&
		  (interface_tmp->et_socket == 0))
		{
		  interface = interface_tmp;
		  done = 1;
		}
	      interface_tmp = interface_tmp->next;
	    }

	  next_hop.nl_head.ipv4_addr = htonl (next_mhop[i]);
	  mcc = ll_iovsend (interface, next_hop,
			    SCPSNP, (int) len, &out_msg, s->rt_route, &(s->np_rqts));

	  /* if this is the first next hop for this multicast
	   * or if ll_iovsend returned a lower value than 
	   * previously, flag this new value to be returned
	   * to the user 
	   */
	  if (!i || mcc < cc)
	    cc = mcc;
	}
      /* Since this is unreliable multicasting, we're counting *any* pkt
       * that was accepted by the lower layer as being sent. Therefore,
       * NONE of the copies must have been accepted by the lower layer for
       * it to be put on the precedence queue.
       */
      if (cc == -1)
	{
	  np_Int.send_pkts = TRUE;
	  /* we have to reserve NP space to hold this and then copy it in */
	  np_dg = (NP_dg *) malloc (sizeof (NP_dg));
/*
*  CHANGE BCOPY TO MEMCPY --
         bcopy((char*)(&(np_templ->header)),(char*)(&(np_dg->dg)), len);
*/
	  memcpy ((char *) (&(np_dg->dg)), (char *) (&(np_templ->header)), len);
	  np_dg->is_mc = TRUE;

	  /* keep all of the addresses since none of them worked */
	  for (i = 0; i < MAX_ADDR && next_mhop[i]; i++)
	    np_dg->next_addrs.next_mhop[i] = next_mhop[i];
	  np_dg->len = len;

	  np_Int.send_prec = TRUE;
	  /* if prec not specified, use default */
	  if (!(np_templ->pointers[BQOS_PTR]))
	    {
	      q_addt (np_Int.sendprec_q[DEF_PREC], (char *) np_dg);
	      if (DEF_PREC > np_Int.send_prec)
		np_Int.send_prec = DEF_PREC;
	    }
	  else
	    {
	      /* otherwise, go to the BQoS field, shift to get rid of routing rqts,
	       * and then use precedence to index proper prec queue */
	      cur_prec = (np_templ->header[np_templ->pointers[BQOS_PTR]]) >> 4;
	      q_addt (np_Int.sendprec_q[cur_prec], (char *) np_dg);
	      if (cur_prec > np_Int.send_prec)
		np_Int.send_prec = cur_prec;
	    }
	}
    }
  else
    {
/* Find the correct corresponding interface */

      if (!(np_templ->pointers[BQOS_PTR]))
	{
	  cur_prec = DEF_PREC;
	}
      else
	{
	  cur_prec = (np_templ->header[np_templ->pointers[BQOS_PTR]]) >> 4;
	}

      if (np_Int.sendprec_q[cur_prec]->q_len > 0)
	{
	  int is_mc = 0;
	  /* we have to reserve NP space to hold this and then copy it in */
	  np_dg = (NP_dg *) malloc (sizeof (NP_dg));
/*
*  CHANGE BCOPY TO MEMCPY --
            bcopy((char*)(&(in_data->data)),(char*)(&(np_dg->dg)), cc);
*/
	  memcpy ((char *) (&(np_dg->dg)), (char *) (&(in_data->data)), cc);
/* 
            np_dg->is_mc = FALSE;
            np_dg->next_addrs.next_hop = nexthop;
*/
	  np_dg->is_mc = is_mc;
	  if (is_mc)
	    {
	      for (i = 0; (next_mhop[i]); i++)
		{
		  np_dg->next_addrs.next_mhop[i] = next_mhop[i];
		}
	    }
	  else
	    {
	      np_dg->next_addrs.next_hop = nexthop;
	    }
	  np_dg->len = cc;
	  np_dg->src_addr = np_templ->dst_npaddr;

	  q_addt (np_Int.sendprec_q[cur_prec], (char *) np_dg);
	  np_Int.total_proc_pkts++;
	  /* if no other pkts waiting, set the flags */
	  if (np_Int.send_prec < cur_prec)
	    np_Int.send_prec = cur_prec;
	  np_Int.send_pkts = TRUE;

	  check_sendqueues (np_templ);
	  if (np_Int.total_proc_pkts >= CONG_LEVEL)
	    purge_send_queues ();
	}
      else
	{
          if (s->np_rqts.interface)
            interface_tmp = s->np_rqts.interface;
          else
            interface_tmp = scheduler.interface;

	  done = 0;
	  while (!done && interface_tmp)
	    {
	      uint32_t addr = 0x01000000;
	      if ((nexthop == addr) &&
		  (interface_tmp->et_socket == ET_MAGIC))
		{
		  interface = interface_tmp;
		  done = 1;
		}
	      if ((nexthop != addr) &&
		  (interface_tmp->et_socket == 0))
		{
		  interface = interface_tmp;
		  done = 1;
		}
	      interface_tmp = interface_tmp->next;
	    }

	  next_hop.nl_head.ipv4_addr = nexthop;
	  cc = ll_iovsend (interface, next_hop,
			   SCPSNP, (int) len, &out_msg, s->rt_route, &(s->np_rqts));
	  /* if !cc, assuming that data didn't get sent; put it on the prec queue.
	   * Because we don't want to "re-get" the next hop addrs, etc, save them
	   * for later.
	   * NOTE: previous code flagged a zero cc as an error to the NP user.
	   *       This new code will still flag an error even though the data will
	   *       try to be resent later. TP may want something else returned
	   *       instead of a zero cc.
	   */
	  if (cc == -1)
	    {
	      int is_mc = 0;
	      /* we have to reserve NP space to hold this and then copy it in */
	      np_dg = (NP_dg *) malloc (sizeof (NP_dg));
	      memcpy ((char *) (&(np_dg->dg)), (char *) (&(np_templ->header)), len);
/*
         np_dg->is_mc = FALSE;
         np_dg->next_addrs.next_hop = nexthop;
*/
	      np_dg->is_mc = is_mc;
	      if (is_mc)
		{
		  for (i = 0; (next_mhop[i]); i++)
		    {
		      np_dg->next_addrs.next_mhop[i] = next_mhop[i];
		    }
		}
	      else
		{
		  np_dg->next_addrs.next_hop = nexthop;
		}
	      np_dg->len = len;

	      np_Int.send_pkts = TRUE;
	      /* if prec not specified, use default */
	      if (!(np_templ->pointers[BQOS_PTR]))
		{
		  q_addt (np_Int.sendprec_q[DEF_PREC], (char *) np_dg);
		  np_Int.total_proc_pkts++;
		  if (DEF_PREC > np_Int.send_prec)
		    np_Int.send_prec = DEF_PREC;
		}
	      /* otherwise, go to the BQoS field, shift to get rid of routing rqts,
	         else {
	         * and then use precedence to index proper prec queue */
	      cur_prec = (np_templ->header[np_templ->pointers[BQOS_PTR]]) >> 4;
	      q_addt (np_Int.sendprec_q[cur_prec], (char *) np_dg);
	      np_Int.total_proc_pkts++;
	      if (cur_prec > np_Int.send_prec)
		np_Int.send_prec = cur_prec;
	    }
	}
    }
  return (cc);
}

int
scps_np_ind (rqts, length, data_offset)
     scps_np_rqts *rqts;
     short length;
     int *data_offset;
{
  int len = 0, i = 0, cc, mcc, len_to_send;
  short addr_len = 2, octet3 = 0, octet4 = 0, cur_index = 3, is_mc = FALSE;
  short ipv6 = 0, expaddr = 0, keep_copy = 0, fwd_copy = 0, is_bc = 0,
  addr_ptr = 4, addr_len2 = 2;	/* <- default addr len */
  uint32_t cksum, chsum;
  unsigned short temp = 0;
  struct _interface *interface;
  struct _interface *interface_tmp2;
  struct _interface *interface_tmp;
  ts_fmt tsf;
  scps_np_addr next_hop_addr = 0;
  int offset = 0;
  int done = 0;
  byte *inbuf = in_data->data;
  uint32_t dstaddr = 0, next_mhop[MAX_ADDR];
  BOOL was_sent = FALSE;
  NP_dg *np_dg;
  int location_of_hop_count = 0;
  int loop_ctr = 100;
  int did_something = 0;
  int queueit = 0;
  struct addrs next_hop;

  /* get incoming data, if any */

again2:
  interface_tmp2 = (struct _interface *) scheduler.interface;

again:
  len = 0;
  addr_len = 2;
  octet3 = 0;
  octet4 = 0;
  cur_index = 3;
  is_mc = FALSE;
  ipv6 = 0;
  expaddr = 0;
  keep_copy = 0;
  fwd_copy = 0;
  is_bc = 0;
  addr_len2 = 2;
  temp = 0;
  queueit = 0;

  while (interface_tmp2 && (!(interface_tmp2->incoming.size)))
    {


      interface_tmp2 = interface_tmp2->next;
    }
  interface = interface_tmp2;
  if (interface &&
      ((cc = ll_nbreceive (interface, &in_data, MAX_MTU, &offset)) > 0))
    {

      did_something = 1;
#ifdef LL_RAWIP
      if (cc > 20)		/* NP packet is wrapped in a raw IP header that we need to ignore */
	{
	  in_data->offset += htons (20);	/* Point past it */
	  cc -= 20;		/* Reduce the overall length -- CHECK THIS!! */
	}
#else /* LL_RAWIP */
#ifdef NOT_DEFINED
      if (interface->et_socket != ET_MAGIC)
	{			/* If operating over Emerging Technologies serial IF */
	  in_data->offset += htons (20);
	  cc -= 20;
	}
#endif /* NOT_DEFINED */
#endif /* LL_RAWIP */

#ifdef GATEWAY_DUAL_INTERFACE
      {     
        int layering = GATEWAY_LAYERING_NORMAL;
        int overhead = 0;
        ip_template *ip;
        udp_Header *up;
  
        ip = (in_Header *) ((void *) in_data->data + in_data->offset);
        if (in_GetProtocol (ip) == SCPSUDP) {
              
          up = (udp_Header *) ((void*) in_data->data + in_data->offset + 20);
                
          if (ntohs (up->dstPort) == scps_udp_port) {
                  
              if (gw_ifs.aif_layering == GATEWAY_LAYERING_UDP) {
                layering = gw_ifs.aif_layering;
                overhead = gw_ifs.aif_overhead;
                in_data -> layering  = layering;
                in_data -> special_udp_port = ntohs (up->srcPort);
                in_data -> special_ip_addr = (ip->source);
              }

              if (gw_ifs.bif_layering == GATEWAY_LAYERING_UDP) {
                layering = gw_ifs.bif_layering;
                overhead = gw_ifs.bif_overhead;
                in_data -> layering  = layering;
                in_data -> special_udp_port = ntohs (up->srcPort);
                in_data -> special_ip_addr = (ip->source);
              }
 
              if (layering != GATEWAY_LAYERING_NORMAL) {
                in_data->offset += overhead;
                cc -= overhead;
                offset += overhead;
              }
           }
        }

      }
#endif /* GATEWAY_DUAL_INTERFACE */

      inbuf = in_data->data + in_data->offset;

      npmib.npInReceives++;
      if (cc <= MIN_NPHDR_LEN)
	{
	  SET_ERR (SCPS_EWOULDBLOCK);
	  npmib.npInBadLength++;
	  npmib.npInDiscards++;
	  return (-1);
	}

      /* initialize rqts struct */

      memset (rqts, 0, sizeof (scps_np_rqts));

      rqts->nl_protocol = NL_PROTOCOL_NP;

      /* Check for precedence; basic QoS field is now
         immediately after the dest/src addresses. */

      /* see if either there's no "bit field continues"
         in octet 2 or if there's no BQoS field set
         in octet 3. If neither, then set precedence
         to be the default level. (Note: I count octets
         from 0, not 1.)
       */
      if (!(inbuf[2] & 0x8) || !(inbuf[3] & 0x4))
	rqts->bqos.precedence = DEF_PREC;
      else
	{
	  /* check for bit field continues in octet 3 */
	  if (!(inbuf[3] & 0x80))
	    {
	      /* start out assuming the BQoS field is at
	         octet 4. We do this because the control
	         field ends at octet 3. */
	      addr_ptr = 4;

	      /* if ExAddr bit set, double the length of
	         the addresses. (was set to 2 above) */
	      if (inbuf[3] & ExADD_MASK)
		addr_len2 = addr_len2 << 1;
	    }
	  else
	    {
	      addr_ptr = 5;
	      /* Future modification:
	         if IPv6, addr_len2 << 3;
	       */
	    }
	  /* double if source address present */
	  if (inbuf[3] & SA_MASK)
	    addr_len2 = (addr_len2 << 1);
	  addr_ptr += addr_len2;
	  rqts->bqos.precedence = ((inbuf[addr_ptr]) >> 4);
	}

      /* process any higher-priority waiting packet before this one */
      if ((np_Int.total_proc_pkts) && (rqts->bqos.precedence <=
				       np_Int.proc_prec))
	{
	  queueit = check_procqueues (rqts->bqos.precedence);
	}

      /* check for correct VPI */
      if ((inbuf[0] & 0xe0) != VPI)
	{
	  /* this is a locally-set action. This implementation chooses to
	     ** treat an unexpected version as an error.
	   */
	  npmib.npInBadVersion++;
	  SET_ERR (SCPS_EVERSION);
	  return (-1);
	}

      /* get rid of VPI to find out pk length field. */
      /* Remember that this number includes hdr len, too */
      len = (inbuf[0] & 0x1f);
      len = (len << 8);
      len |= inbuf[1];

      /* check to see if the length is too big or small */
      if (len < MIN_NPHDR_LEN || len > MAX_NP_TOTAL_LEN)
	{
	  npmib.npInBadLength++;
	  SET_ERR (SCPS_ELENGTH);
	  return (-1);
	}

      rqts->interface = interface;

      {
	int convert = 0;

	switch (((inbuf[2]) >> 4))
	  {
	  case 1:
	    convert = SCMP;
	    break;
	  case 4:
	    convert = SCPSCTP;
	    break;
	  case 5:
	    convert = SCPSUDP;
	    break;
	  case 6:
	    convert = SCPSTP;
	    break;
	  case 8:
	    convert = SP;
	    break;
	  case 10:
	    convert = IPV6AUTH;
	    break;
	  case 11:
	    convert = IPV6ESP;
	    break;
	  }

	rqts->tpid = convert;
      }

#ifdef SCPSSP
      rqts->tpid = SP;
#endif /* SCPSSP */

      /* Check for valid Transport Protocol ID. If invalid,
         incrememt MIB statistic and set error num.
       */
      switch (rqts->tpid)
	{
	case (SCPSTP):
	  break;

	case (SCMP):
	  break;

#ifdef SCPSSP
	case (SP):
	  break;
#endif /*SCPSSP */


	case (SCPSUDP):
	  break;

	case (SP3):
	  break;

	case (SCPSCTP):
	  break;

	case (IPV6ESP):
	  break;

	case (IPV6AUTH):
	  break;

	default:
	  npmib.npInUnknownProtos++;
	  SET_ERR (SCPS_EPROTONOSUPPORT);
	  break;
	}
      if (inbuf[2] & BFC1_MASK)
	{
	  octet3 = TRUE;
	  if (inbuf[3] & ExADD_MASK)
	    {
	      expaddr = TRUE;
	      addr_len += 2;
	    }

	  if (inbuf[3] & BFC_MASK)
	    {
	      octet4 = TRUE;
	      cur_index = 5;

	      if (inbuf[4] & IPv6_MASK)
		{
		  ipv6 = TRUE;
		  addr_len += 14;
		  /* IPv6 not yet fully defined by standards body 
		   * This error flag will go away with IPv6 release */
		  SET_ERR (SCPS_EIPV6);
		  return (-1);
		}
	    }
	  else
	    cur_index = 4;
	}

      /* Error: both ExpAddr & IPv6 bits set in NP hdr */
      if (addr_len > 16)
	{
	  npmib.npInBadAddress++;
	  SET_ERR (SCPS_EREQADDR);
	  return (-1);
	}

      if (inbuf[2] & DA_MASK)
	{
	  /* check if broadcast address: all '1's for addr len */
	  if (inbuf[cur_index] == 0xff)
	    {
	      if (addr_len == 2)
		is_bc = TRUE;
	      else if ((inbuf[cur_index + 1] == 0xff) && (addr_len == 4))
		is_bc = TRUE;
	    }
	  /* not broadcast; check if multicast. 
	     This version supports multicast addresses of 2 bytes ONLY */
	  else if (addr_len == 2 && (inbuf[cur_index + 1] & 0x1))
	    {
	      is_mc = TRUE;
/*
                rqts->ipv4_dst_addr = (in_data->data[cur_index] << 8)
                                | ((uint32_t) in_data->data[cur_index+1]);
*/
	      rqts->ipv4_dst_addr = (inbuf[cur_index] << 8)
		| ((uint32_t) inbuf[cur_index + 1]);
	      /* Get IP address for later use */
	      dstaddr = NP_array_to_IP (cur_index, addr_len);
	    }

	  /* if not bc or mc, must be es addr */
	  else
	    {
	      /* Iff there's a source address, this is an end system address */
	      /* NP_array_to_IP will check both end system and path matches */
	      rqts->ipv4_dst_addr = NP_array_to_IP (cur_index, addr_len);
	      if (!(rqts->ipv4_dst_addr))
		{
		  npmib.npInBadAddress++;
		  SET_ERR (SCPS_ENODSTADDR);
		  return (-1);
		}
	    }
	  cur_index += addr_len;
	}

      /* SRC ADDRESS */
      if (octet3 && (inbuf[3] & SA_MASK))
	{
	  rqts->ipv4_src_addr = NP_array_to_IP (cur_index, addr_len);
	  if (!(rqts->ipv4_src_addr))
	    {
	      npmib.npInBadAddress++;
	      SET_ERR (SCPS_ENOSRCADDR);
	      return (-1);
	    }
	  cur_index += addr_len;
	}
      else
	{
	  rqts->ipv4_src_addr = 0;
	}

      /* FWD this packet? */
      if (is_mc && rqts->ipv4_src_addr)
	{
	  if (MC_mbr (ntohl (rqts->ipv4_dst_addr)))
	    {
	      keep_copy = TRUE;
	      rqts->ipv4_dst_addr = dstaddr;
	    }
	  else
	    {
	      fwd_copy = TRUE;
	    }
	  dstaddr = ntohl (rqts->ipv4_dst_addr);
	}
      /* if src addr here, then end system or IP addr */
      else if (rqts->ipv4_src_addr)
	{
	  if (rqts->ipv4_dst_addr == ntohl (np_local_addr))
	    keep_copy = TRUE;
	  else
	    {
	      fwd_copy = TRUE;	/* not for me, must fwd */
	    }
	  dstaddr = ntohl (rqts->ipv4_dst_addr);
	}
      /* else, check if path addr */
      else
	{
	  dstaddr = get_path_dst (rqts->ipv4_dst_addr, &is_mc);
	  if (dstaddr == np_local_addr)
	    keep_copy = TRUE;
	  else
	    fwd_copy = TRUE;
	}


      if (octet4 && (inbuf[4] & INT_DEL_MASK))
	keep_copy = rqts->int_del = TRUE;	/* but I get to keep a copy */
      /* if to be fwded, check to see if we know the next hop */
      if (!is_mc)
	{
	  if (fwd_copy)
	    {
	      next_hop_addr = get_next_hop (IP_to_NP_long (dstaddr));
	      if (!next_hop_addr)
		{
		  fwd_copy = FALSE;	/* this destaddr not in my routing table */
		  npmib.npOutNoRoutes++;
		}
	    }
	}
      /* check if there are next hops and if we know how to reach them */
      else
	{
	  memset (&(next_mhop), 0, MAX_ADDR * sizeof (uint32_t));
	  if (rqts->ipv4_src_addr)
	    {
	      if (get_next_mhop (dstaddr, next_mhop))
		fwd_copy = TRUE;
	      else if (!keep_copy)
		npmib.npOutNoRoutes++;
	    }
	  /* else, is path addr */
	  else
	    {
	      if (get_path_mhop (dstaddr, next_mhop))
		fwd_copy = TRUE;
	      else if (!keep_copy)
		npmib.npOutNoRoutes++;
	    }
	}

#ifdef GATEWAY
      keep_copy = TRUE;
      fwd_copy = FALSE;
#endif /* GATEWAY */

      if (!keep_copy && !fwd_copy)
	{
	  SET_ERR (SCPS_EDELIVER);
	  return (-1);
	}

      if (octet3)
	{
	  /* HOP COUNT */
	  /* WE CANT MUCK WITH THE HOP COUNT UNTIL WE HAVE DONE THE CKSUM */
	  if (inbuf[3] & HP_MASK)
	    {
	      location_of_hop_count = cur_index;
	      cur_index++;
	    }

	  /* TIMESTAMP */
	  else if ((tsf = ((inbuf[3] & TS_MASK) >> 3)))
	    {
	      rqts->timestamp.format = tsf;
	      for (i = 0; i < 3; i++)
		rqts->timestamp.ts_val[i] = inbuf[cur_index++];
	      if (tsf == SCPS32)
		rqts->timestamp.ts_val[i] = inbuf[cur_index++];
	    }

	  /* QoS */
	  if (inbuf[3] & QOS_MASK)
	    {
	      rqts->bqos.precedence = (inbuf[addr_ptr] >> 4);
	      rqts->bqos.routing = ((inbuf[addr_ptr] & 0xc) >> 2);
	      rqts->bqos.pro_specific = (inbuf[addr_ptr] & 0x3);
	    }

	  /* Exp ADDRESSES -- already taken care of */

	  /* this bit shouldn't be turned on: undefined version  */
	  if (inbuf[3] & 0x1)
	    {
	      /* This is a locally-set action. This implementation chooses
	         ** to treat it as an error.
	       */
	      return (-1);
	    }
	}			/* end of octet3 */

      if (octet4)
	{

	  /* IPv6 ADDRESS -- already taken care of */

	  /* EXPANDED QOS */
	  if (inbuf[4] & ExQOS_MASK)
	    {
	      rqts->eqos.ip_precedence = (inbuf[cur_index] >> 5);
	      rqts->eqos.ip_tos = ((inbuf[cur_index] & 0x1e) >> 1);
	      cur_index++;
	    }

	  /* these bits shouldn't be turned on */
	  if (inbuf[4] & 0xf)
	    {
	      /* this is a locally-set action. This implementation chooses to
	         ** treat an unexpected version as an error.
	       */
	      SET_ERR (SCPS_EVERSION);
	      return (-1);
	    }
	}

      /* CHECKSUM */
      if (inbuf[2] & CKSUM_MASK)
	{
	  rqts->cksum = TRUE;
	  /* recompute the checksum */
	  chsum = htons (checksum ((word *) (&(inbuf[0])), cur_index));

	  /* now extract the checksum sent in the header */
	  cksum = inbuf[cur_index++];
	  cksum = (cksum << 8) | inbuf[cur_index];
	  cur_index++;

	  /* compare the two checksums: */
	  if (chsum != cksum)
	    {
	      npmib.npInBadChecksum++;
	      SET_ERR (SCPS_ECHECKSUM);
	      scmpOutput (rqts->ipv4_src_addr, cur_index, SCMP_CORRUPT, rqts->bqos.precedence);
	      return (-1);
	    }
	  /* if no error in this pkt, note its source address for future
	   * corruption messages. For performance testing, add field
	   * for timestamp and then only keep most recent source addresses. */
	}
      log_srcs (rqts->ipv4_src_addr);

      if (inbuf[3] & HP_MASK)
	{
	  if (fwd_copy && location_of_hop_count)
	    {
	      (inbuf[location_of_hop_count])--;
	      if (inbuf[location_of_hop_count] == 0)
		{
		  npmib.npHopDiscard++;
		  SET_ERR (SCPS_EHOPCOUNT);
		  /* if we're not keeping a copy, discard this input */
		  if (!keep_copy)
		    return (-1);
		  else
		    fwd_copy = FALSE;
		}
	    }
	}

      /* insert cksum if pointer set */
      if ((inbuf[2]) & CKSUM_MASK)
	{
	  /* NOTE: cur_index points to the end of the np header */
	  chsum = checksum ((word *) (&(inbuf[0])), cur_index - 2);
	  inbuf[cur_index - 2] = (chsum >> 8);
	  inbuf[cur_index - 1] = chsum;
	}
      /* FWD: now that we know the checksum is OK, can fwd if needed */
      if (fwd_copy)
	{

	  if ((rqts->bqos.precedence <= np_Int.proc_prec) ||
	      (np_Int.procprec_q[rqts->bqos.precedence]->q_len > 0) ||
	      queueit)
	    {
	      /* we have to reserve NP space to hold this and then copy it in */
	      np_dg = (NP_dg *) malloc (sizeof (NP_dg));
	      memcpy ((char *) (&(np_dg->dg)), (char *)
		      (&(in_data->data[in_data->offset])), cc);
/*
            np_dg->is_mc = FALSE;
            np_dg->next_addrs.next_hop = next_hop_addr;
*/
	      np_dg->is_mc = is_mc;
	      if (is_mc)
		{
		  for (i = 0; (next_mhop[i]); i++)
		    {
		      np_dg->next_addrs.next_mhop[i] = next_mhop[i];
		    }
		}
	      else
		{
		  np_dg->next_addrs.next_hop = next_hop_addr;
		}
	      np_dg->len = cc;
	      np_dg->src_addr = rqts->ipv4_src_addr;

	      q_addt (np_Int.procprec_q[rqts->bqos.precedence], (char *) np_dg);
	      np_Int.total_proc_pkts++;
	      /* if no other pkts waiting, set the flags */
	      if (np_Int.proc_prec < rqts->bqos.precedence)
		np_Int.proc_prec = rqts->bqos.precedence;
	      np_Int.proc_pkts = TRUE;

	      /* check if we've already seen this src addr
	       * during this purge */
	      if (np_Int.total_proc_pkts > CONG_LEVEL - PURGE_AMT)
		{
		  int m;
		  int k = rqts->bqos.precedence;
		  int found = 0;

		  for (m = 0; m > k && np_dg->src_addr && !found; m++)
		    {
		      if (np_dg->src_addr == quench_addrs[m])
			{
			  found = TRUE;
			}
		    }
		  if (!found)
		    {
			      quench_addrs[m] = np_dg->src_addr;
			      if ((time_last_quench_sent[m] == 0) || (tp_now -
								      time_last_quench_sent[m]
								      > 1000000))
				{
				  scmpOutput (np_dg->src_addr, 0, SCMP_SOURCEQUENCH, rqts->bqos.precedence);
			}
		      time_last_quench_sent[m] = tp_now;
		    }
		}

	      check_procqueues (rqts->bqos.precedence);
	      if (np_Int.total_proc_pkts >= CONG_LEVEL)
		purge_proc_queues ();

	    }
	  else
	    {
	      out_msg.msg_iovlen = 2;
	      out_msg.msg_iov[1].iov_base = (void *) (&(in_data->data)) + in_data->offset;
	      out_msg.msg_iov[1].iov_len = cc;
	      len_to_send = cc;
	      if (!is_mc)
		{
                  if (rqts->interface)
                    interface_tmp = rqts->interface;
                  else 
                    interface_tmp = scheduler.interface;

		  done = 0;
		  while (!done && interface_tmp)
		    {
		      uint32_t addr = 0x01000000;
		      if ((next_hop_addr == addr) &&
			  (interface_tmp->et_socket == ET_MAGIC))
			{
			  interface = interface_tmp;
			  done = 1;
			}
		      if ((next_hop_addr != addr) &&
			  (interface_tmp->et_socket == 0))
			{
			  interface = interface_tmp;
			  done = 1;
			}
		      interface_tmp = interface_tmp->next;
		    }

	          next_hop.nl_head.ipv4_addr = htonl (next_hop_addr);
		  cc = ll_iovsend (interface, next_hop,
				   SCPSNP, (int) len_to_send, &out_msg, def_route, NULL);
		  if (cc != -1) {
		    npmib.npForwDatagrams++;
                    return (-1);
		  }
		  else
		    {
		      /* we have to reserve NP space to hold this and then copy it in */
		      np_dg = (NP_dg *) malloc (sizeof (NP_dg));
/*
*  CHANGE BCOPY to MEMCPY --
            bcopy((char*)(&(in_data->data[in_data ->offset])),(char*)(&(np_dg->dg)), len_to_send);
*/
		      memcpy ((char *) (&(np_dg->dg)), (char *)
			      (&(in_data->data[in_data->offset])), len_to_send);
/*
            np_dg->is_mc = FALSE;
            np_dg->next_addrs.next_hop = next_hop_addr;
*/
		      np_dg->is_mc = is_mc;
		      if (is_mc)
			{
			  for (i = 0; (next_mhop[i]); i++)
			    {
			      np_dg->next_addrs.next_mhop[i] = next_mhop[i];
			    }
			}
		      else
			{
			  np_dg->next_addrs.next_mhop[i] = next_hop_addr;
			}
		      np_dg->len = len_to_send;
		      np_dg->src_addr = rqts->ipv4_src_addr;

		      q_addt (np_Int.procprec_q[rqts->bqos.precedence],
			      (char *) np_dg);
		      np_Int.total_proc_pkts++;
		      /* if no other pkts waiting, set the flags */
		      if (np_Int.proc_prec < rqts->bqos.precedence)
			np_Int.proc_prec = rqts->bqos.precedence;
		      np_Int.proc_pkts = TRUE;

		      /* test for congestion; don't want to test this before adding the pkt
		       * because then you might be purging a higher-priority pkt over a
		       * lower priority one. */
		      if (np_Int.total_proc_pkts >= CONG_LEVEL)
			purge_proc_queues ();
		    }
		}
	      /* is mc - must check for multiple next hops */
	      else
		{
		  for (i = 0; i < MAX_ADDR && next_mhop[i]; i++)
		    {
		      interface_tmp = scheduler.interface;
		      done = 0;
		      while (!done && interface_tmp)
			{
			  uint32_t addr = 0x01000000;
			  if ((next_mhop[i] == addr) &&
			      (interface_tmp->et_socket == ET_MAGIC))
			    {
			      interface = interface_tmp;
			      done = 1;
			    }
			  if ((next_mhop[i] != addr) &&
			      (interface_tmp->et_socket == 0))
			    {
			      interface = interface_tmp;
			      done = 1;
			    }
			  interface_tmp = interface_tmp->next;
			}

                      if (rqts->interface)
                        interface = rqts->interface;
                      else
                        interface = scheduler.interface;

	        	next_hop.nl_head.ipv4_addr = next_mhop[i];
		      mcc = ll_iovsend (interface, next_hop,
					SCPSNP, (int) len_to_send, &out_msg, def_route, NULL);

		      if (len_to_send == mcc)
			{
			  was_sent = TRUE;
			  npmib.npForwDatagrams++;
			}
		    }
		  /* put on queue if pkt wasn't sent */
		  if (!was_sent)
		    {
		      np_Int.proc_pkts = TRUE;
		      np_dg = (NP_dg *) malloc (sizeof (NP_dg));
/*
*  CHANGE BCOPY to MEMCPY --
            bcopy((char*)(&(in_data->data[in_data ->offset])),(char*)(&(np_dg->dg)), len_to_send);
*/
		      memcpy ((char *) (&(np_dg->dg)), (char *)
			      (&(in_data->data[in_data->offset])), len_to_send);
		      np_dg->is_mc = TRUE;
		      np_dg->next_addrs.next_hop = next_hop_addr;
		      np_dg->len = len_to_send;

		      for (i = 0; i < MAX_ADDR && next_mhop[i]; i++)
			np_dg->next_addrs.next_mhop[i] = next_mhop[i];
		      np_dg->len = len_to_send;
		      q_addt (np_Int.procprec_q[rqts->bqos.precedence],
			      (char *) np_dg);
		      np_Int.total_proc_pkts++;
		      if (np_Int.proc_prec < rqts->bqos.precedence)
			np_Int.proc_prec = rqts->bqos.precedence;

		      /* test for congestion; don't want to test this before adding the pkt
		       * because then you might be purging a higher-priority pkt over a
		       * lower priority one. */
		      if (np_Int.total_proc_pkts >= CONG_LEVEL)
			purge_proc_queues ();
		    }
		}

	    }
	  /* XXX XXX VERY IMPORTANT */
	  if (!keep_copy)
	    free_ll_queue_element (rqts->interface, in_data);
	}

      /* subtract off length of hdr to get data length */
      len -= cur_index;

      /* checksum is done and the packet is for us; see if it's SCMP */
      if ((keep_copy) && (rqts->tpid == SCMP))
	{
	  scmpHandler (cur_index, len);
	  /* this pkt was for me, not the user; zero out his rqts struct */
	  /*
	     bzero ( rqts, (sizeof(scps_np_rqts))); 
	   */
	  memset (rqts, 0, sizeof (scps_np_rqts));
	  return (0);
	}
      if (keep_copy)
	{
	  /* put addrs in HOST BYTE ORDER, if necessary */
	  /* Durst 12/97 */
	  /* if a Path address, must convert back to source and dest IP addrs */
	  if (!(rqts->ipv4_src_addr))
	    {
	      /* Path addr is in rqts->dst_addr.  Need to get source addr
	         from Path table that corresponds to that Path addr */
	      for (i = 0; i < MAX_ADDR && npPathTable[i].addr; i++)
		{
		  if (rqts->ipv4_dst_addr == npPathTable[i].addr)
		    {
		      rqts->ipv4_src_addr = ntohl (npPathTable[i].src);
		      break;
		    }		/* if rqts->ipv4_dst_addr */
		}		/* for i */
	      rqts->ipv4_dst_addr = ntohl (dstaddr);
	    }			/* if !rqts->ipv4_src_addr */
/*
      rqts->ipv4_dst_addr = ntohl(rqts->dipv4_st_addr);
      rqts->ipv4_src_addr = ntohl(rqts->ipv4_src_addr);
*/
	  npmib.npInDelivers++;

#ifdef LL_RAWIP
	  if (interface->et_socket == ET_MAGIC)
	    *data_offset = offset + cur_index;
	  else
	    *data_offset = offset + cur_index + htons (20);
#else /* LL_RAWIP */
	  *data_offset = offset + cur_index;
#endif /* LL_RAWIP */

	  if (len <= length)
	    return (len);
	  /* else, too much data arrived to give to user */
	  else
	    {
	      SET_ERR (SCPS_EMSGSIZE);
	      return (length);
	    }

	}
      /* if acting as a routing but not keeping a copy, return 0 */
      else
	{
	  *data_offset = 0x0;
	  interface_tmp2 = interface_tmp2->next;
	  goto again;
	  return (0);
	}


    }				/* end of "if-then" for cc=ll_nbreceive loop.... */
  /* if we get here, there's an error: len == 0 -> no data! */
  if (interface_tmp2 != NULL)
    {
      *data_offset = 0x0;
      interface_tmp2 = interface_tmp2->next;
      goto again;
    }

/*
  if ((loop_ctr == 100) && (!did_something)) {
      if (np_Int.total_proc_pkts > 0) 
          check_procqueues(rqts->bqos.precedence);
  } */

  loop_ctr--;
  if ((loop_ctr) && (did_something))
    {
      did_something = 0;
      goto again2;
    }

  len = -1;
  *data_offset = 0x0;
  SET_ERR (SCPS_EWOULDBLOCK);
  return (-1);
}

uint32_t
IP_to_NP_long (uint32_t ip)
{
  short i;
  uint32_t ret = ip;

  for (i = 0; i < MAX_ADDR && npAddrConvTable[i].ip; i++)
    {
      if (ip == npAddrConvTable[i].ip)
	{
	  ret = npAddrConvTable[i].np;
	  break;
	}
    }
  return (ret);
}

uint32_t
Convert_to_np (addr, mc_addr)
     uint32_t addr;
     short *mc_addr;
{
  short i, found = FALSE;
  uint32_t ret = 0;

  /* search my IP-NP table */
  for (i = 0; i < MAX_ADDR && npAddrConvTable[i].ip; i++)
    {
      if (addr == npAddrConvTable[i].ip)
	{
	  ret = npAddrConvTable[i].np;
	  if ((ntohl (ret)) & 0xffff0000)
	    nptype2 = es_extended;
	  else
	    nptype2 = es_basic;
	  found = TRUE;
	  break;
	}
    }
  /* if can't find, search my PATH table */
  if (!found)
    {
      for (i = 0; i < MAX_ADDR && npPathTable[i].addr; i++)
	{
	  if ((np_local_addr == npPathTable[i].src) &&
	      ((addr == npPathTable[i].dst[0]) || (addr ==
						   npPathTable[i].dst[1])))
	    {
	      ret = npPathTable[i].addr;
	      if ((ntohl (ret)) & 0xffff0000)
		nptype2 = path_extended;
	      else
		nptype2 = path_basic;
	      found = TRUE;
	      if (npPathTable[i].dst[1])
		*mc_addr = TRUE;
	      break;
	    }
	}
    }
  /* if still can't find, search my MC table */
  if (!found && mc_addr)
    {
      for (i = 0; i < MAX_NUM_GROUPS && npMultiNextHopTable[i].dst; i++)
	{
	  if (addr == npMultiNextHopTable[i].dst)
	    {
	      ret = addr;
	      if (ret & 0xffff0000)
		nptype2 = es_extended;
	      else
		nptype2 = es_basic;
	      *mc_addr = TRUE;
	      found = TRUE;
	      break;
	    }
	}
    }
  /* if not in my tables, must assume it's IPv4 if proper length */
  if (!found && (addr & 0xffff0000))
    {
      ret = addr;
      nptype2 = es_IP;
    }
  return (ret);
}

uint32_t
NP_long_to_IP (np)
     uint32_t np;
{
  short i;
  uint32_t ret = 0;

  for (i = 0; i < MAX_ADDR && npAddrConvTable[i].ip; i++)
    {
      if (np == npAddrConvTable[i].np)
	{
	  ret = npAddrConvTable[i].ip;
	  break;
	}
    }
  return (ret);
}

uint32_t
NP_array_to_IP (cur_index, addr_len)
     short cur_index;
     short addr_len;
{
  short i;
  uint32_t np, ret = 0;

  np = in_data->data[cur_index + in_data->offset];
  for (i = 1; i < addr_len; i++)
    {
      np = (np << 8) | ((uint32_t) in_data->data[cur_index + i + in_data->offset]);
    }
  for (i = 0; i < MAX_ADDR && npAddrConvTable[i].ip; i++)
    {
      if (np == ntohl (npAddrConvTable[i].np))
	{
	  ret = ntohl (npAddrConvTable[i].ip);
	  break;
	}
    }
  /* if no IP address for this NP, check if it's PATH */
  if (!ret)
    {
      for (i = 0; i < MAX_ADDR && npPathTable[i].addr; i++)
	{
	  if (np == ntohl (npPathTable[i].addr))
	    {
	      ret = ntohl (np);
	      break;
	    }
	}
      /* else, see if it's an IP address format */
      if (!ret)
	{
	  if (np & 0xffff0000)
	    ret = np;
	}
    }

  return (ret);
}

short
get_next_mhop (uint32_t dst_addr, uint32_t * next_mhop)
{
  short i, j, ret = 0;

  for (i = 0; i < MAX_NUM_GROUPS && npMultiNextHopTable[i].dst; i++)
    {
      if (dst_addr == npMultiNextHopTable[i].dst)
	{
	  for (j = 0; j < (MAX_NUM_IF + 1) &&
	       npMultiNextHopTable[i].nexthop[j]; j++)
	    {
/*
            next_mhop[j] = NP_long_to_IP(npMultiNextHopTable[i].nexthop[j]);
*/
	      next_mhop[j] = npMultiNextHopTable[i].nexthop[j];
	      /* if there's no route to this next hop, it's an ERROR */
	      if (!(next_mhop[j]))
		{
		  npmib.npOutNoRoutes++;
		  return (ret);
		}
	    }
	  ret = 1;
	  break;
	}
    }
  return (ret);
}


short
MC_mbr (dst_addr)
     uint32_t dst_addr;

{
  short i;
  short group_mbr;

  group_mbr = (short) 0;

  for (i = 0; ((i < MAX_NUM_GROUPS) && (mc_local_addrs[i])); i++)
    {
      if (dst_addr == mc_local_addrs[i])
	{
	  group_mbr = (short) 1;
	  break;
	}
    }
  return ((short) (group_mbr));
}

uint32_t
get_path_dst (path_addr, is_mc)
     uint32_t path_addr;
     short *is_mc;
{
  short i;
  uint32_t ret = 0;

  for (i = 0; i < MAX_ADDR && npPathTable[i].addr; i++)
    {
      if (path_addr == npPathTable[i].addr)
	{
	  /* get dst addr from path definition */
	  ret = npPathTable[i].dst[0];
	  if (!(npPathTable[i].dst[1]) && is_mc != NULL)
	    *is_mc = TRUE;
	  break;
	}
    }
  return (ret);
}

short
get_path_mhop (uint32_t path_addr, uint32_t * next_mhop)
{
  short i, ret = 0;

  for (i = 0; i < MAX_ADDR && npPathTable[i].addr; i++)
    {
      if (path_addr == npPathTable[i].addr)
	{
	  /* get dst addrs from path definition */
	  next_mhop[0] = npPathTable[i].dst[0];
	  next_mhop[1] = npPathTable[i].dst[1];
	  if (!(next_mhop[0]) && !(next_mhop[1]))
	    {
	      npmib.npOutNoRoutes++;
	      return (ret);
	    }
	  ret = 1;
	  break;
	}
    }
  return (ret);

}

uint32_t
get_next_hop (dst_addr)
     uint32_t dst_addr;
{
  short i;
  uint32_t ret = 0;

  for (i = 0; i < MAX_ADDR && npNextHopTable[i].dst; i++)
    {
      if (dst_addr == npNextHopTable[i].dst)
	{
	  /* get linklayer next hop address */
	  ret = npNextHopTable[i].nexthop;
/* pdf xxx	  ret = NP_long_to_IP(npNextHopTable[i].nexthop); */
	  break;
	}
    }
  return (ret);
}

void
scmpHandler (pos, len)
     short pos;
     int len;
{
  short type, code;
  scps_np_rqts rqts;
  byte *inbuf = in_data->data + in_data->offset;
  tp_Header *tp = NULL;

  npmib.scmpInMsgs++;
  type = inbuf[pos++];
  code = inbuf[pos++];

  /* skip over the checksum; what pos points to now is data, if any */
  pos += 2;


  if (len > 13)
    {
      get_np_template (&rqts, &pos);
      tp = (tp_Header *) & in_data->data[in_data->offset + pos];
    }

  switch (type)
    {
    case (SCMP_ECHOREPLY):
      npmib.scmpInEchoReps++;
      break;

    case (SCMP_UNREACH):
      npmib.scmpInDestUnreachs++;
      npmib.scmpInErrors++;

      switch (code)
	{
	case (SCMP_UNREACH_NET):
	  break;

	case (SCMP_UNREACH_HOST):
	  break;

	case (SCMP_UNREACH_PROTOCOL):
	  break;

	case (SCMP_UNREACH_PORT):
	  break;

	case (SCMP_UNREACH_NEEDFRAG):
	  break;

	case (SCMP_UNREACH_UNHOST):
	  break;

	case (SCMP_UNREACH_QOSNET):
	  break;

	case (SCMP_UNREACH_QOSHOST):
	  break;

	case (SCMP_UNREACH_ADMIN):
	  break;

	case (SCMP_UNREACH_HOSTPREC):
	  break;

	case (SCMP_UNREACH_MINPREC):
	  break;

	case (SCMP_UNREACH_LINKOUT):
	  break;

	default:
	  break;
	}
      break;

    case (SCMP_CORRUPT):
      {
	tp_Socket *s;
/*
           for (s = tp_allsocs; s; s = s->next) {
               if (s->hisport != 0 &&
                   tp->dstPort == s->myport && 
                   tp->srcPort == s->hisport)
               break;
           }
	   */

	for (s = tp_allsocs; s; s = s->next)
	  {
	    if (s->hisport)
	      tp_quench (s);
	  }
	npmib.scmpInCorrExps++;
	npmib.scmpInErrors++;
	SET_ERR (SCPS_ECORRUPTION);
      }
      break;

    case (SCMP_REDIRECT):
      npmib.scmpInRedirects++;
      switch (code)
	{
	case (SCMP_REDIRECT_HOST):
	  break;

	case (SCMP_REDIRECT_QOSHOST):
	  break;

	case (SCMP_REDIRECT_LINK):
	  break;

	default:
	  break;
	}
      break;

    case (SCMP_ECHO):
      npmib.scmpInEchos++;
      /* must reply to this message */
/*
       bzero(&rqts, sizeof(rqts));
       rqts.ipv4_dst_addr = src_addr;
       rqts.ipv4_src_addr = np_local_addr; 
*/
      break;

    case (SCMP_TIMXCEED):
      npmib.scmpInTimeExcds++;
      npmib.scmpInErrors++;
      break;

    case (SCMP_PARAMPROB):
      npmib.scmpInParmProbs++;
      npmib.scmpInErrors++;
      break;

    case (SCMP_SOURCEQUENCH):
      {
	tp_Socket *s;

	for (s = tp_allsocs; s; s = s->next)
	  {
	    if (s->hisport != 0 &&
		tp->dstPort == s->myport &&
		tp->srcPort == s->hisport)
	      break;
	  }

	if (s)
	  tp_quench (s);
	else
	  printf
	    ("ERROR:  Could not demux SCMP Source Quench to active socket\n");

	npmib.scmpInSrcQuenchs++;
	SET_ERR (SCPS_ESRCQUENCH);
	break;
      }
    default:
      break;
    }

  return;
}

/* Parameter data must be an array of bytes. It should start
 * here at the index where the SCMP message starts. Recall
 * that a NP header precedes the SCMP message.   */
int
scmpOutput (uint32_t src_addr, short indx, short type, int prior)
{
  short i, mc_addr;
  u_char th_off = 0;
  scps_np_rqts rqts;
  tp_Socket s;
  int32_t cc;

  switch (type)
    {
    case (SCMP_CORRUPT):
      if ((time_last_corrupt_sent == 0) || (tp_now - time_last_corrupt_sent
					    > 1000000))
	{
	  time_last_corrupt_sent = tp_now;

	  npmib.scmpOutCorrExps++;
	  npmib.scmpOutErrors++;

	  memset (&rqts, 0, sizeof (rqts));
	  rqts.tpid = SCMP;
	  rqts.ipv4_src_addr = htonl (np_local_addr);
	  rqts.cksum = TRUE;
	  rqts.bqos.precedence = prior;

	  /* loop through the most-recent source addresses
	   * and send the SCMP corruption msg to each of them. */
	  for (i = 0; i < MAX_ADDR && np_Int.rec_srcs[i]; i++)
	    {
	      rqts.ipv4_dst_addr = Convert_to_np (htonl (np_Int.rec_srcs[i]), &mc_addr);
	      cc = scps_np_get_template (&rqts, &(s.np_templ));
	      if (cc != -1)
		{
		  /* now set the SCMP-specific fields */
		  s.np_templ.header[s.np_templ.hdr_len] = SCMP_CORRUPT;

		  /* add 2 to hdr_len to get 'type' and 'code' fields
		   * in the checksum. */

		  /* space for checksum has not been accounted for in
		   * hdrlen for SCMP-related fields. Therefore, must
		   * 'count forward' to get to proper offset. */
/*
                  s.np_templ.header[s.np_templ.hdr_len+2] = (chsum >> 8);
                  s.np_templ.header[s.np_templ.hdr_len+3] = chsum;
*/

		  /* try to send the datagram */
		  cc = scps_np_trequest (&s, NULL, NULL, 4, NULL, th_off);
		}
	      else
		{
		  return (-1);
		  /* maybe there should be an error flag set here? */
		}
	    }
	}
      break;

    case (SCMP_SOURCEQUENCH):
      {
	npmib.scmpOutSrcQuenchs++;
	npmib.scmpOutErrors++;

	memset (&rqts, 0, sizeof (rqts));
	rqts.tpid = SCMP;
	rqts.ipv4_src_addr = htonl (np_local_addr);
	rqts.ipv4_dst_addr = Convert_to_np (htonl (src_addr), &mc_addr);
	rqts.bqos.precedence = prior;

	rqts.cksum = TRUE;

	cc = scps_np_get_template (&rqts, &(s.np_templ));
	if (cc != -1)
	  {

	    char *pkt = in_data->data + in_data->offset;
	    int i;
	    /* now set the SCMP-specific fields */
	    s.np_templ.header[s.np_templ.hdr_len] = SCMP_SOURCEQUENCH;

	    /* add 2 to hdr_len to get 'type' and 'code' fields
	     * in the checksum. */

	    /* Insert the first 50 bytes of the pkt header */
	    for (i = 0; i < 50; i++)
	      {
		s.np_templ.header[s.np_templ.hdr_len + 4 + i] = pkt[i];
	      }

	    /* space for checksum has not been accounted for in
	       * hdrlen for SCMP-related fields. Therefore, must
	       * 'count forward' to get to proper offset. */
/*
                s.np_templ.header[s.np_templ.hdr_len+2] = (chsum >> 8);
                s.np_templ.header[s.np_templ.hdr_len+3] = chsum;
*/

	    /* try to send the datagram */
	    cc = scps_np_trequest (&s, NULL, NULL, 54, NULL, th_off);
	  }
	else
	  {
	    return (-1);
	    /* maybe there should be an error flag set here? */
	  }
      }
      break;

    default:
      break;
    }
  return (1);
}


void
scps_np_init ()
{
  FILE *fp;
  short i = 0;

  memset (&npAddrConvTable, 0, MAX_ADDR * (sizeof (ip_np_entry)));
  memset (&npNextHopTable, 0, MAX_ADDR * (sizeof (npNextHopEntry)));

  fp = fopen (npIP_NP_File, "r");
  if (fp != NULL)
    {
      while ((fscanf (fp, "%x %x", &(npAddrConvTable[i].ip),
		      &(npAddrConvTable[i].np
		      )) != EOF) && (i < MAX_ADDR))
	{
	  npAddrConvTable[i].ip = htonl (npAddrConvTable[i].ip);
	  npAddrConvTable[i].np = htonl (npAddrConvTable[i].np);
	  i++;
	}
      fclose (fp);
    }
  /* if couldn't open, unrecoverable error */
  else
    {
      SET_ERR (SCPS_EFILEOPEN);
      return;
    }

  fp = fopen (npNextHopFile, "r");
  if (fp != NULL)
    {
      fscanf (fp, "%x", (unsigned int *) &(np_local_addr));
      np_local_addr = htonl (np_local_addr);
      i = 0;
      while ((fscanf (fp, "%x %x",
		      (unsigned int *) &(npNextHopTable[i].dst),
		      (unsigned int *) &(npNextHopTable[i].nexthop))
	      != EOF) && (i < MAX_ADDR))
	{
	  npNextHopTable[i].dst = htonl (npNextHopTable[i].dst);
	  npNextHopTable[i].nexthop = htonl (npNextHopTable[i].nexthop);
	  i++;
	}
      fclose (fp);
    }
  /* if couldn't open, unrecoverable error */
  else
    {
      SET_ERR (SCPS_EFILEOPEN);
      return;
    }

  memset (&npMultiNextHopTable, 0, sizeof (npMultiNextHopTable));
  fp = fopen (npMultiNextHopFile, "r");
  if (fp != NULL)
    {
      /* first line is mc groups I'm a RECIPIENT of */
      fscanf (fp, "%x %x %x", (unsigned int *) &(mc_local_addrs[0]),
	      (unsigned int *) &(mc_local_addrs[1]),
	      (unsigned int *) &(mc_local_addrs[2]));
      mc_local_addrs[0] = htonl (mc_local_addrs[0]);
      mc_local_addrs[1] = htonl (mc_local_addrs[1]);
      mc_local_addrs[2] = htonl (mc_local_addrs[2]);
      i = 0;
      while (
	      fscanf (fp, "%x %x %x",
		      (unsigned int *) &(npMultiNextHopTable[i].dst),
		      (unsigned int *) &((npMultiNextHopTable[i]).nexthop[0]),
		      (unsigned int *) &((npMultiNextHopTable[i]).nexthop[1])
	      )
	      != EOF
	      &&
	      i < MAX_NUM_GROUPS
	)
	{
	  npMultiNextHopTable[i].dst = htonl (npMultiNextHopTable[i].dst);
	  npMultiNextHopTable[i].nexthop[0] = htonl
	    (npMultiNextHopTable[i].nexthop[0]);
	  npMultiNextHopTable[i].nexthop[1] = htonl
	    (npMultiNextHopTable[i].nexthop[1]);
	  i++;
	}
      fclose (fp);
    }

  memset (&npPathTable, 0, sizeof (npPathTable));
  fp = fopen (npPathFile, "r");
  if (fp != NULL)
    {
      i = 0;
      while (
	      fscanf (fp, "%x %x %x %x",
		      (unsigned int *) &(npPathTable[i].addr),
		      (unsigned int *) &(npPathTable[i].src),
		      (unsigned int *) &(npPathTable[i].dst[0]),
		      (unsigned int *) &(npPathTable[i].dst[1])
	      )
	      != EOF
	)
	{
	  npPathTable[i].addr = htonl (npPathTable[i].addr);
	  npPathTable[i].src = htonl (npPathTable[i].src);
	  npPathTable[i].dst[0] = htonl (npPathTable[i].dst[0]);
	  npPathTable[i].dst[1] = htonl (npPathTable[i].dst[1]);
	  i++;
	}
      fclose (fp);
    }

  npmib.npOutRequests = 0;
  npmib.npOutDiscards = 0;
  npmib.npOutNoRoutes = 0;
  npmib.npInReceives = 0;
  npmib.npInBadLength = 0;
  npmib.npInBadVersion = 0;
  npmib.npInBadAddress = 0;
  npmib.npInBadChecksum = 0;
  npmib.npInAddrErrors = 0;
  npmib.npInUnknownProtos = 0;
  npmib.npInDiscards = 0;
  npmib.npInDelivers = 0;
  npmib.npForwDatagrams = 0;
  npmib.npHopDiscard = 0;
  npmib.npDefaultHopCount = DEFAULT_HOP_COUNT;

  for (i = 0; i < MAX_PREC; i++)
    {
      np_Int.procprec_q[i] = q_create ();
      np_Int.sendprec_q[i] = q_create ();
    }
  np_Int.send_pkts = np_Int.proc_pkts = FALSE;
  np_Int.send_prec = np_Int.proc_prec = np_Int.total_proc_pkts = 0;
  memset (&np_Int.rec_srcs, 0, MAX_ADDR * sizeof (scps_np_addr));

  for (i = 0; i > MAX_ADDR; i++)
    {
      np_Int.rec_srcs[i] = 0;
      quench_addrs[i] = 0;
      time_last_quench_sent[i] = 0;;
    }

  /* for testing */
  PRINT_HDR = TRUE;
  return;
}

void
log_srcs (scps_np_addr src)
{
  short i;

  for (i = 0; i < MAX_ADDR; i++)
    {
      if (src == np_Int.rec_srcs[i] || !(np_Int.rec_srcs[i]))
	break;
    }
  if (!(np_Int.rec_srcs[i]) && src)
    np_Int.rec_srcs[i] = src;

  return;
}

short
check_sendqueues (scps_np_template * np_templ)
{
  NP_dg *np_dg;
  short i, prec = DEF_PREC, send_prec;
  int cc = 0, mcc = 0;
  struct _interface *interface = scheduler.interface;
  struct _interface *interface_tmp;
  struct addrs next_hop;

  /* NOTE: it would save alot of NP code if I could query the lower layer to
   * find out if it's busy before I try to send something.   */

  /* Are there pkts waiting to be sent? */
  if (np_Int.send_pkts)
    {
      if (np_templ->pointers[BQOS_PTR])
	prec = np_templ->header[np_templ->pointers[BQOS_PTR]] >> 4;

      /* now check for waiting higher-prec level packets */
      send_prec = np_Int.send_prec;
      while (prec <= send_prec)
	{
	  if ((NP_dg *) q_headcpy (np_Int.sendprec_q[send_prec]))
	    np_dg = (NP_dg *) q_deq (np_Int.sendprec_q[send_prec]);
	  np_Int.total_send_pkts--;
	  /* try to send pkt */
	  out_msg.msg_iovlen = 2;
	  out_msg.msg_iov[1].iov_base = (void *) &(np_dg);
	  out_msg.msg_iov[1].iov_len = np_dg->len;

	  if (np_dg->is_mc)
	    {
	      for (i = 0; i < MAX_ADDR && np_dg->next_addrs.next_mhop[i];
		   i++)
		{
		  int done;
		  /* Find the correct corresponding interface */

		  interface_tmp = scheduler.interface;
		  done = 0;
		  while (!done && interface_tmp)
		    {
		      uint32_t addr = 0x01000000;
		      if ((np_dg->next_addrs.next_mhop[i] == addr) &&
			  (interface_tmp->et_socket == ET_MAGIC))
			{
			  interface = interface_tmp;
			  done = 1;
			}
		      if ((np_dg->next_addrs.next_mhop[i] != addr) &&
			  (interface_tmp->et_socket == 0))
			{
			  interface = interface_tmp;
			  done = 1;
			}
		      interface_tmp = interface_tmp->next;
		    }

	  	next_hop.nl_head.ipv4_addr = np_dg->next_addrs.next_mhop[i];
		  mcc = ll_iovsend (interface, next_hop,
				    SCPSNP, (int) np_dg->len, &out_msg, def_route, NULL);
		  if (!i || mcc < cc)
		    cc = mcc;
		}
	      /* if nothing was sent, put the pkt back on the head of the queue */
	      if (cc == -1)
		{
		  q_addh (np_Int.sendprec_q[send_prec], np_dg);
		  np_Int.total_send_pkts++;
		  break;
		}
	      else
		free ((char *) np_dg);
	    }
	  else
	    {
	      int done = 0;
	      /* Find the correct corresponding interface */

	      interface_tmp = scheduler.interface;
	      done = 0;
	      while (!done && interface_tmp)
		{
		  uint32_t addr = 0x01000000;
		  if ((np_dg->next_addrs.next_hop == addr) &&
		      (interface_tmp->et_socket == ET_MAGIC))
		    {
		      interface = interface_tmp;
		      done = 1;
		    }
		  if ((np_dg->next_addrs.next_hop != addr) &&
		      (interface_tmp->et_socket == 0))
		    {
		      interface = interface_tmp;
		      done = 1;
		    }
		  interface_tmp = interface_tmp->next;
		}

	      next_hop.nl_head.ipv4_addr =  np_dg->next_addrs.next_hop;
	      mcc = ll_iovsend (interface, next_hop,
				SCPSNP, (int) np_dg->len, &out_msg, def_route, NULL);

	      /* if nothing was sent, put the pkt back on the head of the queue */
	      if (cc == -1)
		{
		  q_addh (np_Int.sendprec_q[send_prec], np_dg);
		  np_Int.total_send_pkts++;
		  break;
		}
	      else
		free ((char *) np_dg);
	    }

	  /* if we're done with this prec level, find the next lower level
	   * that has any pkts in it. */
	  if ((np_Int.sendprec_q[send_prec])->q_len == 0)
	    {
	      do
		{
		  send_prec = np_Int.send_prec--;
		}
	      while (send_prec >= 0 && !((np_Int.sendprec_q[send_prec])->q_len));
	    }
	  if (send_prec < 0)
	    {
	      send_prec = 0;
	      np_Int.send_pkts = FALSE;
	      break;
	    }

	}
    }

  return (1);
}

int
check_procqueues (prec)
     short prec;
{
  short proc_prec = np_Int.proc_prec, i;
  BOOL was_sent = FALSE;
  NP_dg *np_dg;
  int cc, mcc;
  int keep_trying = 1;
  struct _interface *interface = scheduler.interface;
  struct _interface *interface_tmp;
  struct addrs next_hop;

  /* use a do-while loop since we'll only get here if there's
   * at least one pkt waiting */
  do
    {
      proc_prec = np_Int.proc_prec;	/* I think I can move this before the 'do' */
      if ((NP_dg *) q_headcpy (np_Int.procprec_q[proc_prec]))
	{
	  np_Int.total_proc_pkts--;
	  np_dg = (NP_dg *) q_deq (np_Int.procprec_q[proc_prec]);

	  /* try to send pkt */
	  out_msg.msg_iovlen = 2;
	  out_msg.msg_iov[1].iov_base = (void *) &(np_dg->dg);
	  out_msg.msg_iov[1].iov_len = np_dg->len;
	  if (!(np_dg->is_mc))
	    {
	      int done;
	      /* Find the correct corresponding interface */

	      interface_tmp = scheduler.interface;
	      done = 0;
	      while (!done && interface_tmp)
		{
		  uint32_t addr = 0x01000000;
		  if ((np_dg->next_addrs.next_hop == addr) &&
		      (interface_tmp->et_socket == ET_MAGIC))
		    {
		      interface = interface_tmp;
		      done = 1;
		    }
		  if ((np_dg->next_addrs.next_hop != addr) &&
		      (interface_tmp->et_socket == 0))
		    {
		      interface = interface_tmp;
		      done = 1;
		    }
		  interface_tmp = interface_tmp->next;
		}


	      next_hop.nl_head.ipv4_addr = np_dg->next_addrs.next_hop;
	      cc = ll_iovsend (interface, next_hop,
			       SCPSNP, (int) np_dg->len, &out_msg, def_route, NULL);
	      /* if the pkt was sent, free the struct and move on */
	      if (cc != -1)
		{
		  npmib.npForwDatagrams++;
		  free ((char *) np_dg);
		}
	      /* was not sent, put it back on the queue and return */
	      else
		{
		  q_addh (np_Int.procprec_q[proc_prec], (char *) np_dg);
		  np_Int.total_proc_pkts++;
		  keep_trying = 0;
#ifdef NOT_DEFINED
		  break;	/* should this be return ? */
#endif /* NOT_DEFINED */
		  return (0);
		}
	    }
	  /* pkt is multicast */
	  else
	    {
	      for (i = 0; i < MAX_ADDR && np_dg->next_addrs.next_mhop[i];
		   i++)
		{
		  int done;
		  /* Find the correct corresponding interface */

		  interface_tmp = scheduler.interface;
		  done = 0;
		  while (!done && interface_tmp)
		    {
		      uint32_t addr = 0x01000000;
		      if ((np_dg->next_addrs.next_mhop[i] == addr) &&
			  (interface_tmp->et_socket == ET_MAGIC))
			{
			  interface = interface_tmp;
			  done = 1;
			}
		      if ((np_dg->next_addrs.next_mhop[i] != addr) &&
			  (interface_tmp->et_socket == 0))
			{
			  interface = interface_tmp;
			  done = 1;
			}
		      interface_tmp = interface_tmp->next;
		    }

	  	  next_hop.nl_head.ipv4_addr = np_dg->next_addrs.next_mhop[i];
		  mcc = ll_iovsend (interface, next_hop,
				    SCPSNP, (int) np_dg->len, &out_msg, def_route, NULL);


		  if (mcc == np_dg->len)
		    was_sent = TRUE;
		}
	      /* if nothing was sent, put the pkt back on the head of the queue */
	      if (!was_sent)
		{
		  q_addh (np_Int.procprec_q[proc_prec], np_dg);
		  return (0);	/* should this be 'break' */
		}
	      else
		{
		  npmib.npForwDatagrams++;
		  free ((char *) np_dg);
		}
	    }
	}			/* end if q_headcpy */

      /* check to see if we're done with this prec level. If so, find the next
       * lower level that has any pkts in it */
      if ((np_Int.procprec_q[proc_prec])->q_len == 0)
	{
	  do
	    {
	      np_Int.proc_prec--;
	      proc_prec = np_Int.proc_prec;
	    }
	  while (proc_prec >= 0 && !((np_Int.procprec_q[proc_prec])->q_len));

	  if (proc_prec < 0)
	    {
	      proc_prec = np_Int.proc_prec = 0;
	      np_Int.proc_pkts = FALSE;		/* should this be return ??? */
	      break;
	    }
	}
      if (!keep_trying) {
	if (prec > proc_prec) {
	  return (0);
	} else {
	  return (1);
        }
      }	  
    }
  while (prec < proc_prec);

  if (prec > proc_prec)
/*   if (np_Int.procprec_q[prec] -> q_len == 0) */
    return (0);
  else
    return (1);
}

void
purge_proc_queues ()
{
  /* start with lowest priority packets, head (oldest) first;
   * this order can be changed if not appropriate for a
   * particular system. ie., can do youngest first. */

  NP_dg *np_dg;
  int todrop;
  short i = 0, j = 0;

/* Once the MIB is used throughout and we have a definite number on
 * the size of the queues we want, we'll add this to do it
 * 'on the fly', rather than a fixed purge number.
   todrop = (int)((myself->out_pkts)*(1.0-npmib.npInCongThreshold)) + 1;
*/

  todrop = PURGE_AMT;

  /* i runs over the data in each prec level queue, while j
   * switches between prec levels */
  while (i < todrop && j <= MAX_PREC)
    {
      if ((np_dg = ((NP_dg *) q_deq (np_Int.procprec_q[j]))))
	{
	  i++;
	  np_Int.total_proc_pkts--;
	}
      else
	j++;
    }
  /* note: don't have to worry about proc_pkts, or proc_prec because
   * they measure the highest priorty and we're purging from the
   * lowest priority */
  return;
}

void
purge_send_queues ()
{
  /* start with lowest priority packets, head (oldest) first;
   * this order can be changed if not appropriate for a
   * particular system. ie., can do youngest first. */

  NP_dg *np_dg;
  int todrop;
  short i = 0, j = 0, k = 0, m = 0;
  uint32_t quench_addrs[MAX_ADDR];
  BOOL found = FALSE;

/* Once the MIB is used throughout and we have a definite number on
 * the size of the queues we want, we'll add this to do it
 * 'on the fly', rather than a fixed purge number.
   todrop = (int)((myself->out_pkts)*(1.0-npmib.npInCongThreshold)) + 1;
*/

  todrop = PURGE_AMT;

  /* i runs over the data in each prec level queue, while j
   * switches between prec levels */
  while (i < todrop && j <= MAX_PREC)
    {
      if ((np_dg = ((NP_dg *) q_deq (np_Int.sendprec_q[j]))))
	{
	  i++;
	  np_Int.total_send_pkts--;

	  /* check if we've already seen this src addr
	   * during this purge */
	  for (m = 0; m > k && np_dg->src_addr && !found; m++)
	    {
	      if (np_dg->src_addr == quench_addrs[m])
		{
		  found = TRUE;
		}
	    }
	  /* then free the data */
	  free (np_dg);
	}
      else
	j++;
    }
  /* note: don't have to worry about senc_pkts, or send_prec because
   * they measure the highest priorty and we're purging from the
   * lowest priority */
  return;
}

int
get_np_template (rqts, position)
     scps_np_rqts *rqts;
     short *position;

{
  int cur_index = 3;
  int addr_len2 = 2, addr_len = 2;
  int addr_ptr = 4;
  byte *inbuf = in_data->data + in_data->offset + *position;
  short ipv6 = 0, expaddr = 0, octet3 = 0, octet4 = 0;
  ts_fmt tsf;
  int len = 0, i;

  if (!(inbuf[2] & 0x8) || !(inbuf[3] & 0x4))
    rqts->bqos.precedence = DEF_PREC;
  else
    {
      /* check for bit field continues in octet 3 */
      if (!(inbuf[3] & 0x80))
	{
	  /* start out assuming the BQoS field is at
	     octet 4. We do this because the control
	     field ends at octet 3. */
	  addr_ptr = 4;

	  /* if ExAddr bit set, double the length of
	     the addresses. (was set to 2 above) */
	  if (inbuf[3] & ExADD_MASK)
	    addr_len2 = addr_len2 << 1;
	}
      else
	{
	  addr_ptr = 5;
	  /* Future modification:
	     if IPv6, addr_len2 << 3;
	   */
	}

      /* double if source address present */
      if (inbuf[3] & SA_MASK)
	addr_len2 = (addr_len2 << 1);
      addr_ptr += addr_len2;
      rqts->bqos.precedence = ((inbuf[addr_ptr]) >> 4);
    }


  /* get rid of VPI to find out pk length field. */
  /* Remember that this number includes hdr len, too */
  len = (inbuf[0] & 0x1f);
  len = (len << 8);
  len |= inbuf[1];

  /* check to see if the length is too big or small */
  if (len < MIN_NPHDR_LEN || len > MAX_NP_TOTAL_LEN)
    {
      npmib.npInBadLength++;
      SET_ERR (SCPS_ELENGTH);
      return (-1);
    }


  {
    int convert = 0;

    switch (((inbuf[2]) >> 4))
      {
      case 1:
	convert = SCMP;
	break;
      case 4:
	convert = SCPSCTP;
	break;
      case 5:
	convert = SCPSUDP;
	break;
      case 6:
	convert = SCPSTP;
	break;
      case 8:
	convert = SP;
	break;
      case 10:
	convert = IPV6AUTH;
	break;
      case 11:
	convert = IPV6ESP;
	break;
      }

    rqts->tpid = convert;
  }

#ifdef SCPSSP
  rqts->tpid = SP;
#endif /* SCPSSP */

  if (inbuf[2] & BFC1_MASK)
    {
      octet3 = TRUE;
      if (inbuf[3] & ExADD_MASK)
	{
	  expaddr = TRUE;
	  addr_len += 2;
	}

      if (inbuf[3] & BFC_MASK)
	{
	  octet4 = TRUE;
	  cur_index = 5;

	  if (inbuf[4] & IPv6_MASK)
	    {
	      ipv6 = TRUE;
	      addr_len += 14;
	      /* IPv6 not yet fully defined by standards body
	         * This error flag will go away with IPv6 release */
	      SET_ERR (SCPS_EIPV6);
	      return (-1);
	    }
	}
      else
	{
	  cur_index = 4;
	}
    }

  /* Error: both ExpAddr & IPv6 bits set in NP hdr */
  if (addr_len > 16)
    {
      npmib.npInBadAddress++;
      SET_ERR (SCPS_EREQADDR);
      return (-1);
    }

  if (inbuf[2] & DA_MASK)
    {
      /* check if multicast or broadcast address */
      if ((inbuf[cur_index + addr_len - 1] & 0x1) && (1 == 0))
	{			/* last bit set */
	}
      else
	{
	  rqts->ipv4_dst_addr = NP_array_to_IP (cur_index, addr_len);
	  if (!(rqts->ipv4_dst_addr))
	    {
	      npmib.npInBadAddress++;
	      SET_ERR (SCPS_ENODSTADDR);
	      return (-1);
	    }
	}
      cur_index += addr_len;
    }

  /* SRC ADDRESS */
  if (octet3 && (inbuf[3] & SA_MASK))
    {
      rqts->ipv4_src_addr = NP_array_to_IP (cur_index, addr_len);
      if (!(rqts->ipv4_src_addr))
	{
	  npmib.npInBadAddress++;
	  SET_ERR (SCPS_ENOSRCADDR);
	  return (-1);
	}
      cur_index += addr_len;
    }

  if (octet3)
    {
      /* HOP COUNT WE CANT MODIFY WITH THE HOP COUNT UNTIL WE HAVE DONE THE CKSUM */
      if (inbuf[3] & HP_MASK)
	{
	  cur_index++;
	}

      /* TIMESTAMP */
      if ((tsf = ((inbuf[3] & TS_MASK) >> 3)))
	{
	  rqts->timestamp.format = tsf;
	  for (i = 0; i < 3; i++)
	    rqts->timestamp.ts_val[i] = inbuf[cur_index++];
	  if (tsf == SCPS32)
	    rqts->timestamp.ts_val[i] = inbuf[cur_index++];
	}

      /* QoS */
      if (inbuf[3] & QOS_MASK)
	{
	  rqts->bqos.precedence = (inbuf[addr_ptr] >> 4);
	  rqts->bqos.routing = ((inbuf[addr_ptr] & 0xc) >> 2);
	  rqts->bqos.pro_specific = (inbuf[addr_ptr] & 0x3);
	}

      /* Exp ADDRESSES -- already taken care of */

      /* this bit shouldn't be turned on: undefined version  */
      if (inbuf[3] & 0x1)
	{
	  /* This is a locally-set action. This implementation chooses
	     ** to treat it as an error.
	   */
	  return (-1);
	}
    }				/* end of octet3 */

  if (octet4)
    {

      /* IPv6 ADDRESS -- already taken care of */

      /* EXPANDED QOS */
      if (inbuf[4] & ExQOS_MASK)
	{
	  rqts->eqos.ip_precedence = (inbuf[cur_index] >> 5);
	  rqts->eqos.ip_tos = ((inbuf[cur_index] & 0x1e) >> 1);
	  cur_index++;
	}

      /* these bits shouldn't be turned on */
      if (inbuf[4] & 0xf)
	{
	  /* this is a locally-set action. This implementation chooses to
	   ** treat an unexpected version as an error.
	   */
	  SET_ERR (SCPS_EVERSION);
	  return (-1);
	}
    }

/* CHECKSUM */
  if (inbuf[2] & CKSUM_MASK)
    {
      rqts->cksum = TRUE;

      cur_index++;
      cur_index++;
    }
  /* MJZ - don't convert to host byte order; TP seems to want
   * them in network byte order. 
   rqts->ipv4_dst_addr = ntohl(rqts->ipv4_dst_addr);
   rqts->ipv4_src_addr = ntohl(rqts->ipv4_src_addr);
   */
  *position += cur_index;

  return (1);
}
