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
#include "scps_ip.h"
#include "scpsudp.h"
#include "tp_debug.h"  // Included for LOG_PACKET in case DEBUG_TCPTRACE is defined.

#ifdef __FreeBSD__
#define __ISBSDISH__
#endif /* __FreeBSD__ */
#ifdef NETBSD
#define __ISBSDISH__
#endif /* NETBSD */

#ifdef __OpenBSD__
#define __ISBSDISH__
#endif /* __OpenBSD__ */

#ifdef LL_RAWIP
int ll_rawip = 1;
#else /* LL_RAWIP */
int ll_rawip = 0; 
#endif /* LL_RAWIP */

#ifdef TAP_INTERFACE
#include "tap.h"
#include "other_proto_handler.h"
#endif /* TAP_INTERFACE */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: ip.c,v $ -- $Revision: 1.40 $\n";
#endif

extern struct msghdr out_msg;
extern struct _ll_queue_element *in_data;

extern int scps_udp_port;

udp_Header *up;
#ifdef GATEWAY
#include "rs_config.h"
extern GW_ifs gw_ifs;
extern struct _interface *sock_interface;
extern struct _interface *divert_interface;

#ifdef GATEWAY_DUAL_INTERFACE
extern int special_port_number;
extern uint32_t special_ip_addr;
#endif /* GATEWAY_DUAL_INTERFACE */

#endif /* GATEWAY */

/*
 * Pass in a requirements structure and generate a 
 * template for it; Pass the template back to the 
 * caller.
 */

int
ip_get_template (scps_np_rqts * rqts, ip_template * ip_templ)
{
  ip_templ->nl_head.ipv4.vht = htons (0x4500 | rqts->DSCP);
  ip_templ->nl_head.ipv4.identification = htons (rqts->tpid);
  ip_templ->nl_head.ipv4.frag = 0;
/* 
 * The following is actually wrong; 
 * Use of the SP should be determined on a socket-by-socket 
 * basis, not mandated at compile time. This needs to be
 * fixed.
 */
  ip_templ->nl_head.ipv4.ttlProtocol = htons ((250 << 8) + rqts->tpid);
  ip_templ->nl_head.ipv4.checksum = 0;
  ip_templ->nl_head.ipv4.source = htonl (rqts->ipv4_src_addr);
  ip_templ->nl_head.ipv4.destination = htonl (rqts->ipv4_dst_addr);
  ip_templ->nl_head.ipv4.length = 0;
  ip_templ->protocol_fam = NL_PROTOCOL_IPV4;
  return (20);

}

/* This function looks like ip_request, but all I want it
 * to do is tell me how int32_t the ip-header will be so I 
 * can make room for it in the mbuffer;
 */
int
ip_header_len (rqts, nroute, length, data)
{
  /* This is good enough for right now */
  return (20);
}

/* 
 * The "one-shot" approach to sending an ip datagram; 
 * The requirements structure is passed down, and a template
 * is generated for it prior to calling ip_trequest. This is
 * only going to be used for connectionless transport protocols
 * (unless they've called connect() to bind to a destination address
 * 
 * An obvious improvement to this code would be to cache the last
 * generated template since odds are that it will be identical to
 * the next one generated (packet-trains)
 * 
 */

int
ip_request (tp_Socket * s, struct mbuff *m, uint32_t * bytes_sent)
{
  ip_template ph;
  int cc;

  ip_get_template (&(s->np_rqts), &ph);
  cc = ip_trequest (s, m, bytes_sent);
  return (cc);
}

/* 
 * Coallesce a locally generated network protocol header and the
 * data passed down to me, then push it onto the appropriate network
 * interface.
 *
 * This function (and all it's equivalents (PATH, SCPS-NP, etc.) 
 * need the following passed in as parameters:
 *
 * int
 * ip_trequest (tp_Socket *s, struct mbuff *m, uint32_t *bytes_sent) 
 * tp_Socket    *s           <- The owning socket
 * struct mbuff *m           <- The transport & SP header and actual data
 * uint32_t     *bytes_sent  <- The number of bytes we expect to send
 *
 * I want this to pass me a iov_vector instead of the data and then
 * I want ot push out the iov_vector with a writev()
 */

int
ip_trequest (tp_Socket * s, struct mbuff *m, uint32_t * bytes_sent)
{
  ip_template *ip_templ;
  route *nroute;
  uint32_t length;
  struct _interface *interface;
  struct addrs next_hop;
  int cc;

  /* 
   * Grab the appropriate template and route from the socket structure:
   * This will be cleaner when the template in the socket is also
   * a pointer, but for now...
   */

  ip_templ = &(s->ip_templ);
  nroute = s->rt_route;


#ifdef TAP_INTERFACE
      memcpy (&(s->np_rqts.dst_mac_addr [0]), &(s->dst_mac_addr [0]), 6);
      memcpy (&(s->np_rqts.src_mac_addr [0]), &(s->src_mac_addr [0]), 6);
      s->np_rqts.frame_type = s->frame_type;
      s->np_rqts.recv_tap_if = s->recv_tap_if;
#endif /* TAP_INTERFACE */

  /* Setup the out_msg structure and leave space for:
   *   slot[0]  : raw link protocol packet (or Raw-IP)
   *   slot[1]  : network protocol header (to be built here)
   *   slot[2]  : the security and transport protocol headers
   */

  out_msg.msg_iovlen = buff_vec (m, &out_msg, 3);

  /*
   * Attach the security and transport headers in the mbuff */

  out_msg.msg_iov[2].iov_base = m->m_pktdat + s->th_off;
  out_msg.msg_iov[2].iov_len = m->m_len;

  /* Was... */
  /* length = m->m_len + m->m_ext.len + s->np_size; */
  length = m->m_len + ((m->m_flags & M_EXT) ? 1 : 0) * m->m_ext.len + s->np_size;

  /* 
   * Initial length is the size of the data plus
   * transport & security headers already in mbuff
   * plus the header we are building here.
   */

  if (length > MAX_MTU)
    {
      SET_ERR (SCPS_EMSGSIZE);
      return (-1);
    }

  /* 
   * I've got the prototype IP header in s->ip_templ, so I should have
   * all the information that I need except the length of this header...
   */

  s->ip_templ.nl_head.ipv4.length = htons (length);	/* Could have done this asignment above */
  s->ip_templ.nl_head.ipv4.checksum = 0;
  s->ip_templ.nl_head.ipv4.identification++;
  s->ip_templ.nl_head.ipv4.checksum = ~checksum ((word *) & (s->ip_templ),

				 inv4_GetHdrlenBytes ((in_Header *) & (s->ip_templ)));

  /* Stuff the data into the iovec */

#ifdef DIVERT_N_RAWIP
  out_msg.msg_iov[1].iov_base = (void *) &(s->ip_templ.nl_head.ipv4);
  out_msg.msg_iov[1].iov_len = s->np_size;
#else /* DIVERT_N_RAWIP */
if (!ll_rawip) {
  out_msg.msg_iov[1].iov_base = (void *) &(s->ip_templ.nl_head.ipv4);
  out_msg.msg_iov[1].iov_len = s->np_size;
} else {
  out_msg.msg_iov[1].iov_len = 0;
}
#endif /* DIVERT_N_RAWIP */

  /* We really need to decide which interface to go out on... */
  /* We can move this into the np_rqts structure as the default interface */

  if (s->np_rqts.interface)
    interface = s->np_rqts.interface;
  else
    interface = scheduler.interface;

#ifdef GATEWAY_DUAL_INTERFACE
  if (interface == sock_interface) {
        special_port_number = s->special_udp_port;

        special_ip_addr = 0;
	special_ip_addr = interface->remote_ipaddr; 
	if (s->special_ip_addr) {
     		special_ip_addr = s->special_ip_addr;
	}
  } 
#endif /* GATEWAY_DUAL_INTERFACE */

#ifndef DIVERT_N_RAWIP
  next_hop.nl_protocol = NL_PROTOCOL_IPV4;
  next_hop.nl_head.ipv4_addr = s->ip_templ.nl_head.ipv4.destination;

  cc = ll_iovsend (interface, next_hop,
		   s->np_rqts.tpid, (int) length, &out_msg, s->rt_route,&(s->np_rqts));
#else /* DIVERT_N_RAWIP */
  next_hop.nl_protocol = NL_PROTOCOL_IPV4;
  next_hop.nl_head.ipv4_addr = s->gateway_next_hop;
  cc = ll_iovsend (interface, next_hop,
		   s->np_rqts.tpid, (int) length, &out_msg, s->rt_route, &(s->np_rqts));
#endif /* DIVERT_N_RAWIP */

  LOGPACKET(s, m->m_seq, m->m_len + ((m->m_flags & M_EXT) ? 1 : 0) * m->m_ext.len);

  cc += s->np_size;
  *bytes_sent = cc;

  if (cc != length)
    {
#ifdef DEBUG_PRINT
      printf ("XXX  XXX \n");
      printf
	("PDF Error for seq number %lu tried to send %ld octets sent only %d octets\n",
	 m->m_seq, length, cc);
#endif /* DEBUG_PRINT */
    }

  return (cc);
}


int
ip_ind (scps_np_rqts * rqts, int length, int *data_offset)
{
  int cc = 0, len = 0;
  int offset = 0;
  word ip_cks = 0;
  ip_template *ip;
  struct _interface *interface;
  int total_offset = 0;
  unsigned ip_frag;

#ifdef TAP_INTERFACE
  int rc;
  unsigned char proto;
#endif /* TAP_INTERFACE */
  /* Find an interface with data */

  for (interface = ((struct _interface *) scheduler.interface);
       (interface && (!(interface->incoming.size)));
       interface = interface->next);

  if ((interface &&
       (cc = ll_nbreceive (interface, &in_data, MAX_MTU, &offset)) > 0))
    {
	in_data->interface = interface;

#ifdef TAP_INTERFACE
    {
	rqts->interface = interface;
	rc = tap_ind (interface, &in_data, MAX_MTU, &offset, rqts);

#ifdef DEBUG_TAP_INTERFACE
        printf ("DST %02x %02x %02x %02x %02x %02x\n",
                rqts->dst_mac_addr [0],
                rqts->dst_mac_addr [1],
                rqts->dst_mac_addr [2],
                rqts->dst_mac_addr [3],
                rqts->dst_mac_addr [4],
                rqts->dst_mac_addr [5]);

        printf ("SRC %02x %02x %02x %02x %02x %02x\n",
                rqts->src_mac_addr [0],
                rqts->src_mac_addr [1],
                rqts->src_mac_addr [2],
                rqts->src_mac_addr [3],
                rqts->src_mac_addr [4],
                rqts->src_mac_addr [5]);

        printf ("Frame type = %x\n", rqts->frame_type);
#endif /* DEBUG_TAP_INTERFACE */

	switch (rc) {
		case 0:
			return (-1);
		break;

		case -1:
		break;

		default:
		break;
	}
    }	
#endif /* TAP_INTERFACE */

#ifdef ENCAP_RAW
      in_data->offset += 20;
      total_offset +=20;
      cc -= 20;
      offset += 20;
#endif /* ENCAP_RAW */

#ifdef MPF
      ip = (in_Header *) ((void *) in_data->data + in_data->offset);
      if (inv4_GetProtocol (ip) == 0x04) {
          in_data->offset += 20;
          total_offset +=20;
          cc -= 20;
          offset += 20;
      }
#endif /* MPF */

#ifdef GATEWAY_DUAL_INTERFACE
      {
        int layering = GATEWAY_LAYERING_NORMAL;
        int overhead = 0;

	
        ip = (in_Header *) ((void *) in_data->data + in_data->offset);
        if (inv4_GetProtocol (ip) == SCPSUDP) {

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
		total_offset +=overhead;
                cc -= overhead;
                offset += overhead;
              }
           } 
        }
      
      }
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef PRINT_PKT
{
        int i;
                
        printf ("%s %d printing packet (%d)\n", __FILE__, __LINE__, in_data->offset);
        ip = (in_Header *) ((void *) in_data->data + in_data->offset);
        for (i = 0; i < cc; i++) {
                printf ("%2x ", in_data->data [i]);
                if ((i + 1) % 16 == 0) {
                        printf ("\n");
                }
        }
        printf ("\n");
}       
#endif /* PRINT_PKT */

	ip = (in_Header *) ((void *) in_data->data + in_data->offset);

	if ((ntohs (ip->nl_head.ipv4.vht) & 0xf000) != 0x4000) {
		in_data ->offset -= total_offset;
#ifdef TAP_INTERFACE_XXX    ==>  I LEFT THIS OUT NOT SURE  <===
#endif /*  TAP_INTERFACE_XXX  */
                in_data->offset -=SIZE_OF_ETHER_PART;
                in_data->size +=SIZE_OF_ETHER_PART;
		if (interface ->incoming.head == NULL) {
			interface ->incoming.head = in_data;
			interface ->incoming.tail = in_data;
			interface ->incoming.head->next = NULL;
		} else {
			in_data ->next = interface ->incoming.head;
			interface ->incoming.head = in_data;
		}
		interface->incoming.size++;
		scheduler.interface_data++;

#ifdef IPV6
        if ((ntohs (ip->nl_head.ipv4.vht) & 0xf000) == 0x6000) {
                return (NL_TRY_IPV6);
        } else {
                return (NL_TRY_NP);
        }
#else /* IPV6 */
        if ((ntohs (ip->nl_head.ipv4.vht) & 0xf000) != 0x4000) {
                return (NL_TRY_NP);
        }
#endif /* IPV6 */


		return (NL_TRY_NP);
	}

#ifdef GATEWAY
{
	struct stat sb;
	if (gw_ifs.c_pkt_io_filename[0] != '\0') {
		if ((stat (gw_ifs.c_pkt_io_filename, &sb)) < 0) {
		} else {
			syslog (LOG_ERR,"Gateway: Reading data from OS %d\n",cc);
		}		
	}
}
#endif /* GATEWAY */

#ifdef PRINT_PKT 
{
	int i;

	ip = (in_Header *) ((void *) in_data->data + in_data->offset);
	for (i = 0; i < cc; i++) {
		printf ("%2x ", in_data->data [i]);
 		if ((i + 1) % 16 == 0) {
			printf ("\n");
		}
	}
	printf ("\n");
}
#endif /* PRINT_PKT */
	cc = ntohs (ip->nl_head.ipv4.length);

#ifdef TAP_INTERFACE
     ip = (in_Header *) ((void *) in_data->data + in_data->offset);
     proto = inv4_GetProtocol (ip);

     switch (proto) {
         case SCPSTP:
         case SCPSCTP:
	 case ICMP:
//         case SCPSUDP:
           break;

         default:
           other_proto_Handler (interface, &in_data, MAX_MTU, &offset, rqts, proto);
           return (-1);
           break;
     }

#endif /* TAP_INTERFACE */

	if (ll_rawip) {
#ifdef SUNOS
		ip->nl_head.ipv4.length += htons (20);
#endif /* SUNOS */
#ifdef SOLARIS
		ip->nl_head.ipv4.length += htons (20);
#endif /* SOLARIS */
#ifdef IRIX
		ip->nl_head.ipv4.length += htons (20);
#endif /* IRIX */
#ifdef __ISBSDISH__
		ip->nl_head.ipv4.checksum = 0;
#endif /* __ISBSDISH__ */
      }

      /* Make sure that the checksum passes for the IP header */

      if ((ip->nl_head.ipv4.checksum == 0) ||
	  ((ip_cks = checksum ((word *) ip, inv4_GetHdrlenBytes (ip))) == 0xFFFF))
	{
	  /* Fill out the requirements template for the incoming packet */
	  rqts->tpid = inv4_GetProtocol (ip);
	  rqts->ipv4_dst_addr = ntohl (ip->nl_head.ipv4.destination);
	  rqts->ipv4_src_addr = ntohl (ip->nl_head.ipv4.source);
	  /* rqts->timestamp = ; */
	  /* rqts->bqos = ; */
	  /* rqts->eqos = ; */
	  rqts->cksum = 0;
	  rqts->interface = interface;
	  /* rqts->int_del = ; */
	  rqts->nl_protocol = NL_PROTOCOL_IPV4;
	  rqts->DSCP = (unsigned char ) ((ntohs (ip->nl_head.ipv4.vht)) & 0x00ff);
	}
      else
	{
	  syslog (LOG_ERR, "IP checksum failed src = %ud dst = %ud\n",
		  rqts->ipv4_src_addr, rqts->ipv4_dst_addr);
	  fflush (stdout);
	  rqts->interface = interface;
	  rqts->tpid      = 0;
	}

      *data_offset = offset + inv4_GetHdrlenBytes (ip);

	if (ll_rawip) {
#ifdef __ISBSDISH__
		len = (int) ip->nl_head.ipv4.length;
		ip->checksum = 0;
#else /* __ISBSDISH__ */
		len = (int) (ntohs (ip->nl_head.ipv4.length) - inv4_GetHdrlenBytes (ip));
#endif /* __ISBSDISH */
	} else {
		len = (int) (ntohs (ip->nl_head.ipv4.length) - inv4_GetHdrlenBytes (ip));
	}

#ifdef GATEWAY 
#define IP_RF		0x0080
#define IP_DF		0x0040
#define IP_MF		0x0020
#define IP_OFFMASK	0xff1f

	ip_frag = ip->nl_head.ipv4.frag;

      if ((ip_frag & IP_DF) == IP_DF) {

// ONLY DF flag is set - this is ok
	return (len);
      }

      if (ip_frag & (IP_MF | IP_OFFMASK))  {
	syslog (LOG_ERR,"Gateway: Got a fragment\n");
	printf ("Gateway: Got a fragment\n");
	free_ll_queue_element (rqts->interface, in_data);
  	return (-1);
      }
#endif /* GATEWAY  */
      return (len);
    }
  SET_ERR (SCPS_EWOULDBLOCK);
  return (-1);
}
