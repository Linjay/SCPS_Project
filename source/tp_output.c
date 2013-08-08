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
#include "scpserrno.h"
#include "scps_ip.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include "tp_debug.h"

#ifdef SCPSSP
#include "scps_sp.h"
int sp_trequest (tp_Socket * s, route * nroute, int *bytes_sent,
		 struct mbuff *m, int th_off);

#endif /* SCPSSP */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_output.c,v $ -- $Revision: 1.50 $\n";
#endif

int scps_np_get_template (scps_np_rqts * rqts, scps_np_template * templ);
int scps_np_trequest (tp_Socket * s, scps_ts * ts, route * nproute, uint32_t
		      length, struct mbuff *m, u_char th_off);

extern unsigned short tp_id;
extern unsigned short udp_id;
extern struct msghdr out_msg;
extern uint32_t tp_now;

extern int persist_time_outs [TP_MAX_PERSIST_SHIFT];

#define MAX_TPOPTLEN  40	/* should be 40, not 44 */


void
tp_BuildHdr_add_ecbs_header (unsigned char opt[], unsigned short *opt_len, unsigned short *tpopt_len_location)

{
	opt[*opt_len] = TPOPT_SCPS;
        (*opt_len) = (*opt_len) + 1;
	*tpopt_len_location = *opt_len;
        (*opt_len) = (*opt_len) + 1;
}

void
tp_BuildHdr_add_ecbs_header_len (unsigned char opt[], unsigned short *opt_len, unsigned short *tpopt_len_location)

{
	opt [*tpopt_len_location] = *opt_len - *tpopt_len_location + 1;

}

void
tp_BuildHdr_add_ecbs_pad (unsigned char opt[], unsigned short *opt_len, unsigned short *tpopt_len_location)

{
	/* PAD TO 4 octet word */
	while (((*opt_len - ((*tpopt_len_location) -1)) % 4) != 0) {
		opt [*opt_len] = TPOPT_NOP;
        	(*opt_len) = (*opt_len) + 1;
	}


}

int
tp_BuildHdr_add_ecbs1_req (tp_Socket *s, unsigned char opt[], unsigned short *opt_len)


{
	int i;
	int ecbs1_start_value; 
	int ecbs1_len_location;
	unsigned char  ecbs1_len_value;
	u_char value = 0x00;
	int nibble_location;
		   
	ecbs1_start_value = *opt_len;

	if (s->ecbs1 < 255) {
		opt [*opt_len] = s->ecbs1;
        	(*opt_len) = (*opt_len) + 1;
		ecbs1_len_location = *opt_len;
		nibble_location = 1;
	} else {
		opt [*opt_len] = 0xff;
	        (*opt_len) = (*opt_len) + 1;
		ecbs1_len_location = *opt_len;
	        (*opt_len) = (*opt_len) + 1;
		opt [*opt_len] = s->ecbs1 - 256;
		nibble_location = 0;
	        (*opt_len) = (*opt_len) + 1;
	}

	for (i = 0; i < s->ecbs1_len; i++) {
		switch (s->ecbs1_value [i]) {
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
			case '8': case '9':
				value = s->ecbs1_value [i] - '0';
			break;

			case 'A': case 'B': case 'C': case 'D':
			case 'E': case 'F':
				value = s->ecbs1_value [i] - 'A' + 10;
			break;

			case 'a': case 'b': case 'c': case 'd':
			case 'e': case 'f':
				value = s->ecbs1_value [i] - 'a' + 10;
			break;

			default:
			break;
		}

		if (nibble_location % 2 == 0) {
		/* first nibble */
			value = value << 4;
			opt[*opt_len] |=value;
		} else {
		/*second nibble */
			opt[*opt_len] |=value;
        		(*opt_len) = (*opt_len) + 1;
		}
		nibble_location++;
	}

	if (nibble_location % 2 == 1) {
		/* we need to pad to a nibble */
        	(*opt_len) = (*opt_len) + 1;
	}
             
	if ((*opt_len - ecbs1_start_value) % 2 == 1) {
		/* Now we need to pad to a 16 bit word */
        	(*opt_len) = (*opt_len) + 1;
	}

	ecbs1_len_value = ((*opt_len - ecbs1_start_value)/2)-1;
	opt [ecbs1_len_location] |= ecbs1_len_value <<4;

	return (1);
}

int
tp_BuildHdr_add_ecbs1_reply (tp_Socket *s, unsigned char opt[], unsigned short *opt_len)
{
	unsigned short ecbs1_start_value;
	int ecbs1_len_location;
	unsigned char  ecbs1_len_value;
	u_char value = 0x00;
	u_char value_req= 0x00;
	int nibble_location;
	int i;

	ecbs1_start_value = *opt_len;

	if (s->ecbs1 < 255) {
		opt [(*opt_len)] = s->ecbs1;
		(*opt_len) = (*opt_len) +1;
		ecbs1_len_location = (*opt_len);
		nibble_location = 1;
	} else {
		opt [(*opt_len)] = 0xff;
		(*opt_len) = (*opt_len) +1;
		ecbs1_len_location = (*opt_len);
		(*opt_len) = (*opt_len) +1;
		opt [(*opt_len)] = s->ecbs1 - 256;
		nibble_location = 0;
		(*opt_len) = (*opt_len) +1;
	}

	for (i = 0; i < s->ecbs1_len; i++) {
		switch (s->ecbs1_value [i]) {
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
			case '8': case '9':
				value = s->ecbs1_value [i] - '0';
			break;

			case 'A': case 'B': case 'C': case 'D':
			case 'E': case 'F':
				value = s->ecbs1_value [i] - 'A' + 10;
			break;

			case 'a': case 'b': case 'c': case 'd':
			case 'e': case 'f':
				value = s->ecbs1_value [i] - 'a' + 10;
			break;

			default:
			break;
		}

		switch (s->ecbs1_req_value [i]) {
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
			case '8': case '9':
				value_req = s->ecbs1_req_value [i] - '0';
			break;

			case 'A': case 'B': case 'C': case 'D':
			case 'E': case 'F':
				value_req = s->ecbs1_req_value [i] - 'A' + 10;
			break;

			case 'a': case 'b': case 'c': case 'd':
			case 'e': case 'f':
				value_req = s->ecbs1_req_value [i] - 'a' + 10;
			break;

			default:
			break;
		}

		value = value & value_req;
		if (nibble_location % 2 == 0) {
			/* first nibble */
			value = value << 4;
			opt[(*opt_len)] |=value;

		} else {
			/*second nibble */
			opt[(*opt_len)] |=value;
			(*opt_len) = (*opt_len) +1;
		}
		nibble_location++;
	}

	if (nibble_location % 2 == 1) {
		/* we need to pad to a nibble */
		(*opt_len) = (*opt_len) +1;
	}
             
	if (((*opt_len) - ecbs1_start_value) % 2 == 1) {
		/* Now we need to pad to a 16 bit word */
		(*opt_len) = (*opt_len) +1;
	}

	ecbs1_len_value = (((*opt_len) - ecbs1_start_value)/2)-1;
	opt [ecbs1_len_location] |= ecbs1_len_value <<4;

	return (1);
}

int
tp_BuildHdr_add_ecbs2_req (tp_Socket *s, unsigned char opt[], unsigned short *opt_len)


{
	int i;
	unsigned short ecbs2_start_value;
	int ecbs2_len_location;
	unsigned char  ecbs2_len_value;
	u_char value = 0x00;
	int nibble_location;
		   
	ecbs2_start_value = *opt_len;

	if (s->ecbs2 < 255) {
		opt [*opt_len] = s->ecbs2;
        	(*opt_len) = (*opt_len) + 1;
		ecbs2_len_location = *opt_len;
		nibble_location = 1;
	} else {
		opt [*opt_len] = 0xff;
	        (*opt_len) = (*opt_len) + 1;
		ecbs2_len_location = *opt_len;
	        (*opt_len) = (*opt_len) + 1;
		opt [*opt_len] = s->ecbs2 - 256;
		nibble_location = 0;
	        (*opt_len) = (*opt_len) + 1;
	}

	for (i = 0; i < s->ecbs2_len; i++) {
		switch (s->ecbs2_value [i]) {
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
			case '8': case '9':
				value = s->ecbs2_value [i] - '0';
			break;

			case 'A': case 'B': case 'C': case 'D':
			case 'E': case 'F':
				value = s->ecbs2_value [i] - 'A' + 10;
			break;

			case 'a': case 'b': case 'c': case 'd':
			case 'e': case 'f':
				value = s->ecbs2_value [i] - 'a' + 10;
			break;

			default:
			break;
		}

		if (nibble_location % 2 == 0) {
		/* first nibble */
			value = value << 4;
			opt[*opt_len] |=value;
		} else {
		/*second nibble */
			opt[*opt_len] |=value;
        		(*opt_len) = (*opt_len) + 1;
		}
		nibble_location++;
	}

	if (nibble_location % 2 == 1) {
		/* we need to pad to a nibble */
        	(*opt_len) = (*opt_len) + 1;
	}
             
	if ((*opt_len - ecbs2_start_value) % 2 == 1) {
		/* Now we need to pad to a 16 bit word */
        	(*opt_len) = (*opt_len) + 1;
	}

	ecbs2_len_value = ((*opt_len - ecbs2_start_value)/2)-1;
	opt [ecbs2_len_location] |= ecbs2_len_value <<4;

	return (1);
}

int
tp_BuildHdr_add_ecbs2_reply (tp_Socket *s, unsigned char opt[], unsigned short *opt_len)
{
	unsigned short ecbs2_start_value;
	int ecbs2_len_location;
	unsigned char  ecbs2_len_value;
	u_char value = 0x00;
	u_char value_req = 0x00;
	int nibble_location;
	int i;

	ecbs2_start_value = *opt_len;

	if (s->ecbs2 < 255) {
		opt [(*opt_len)] = s->ecbs2;
		(*opt_len) = (*opt_len) +1;
		ecbs2_len_location = (*opt_len);
		nibble_location = 1;
	} else {
		opt [(*opt_len)] = 0xff;
		(*opt_len) = (*opt_len) +1;
		ecbs2_len_location = (*opt_len);
		(*opt_len) = (*opt_len) +1;
		opt [(*opt_len)] = s->ecbs2 - 256;
		nibble_location = 0;
		(*opt_len) = (*opt_len) +1;
	}

	for (i = 0; i < s->ecbs2_len; i++) {
		switch (s->ecbs2_value [i]) {
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
			case '8': case '9':
				value = s->ecbs2_value [i] - '0';
			break;

			case 'A': case 'B': case 'C': case 'D':
			case 'E': case 'F':
				value = s->ecbs2_value [i] - 'A' + 10;
			break;

			case 'a': case 'b': case 'c': case 'd':
			case 'e': case 'f':
				value = s->ecbs2_value [i] - 'a' + 10;
			break;

			default:
			break;
		}

		switch (s->ecbs2_req_value [i]) {
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
			case '8': case '9':
				value_req = s->ecbs2_req_value [i] - '0';
			break;

			case 'A': case 'B': case 'C': case 'D':
			case 'E': case 'F':
				value_req = s->ecbs2_req_value [i] - 'A' + 10;
			break;

			case 'a': case 'b': case 'c': case 'd':
			case 'e': case 'f':
				value_req = s->ecbs2_req_value [i] - 'a' + 10;
			break;

			default:
			break;
		}

		value = value & value_req;
		if (nibble_location % 2 == 0) {
			/* first nibble */
			value = value << 4;
			opt[(*opt_len)] |=value;

		} else {
			/*second nibble */
			opt[(*opt_len)] |=value;
			(*opt_len) = (*opt_len) +1;
		}
		nibble_location++;
	}

	if (nibble_location % 2 == 1) {
		/* we need to pad to a nibble */
		(*opt_len) = (*opt_len) +1;
	}
             
	if (((*opt_len) - ecbs2_start_value) % 2 == 1) {
		/* Now we need to pad to a 16 bit word */
		(*opt_len) = (*opt_len) +1;
	}

	ecbs2_len_value = (((*opt_len) - ecbs2_start_value)/2)-1;
	opt [ecbs2_len_location] |= ecbs2_len_value <<4;

	return (1);
}


struct mbuff *
tp_BuildHdr (tp_Socket * s, struct mbuff *mbuffer, int push)
{
  tp_Header *th;
  uint32_t *option_start;
  short offset;
  uint32_t long_temp = 0;
  u_char opt[MAX_TPOPTLEN];
  unsigned short optlen;
  struct mbuff *temp_var;
  struct mbuff *ptr;

  int tp_hdr_len, tp_data_len;
  u_char snack_ok = 0;
  int snack_hole, snack_offset;

  memset (opt, 0x0, MAX_TPOPTLEN);
  temp_var = mbuffer;

  if (!(mbuffer))
    {
      mbuffer = alloc_mbuff (MT_HEADER);
      long_temp = 1;
      snack_ok = 1;
    }
  if (!(mbuffer))
    {
      SET_ERR (SCPS_ENOMEM);
      return (0x0);
    }
  if (push)
    s->flags |= tp_FlagPUSH;
  else
    s->flags &= ~tp_FlagPUSH;

  offset = (short) (s->th_off);
  th = (tp_Header *) (mbuffer->m_pktdat + offset);

  mbuffer->m_offset = offset;

#ifdef MFX_TRANS
  mbuffer->m_mfx_count = 0;
#endif /* MFX_TRANS */

  option_start = (uint32_t *) ((uint32_t) (th) + 20);
  /* end of basic TP header */

  tp_hdr_len = 20;		/* start the tp length calculation 
				 * with the tp header size */

  th->srcPort = s->myport;
  th->dstPort = s->hisport;
  th->urgentPointer = 0;

#ifdef GATEWAY
  if (s->funct_flags & FUNCT_REL_SEQ_NUM_URG_PTR) {
    uint32_t x;

    x = s-> rel_seq_num_urg_ptr - (s->seqnum - s->initial_seqnum);

    if (x < TP_MAXWIN) {
      s->flags |= tp_FlagURG; 
      th->urgentPointer = htons (x);
    }
  }
#endif /*  GATEWAY */

  /*
   * long_temp is a 1 if this call had no data associated with it.
   * If this is the case, this segment will go out promptly, since 
   * it is a pure ack.  Check FIN and SYN!
   */

  if (long_temp) {
    th->seqnum = htonl (s->seqsent);
  } else {
    th->seqnum = htonl (s->seqnum);
  }
  tp_WinAck (s, th);
  /* if (s->otimers[Del_Ack]->set)
     clear_timer(s->otimers[Del_Ack], 1); */
  th->th_x2 = 0;		/* Clear reserved bits */
  th->flags = s->flags;
  th->th_off = 0x5;		/* 4-bit header len */
  th->checksum = 0;

  /*
   * Before ESTABLISHED, force sending of initial options unless TP
   * set not to do any options. NOTE: we assume that the IP/TP header
   * plus TP options always fit in a single mbuf, leaving room for a
   * maximum link header, i.e. max_linkhdr + sizeof (struct tpiphdr) +
   * optlen <= MHLEN
   */

  optlen = 0;
  if (s->flags & tp_FlagSYN)
    {
#ifdef OPT_SCPS

      if (s->capabilities & CAP_JUMBO)
	{
	   if (s->RTO_TO_PERSIST_CTR)  {
              s->rt_route->flags |= RT_LINK_AVAIL;
           }
	  /* 
	   * Going to build a jumbo-SCPS option for the SYN. 
	   * The format of the jumbo-SCPS option is as follows: 
	   * 
	   * +--------+---------+--------------+-------------+----------------+
	   * |  type = 17 | length = ?? |  capability bitmap |  option values |
	   * +--------+---------+--------------+-------------+----------------+
	   *
	   * capability bitmap:
	   * one byte bitmap representing the following:
	   * 
	   * +=====+========+========+======+==========+======+======+======+
	   * |BETS | SNACK1 | SNACK2 | Header | Time   | Rsvd | Rsvd | Rsvd |
	   * | OK  | OK     |   OK   | Comp.  | Stamps |      |      |      |
	   * +=====+========+========+======+==========+======+======+======+
	   *
	   * option values (in order of appearance if capability selected):
	   * 
	   * BETS Permitted        = +0  (No length impact)
	   * SNACK1 Permitted      = +0  (No length impact)
	   * SNACK2 Permitted      = +0  (No length impact)
	   * Header Compression    = +1 byte (for compression ID)
	   * TimeStamps            = +0  (No length impact)
	   *
	   * length : The length field is calculated as follows:
	   * base option length   =  3  (type, length, capability bitmap)
	   * SNACK Permitted      = +0  (No length impact)
	   * BETS Permitted       = +0  (No length impact)
	   * Header Compression   = +1  (Single byte of local compression Id)
	   * TimeStamps           = +8  (8 bytes of timestamp)
	   * Padding via NOPs     = 0/1 (depends upon total length prior to padding)
	   *
	   */

	  opt[0] = TPOPT_SCPS;
	  optlen = 4;
	  opt[2] = 0x0;		/* Start with a clear bitmap */
	  opt[3] = 0;

#ifdef OPT_BETS
	  if (s->capabilities & CAP_BETS)
	    {
	      if (s->BETS.Flags & BF_REQUEST_BETS)
		opt[2] |= 0x80;	/* Mask in the BETS bit */
	    }
#endif /* OPT_BETS */
#ifdef OPT_SNACK1
	  if (s->capabilities & CAP_SNACK)
	    opt[2] |= 0x40;	/* Mask in the Opt_SNACK1 bit */
#endif /* OPT_SNACK1 */
#ifdef OPT_SNACK2
	  if (s->capabilities & CAP_SNACK2)
	    opt[2] |= 0x20;	/* Mask in the Opt_SNACK1 bit */
#endif /* OPT_SNACK2 */
#ifdef OPT_COMPRESS
	  if (s->capabilities & CAP_COMPRESS)
	    {
	      s->sockFlags |= TF_REQ_COMPRESS;
	      opt[2] |= 0x10;	/* Mask in the Compression bit */
	      opt[3] = (byte) s->local_conn_id;
	    }
#endif /* OPT_COMPRESS */
#ifdef NOT_DEFINED
	  if (s->capabilities & CAP_TIMESTAMP)
	    opt[2] |= 0x08;
#endif /* NOT_DEFINED */
	  opt[1] = 4;		/* We *always* are 4 bytes in length; */
	}
#endif /* OPT_SCPS */
#ifdef OPT_SCPS 
        if (s->ecbs1_len > 0) {
		if (s->ecbs1_req_len == 0) {
                	/* We are Initiating the stuff here */
			unsigned short opt_len_location;
			tp_BuildHdr_add_ecbs_header (opt, &optlen, &opt_len_location);
			tp_BuildHdr_add_ecbs1_req (s, opt, &optlen);
			if (s->ecbs2_len >0) {
				tp_BuildHdr_add_ecbs2_req (s, opt, &optlen);
			}
			tp_BuildHdr_add_ecbs_header_len (opt, &optlen, &opt_len_location);
			tp_BuildHdr_add_ecbs_pad (opt, &optlen, &opt_len_location);
                } else {
			/* We are responding to the stuff here */
			unsigned short opt_len_location;
			if ( (s->ecbs1 == s->ecbs1_req) || ( (s->ecbs2_len >0) && (s->ecbs2 == s->ecbs2_req)) ) {
				tp_BuildHdr_add_ecbs_header (opt, &optlen, &opt_len_location);
				if (s->ecbs1 == s->ecbs1_req) {
					tp_BuildHdr_add_ecbs1_reply (s, opt, &optlen);
				}
				if ( (s->ecbs2_len >0) && (s->ecbs2 == s->ecbs2_req)) {
					tp_BuildHdr_add_ecbs2_reply (s, opt, &optlen);
				}
				tp_BuildHdr_add_ecbs_header_len (opt, &optlen, &opt_len_location);
				tp_BuildHdr_add_ecbs_pad (opt, &optlen, &opt_len_location);
			}
                }
         }
#endif /* OPT_SCPS */

      /* Send MAXSEG Option */
      opt[optlen] = TPOPT_MAXSEG;
      opt[optlen + 1] = 4;

      /* A temporary variable would be better here... */
      s->maxseg = htons (s->maxseg);
      memcpy ((void *) (opt + optlen + 2),
	      (void *) &(s->maxseg),
	      sizeof (s->maxseg));
      s->maxseg = ntohs (s->maxseg);
      s->my_mss_offer = s->maxseg;
      optlen += 4;

#ifdef OPT_SCALE
      /* Window Scaling Option */
      if ((s->sockFlags & TF_REQ_SCALE) &&
	  ((s->flags & tp_FlagACK) == 0 ||
	   (s->sockFlags & TF_RCVD_SCALE)))
	{
	  *((uint32_t *) (opt + optlen)) =
	    htonl (
		    TPOPT_NOP << 24 |
		    TPOPT_WINDOW << 16 |
		    TPOLEN_WINDOW << 8 |
		    s->request_r_scale);
	  optlen += 4;
	}
#endif /* OPT_SCALE */

      /*
       * We handle BETS, SNACK, TimeStamps and Compression here if
       * we don't specify the Jumbo SCPS option at compile time
       */
#ifndef OPT_SCPS
#ifdef  OPT_SNACK1
      if (s->capabilities & CAP_SNACK)
	{
	  if (s->sockFlags & TF_REQ_SNACK1)
	    {

	      *((uint32_t *) (opt + optlen)) =
		htonl (TPOPT_NOP << 24 |
		       TPOPT_NOP << 16 |
		       TPOPT_SNACK1_PERMITTED << 8 |
		       TPOLEN_SNACK1_PERMITTED);
	      optlen += 4;
	    }
	}
#endif /* OPT_SNACK1 */
#ifdef OPT_TSTMP
      if (s->capabilities & CAP_TIMESTAMP)
	{

	}
#endif /* OPT_TSTMP */
#endif /* OPT_SCPS */

#ifdef OPT_BETS
      if (s->capabilities & CAP_BETS)
	{
	  if (s->BETS.Flags & BF_REQUEST_BETS)
	    {
	      *((uint32_t *) (opt + optlen)) =
		htonl (
			TPOPT_NOP << 24 |
			TPOPT_NOP << 16 |
			TPOPT_BETS_PERMITTED << 8 |
			TPOLEN_BETS_PERMITTED);
	      optlen += 4;
	    }
	}
#endif /* OPT_BETS */
    }

#ifdef OPT_TSTMP
  if (s->capabilities & CAP_TIMESTAMP)
    {
      /*
       * Send a timestamp and echo-reply if 
       * this is a SYN and our side wants to 
       * use timestamps (TF_REQ_TSTMP is set) 
       * or both our side and our peer have 
       * sent timestamps in our SYN's.
       */

      if ((s->sockFlags & TF_REQ_TSTMP) &&
	  ((s->flags & tp_FlagRST) == 0) &&
	  (((s->flags & (tp_FlagSYN | tp_FlagACK)) == tp_FlagSYN) ||
	   (s->sockFlags & TF_RCVD_TSTMP)))
	{
	  uint32_t *lp = (uint32_t *) (opt + optlen);

	  /* Form timestamp option as shown in appendix A of RFC 1323. */
	  *lp++ = htonl (TPOPT_TSTAMP_HDR);
	  *lp++ = htonl (tp_now);
	  *lp = htonl (s->ts_recent);
	  optlen += TPOLEN_TSTAMP_APPA;
	}
    }
#endif /* OPT_TSTMP */

#ifndef OPT_SCPS
#ifdef OPT_COMPRESS
  if (s->capabilities & CAP_COMPRESS)
    {
      /*
       * Send a compress option with our connection id 
       * if this is a SYN and our side wants to use 
       * compression (TF_REQ_COMPRESS) or we want to
       * do compression and the other side has already 
       * said it wants to also.
       */

      if ((s->flags & tp_FlagSYN) && (s->sockFlags & TF_REQ_COMPRESS) &&
	  (((s->flags & tp_FlagACK) == 0) || (s->sockFlags & TF_RCVD_COMPRESS)))
	{
	  uint32_t *lp = (uint32_t *) (opt + optlen);
	  *lp++ = htonl (TPOPT_COMPRESS_HDR | (byte) s->local_conn_id);
	  optlen += TPOLEN_COMPRESS_PAD;
	}
    }
#endif /* OPT_COMPRESS */
#endif /* OPT_SCPS */

  /*
   * If the EOR flag is set in the mbuffer, 
   * generate an End-Of-Record Option
   */
  if (mbuffer->m_flags & M_EOR)
    {
      uint32_t *lp = (uint32_t *) (opt + optlen);

      *lp = htonl (TPOPT_EOR_HDR);
      optlen += TPOLEN_EOR_PAD;
    }

  /*
   * If the SEND_SNACK bit is set in 
   * s->SNACK_Flags, build a SNACK Option
   *
   *
   * Simple SNACK1 format: 
   +--------------+ 
   | Kind         |
   +--------------+ 
   | Opt Len      | 
   +--------------+
   | Hole offset  |  Hole offset = 
   +--------------+
   | Hole offset  +      |
   +--------------+ 
   | Hole 1 size  |  Hole = s->SNACK1_Seq - s->acknum 
   +--------------+ 
   | Hole 1 size  | 
   +--------------+
   */

#ifdef OPT_SNACK1
 if ((s->capabilities & CAP_SNACK) && (s->sockFlags & TF_SNACK1_PERMIT)) { 
/*  if (s->capabilities & CAP_SNACK)
    { */
      if ((snack_ok) && (s->SNACK1_Flags & SEND_SNACK1))
	{
	  uint32_t *lp = (uint32_t *) (opt + optlen);
	  if (s->Out_Seq->start)
	    {
#ifdef DEBUG_SNACK
	      printf ("%s s->Out_Seq->start(%p) advance_hole(%d)\n",
		      stringNow (), s->Out_Seq->start, s->advance_hole);
#endif /* DEBUG_SNACK */
	      for (ptr = s->Out_Seq->start;
		   ptr && SEQ_LEQ (ptr->m_seq, s->SNACK1_Receive_Hole);
		   ptr = ptr->m_next);
	      if (ptr || ((s->advance_hole) < RESNACK_THRESH))
		{
		  /*
		   * This causes us to re-snack the segment at snd_una a
		   * number of times.  We do this because it's _REALLY_BAD_ if
		   * you lose the snack for the guy at snd_una.
		   */
		  if ((s->advance_hole) < RESNACK_THRESH)
		    {
		      (s->advance_hole)++;
		      ptr = s->Out_Seq->start;
#ifdef DEBUG_SNACK
		      printf ("      force resnack of snd_una(%lu)\n", ptr->m_seq);
#endif /* DEBUG_SNACK */
		    }
		  else
		    {
#ifdef DEBUG_SNACK
		      printf ("      voluntary snack of (%lu)\n", ptr->m_seq);
#endif /* DEBUG_SNACK */
		      s->SNACK1_Receive_Hole = ptr->m_seq;
		    }
		  if (ptr->m_prev)
		    {
		      snack_offset = (int)
			((ptr->m_prev->m_seq + ptr->m_prev->m_plen) -
			 s->acknum) /
			(s->mss_offer - TP_HDR_LEN);
		      if (snack_offset <= 65535)
			snack_hole = (int)
			  (ptr->m_seq - (ptr->m_prev->m_seq +
					 ptr->m_prev->m_plen)) /
								  (s->mss_offer -
								  TP_HDR_LEN) +
			  ((ptr->m_seq - (ptr->m_prev->m_seq +
					  ptr->m_prev->m_plen)) %
			   (s->mss_offer - TP_HDR_LEN)
			   ? 1 : 0);
		      else
			snack_hole = 0;
		    }
		  else
		    {
		      snack_offset = 0;
		      snack_hole = (int) (ptr->m_seq - s->acknum) /
			(s->mss_offer - TP_HDR_LEN)
			+ (((ptr->m_seq - s->acknum) %
			    (s->mss_offer - TP_HDR_LEN)) ? 1 : 0);
		    }

		  if (snack_hole)
		    {
		      if (snack_hole > 65535)
			snack_hole = 65535;
		      *lp++ = htonl (TPOPT_SNACK1 << 24 | TPOLEN_SNACK1 << 16
				     | ((u_short) snack_offset));
		      *lp = htonl ((snack_hole << 16) | TPOPT_NOP << 8 | TPOPT_NOP);
		      optlen += TPOLEN_SNACK1_PAD;	/* This doesn't take into 
							 * account any bit vector */
		      s->sockFlags |= SOCK_DELACK;
		    }		/* if snack_hole != 0 */
		}		/* if we found a hole to signal */
	      else
		s->SNACK1_Flags &= ~SEND_SNACK1;
	    }			/* if there's an out of sequence queue */
	}			/* if SNACK was enabled and requested */
    }
#endif /* OPT_SNACK1 */

  memcpy (option_start, opt, optlen);

  tp_hdr_len += optlen;

  th->th_off = (tp_hdr_len >> 2);

  tp_data_len = mbuffer->m_ext.len;	/* data length */

  mbuffer->m_len = tp_hdr_len;
  mbuffer->m_seq = s->seqnum;
  mbuffer->m_ts = 1;		/* set a flag so the time will be 
				   * recorded on the first shipment ONLY */

  s->seqnum += mbuffer->m_ext.len;
  if (s->flags & (tp_FlagSYN | tp_FlagFIN))
    s->seqnum++;

  if (tp_data_len)
    {
      mbuffer->m_ext.checksum =
	data_checksum (((struct mbcluster *) mbuffer->m_ext.ext_buf),
		       tp_data_len, mbuffer->m_ext.offset);
    }
  return (mbuffer);
}


void
fix_tp_header (void *socket, struct mbuff *mbuffer)
{
  tp_Header *th;
  short th_len;
  tp_Socket *s;

  s = socket;

  th = (tp_Header *) (mbuffer->m_pktdat + s->th_off);

  th_len = th->th_off << 2;

  /* Fix the sequence number in the transport header */
  th->seqnum = htonl (mbuffer->m_seq);

  /* Recalculate the transport header checksum */
  s->ph.nl_head.ipv4.length = htons ((short) ((th_len) + mbuffer->m_ext.len));
  th->checksum = 0;
  s->ph.nl_head.ipv4.checksum = checksum ((word *) th, (th_len));
  th->checksum = ~checksum ((word *) & (s->ph), 14);

#ifdef DEBUG_GATEWAY
  if (mbuffer->m_ext.len)
    {
      logEventv(s, gateway, "In fix_tp_header\n");
    }
#endif /* DEBUG_GATEWAY */
  mbuffer->m_ext.checksum =
    data_checksum (((struct mbcluster *) mbuffer->m_ext.ext_buf),
		   mbuffer->m_ext.len, mbuffer->m_ext.offset);
}


struct mbuff *
tp_next_to_send (tp_Socket * s, struct _hole_element **hole)
{
  struct mbuff *mbuffer = 0x0;
  struct _hole_element *local_hole = 0x0;

  local_hole = s->send_buff->holes;

  while ((local_hole) && (local_hole->Embargo_Time != 0) &&
	 (SEQ_GT (local_hole->Embargo_Time, tp_now)))
    {
      local_hole = local_hole->next;
    }

  if (local_hole)
    {
      if (local_hole->Embargo_Time)
	{
#ifdef EXPERIMENTAL
          local_hole->rx_ctr++;
#endif /* EXPERIMENTAL */
	  local_hole->Embargo_Time = 0;
	}
#ifdef MFX_SND_UNA_HOLE
      mbuffer = local_hole->next_to_send;
#else /* MFX_SND_UNA_HOLE */
      if (local_hole->hole_start->m_mfx_count)
	{
	  mbuffer = local_hole->hole_start;
	}
      else
	{
	  mbuffer = local_hole->next_to_send;
	}
#endif /* MFX_SND_UNA_HOLE */
    }
  else
    {
      mbuffer = s->send_buff->send;
      local_hole = 0x0;
    }

  *hole = &(*local_hole);

  DEBUG_SEQNUM_CALL (s, mbuffer);
  return (mbuffer);
}

uint32_t
tp_NewSend (tp_Socket * s, struct mbuff * mbuffer, BOOL force)
{

  tp_Header *th;
  in_Header *nh = NULL;
  unsigned short tp_hdr_len;
  struct mbuff *buf = NULL;
  struct _hole_element *hole = 0x0;
  uint32_t long_temp = 0;
  uint32_t *lp;
  uint32_t bytes_sent = 0;
  int took_while = 0;
  int test_val = 0;
  int max_to_send = 0;
  volatile uint32_t flippedseqnum;
  struct timeval mytime;
  int rx_shift_value = 0;

  mytime.tv_sec = 0;
#ifdef FAIRER_GATEWAY
  s-> gateway_fairness_ctr = 0;
#endif /* FAIRER GATEWAY */

  if ((s->rt_route) && (s->rt_route->flags & RT_LINK_AVAIL))
    {

      /* 
       * Change of rules here;
       * 
       * What we *really* need to be doing here is this:
       *
       *    Walk the Pending Retransmission Queue and 
       *    transmit any elements where either
       *        - The Embargo Time is clear    or
       *        - The Embargo Time is < tp_now
       *    (both are handled by the test (tp_now >= Embargo_Time)
       *
       *    Following emission of retransmissions, we then
       *    send any new data available.
       *
       * Issue:
       *
       *    In the cases where we want to explicitly transmit a 
       *    segment (such as an ACK) and we pass in the mbuff, do
       *    we handle this one first, or do we treat it as new data?
       */
      max_to_send = (s->rt_route->MTU << 1);

      tp_now = clock_ValueRough ();
      while (
#ifdef FAIRER_GATEWAY
	     ((buf=NULL) == NULL) && (s->gateway_fairness_ctr < GATEWAY_MAX_BURST) &&
#endif /* FAIRER_GATEWAY */
             !(force) && (buf = tp_next_to_send (s, &hole)) &&
	     (test_val = min (s->rt_route->MTU,
			      ((int) buf->m_ext.len + buf->m_len +
			       s->np_size))) &&
	     SEQ_GEQ (s->lastuwein, buf->m_plen + buf->m_seq) &&
#ifdef CONGEST
#ifdef MIN_RATE_THRESH
             ((s->rt_route->min_current_credit >= test_val)  ||
	     (((!((s->capabilities & CAP_CONGEST))) ||
	      ((s->capabilities & CAP_CONGEST) &&
	       ((int) s->snd_cwnd >= (int) buf->m_ext.len))))) &&
#else /* MIN_RATE_THRESH */
	     ((!((s->capabilities & CAP_CONGEST))) ||
	      ((s->capabilities & CAP_CONGEST) &&
	       ((int) s->snd_cwnd >= (int) buf->m_ext.len))) &&
#endif /* MIN_RATE_THRESH */
#endif /* CONGEST */
#ifdef FLOW_CONTROL_THRESH
	      (( !(s->cong_algorithm == FLOW_CONTROL_CONGESTION_CONTROL)) ||
	       ( (s->cong_algorithm == FLOW_CONTROL_CONGESTION_CONTROL) &&
                 (s->rt_route->flow_control >= ((int) test_val)))) &&
#endif /* FLOW_CONTROL_THRESH */
#ifdef GATEWAY
	     ((!(s->gateway_flags & GATEWAY_SCPS_TP_SESSION)) ||
	      ((s->gateway_flags & GATEWAY_SCPS_TP_SESSION) &&
	       (s->rt_route->current_credit >= test_val))) && 
#else /* GATEWAY */
	     (s->rt_route->current_credit >= test_val) &&
#endif /* GATEWAY */
	     (((!s->rt_route->encrypt_ipsec) ||
 	      ((s->rt_route->encrypt_ipsec) &&
                (((test_val + s->rt_route->encrypt_pre_overhead) %
                   s->rt_route->encrypt_block_size) ==0)  &&
                   ((test_val + s->rt_route->encrypt_pre_overhead + 
                     s->rt_route->encrypt_post_overhead)
			 <= s->rt_route->current_credit)
              )
             ) ||

	     ((!s->rt_route->encrypt_ipsec) ||
	      ((s->rt_route->encrypt_ipsec) &&
                (((test_val + s->rt_route->encrypt_pre_overhead) %
                   s->rt_route->encrypt_block_size) !=0)  &&
                   (( (test_val + s->rt_route->encrypt_pre_overhead) +

                       (s->rt_route->encrypt_block_size -
                         ((test_val + s->rt_route->encrypt_pre_overhead) %
                            s->rt_route->encrypt_block_size)) + 

                       (s->rt_route->encrypt_post_overhead))
			 <= s->rt_route->current_credit)
               )
              )) &&

	     (s->rt_route->max_burst_bytes >= test_val) &&
	     (max_to_send >= test_val))
	{
#ifdef FAIRER_GATEWAY
	  s-> gateway_fairness_ctr++;
#endif /* FAIRER GATEWAY */
	  took_while = 1;
	  tp_now = clock_ValueRough ();

	  th = (tp_Header *) (buf->m_pktdat + s->th_off);
	  flippedseqnum = ntohl (th->seqnum);
	  tp_hdr_len = th->th_off << 2;
	  /*
	   * If the user specified an mbuffer (and force was
	   * not true) the mbuffer contains a pure ack.  Since
	   * there's data to send, rather than sending the ACK,
	   * piggyback the data on the outgoing segment(s) by
	   * updating the receive window and acknum fields in
	   * the stored segments
	   */
	  if ((mbuffer) || ((s->sockFlags & (TF_RCVD_TSTMP | TF_REQ_TSTMP))
			    == (TF_RCVD_TSTMP | TF_REQ_TSTMP)))
	    {
	      /* update window and ack fields */
	      tp_WinAck (s, th);

#ifdef OPT_TSTMP
	      if (s->capabilities & CAP_TIMESTAMP)
		{
		  if ((tp_hdr_len > 22) &&
		      (((u_char *) th)[22] == TPOPT_TIMESTAMP))
		    {
		      lp = (uint32_t *) (((u_char *) th) + 24);
		      *lp++ = htonl (tp_now);
		      *lp = htonl (s->ts_recent);
		    }
		}
#endif /* OPT_TSTMP */
	      /* tp_FinalCksum (s, buf, th, tp_hdr_len); */
	      /* clear_timer(s->otimers[Del_Ack], 1); */
/* s->sockFlags &= ~SOCK_DELACK; *//* Cancel any pending
   * delayed ack */
	    }

	  /* During a congestion epoch, remember the highest sequence
	   * number sent.  Later we won't credit our snd_cwnd for the
	   * acks from these packets.
	   * 
	   * The rationale here is this:  On entering a congestion epoch,
	   * we cut our transmission rate 
	   * (since snd_cwnd will generally go negative, so we have to wait
	   * until 1/2 a window of dupacks come in before we sent anything)
	   * and then start remembering the
	   * highest sequence number sent during the epoch.  On leaving
	   * the epoch, we're going to give ourselves a full snd_cwnd
	   * of credit and NOT credit for acks from packets sent during the
	   * epoch.
	   */
	  if ((s->funct_flags & FUNCT_HIGH_SEQ) &&
               SEQ_GT (flippedseqnum + buf->m_ext.len,
				     s->high_congestion_seq))
	    {
	      s->high_congestion_seq = flippedseqnum + buf->m_ext.len;
              s->funct_flags = s->funct_flags | FUNCT_HIGH_CONGESTION_SEQ;
#ifdef DEBUG_XPLOT
	      logEventv(s, xplot, "pink\nline %s %lu %s %lu\n",
			stringNow2 (), s->high_congestion_seq,
			stringNow3 (0.05), s->high_congestion_seq);
#endif	/* DEBUG_XPLOT */
	    }

	  /* Coalesce in output buffer and send */
	  /* Note:  this should be a hard less than */
	  tp_FinalCksum (s, buf, th, tp_hdr_len);
	  if (SEQ_LEQ ((flippedseqnum + buf->m_ext.len), s->lastuwein))
	    {
	      long_temp = tp_iovCoalesce (s, (struct mbuff *) buf,
					  &bytes_sent);
	    }
	  if (long_temp > 0)
	    {

#ifdef MFX_TRANS
	      /* 
	       * Real sleaze here, but:
	       * 
	       * Increment segment's m_mfx_count++ (from 0 to 1)
	       * Create a "hole" associated with this segment;
	       * Add it to the list of holes;
	       * Set the hole's Embargo time to MFX_RETRANSMISSION_INTERLEAVE
	       * Hole will be purged when
	       * buf->m_mfx_count == s->MFX_RETRANSMISSION_COUNT
	       */

	      if ((s->capabilities & CAP_MFX) && (!(hole)))
		{
		  buf->m_mfx_count++;
		  hole = alloc_hole_element ();
		  hole->hole_start = hole->hole_end = buf;
		  hole->length = buf->m_ext.len;
		  hole->hole_start_seq = buf->m_seq;
		  hole->hole_end_seq = buf->m_seq + buf->m_ext.len - 1;
		  s->send_buff->holes =
		    insert_hole (s->send_buff->holes, hole, tp_now, s->snack_delay);
		  hole->Embargo_Time = tp_now;
		  /* tp_now + 10000; */
		}
#endif /* MFX_TRANS */

#ifdef MFX_SND_UNA_HOLE
	      /* YAK (Yet Another Knob) We are trying to do the following:
	       * If we are trying to retransmit the first hole in the hole
	       * list (i.e., the packets at snd_una) then we will transmit
	       * them multiple times.  We do this by setting the Embargo_time
	       * for the entire hole to now and incrementing each buffers
	       * mfx count.  If we have sent MFX the hole  XXX times we then
	       * the embargo time to what is should be.  -  the unknown knobber.
	       */
	      if ((hole)
//                   && (s->send_buff->holes)
		  && SEQ_LT (buf->m_seq, s->send_buff->holes->hole_end_seq)
		  && SEQ_GEQ (buf->m_seq,
			      s->send_buff->holes->hole_start_seq))
		{
		  hole->Embargo_Time = tp_now;
		  hole->Embargo_Time = 0;
		  printf
		    ("%s Setting the embargo time to tp_now for hole (%u,%u) mbuf(%u), mfx_count(%d)\n",
		     stringNow (),
		     hole->hole_start_seq, hole->hole_end_seq - hole->hole_start_seq,
		     buf->m_seq, buf->m_mfx_count);
		  (buf->m_mfx_count)++;
		  if ((!(hole->next_to_send)) ||
		      (hole->next_to_send == hole->hole_end))
		    hole->next_to_send = hole->hole_start;
		  else
		    hole->next_to_send = hole->next_to_send->m_next;
		  if (hole->hole_end->m_mfx_count >= s->mfx_snd_una ||
		      buf->m_mfx_count > s->mfx_snd_una + 1)
		    {
		      struct mbuff *foo;
		      printf
			("Setting embargo time of hole at %u to normal.\n",
			 hole->hole_end->m_seq);
			  if ( s->t_srtt ) {
			    hole->Embargo_Time = (tp_now + (s->t_srtt >> TP_RTT_SHIFT));
			  } else {
			    hole->Embargo_Time = (tp_now + (s->rt_route->initial_RTO));
			  }
		      for (foo = hole->hole_start; foo != hole->hole_end;
			   foo = foo->m_next)
			{
			  foo->m_mfx_count = 0;
			}
		      if (foo)
			foo->m_mfx_count = 0;
		    }
		}
	      fflush (stdout);
#endif /* MFX_SND_UNA_HOLE */


	      /* See if we are retransmitting a segment we are timing */
#ifdef NOT_YET
	      if ((s->rtt) && (s->rtseq == buf->m_seq + buf->m_ext.len))
		{
		  s->rtt = 0;
		  s->rt_prev_ts_val = 0;
		}
	      else
		/* If a segment is not currently being timed, time this one! */
		if ((!(s->rtt)) &&
		    (SEQ_GEQ (buf->m_seq + buf->m_ext.len, s->max_seqsent)))
#else /* NOT_YET */
	      if (!(s->rtt))
#endif /* NOT_YET */
		{
		  s->rtt = 1;
		  if (buf->m_prev)
		    {
		      s->rt_prev_ts_val = buf->m_prev->m_ts;
		    }
		  else
		    {
		      s->rt_prev_ts_val = tp_now;
		    }
		  s->rt_prev_ts_val = tp_now;
		  s->rtseq = buf->m_seq + buf->m_ext.len;
#ifdef DEBUG_TIMING
		  logEventv(s, timing, TIMING_FORMAT,
			    stringNow (),
			    "start_timing",
			    (uint32_t) buf->m_ext.len,
			    s->lastuwein,
			    s->snd_cwnd,
			    s->snd_prevcwnd,
			    s->snd_ssthresh,
			    s->rtt,
			    s->rtseq,
			    s->snduna,
			    s->seqsent);
#endif	/* DEBUG_TIMING */

#ifdef DEBUG_XPLOT
		  logEventv(s, xplot, "yellow\ndiamond %s %lu\n", stringNow2 (), s->rtseq);
		  sprintf(timingStartString, "%s", stringNow2());
#endif	/* DEBUG_XPLOT */
		}

		}  /* PDF XXX PDF added this to correspond to coal ok */

	      if (SEQ_GT ((flippedseqnum + buf->m_ext.len), s->seqsent)) 
		{
		  s->seqsent = flippedseqnum + buf->m_ext.len;
		} 


              /* Update max_seqsent if seqsent move on ahead -- PDF */
	      if (SEQ_GT (s->seqsent, s->max_seqsent)) {
		  s->max_seqsent = s->seqsent;
	      }
	      s->lastack = s->acknum;

	      s->lastuwe = s->acknum + s->rcvwin;

	      if (th->flags & tp_FlagSYN) {
		s->seqsent++;
		s->max_seqsent++;
              }

	      if (th->flags & tp_FlagFIN)
		{
		  s->seqsent++;
		  s->max_seqsent++;
		  switch (s->state)
		    {
		    case tp_StateFINWT1PEND:
		      {
			s->state_prev = s->state;
			s->state = tp_StateFINWT1;
			PRINT_STATE (s->state, s);
		      }
		      break;
		    case tp_StateFINWTDETOUR:
		      {
			s->state_prev = s->state;
			s->state = tp_StateCLOSING;
			PRINT_STATE (s->state, s);
			clear_timer (s->otimers[Rexmit], 1);
		      }
		      break;
		    case tp_StateLASTACKPEND:
		      {
			s->state_prev = s->state;
			s->state = tp_StateLASTACK;
			PRINT_STATE (s->state, s);
                        s->timeout = s->TWOMSLTIMEOUT;
                        mytime.tv_sec = s->TWOMSLTIMEOUT;
                        mytime.tv_usec = 0;
                        set_timer (&mytime, s->otimers[TW], 1);
                        mytime.tv_sec = 0;
                        mytime.tv_usec = ((s->t_srtt>>TP_RTT_SHIFT) +
                                          max (500000, ((s->t_rttvar>>TP_RTTVAR_SHIFT) << 2)));
                        mytime.tv_usec = max (mytime.tv_usec, s->RTOMIN);
                        mytime.tv_usec = min (mytime.tv_usec, s->RTOMAX);
                        set_timer (&mytime, s->otimers[Rexmit], 1);
		      }
		      break;
		    case tp_StateCLOSING:
//		      break;	/* Is this correct? What about the lines below? */
		      s->state_prev = s->state;
		      s->state = tp_StateTIMEWT;
		      PRINT_STATE (s->state, s);
		      s->timeout = s->TWOMSLTIMEOUT;
                      mytime.tv_sec = s->TWOMSLTIMEOUT;
                      mytime.tv_usec = 0;
                      set_timer (&mytime, s->otimers[TW], 1);
		      clear_timer (s->otimers[Rexmit], 1);
		      break;
		    case tp_StateESTAB:
		      break;
		    default:
		      break;
		    }
		}
	      if ((s->send_buff->send) && (buf->m_seq ==
					   s->send_buff->send->m_seq))
		{
		  if (s->send_buff->snd_una == NULL)
		    s->send_buff->snd_una = s->send_buff->send;
		  s->send_buff->send = s->send_buff->send->m_hdr.mh_next;

		}

	      if (buf->m_mfx_count)
		{
#ifdef MFX_TRANS
		  if (buf->m_mfx_count++ >= s->MFX_SETTING)
		    {
		      s->send_buff->holes =
			remove_hole (s->send_buff->holes, hole);
		      hole = 0x0;
		    }
		  else
		    hole->Embargo_Time = tp_now;
		  /* (tp_now + 10000); */
#endif /* MFX_TRANS */
		}
	      else
		{
		  /* 
		   * We set the Embargo_Time only if we've 
		   * walked the entire hole.
		   */
		  if ((hole) && (buf == hole->hole_end))
		    {
#ifdef DEBUG_SNACK
		      printf
			("%s Setting embargo time of hole (%u, %u) to normal3.  srtt(%u) s->rt_route->rtt(%u) s->rt_route->initial_RTO(%u)\n",
			 stringNow (), hole->hole_start_seq,
			 hole->hole_end_seq - hole->hole_start_seq, s->t_srtt>>TP_RTT_SHIFT,
			 s->rt_route->rtt, s->rt_route->initial_RTO);
#endif /* DEBUG_SNACK */

/*
 * Set the embargo time for the first hole to the tp_now + srtt.  Set
 *  the embargo time for the other holes to tp_now + (srtt * 2)
 */

#ifdef GATEWAY
		      hole->rxmit_ctr ++;
		      if (hole->rxmit_ctr >= s->TIMEOUT) {
 			  s->gateway_flags |= GATEWAY_ABORT_NOW;
		      }
#endif /* GATEWAY */
		      if (hole->rxmit_ctr >= s->EMBARGO_FAST_RXMIT_CTR) {
			  rx_shift_value = hole->rxmit_ctr - s->EMBARGO_FAST_RXMIT_CTR;
                      } else {
			  rx_shift_value = 0;
		      }

		      if ((SEQ_GEQ ((uint32_t)buf->m_seq,
				    (uint32_t)s->send_buff->holes->hole_start_seq)) &&
			  (SEQ_LEQ ((uint32_t)buf->m_seq,
				    (uint32_t)s->send_buff->holes->hole_end_seq)))
			{
			  if ( s->t_srtt ) {
			    hole->Embargo_Time = tp_now + (min (s->RTOMAX, ((max (s->RTOMIN,
                                                  s->t_srtt) >> TP_RTT_SHIFT) << rx_shift_value)));
			  } else {
			    hole->Embargo_Time = tp_now + (min (s->RTOMAX, (max (s->RTOMIN,
                                                  s->rt_route->initial_RTO) << rx_shift_value)));
			  }
			}
		      else
			{
			  if ( s->t_srtt ) {
			    /* If the RTO is less than 2x the srtt, use it instead */
			    hole->Embargo_Time = tp_now + min (s->RTOMAX, (((max (s->RTOMIN,
                                                 s->t_srtt) >> TP_RTT_SHIFT) * 2) << rx_shift_value));
//                              min (s->t_rxtcur,
//			      ((s->t_srtt >> TP_RTT_SHIFT) << 1));
			  } else {
			    hole->Embargo_Time =
			      tp_now + min (s->RTOMAX, (max (s->RTOMIN,
                              s->rt_route->initial_RTO)<< rx_shift_value));
			  }
			}
#ifdef DEBUG_XPLOT
		      {
			/*
			 * The ((tp_now%20)+1) stuff randomizes the position (height) of the
			 * embargo timer line within the sequence space of the SNACK.  We need
			 * the +1 to keep from getting the occasional floating point exception...
			 */
			int hole_len = hole->hole_end_seq - hole->hole_start_seq;
			int yValue = hole->hole_start_seq+hole_len/((tp_now%20)+1);
			logEventv(s, xplot, "; EMBARGO TIMER 2\n");
			logEventv(s, xplot, "orange\nline %s %lu %s %lu\n",
				  stringNow2(), yValue,
				  stringNow3(((double) hole->Embargo_Time-tp_now)/1000000), yValue);
			logEventv(s, xplot, "dtick %s %lu\n",
				  stringNow3(((double) (s->t_srtt>>TP_RTT_SHIFT))/1000000),
				  yValue);
		      }
#endif /* DEBUG_XPLOT */
		    }
		  if (hole)
		    {
		      if ((!(hole->next_to_send)) ||
			  (hole->next_to_send == hole->hole_end))
			hole->next_to_send = hole->hole_start;
		      else
			hole->next_to_send = hole->next_to_send->m_next;
		    }
		}

	      /* If the Rexmit timer isn't already running, set it */
	      if (!(s->otimers[Rexmit]->set) && (!s->otimers[Rexmit]->expired))
		{
		  /*
		   * If we have a notion of srtt, set the retransmission
		   * timer appropriately.  If not, then set the retransmission
		   * timer to the initial value in the rt_route structure.
		   */
		  if ( s->t_srtt ) {
		    /* When we use the rttvar in calculating the rxtcur, we need to make
		     * sure the var is at least 0.5 seconds.  Rational is the following.
		     * with implementation of TCP, the unit of variance is 1/4 of a tick
		     * and a tick is 0.5 seconds.  The smallest value of the variable
		     * is 0.125 seconds.  Therefore when you multiply it by 4, the minimum
		     * value of the variance term is 500000 microseconds.  - PDF 
		     */
		    mytime.tv_usec = ((s->t_srtt >> TP_RTT_SHIFT) +
				      max (500000, ((s->t_rttvar>>TP_RTTVAR_SHIFT) << 2)));
		  } else {
		    mytime.tv_usec = s->rt_route->initial_RTO;
		  }
                  mytime.tv_usec = max (s->RTOMIN, mytime.tv_usec) << s->t_rxtshift;         /* Scale the rtt */           
		  mytime.tv_usec = min (mytime.tv_usec, s->RTOMAX);
		  set_timer (&mytime, s->otimers[Rexmit], 1);
#ifdef DEBUG_XPLOT
		  /* Plot a pink line to the right of and slightly above
		   * the segment that
		   * stops where the retransmission timer for that segment
		   * would expire.
		   */
		  logEventv(s, xplot, "pink\nline %s %u %s %u\n",
			    stringNow2(),
			    buf->m_seq + 10,
			    stringNow3((double) mytime.tv_usec/1000000),
			    buf->m_seq + 10);
		  logEventv(s, xplot, "white\nuarrow %s %u\nuarrow %s %u\n",
			    stringNow2(),
			    buf->m_seq + 10,
			    stringNow3((double) mytime.tv_usec/1000000),
			    buf->m_seq + 10);
#endif /* DEBUG_XPLOT */
/*		} */
	    }
	}


#if ( defined(DEBUG_RATE) || defined(DEBUG_XPLOT))
      if (buf && !force)
	{
#ifdef DEBUG_RATE
	if ( (s->myport>0) && (s->hisport>0) ) {
	  static int lastRate = 0;
	  static int lastsnd_cwnd = 0;
	  static int lastuwe = 0;

	  if (s->rt_route->current_credit != lastRate &&
	      (s->rt_route->current_credit < test_val))
	    {
	      lastRate = s->rt_route->current_credit;
	      logEventv(s, logRate, "%s NewSend rate %lu %lu \n",
			stringNow2 (), buf->m_seq, s->rt_route->current_credit);
	    }

	  if (lastuwe != s->lastuwein && SEQ_LT (s->lastuwein, buf->m_plen + buf->m_seq))
	    {
	      lastuwe = s->lastuwein;
	      logEventv(s, logRate, "%s NewSend uwe %lu %lu\n",
			stringNow2 (), buf->m_seq, s->snd_cwnd);
	    }

	  if ((s->snd_cwnd != lastsnd_cwnd) && (s->snd_cwnd <
						buf->m_ext.len))
	    {
	      lastsnd_cwnd = s->snd_cwnd;
	      logEventv(s, logRate, "%s NewSend snd_cwnd %lu %lu\n",
			stringNow2 (), buf->m_seq, s->snd_cwnd);
	    }

	  if (s->rt_route->max_burst_bytes < test_val)
	    {
	      logEventv(s, logRate, "%s NewSend burst %lu %lu\n",
			stringNow2 (), buf->m_seq, s->rt_route->max_burst_bytes);
	    }

	  if (max_to_send < test_val)
	    {
	      logEventv(s, logRate, "%s NewSend max_to_send %lu %u\n",
			stringNow2 (), buf->m_seq, max_to_send);
	    }
	}
#endif	/* DEBUG_RATE */
	}
      else if (!force)
	{
#ifdef DEBUG_XPLOT
#ifdef MAKES_THE_FILE_REALLY_BIG
	  if (SEQ_LT (s->snduna - 4000, s->snduna))
	    {
	      logEventv(s, xplot, "purple\nline %s %lu %s %lu\n",
			stringNow2 (), s->snduna - 2500,
			stringNow2 (), s->snduna - 2000);
#endif /* MAKES_THE_FILE_REALLY_BIG */
#endif	/* DEBUG_XPLOT */
	}
#endif /* Rate or xplot */

      if (!(took_while) && (buf) && (s->lastuwein == buf->m_seq))
	{
	  if (!(s->otimers[Persist]->set) && !(s->otimers[Rexmit]->set) &&
              !(s->otimers[Rexmit]->expired))
	    {
	      /* Transition into persist state */
	      struct timeval mytime;
	      int diff;
	      uint32_t flippedack;

	      flippedack = s->lastuwein - s->snd_awnd;
	      diff = flippedack - s->snduna;

/*                                      printf("%s %s Setting persist timer lastuwein(%u) buf->m_seq(%u))\n",
 *                                                               stringNow(), printPorts(s), s->lastuwein, buf->m_seq);
 */
              mytime.tv_sec = 0;
              s->persist_shift ++;
	      s->maxpersist_ctr ++;
              if (s->persist_shift == TP_MAX_PERSIST_SHIFT) {
                s->persist_shift = TP_MAX_PERSIST_SHIFT - 1;
              } 
              mytime.tv_usec = persist_time_outs [s->persist_shift] * 1000 * 1000;
              mytime.tv_usec = min (mytime.tv_usec, s->RTOPERSIST_MAX);
              set_timer (&mytime, s->otimers[Persist], 1);
              clear_timer (s->otimers[Rexmit], 1);
              s->timeout = s->LONGTIMEOUT;
	    }
	}

      if ((mbuffer) && !(took_while))
	{
	  th = (tp_Header *) (mbuffer->m_pktdat + s->th_off);
	  nh = (in_Header *) (mbuffer->m_pktdat + s->nh_off);
	  tp_hdr_len = th->th_off << 2;

#ifdef OPT_TSTMP
	  if (s->capabilities & CAP_TIMESTAMP)
	    {
	      tp_now = clock_ValueRough ();

	      if ((s->sockFlags & (TF_RCVD_TSTMP | TF_REQ_TSTMP))
		  == (TF_RCVD_TSTMP | TF_REQ_TSTMP))
		{
		  tp_WinAck (s, th);
		  s->lastack = s->acknum;
		  s->lastuwe = s->acknum + s->rcvwin;
		  if ((tp_hdr_len > 22) &&
		      (((u_char *) th)[22] == TPOPT_TIMESTAMP))
		    {
		      lp = (uint32_t *) (((u_char *) th) + 24);
		      *lp++ = htonl (tp_now);
		      *lp = htonl (s->ts_recent);
		    }
		}
	    }
#endif /* OPT_TSTMP */
	  tp_FinalCksum (s, mbuffer, th, tp_hdr_len);

	  if (SEQ_LEQ ((ntohl (th->seqnum) + mbuffer->m_ext.len), s->lastuwein)) {
	    long_temp = tp_iovCoalesce (s, (struct mbuff *) mbuffer,
					&bytes_sent);
          } else {
	  }

	  max_to_send -= long_temp;

	  /* On a retransmitted packet we must also move s->send_buff->send
           * to the next packet to be transmitted.  We must also set
           * s->send_buff->snd_una properly.  -  PDF
           */

          if ((s->send_buff->send) &&
              (mbuffer->m_seq == s->send_buff->send->m_seq)) {

             if (s->send_buff->snd_una == NULL) {
                 s->send_buff->snd_una = s->send_buff->send;
             }

             s->send_buff->send = s->send_buff->send->m_hdr.mh_next;

          }

	  if ((long_temp) && (force))
	    {
	      /* 
	       * Set the Embargo Time *only* if we  
	       * have walked the entire hole.
	       */
#ifdef MFX_SND_UNA_HOLE
	      /* YAK (yet Another knob) We are trying to do the following
	       * If we are trying to retransmit the first hole in the hole
	       * list (i.e., the packets at snd_una) then we will transmit
	       * them multiple times.  We do this by setting the Embargo_time
	       * for the entire hole to now and incrementing each buffers
	       * mfx count.  If we have sent it XXX times the set the embargo
	       * time to what is should be.  -  the unknowned knobber.
	       */
	      hole = s->send_buff->holes;
	      if ((hole)
		  && SEQ_LT (mbuffer->m_seq, hole->hole_end_seq)
		  && SEQ_GEQ (mbuffer->m_seq, hole->hole_start_seq))
		{
		  hole->Embargo_Time = tp_now;
		  hole->Embargo_Time = 0;
#ifdef DEBUG_SNACK
		  printf
		    ("%s B Setting the embargo time to tp_now for hole (%u,%u) mbuf(%u), mfx_count(%d)\n",
		     stringNow (),
		     hole->hole_start_seq, hole->hole_end_seq - hole->hole_start_seq,
		     mbuffer->m_seq, mbuffer->m_mfx_count);
#endif /* DEBUG_SNACK */
		  (mbuffer->m_mfx_count)++;
		  if ((!(hole->next_to_send)) ||
		      (hole->next_to_send == hole->hole_end))
		    hole->next_to_send = hole->hole_start;
		  else
		    hole->next_to_send = hole->next_to_send->m_next;
		  if (hole->hole_end->m_mfx_count >= s->mfx_snd_una ||
		      mbuffer->m_mfx_count > s->mfx_snd_una + 1)
		    {
		      struct mbuff *foo;
#ifdef DEBUG_SNACK
		      printf
			("%s B Setting embargo time of hole at %u to normal.\n",
			 stringNow (), hole->hole_end->m_seq);
#endif /* DEBUG_SNACK */
		      if ( s->t_srtt ) {
		        hole->Embargo_Time = tp_now + (s->t_srtt >> TP_RTT_SHIFT);
		      } else {
		        hole->Embargo_Time = (tp_now + (s->rt_route->initial_RTO));
		      }
		      for (foo = hole->hole_start; foo != hole->hole_end;
			   foo = foo->m_next)
			{
			  foo->m_mfx_count = 0;
			}
		      if (foo)
			foo->m_mfx_count = 0;
		    }
		}
	      fflush (stdout);
#else /* MFX_SND_UNA_HOLE */
	      if ((hole = find_hole (s->send_buff->holes, mbuffer->m_seq))
		  && (mbuffer == hole->hole_end) && (mbuffer->m_mfx_count == 0))
		{
/*
 * Set the embargo time for the first hole to the tp_now + srtt.  Set
 *  the embargo time for the other holes to tp_now + (srtt * 2)
 */
		  if ((SEQ_GEQ ((uint32_t)mbuffer->m_seq,
				(uint32_t)s->send_buff->holes->hole_start_seq)) &&
		      (SEQ_LEQ ((uint32_t)mbuffer->m_seq,
				(uint32_t)s->send_buff->holes->hole_end_seq)))
		    {
	              if ( s->t_srtt ) {
		        hole->Embargo_Time = tp_now + min (s->RTOMAX, (max (s->RTOMIN, s->t_srtt) >> TP_RTT_SHIFT));
	              } else {
		        hole->Embargo_Time = tp_now + min (s->RTOMAX, max (s->RTOMIN, (s->rt_route->initial_RTO)));
	              }
		    }
		  else
		    { 
	              if ( s->t_srtt ) {
		    hole->Embargo_Time = tp_now + min (s->RTOMAX, ((max (s->RTOMIN, s->t_srtt) >> TP_RTT_SHIFT) * 2));
//		        hole->Embargo_Time = tp_now + 
//			   min (s->RTOMIN, min (s->RTOMAX, max((s->t_srtt >> TP_RTT_SHIFT)*2, s->t_rxtcur));
	              } else {
		        hole->Embargo_Time = (tp_now + min (s->RTOMAX, max (s->RTOMIN, (s->rt_route->initial_RTO))));
	              }
		    }
#ifdef DEBUG_XPLOT
		      {
			uint32_t hole_len = hole->hole_end_seq - hole->hole_start_seq;
			uint32_t yValue = hole->hole_start_seq+hole_len/((tp_now%20)+1);
			logEventv(s, xplot, "; EMBARGO TIMER 3\n");
			logEventv(s, xplot, "orange\nline %s %lu %s %lu\n",
				  stringNow2(),
				  yValue,
				  stringNow3(((double) hole->Embargo_Time-tp_now)/1000000),
				  yValue);
			logEventv(s, xplot, "dtick %s %lu\n",
				  stringNow3(((double) (s->t_srtt>>TP_RTT_SHIFT))/1000000),
				  yValue);
		      }
#endif /* DEBUG_XPLOT */
#ifdef DEBUG_SNACK
		  printf
		    ("%s Setting embargo time of hole (%u, %u) to normal2.\n",
		     stringNow (), hole->hole_start_seq,
		     hole->hole_end_seq - hole->hole_start_seq);
#endif /* DEBUG_SNACK */
		}
#endif /* MFX_SND_UNA_HOLE */
	    }
	}
    }
  return (long_temp);
}

int
tp_Send (tp_Socket * s, struct mbuff *mbuffer)
{
  u_char limit_ok = 224;
  uint32_t min_limit = 0;
  uint32_t bytes_sent = 0;
  short send_size = 0;
  uint32_t test = 0;
  tp_Header *th;
  uint32_t *lp;
  int tp_hdr_len;
  struct timeval mytime;
  mytime.tv_sec = 0;

  while ((limit_ok > 3) && ((mbuffer) || (s->hole_start != s->hole_end)
			    || (s->send_buff->send)))
    {

      min_limit = min (s->rt_route->max_burst_bytes,
		       min (s->rt_route->current_credit, s->snd_cwnd));

      if ((mbuffer) && (limit_ok & MBUFFER_OK))
	{

	  if (((limit_ok == 128) && (mbuffer->m_ext.len > 0))
	      || (s->sockFlags & TF_COMPRESSING))
	    {
#ifdef SCPSSP
	      send_size = (mbuffer->m_len + mbuffer->m_ext.len +
			   np_hdr_size (s->np_rqts) + sp_hdr_size (s->sp_rqts));
#else /* SCPSSP */
	      send_size = (mbuffer->m_len + mbuffer->m_ext.len +
			   np_hdr_size (s->np_rqts) + sp_hdr_size ());
#endif /* SCPSSP */
	      test = bytes_sent + send_size;
	      if (test <= min_limit)
		{
		  tp_iovCoalesce (s, (struct mbuff *) mbuffer, NULL);
		  limit_ok |= TP_SENT;
		  mbuffer = NULL;	/* This isn't a memory leak is it? */
		}
	      else
		{
		  /* errno = ??? */
		  limit_ok &= ~MBUFFER_OK;
		}
	    }
	}			/* End of Mbuffer passed in for retransmission */

      else if (limit_ok & RETRANS_OK)
	{
	  if (s->hole_start != s->hole_end)
	    {
#ifdef SCPSSP
	      send_size = (s->hole_ptr->m_ext.len +
			   np_hdr_size (s->np_rqts) + sp_hdr_size (s->sp_rqts));
#else /* SCPSSP */
	      send_size = (s->hole_ptr->m_ext.len +
			   np_hdr_size (s->np_rqts) + sp_hdr_size ());
#endif /* SCPSSP */
	      test = bytes_sent + send_size;
	      if (test <= min_limit)
		{
		  if (tp_iovCoalesce (s, (struct mbuff *) s->hole_ptr, 0) > 0)
		    {
		      s->hole_start += s->hole_ptr->m_ext.len;
		      if (s->hole_start >= s->hole_end)
			{
			  /* GET NEXT HOLE! */
			  limit_ok |= TP_SENT;
			}
		      else
			{
			  /* Coalese error handling */
			  return (-1);
			}
		    }
		  else
		    limit_ok &= ~RETRANS_OK;
		}
	      else
		limit_ok &= ~RETRANS_OK;
	    }
	}			/* End of Retransmissions to Send */

      else if (limit_ok & NEW_DATA_OK)
	{
	  if (s->send_buff->send)
	    {
#ifdef SCPSSP
	      send_size = s->send_buff->send->m_len +
		s->send_buff->send->m_ext.len +
		sp_hdr_size (s->sp_rqts) + np_hdr_size (s->np_rqts);
#else /* SCPSSP */
	      send_size = s->send_buff->send->m_len +
		s->send_buff->send->m_ext.len +
		np_hdr_size (s->np_rqts);
#endif /* SCPSSP */
	      test = send_size + bytes_sent;
	      if (test < min (min_limit, s->snd_awnd))
		{
		  if ((mbuffer) && (mbuffer->m_ext.len == 0))
		    {		/* Should never get here when compressing */
		      th = (tp_Header *) (s->send_buff->send->m_pktdat
					  + s->th_off);
		      tp_hdr_len = th->th_off << 2;
#ifdef OPT_TSTMP
		      if (s->capabilities & CAP_TIMESTAMP)
			{
			  if ((tp_hdr_len > 22) && (((u_char *) th)[22]
						    == TPOPT_TIMESTAMP))
			    {
			      lp = (uint32_t *) (((u_char *) th) + 24);
			      *lp++ = htonl (clock_ValueRough ());
			      *lp = htonl (s->ts_recent);
			    }
			}
#endif /* OPT_TSTMP */
		      limit_ok |= NEW_ACK;
		      tp_WinAck (s, th);
		      tp_FinalCksum (s, s->send_buff->send, th, tp_hdr_len);
		    }
		  if (tp_iovCoalesce (s, (struct mbuff *)
				      s->send_buff->send, NULL) > 0)
		    {
		      /* If the Rexmit timer isn't already running, set it */
	              if (!(s->otimers[Rexmit]->set) && (!s->otimers[Rexmit]->expired))
			{    
      			  /* When we use the rttvar in calculating the rxtcur, we need to make
       			   * sure the var is at least 0.5 seconds.  Rational is the following.
       			   * with implementation of TCP, the unit of variance is 1/4 of a tick
       			   * and a tick is 0.5 seconds.  The smallest value of the variable
       			   * is 0.125 seconds.  Therefore when you multiply it by 4, the minimum
       			   * value of the variance term is 500000 microseconds.  - PDF 
       			   */
		  	  mytime.tv_usec = ((s->t_srtt>>TP_RTT_SHIFT) +
				max (500000, ((s->t_rttvar>>TP_RTTVAR_SHIFT) << 2)));
                          mytime.tv_usec = max (s->RTOMIN, mytime.tv_usec) << s->t_rxtshift;/* Scale the rtt */           
		  	  mytime.tv_usec = min (mytime.tv_usec, s->RTOMAX);
			  set_timer (&mytime, s->otimers[Rexmit], 1);
#ifdef DEBUG_XPLOT
			  /* Plot a pink line to the right of and slightly above
			   * the segment that
			   * stops where the retransmission timer for that segment
			   * would expire.
			   */
			  logEventv(s, xplot, "pink\nline %s %u %s %u\n",
				    stringNow2(),
				    s->send_buff->send->m_seq + 3,
				    stringNow3((double) mytime.tv_usec/1000000),
				    s->send_buff->send->m_seq + 3);
			  logEventv(s, xplot, "blue\ndarrow %s %u\ndarrow %s %u\n",
				    stringNow2(),
				    s->send_buff->send->m_seq + 3,
				    stringNow3((double) mytime.tv_usec/1000000),
				    s->send_buff->send->m_seq + 3);
#endif /* DEBUG_XPLOT */
			}

		      if (limit_ok & NEW_ACK)
			{
			  s->lastack = s->acknum;
			  s->lastuwe = s->acknum + s->rcvwin;
			  /* s->sockFlags &= ~SOCK_DELACK; */
			  limit_ok &= ~NEW_ACK;
			}
		      limit_ok |= TP_SENT;
		    }
		}
	    }
	  else
	    limit_ok &= ~NEW_DATA_OK;
	}			/* End of New Data to Send */

      if (limit_ok & TP_SENT)
	{
	  bytes_sent += send_size;
	  s->snd_cwnd -= send_size;
	  s->rt_route->current_credit -= send_size;
	  limit_ok = ~TP_SENT;
	  LOGRATE(s->rt_route);
#ifdef DEBUG_LOG
	  logEventv(s, SCPS_log, "%s diff %ld %ld %ld %u %ld %d %lu\n",
		    stringNow2 (),
		    s->acknum,
		    s->snd_prevcwnd,
		    s->snd_ssthresh,
		    -1, /* diff placeholder */
		    s->snd_cwnd,
		    s->rtt,
		    s->rtseq);
#endif /* DEBUG_LOG */
	  LOGCWND(s);
	}
    }				/* End of While loop */
  return (bytes_sent);
}

uint32_t
tp_iovCoalesce (tp_Socket * s, struct mbuff * m, uint32_t * bytes_sent)
{
  struct mbuff *working_mbuff;
  tp_Header *th;
  uint32_t long_temp;
  int chl, cc = 0;

  /* 
   * Build the headers in the output buffer, but then keep 
   * the actual data in the clusters - avoid an outbound copy.
   *
   * assume there is a out_msg structure available...
   *
   */

  th = (tp_Header *) (m->m_pktdat + s->th_off);
  working_mbuff = m;		/* We change this if compressing */

#ifdef OPT_COMPRESS
  if (s->capabilities & CAP_COMPRESS)
    {

      /*
       * If we don't meet the conditions for compression,
       * send the packet uncompressed.  Those conditions
       * are:  
       *   SYN reset, 
       *   not a retransmission, 
       *   both sides agree to do compression,
       *   URG flag not set.  
       * If we meet those conditions, attempt to compress.
       */

      if (((th->flags & tp_FlagSYN) == 0) &&
	  ((s->sockFlags & (TF_COMPRESSING)) == (TF_COMPRESSING)))
	{
/* working_mbuff = clone_mbuff(m); *//* For testing ONLY */
	  copy_mbuff (s->scratch_buff, m);
	  working_mbuff = s->scratch_buff;
	  chl = tp_Compress (s, m,
			     (working_mbuff->m_pktdat + s->th_off));

	  working_mbuff->m_len -= ((th->th_off << 2) - chl);

#ifdef SCPSSP
	  s->sp_size = sp_hdr_size (s->sp_rqts);
	  if (s->sp_rqts.tpid != SCPSCTP)
	    s->sp_rqts.tpid = SCPSCTP;
#else /* SCPSSP */
	  if (s->np_rqts.tpid != SCPSCTP)
	    {
	      s->np_rqts.tpid = SCPSCTP;

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
                        s->np_size = scps_np_get_template (&(s->np_rqts), &(s->np_templ));
                        break;
              }

	    }
#endif /* SCPSSP */

	}
    }
#endif /* OPT_COMPRESS */

  /*
   * Tweak the template length field - everything but network header 
   */

  long_temp = working_mbuff->m_len + working_mbuff->m_ext.len + s->np_size;

  /*
   * Call ip_trequest() to build the network protocol header
   * and push the packet onto an interface/queue
   */

  /* 
   * Regardless of whether the attempted send succeeds, it consumes
   * credit from the rate control - 5/2/96 - this was causing trouble so 
   * I undid it.  Durst
   */

#ifdef GATEWAY
  if ((!(s->gateway_flags & GATEWAY_SCPS_TP_SESSION)) ||
      ((s->gateway_flags & GATEWAY_SCPS_TP_SESSION) &&

       ((s->rt_route->current_credit >= long_temp) &&
	(bytes_sent) && (s->rt_route->max_burst_bytes >= long_temp))))
#else /* GATEWAY */
  if ((s->rt_route->current_credit >= long_temp) &&
      (bytes_sent) && (s->rt_route->max_burst_bytes >= long_temp))
#endif /* GATEWAY */
    {
      int bytes_to_be_credited;

      bytes_to_be_credited = long_temp;
      if (s->rt_route->encrypt_ipsec) {
        if (((long_temp + s->rt_route->encrypt_pre_overhead) % s->rt_route->encrypt_block_size) ==0 ) {
           bytes_to_be_credited = s->rt_route->encrypt_pre_overhead +
				  long_temp + 
				  s->rt_route->encrypt_post_overhead;
        } else {
           bytes_to_be_credited = s->rt_route->encrypt_pre_overhead +
				  long_temp +
				  (s->rt_route->encrypt_block_size -
					 ((long_temp + s->rt_route->encrypt_pre_overhead) %
                                          s->rt_route-> encrypt_block_size)) +
                                   s->rt_route->encrypt_post_overhead;
        }
        long_temp = bytes_to_be_credited;
      }
      *bytes_sent = long_temp;

#ifdef GATEWAY
#ifdef MIN_RATE_THRESH
      if (s->gateway_flags & GATEWAY_SCPS_TP_SESSION) {
	if (s->rt_route->current_credit - long_temp > s->rt_route->current_credit) {
	    s->rt_route->current_credit = 0;
        } else {
	    s->rt_route->current_credit -= long_temp;
	}
	if (s->rt_route->min_current_credit - long_temp > s->rt_route->min_current_credit) {
	    s->rt_route->min_current_credit = 0;
        } else {
	    s->rt_route->min_current_credit -= long_temp;
	}
      }
#else /* MIN_RATE_THRESH */
      if (s->gateway_flags & GATEWAY_SCPS_TP_SESSION) {
	if (s->rt_route->current_credit - long_temp > s->rt_route->current_credit) {
	    s->rt_route->current_credit = 0;
        } else {
	    s->rt_route->current_credit -= long_temp;
	}
      }
#endif /* MIN_RATE_THRESH */

#ifdef FLOW_CONTROL_THRESH
	if (s->cong_algorithm == FLOW_CONTROL_CONGESTION_CONTROL) {
	    s->rt_route->flow_control -= (int) long_temp;


		if (s->rt_route->flow_control < 0) {
			s->rt_route->flow_control = 0;
		}
	}
#endif /*FLOW_CONTROL_THRESH */

#else /* GATEWAY */
	if (s->rt_route->current_credit - long_temp > s->rt_route->current_credit) {
	    s->rt_route->current_credit = 0;
        } else {
	    s->rt_route->current_credit -= long_temp;
	}
#endif /* GATEWAY */

#ifdef SECURE_GATEWAY 
      cc = sp_trequest (s, NULL, (int *) bytes_sent, working_mbuff, s->th_off);
#else /* SECURE_GATEWAY */
#ifdef SCPSSP
      cc = sp_trequest (s, NULL, (int *) bytes_sent, working_mbuff, s->th_off);
#else /* SCPSSP */
  
      switch (s->np_rqts.nl_protocol) {
            case NL_PROTOCOL_IPV4:
                  cc = ip_trequest (s, working_mbuff, bytes_sent);
                  break;
#ifdef IPV6
            case NL_PROTOCOL_IPV6:
                  cc = ipv6_trequest (s, working_mbuff, bytes_sent);
                  break;
#endif /* IPV6 */

            case NL_PROTOCOL_NP:
                  cc = scps_np_trequest (s, NULL, NULL, *bytes_sent, working_mbuff, s->th_off);   
            break;
      }
   
#endif /* SCPSSP */
#endif /* SECURE_GATEWAY */
      LOGRATE(s->rt_route);

    }

  else {
    *bytes_sent = long_temp;
    cc = long_temp;
  }
  if (cc > 0)
    {

#ifdef OPT_COMPRESS
      if (s->capabilities & CAP_COMPRESS)
	memcpy (&(s->old_th), (u_char *) (m->m_pktdat + s->th_off), sizeof (tp_Header));
#endif /* OPT_COMPRESS */
      /* s->total_data += long_temp; */
      s->total_data += m->m_ext.len;

      if (s->sndwin > m->m_ext.len)
	s->sndwin -= m->m_ext.len;
      else
	s->sndwin = 0;

      if (s->snd_awnd >= m->m_ext.len)
	s->snd_awnd -= m->m_ext.len;
      else
	s->snd_awnd = 0;

      if (s->snd_cwnd >= m->m_ext.len)
	{
	  s->snd_cwnd -= m->m_ext.len;
	}
      else
	s->snd_cwnd = 0;

      /* If the timestamp field in the mbuf is set to 1, this 
         packet is being shipped for the first time.  Therefore,
         zero the retransmission bytes.  If it is non-zero,
         the mbuff is a retransmission.  Add its length to the
         retransmissions field so that when the packet is acked,
         mb_trim can return the amount of retransmitted bytes in
         order to clean up the congestion window.  (The congestion
         window gets decremented when something gets sent, and
         incremented when something gets acked.  However, if
         you don't take into account retransmissions, there's a
         leak.  Note - this applies to vegas only, and only when
         assuming that loss is NOT due to congestion.)
       */
      m->m_rx = (m->m_ts == 1) ? 0 : m->m_rx + 1;
      m->m_ts = (m->m_ts == 1) ? tp_now : 0;
      m->m_rt = tp_now + s->t_rxtcur;

      /* If this packet was retransmitted because of an RTO, we must
       * set the time for Vegas to function properly. -- PDF
       */

      if (SEQ_LT (s->seqsent, s->max_seqsent)) {
	m->m_ts = tp_now;
      }

    } else {
    }
  LOGCWND(s);
#ifdef DEBUG_LOG
  logEventv(s, SCPS_log, "%s iovcoalesce %lu %lu %lu %u %lu %d %lu\n",
	    stringNow2 (),
	    s->snduna,
	    s->snd_prevcwnd,
	    s->snd_ssthresh,
	    0 /* diff placeholder */ ,
	    s->snd_cwnd,
	    s->rtt,
	    s->rtseq);
#endif	/* DEBUG_LOG */
#ifdef DEBUG_XPLOT_NOT
  logEventv(s, xplot, "blue\nline %s %u %s %u\n",
	    stringNow3(-0.02),
	    htonl(th->seqnum)+100,
	    stringNow3(0.02),
	    htonl(th->seqnum)+100);
#endif
  return (cc);
}
