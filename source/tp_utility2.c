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
********************************************************
* Portions of this software Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
*      The Regents of the University of California.  All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. All advertising materials mentioning features or use of this software
*    must display the following acknowledgement:
*      This product includes software developed by the University of
*      California, Berkeley and its contributors.
* 4. Neither the name of the University nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.                             
*
* THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/

#include <signal.h>
#include <fcntl.h>
#include <string.h>  /* for bzero */
#include "scps.h"
#include "scpstp.h"
#include "scpsudp.h"
#include "np_scmp.h"
#ifdef SCPSSP
#include "scps_sp.h"
#include "scps_sadb.h"
int get_SAinfo (scps_np_rqts * np_rqts, SA_data * SAinfo);
#endif /* SCPSSP */

int scps_np_get_template (scps_np_rqts * rqts, scps_np_template * templ);

#ifdef GATEWAY
#include "rs_config.h"
#include <stdlib.h>
extern GW_ifs gw_ifs;
extern int init_port_number_offset;
#endif /* GATEWAY */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_utility2.c,v $ -- $Revision: 1.25 $\n";
#endif

extern void free (void *ptr);
extern void *malloc (size_t size);
//extern void *memset (void *s, int c, size_t n);


extern route *def_route;
extern uint32_t tp_now;
extern tp_Socket *tp_allsocs;
extern udp_Socket *udp_allsocs;
extern struct _timer rate_timer;
extern struct msghdr out_msg;
extern struct iovec out_iov[8];
extern char config_span_name[];
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

extern struct _interface *sock_interface;
extern struct _interface *divert_interface;
   

void
tp_mss (tp_Socket * s, unsigned int offer)
{
  unsigned int mss;
  
  extern int tp_mssdflt;
  extern int tp_mssmin;

  /* Get a route and the interface */

  if (!(s->rt_route)) {
     s->rt_route = def_route;      /* temporary */

     if (!(s->rt_route)) {
        return;
     }
  }

  /* Call to route here 
   * **** If route returns 0, return(tp_mssdflt) 
   * At this point, we have a route and an interface 
   *
   * If there's an MTU associated with the route, subtract the size of
   * the TP and lower layer headers from it
   */
  mss = (s->rt_route->MTU) ?
    s->rt_route->MTU - tp_hdr_size () - s->np_size - s->sp_size : tp_mssdflt;

#ifdef GATEWAY_DUAL_INTERFACE
  mss += ENCAP_HDR_LEN;
  if ((struct _interface *)(s->np_rqts.interface) == sock_interface ) {
//    mss -= ((struct _interface *)(s->np_rqts.interface))->mss_ff;
    mss -= s->rt_route->MSS_FF;

  }
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef MPF
            mss -=  s->rt_route->MSS_FF;
#endif /* MPF */

#ifdef GATEWAY
      if (s->divert_port == gw_ifs.aif_divport) {
	s->t_srtt = (int) ((gw_ifs.aif_irto * 1000000)  << TP_RTT_SHIFT);
	s->t_rttvar = (int) (s->t_srtt / 2);
        s->t_rxtcur = (s->t_srtt);
      }

      if (s->divert_port == gw_ifs.bif_divport) {
	s->t_srtt = (int) ((gw_ifs.bif_irto * 1000000)  << TP_RTT_SHIFT);
	s->t_rttvar = (int) (s->t_srtt / 2);
        s->t_rxtcur = (s->t_srtt);
      }

      if (s->t_srtt == 0) {
	s->t_srtt = s->rt_route->rtt << TP_RTT_SHIFT;
	s->t_rttvar = (int) (s->t_srtt / 2);
        s->t_rxtcur = (s->t_srtt);
      }

#else /* GATEWAY */
      s->t_srtt = s->rt_route->rtt << TP_RTT_SHIFT;
      s->t_rttvar = (int) (s->t_srtt / 2);
      s->t_rxtcur = (s->t_srtt);
#endif /* GATEWAY */

  if ((s->t_srtt == 0) && (s->rt_route->rtt))
    {
      /*
       * Note: this isn't the default case, since the default rtt value
       * (in s->rt_route->rtt) is 0.  This conforms to Stevens, where the
       * initial variance is 3s, and the inital RTO is 6s.
       */
#ifdef OLD_CODE
      s->t_rttvar = s->rt_route->rtt << (TP_RTTVAR_SHIFT - 1);
      s->t_rxtcur = (s->t_srtt >> TP_RTT_SHIFT) + s->t_rttvar;
#else /* OLD_CODE */
      /* The -1 in the old code is bad. */
      s->t_rttvar = s->rt_route->rtt_var << TP_RTTVAR_SHIFT;
      s->t_rxtcur = s->rt_route->initial_RTO << TP_RTT_SHIFT;
#endif /* OLD_CODE */
    } else {
      /*
       * This is the 'default' case.  If there's no variance in the
       * socket structure but there IS a variance in the route,
       * use the route's variance
       */
      if ( s->t_rttvar==0 && s->rt_route->rtt_var ) {
	s->t_rttvar = s->rt_route->rtt_var << TP_RTTVAR_SHIFT;
        s->t_rxtcur = s->rt_route->initial_RTO;
      }
    }
#ifdef DEBUG_TIMING
  logEventv(s, SCPS_log, "%s Setting s->srtt(%f) rttvar(%f) RTO(%f)\n",
	 stringNow(),
	 (float) (s->t_srtt>>TP_RTT_SHIFT)/1000000,
	 (float) (s->t_rttvar>>TP_RTTVAR_SHIFT)/1000000,
	 (float) (s->t_rxtcur>>TP_RTT_SHIFT));
#endif /* DEBUG_TIMING */

  /* Round down to multiple of SMCLBYTES */
#if (SMCLBYTES & (SMCLBYTES - 1)) == 0
  if (mss > SMCLBYTES)
    mss &= ~(SMCLBYTES - 1);
#else /* (SMCLBYTES & (SMCLBYTES - 1)) == 0 */
  if (mss > SMCLBYTES)
    mss = (mss / SMCLBYTES) * SMCLBYTES;
#endif /* (SMCLBYTES & (SMCLBYTES - 1)) == 0 */

  /* 
   * Check if destination address is local or non local.
   * If non local, choose lower of mss and tp_mssdflt 
   */

  /* If the other side specified an mss, it's our max */
  if (offer)
    {
      mss = (mss < offer) ? mss : offer;
      s->mss_offer = offer;	/* Save for SNACK processing */
    }
  else
    s->mss_offer = tp_mssdflt;

  mss = (mss > tp_mssmin) ? mss : tp_mssmin;	/* Sanity check */

  mss = mss & ~1;

  if (s->app_sbuff->max_size > (1 << 16))
    s->snd_ssthresh = (1 << 30);
  else
    s->snd_ssthresh = (1 << 16);
  
#ifdef NOT_DEFINED
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

#endif /* NOT_DEFINED */

  s->sockFlags &= ~TF_CC_LINEAR;
  s->maxseg = mss;
  s->maxseg_perm = mss;

  /* 
   * ack after receiving 1/4 the window assuming 
   * max sized segments 
   */
  /*  s->ack_delay_thresh = (s->app_rbuff->max_size / mss >> 2); */

}

void
tp_dooption_ecbs1 (s, cp, opt_index)
tp_Socket *s;
unsigned char *cp;
unsigned short *opt_index;

{
	int ecbs1_actual_len = 0;  
	int value;
	int i;
	int nibble_index = 0;
        int ecbs_overhead;

	if (cp [*opt_index] != 255) {
		s->ecbs1_req = cp [*opt_index];
		(*opt_index) = (*opt_index) + 1;
		/*  Length is value shifted over 4 places, add 1 then times 2 */ 
		ecbs1_actual_len = (((cp[*opt_index] & 0xf0) >> 4) + 1) * 4;
		nibble_index = 1;
        	ecbs_overhead=3;
		s->ecbs1_req_len = ecbs1_actual_len  - ecbs_overhead;
	} else {
		(*opt_index) = (*opt_index) + 1;
		/*  Length is value shifted over 4 places, add 1 then times 2 */ 
		ecbs1_actual_len = (((cp[*opt_index] & 0xf0) >> 4) + 1) * 4;
		(*opt_index) = (*opt_index) + 1;
		s->ecbs1_req = 256 + cp [*opt_index];
		nibble_index = 0;
		(*opt_index) = (*opt_index) + 1;
        	ecbs_overhead=6;
		s->ecbs1_req_len = ecbs1_actual_len  - ecbs_overhead;
	}

	/*
	* ecbs1_actual_len is the length the data in bytes associated with
	* the ecbs.  We add three because that is the nibble that starts
	* the data */
	for (i = 0; i < (ecbs1_actual_len - ecbs_overhead); i++) {
		if (nibble_index % 2 == 0) {
			/* first nibble */
			value = cp [*opt_index];
			value = value & (0xf0);
			value = value >> 4;
		} else {
			/* second nibble */
			value = cp [*opt_index];
			value = value & (0x0f);
			(*opt_index) = (*opt_index) + 1;
		}
		nibble_index ++;
		
		switch (value) {
			case  0: case  1: case  2: case  3: case  4:
			case  5: case  6: case  7: case  8: case  9:
				s->ecbs1_req_value [i] = '0' + value;
			break;

			case 10: case 11: case 12: case 13: case 14:
			case 15:
				s->ecbs1_req_value [i] = 'A' + value - 10;
			break;

			default:
			break;
		}
	}

	if (nibble_index % 2 == 1) {
		(*opt_index) = (*opt_index) + 1;
	}

#ifdef ECBS_DEBUG
	printf ("Received capability id (%d), and the received data is ",s->ecbs1_req);
	for (i = 0; i < s->ecbs1_req_len; i++) {
		printf ("%c", s->ecbs1_req_value[i]);
		if (i % 2 == 1) {
			printf (" ");
		}
	}
	printf ("\n");
#endif /* ECBS_DEBUG */
}

void
tp_dooption_ecbs2 (s, cp, opt_index)
tp_Socket *s;
unsigned char *cp;
unsigned short *opt_index;

{
	int ecbs2_actual_len = 0;  
	int value;
	int i;
	int nibble_index = 0;
        int ecbs_overhead;

	if (cp [*opt_index] != 255) {
		s->ecbs2_req = cp [*opt_index];
		/*  Length is value shifted over 4 places, add 1 then times 4 */ 
		(*opt_index) = (*opt_index) + 1;
		ecbs2_actual_len = (((cp[*opt_index] & 0xf0) >> 4) + 1) * 4;
		nibble_index = 1;
        	ecbs_overhead=3;
		s->ecbs2_req_len = ecbs2_actual_len  - ecbs_overhead;
	} else {
		(*opt_index) = (*opt_index) + 1;
		/*  Length is value shifted over 4 places, add 1 then times 4 */ 
		ecbs2_actual_len = (((cp[*opt_index] & 0xf0) >> 4) + 1) * 4;
		(*opt_index) = (*opt_index) + 1;
		s->ecbs1_req = 256 + cp [*opt_index];
		nibble_index = 0;
		(*opt_index) = (*opt_index) + 1;
        	ecbs_overhead=6;
		s->ecbs2_req_len = ecbs2_actual_len  - ecbs_overhead;
	}

	/*
	* ecbs2_actual_len is the length the data in bytes associated with
	* the ecbs.  We add three because that is the nibble that starts
	* the data */
	for (i = 0; i < (ecbs2_actual_len - ecbs_overhead); i++) {
		if (nibble_index % 2 == 0) {
			/* first nibble */
			value = cp [*opt_index];
			value = value & (0xf0);
			value = value >> 4;
		} else {
			/* second nibble */
			value = cp [*opt_index];
			value = value & (0x0f);
			(*opt_index) = (*opt_index) + 1;
		}
		nibble_index ++;
		
		switch (value) {
			case  0: case  1: case  2: case  3: case  4:
			case  5: case  6: case  7: case  8: case  9:
				s->ecbs2_req_value [i] = '0' + value;
			break;

			case 10: case 11: case 12: case 13: case 14:
			case 15:
				s->ecbs2_req_value [i] = 'A' + value - 10;
			break;

			default:
			break;
		}
	}
	if (nibble_index % 2 == 1) {
		(*opt_index) = (*opt_index) + 1;
	}

#ifdef ECBS_DEBUG
	printf ("Received capability id (%d), and the received data is ",s->ecbs2_req);
	for (i = 0; i < s->ecbs2_req_len; i++) {
		printf ("%c", s->ecbs2_req_value[i]);
		if (i % 2 == 1) {
			printf (" ");
		}
	}
	printf ("\n");
#endif /* ECBS_DEBUG */
}

void
tp_dooptions (tp_Socket * s, int cnt, tp_Header * tp,
	      int *ts_present, uint32_t * ts_val, uint32_t * ts_ecr)
{
  u_short mss, hole, offset;
  int opt, optlen;
  u_char *cp;
  struct mbuff *ptr;
  int snack_send_offset = 0;
  int jumbo_seen = 0;
  cp = (u_char *) tp + 20;

  for (; cnt > 0; cnt -= optlen, cp += optlen)
    {
      opt = cp[0];
      if (opt == TPOPT_EOL)
	break;
      if (opt == TPOPT_NOP)
	optlen = 1;
      else
	{
	  optlen = cp[1];
	  if (optlen <= 0)
	    break;
	}
      switch (opt)
	{
	default:
	  continue;

	case TPOPT_MAXSEG:
	  if (optlen != TPOLEN_MAXSEG)
	    continue;
	  if (!(tp->flags & tp_FlagSYN))
	    continue;
	  memcpy ((char *) &mss, ((char *) cp + 2), sizeof (mss));

	  (void) tp_mss (s, ntohs (mss));
	  break;

#ifdef OPT_SCPS
	case TPOPT_SCPS:
	  if (optlen == TPOLEN_SCPS) {
		  if (!(tp->flags & tp_FlagSYN))
		    continue;
		  /* Start pulling off the various options... */
	
		  jumbo_seen = 1;
	
		  if (cp[2] & 0x80)	/* BETS */
		    {
		      s->BETS.Flags |= BF_BETS_PERMITTED;
		    }
	
		  if (cp[2] & 0x40)	/* SNACK1 */
		    {
		      s->sockFlags |= TF_SNACK1_PERMIT;
		    }
	
		  if (cp[2] & 0x20)	/* SNACK2 */
		    {
	
		    }
		  if (cp[2] & 0x10)	/* COMPRESS */
		    {
		      s->sockFlags |= TF_RCVD_COMPRESS;
	
		      if (!(s->local_conn_id))
			{
			  s->local_conn_id = (global_conn_ID++ & 0xff);
			  if (!(s->local_conn_id))
			    {
			      s->local_conn_id++;
			      global_conn_ID++;
			    }
			}
		      s->remote_conn_id = (short) (cp[3]);
		    }
		  if (cp[2] & 0x08)	/* TIMESTMP */
		    {
		    }
		  break;
          } else {
          /* This is the Extended Capability Binding Space Logic */

		if (optlen <= TPOLEN_SCPS)
			continue;
		if (!(tp->flags & tp_FlagSYN))
			continue;
		if (s->ecbs1_req_len == 0) {
			unsigned short opt_index = 2;
			tp_dooption_ecbs1 (s, cp, &opt_index);
                        /* opt_index points to location after the option is processed */
                        /* optlen does not include the King and length field */
                        if (opt_index - 1 != optlen + 2) {
				tp_dooption_ecbs2 (s, cp, &opt_index);
			}
		} else  {
			unsigned short opt_index = 2;
			tp_dooption_ecbs2 (s, cp, &opt_index);
		}
         }
#endif /* OPT_SCPS */

	case TPOPT_WINDOW:
	  if (optlen != TPOLEN_WINDOW)
	    continue;
	  if (!(tp->flags & tp_FlagSYN))
	    continue;
	  s->sockFlags |= TF_RCVD_SCALE;
	  s->requested_s_scale =
	    (cp[2] < TP_MAX_WINSHIFT) ? cp[2] : TP_MAX_WINSHIFT;
	  break;

	case TPOPT_TIMESTAMP:
	  if (optlen != TPOLEN_TIMESTAMP)
	    continue;
	  *ts_present = 1;
	  memcpy ((char *) ts_val, ((char *) cp + 2), sizeof (*ts_val));
	  *ts_val = ntohl (*ts_val);
	  memcpy ((char *) ts_ecr, ((char *) cp + 6), sizeof (*ts_ecr));

	  *ts_ecr = ntohl (*ts_ecr);

	  /*
	   * A timestamp received in a SYN makes it OK to send
	   * timestamp requests and replies
	   */
	  if (tp->flags & tp_FlagSYN)
	    {
	      s->sockFlags |= TF_RCVD_TSTMP;
	      s->ts_recent = *ts_val;
	      s->ts_recent_age = tp_now;
	    }
	  break;
	case TPOPT_COMPRESS:
	  if (optlen != TPOLEN_COMPRESS)
	    continue;
	  if (!(tp->flags & tp_FlagSYN))
	    continue;
	  s->sockFlags |= TF_RCVD_COMPRESS;
	  s->remote_conn_id = (short) (cp[2]);
	  break;
	case TPOPT_SNACK1_PERMITTED:
	  if (optlen != TPOLEN_SNACK1_PERMITTED)
	    continue;
	  s->sockFlags |= TF_SNACK1_PERMIT;
	  break;

	case TPOPT_SNACK1:
	  if (optlen != TPOLEN_SNACK1)
	    continue;		/* we don't do the int32_t form yet */
	  memcpy ((char *) &offset, ((char *) cp + 2), sizeof (offset));
	  s->SNACK1_Send_Offset =
	    ntohs (offset) * (s->my_mss_offer - TP_HDR_LEN);
	  memcpy ((char *) &hole, ((char *) cp + 4), sizeof (hole));
	  s->SNACK1_Send_Hole = ntohs (hole) * (s->my_mss_offer - TP_HDR_LEN);

	  snack_send_offset = s->SNACK1_Send_Offset;

	  /* 
	   * Find the mbuff(s) associated with this hole; 
	   * ptr will provide the appropriate handle for retransmission
	   */

	  for (ptr = s->send_buff->snd_una;
	       (ptr && SEQ_LT ((ptr->m_seq + ptr->m_ext.len), ntohl (tp->acknum)));
	       ptr = ptr->m_next);

	  if ((ptr) && (ptr->m_seq <= ntohl (tp->acknum)))
	    {
	      snack_send_offset += (ntohl (tp->acknum) - ptr->m_seq);

	      for (; ((snack_send_offset > 0) && (ptr));
		   ptr = ptr->m_next)
		snack_send_offset -= ptr->m_ext.len;

	      if (snack_send_offset < 0)
		snack_send_offset = 0;

	      VERIFY_BUFFER_HOLES (s->send_buff);
	      SCRUB_HOLES (s);
	       s->send_buff->holes =
		    add_hole (s->send_buff->holes, ptr,
			      s->SNACK1_Send_Hole, tp_now, 0, s->max_seqsent,
			      s->snack_delay);
	      VERIFY_BUFFER_HOLES (s->send_buff);
	      SCRUB_HOLES (s);
	    }
	  break;

	case TPOPT_EOR:
	  if (optlen != TPOLEN_EOR)
	    continue;
	  tp->flags |= tp_FlagEOR;
	  break;

	case TPOPT_BETS_PERMITTED:
	  if (optlen != TPOLEN_BETS_PERMITTED)
	    continue;
	  s->BETS.Flags |= BF_BETS_PERMITTED;
	  break;
	}
    }
  if (!jumbo_seen)
    {
      s->capabilities &= (~CAP_JUMBO);
    }
}
