/********************************************************
 *
 *                             NOTICE *
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
#include "scpserrno.h"
#include <sys/types.h>
#include "gateway.h"
#include "tp_debug.h"


#include <stdio.h>
#include <stdlib.h>

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_process.c,v $ -- $Revision: 1.53 $\n";
#endif /* NO_CVS_IDENTIFY */

extern int printf (const char *format, /* args */ ...);
extern void *malloc (size_t size);

extern int persist_time_outs [TP_MAX_PERSIST_SHIFT];

int abs (int i);		/* test function prototype */

extern uint32_t tp_now;

#ifdef DEBUG_XPLOT
static char FR_START[100];
#endif /* DEBUG_XPLOT */

#ifdef GATEWAY_ROUTER
#include "route.h"
#endif /* GATEWAY_ROUTER */

/*
 * process the acknowledgment information in an incoming packet.
 */
void
tp_ProcessAck (tp_Socket * s, tp_Header * tp, int data_len)
{
  int temp = 0;
  int diff = 0;
  struct timeval mytime;
  uint32_t ts_val = 0, ts1 = 0;
  uint32_t temp1, temp2;
  struct mbuff *ptr;
  uint32_t flippedack;
  int deflate_amt = 0;
  uint32_t rexmit_bytes = 0;
  int prev_snduna = 0;
  int enter_fr_from_da = 0;
  mytime.tv_sec = 0;

#if 0
  {
  word flags;
  flags = tp->flags;
  if ( flags & tp_flagsyn ) {
    printf("%s %s tp_processack looking at ack %lu (%lu) syn=%d...\n",
	   stringnow(), printports(s), flippedack,
	   ntohl(tp->acknum)-s->initial_seqnum,
	   tp->flags&tp_flagsyn);
  }
  }
#endif /* 0 */
  /*
   * if this ack advances snd_una, print it.
   */
  PRINT_ACKNUM (ntohl (tp->acknum), s);
  //  LOGACK(s);  // Output tcptrace info to xplot.

  /* 
   * i've got an ack, reset the rexmit timer 
   * (we'll clear it later if appropriate)
   */

  VERIFY_BUFFER_HOLES (s->send_buff);
  SCRUB_HOLES (s);
  /* When we use the rttvar in calculating the rxtcur, we need to make
   * sure the var is at least 0.5 seconds.  Rational is the following.
   * with implementation of TCP, the unit of variance is 1/4 of a tick
   * and a tick is 0.5 seconds.  The smallest value of the variable
   * is 0.125 seconds.  Therefore when you multiply it by 4, the minimum
   * value of the variance term is 500000 microseconds.  - PDF 
   */
  mytime.tv_usec = (s->t_srtt>>TP_RTT_SHIFT) + max (500000, ((s->t_rttvar>>TP_RTTVAR_SHIFT) << 2));
  mytime.tv_usec = max (mytime.tv_usec, s->RTOMIN);
  mytime.tv_usec = mytime.tv_usec << s->t_rxtshift;         /* Scale the rtt */
  mytime.tv_usec = min(mytime.tv_usec, s->RTOMAX);
  set_timer (&mytime, s->otimers[Rexmit], 1);
  /*
   * do not debug plot the retransmit value here; wait to see if it
   * gets cleared later.
   */

#ifdef GATEWAY
  if ((ntohs (tp->window)) && (s->peer_socket) &&
      (s->peer_socket->gateway_flags & GATEWAY_PEER_WIN_NOT_OPENED))
    {
      s->peer_socket->gateway_flags &= (~GATEWAY_PEER_WIN_NOT_OPENED);
      s->peer_socket->sockFlags |= SOCK_ACKNOW;
#ifdef GATEWAY_DEBUG
      printf ("in tp_processack window opened ack now\n");
#endif /* GATEWAY_DEBUG */
    }
#endif /* GATEWAY */
  /* 
   * determine whether to start the persist timer. 
   */
  /*
   * if the advertised window is less than a segment in size,
   * or
   * we think the link is unavailable and we have data to send
   * and the persist timer is not already set
   * then
   * we set the persist timer.
   */
  if ((((ntohs (tp->window) << s->snd_scale) < s->maxseg) ||
       (!(s->rt_route->flags & RT_LINK_AVAIL))) &&
      (s->send_buff->send) && !(s->otimers[Persist]->set) &&
      !(s->otimers[Rexmit]->set) && !(s->otimers[Rexmit]->expired))
    {
      /* transition into persist state */
      flippedack = ntohl (tp->acknum);
      diff = flippedack - s->snduna;
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

#ifdef DEBUG_PERSIST
      printf ("%s %s transitioning into persist a\n", stringnow (),
	      printports (s));
#endif /* DEBUG_PERSIST */
    }
  else if (!(s->otimers[Rexmit]->set) && (!s->otimers[Rexmit]->expired))
    {
      /*       
       * otherwise, if the retransmission timer is not currently
       * running, we need to exit out of persist state
       */
      /*
       * the link is now available (we got something in),
       * so toggle it's state and clear the persist timer.
       */
     if (!(s->rt_route->flags & RT_LINK_AVAIL)) {
#ifdef GATEWAY_ROUTER
	route_rt_avail (s->rt_route);
#endif /* GATEWAY_ROUTER */
     }

      s->rt_route->flags |= RT_LINK_AVAIL;
      s->persist_shift = 0;
      s->maxpersist_ctr = 0;
      clear_timer (s->otimers[Persist], 1);

      /* set the retransmit timer so that it is running */

      /* s->t_rxtcur is a longword, but tv_usec is an int!!! */
      /* When we use the rttvar in calculating the rxtcur, we need to make
       * sure the var is at least 0.5 seconds.  Rational is the following.
       * with implementation of TCP, the unit of variance is 1/4 of a tick
       * and a tick is 0.5 seconds.  The smallest value of the variable
       * is 0.125 seconds.  Therefore when you multiply it by 4, the minimum
       * value of the variance term is 500000 microseconds.  - PDF 
       */
      mytime.tv_usec = (s->t_srtt>>TP_RTT_SHIFT) + max (500000, ((s->t_rttvar>>TP_RTTVAR_SHIFT) << 2));
      mytime.tv_usec = max (mytime.tv_usec, s->RTOMIN);
      mytime.tv_usec = min(mytime.tv_usec, s->RTOMAX);
      set_timer (&mytime, s->otimers[Rexmit], 1);

      s->timeout = s->timeout;
#ifdef DEBUG_PERSIST
      printf ("%s %s transitioning out of persist a\n", stringnow (),
	      printports (s));
#endif /* DEBUG_PERSIST */
    }

  /*
   * diff represents the amount of hitherto unacknowledged data
   * acknowledged by this segment.
   */

  flippedack = ntohl (tp->acknum);
  diff = flippedack - s->snduna;

  /* credit our cwnd for the value of the data acked */
  if (diff > 0)
    {

      /*  this should only be called if you are not in a fast recovery epoch */
      if (!(s->funct_flags & FUNCT_HIGH_SEQ))
	{
	  if (s->cong_algorithm == VJ_CONGESTION_CONTROL) {
	    if ((s->funct_flags & FUNCT_HIGH_CONGESTION_SEQ) &&
                (SEQ_LEQ (flippedack, s->high_congestion_seq)))
	        {
	        /* No soup for you!  See the rationale comment in tp_output.c */
	        }
	    else
	      {
	         if (s->seqsent - (s->snduna + diff) >  s-> snd_prevcwnd + diff) {
		    	/* Do not give yourself any cwnd credit, you already
                             to many packets in flight */
	         } else if (s->seqsent - (s->snduna + diff) <  s-> snd_prevcwnd + diff) {
		  	/* Give yourself the entire any cwnd credit */
			s->snd_cwnd += max (diff, s->maxseg);
	         } else {
			  /* Give yourself some credit so that the number of packets
			   that can be inflight is not less that snd_prevcwnd */
		    	  s->snd_cwnd += max (s->maxseg,
                                              (int) ((s->seqsent - (s->snduna + diff)) - s-> snd_prevcwnd));
	         }
	 
	         /* Always cap snd_cwnd to snd_prevcwnd when you are NOT in an epoch */
	         s->snd_cwnd = min (s->snd_cwnd, s-> snd_prevcwnd);

  	      }
            }

	  if (s->cong_algorithm == VEGAS_CONGESTION_CONTROL) {
	      if (s->seqsent - (s->snduna + diff) >  s-> snd_prevcwnd) {
	  	/* Do not give yourself any cwnd credit, you already
                   to many packets in flight */
	      } else if (s->seqsent - (s->snduna + diff) <  s-> snd_prevcwnd) {
		  /* Give yourself the entire any cwnd credit */
		  s->snd_cwnd += max (s->maxseg, diff);
	      } else {
		  /* Give yourself some credit so that the number of packets
	 	     that can be inflight is not less that snd_prevcwnd */
	      	  s->snd_cwnd += max (s->maxseg,
                                      (int) (s-> snd_prevcwnd - (s->seqsent - (s->snduna + diff))));
	      }
	 
	      /* Always cap snd_cwnd to snd_prevcwnd when you are NOT in an epoch */
#ifdef DEBUG_XPLOT
//	  logEventv(s, xplot, "magenta\natext %s %u\n",
//	  stringNow2(), flippedack);
//	  logEventv(s,xplot,"%ld %ld %ld %ld\n",s->snd_cwnd, s->snd_prevcwnd, );
#endif /* DEBUG_XPLOT */
              s->snd_cwnd = min (s->snd_cwnd, max (0, s-> snd_prevcwnd - ((s->seqsent - (s->snduna + diff)))));
	      s->snd_cwnd = min (s->snd_cwnd, s-> snd_prevcwnd);
	      s->snd_cwnd = max (s->snd_cwnd, 0);
	  }

	}

#ifdef DEBUG_TIMING
      logEventv(s, timing,  TIMING_FORMAT, 
		stringNow (),
		"diff",
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
#ifdef DEBUG_LOG
      logEventv(s, SCPS_log, "%s diff %lu %ld %ld %u %ld %d %lu\n",
		stringNow2 (),
		flippedack,
		s->snd_prevcwnd,
		s->snd_ssthresh,
		diff,
		s->snd_cwnd,
		s->rtt,
		s->rtseq);
#endif	/* DEBUG_LOG */
    }
  else if (diff <= 0)
    {
#ifdef DEBUG_LOG
      logEventv(s, SCPS_log, "%s diff<=0 %lu %ld %ld %u %ld %d %lu\n",
		stringNow2 (),
		flippedack,
		s->snd_prevcwnd,
		s->snd_ssthresh,
		diff,
		s->snd_cwnd,
		s->rtt,
		s->rtseq);
#endif	/* DEBUG_LOG */
    }
  LOGACK(s, flippedack);  // Output tcptrace info to xplot.
  LOGCWND(s);


  if (diff > 0)
    {
      prev_snduna = s->snduna;
      s->snduna = flippedack;
      LOGCWND(s);

      /*  If you move snd_una between seqsent and max_seqsent you must set
       *  seqsent to snduna.  You must also walk s->send_buff-send through the
       *  list of packets in the buffer until you want past the sequece number
       *  snd_una.  This will allow the packet after snd_una to be emitted next.
       *  -- PDF */

      if ( (SEQ_GT (s->snduna, s->seqsent)) && (SEQ_LEQ (s->snduna, s->max_seqsent)) ) {
        s->seqsent = s->snduna;

        while ((s->send_buff->send) &&
               (SEQ_LT (s->send_buff->send->m_seq, s->snduna)) ) {
                s->send_buff->send = s->send_buff->send->m_hdr.mh_next;
        }
      }

#ifdef VJ_CONGEST
      if (s->cong_algorithm == VJ_CONGESTION_CONTROL)
	{
	  /* Moving snd_una forward gets us out of fast retransmit _IF_ snd_una
	   * moves across s->high_seq  Otherwise we remain in fast retransmit
	   * mode, trying to recover 1 lost packet per RTT.
	   */

	  /* PDF -- This code should not be called for an RTO */

	  if ((s->funct_flags & FUNCT_HIGH_SEQ) && SEQ_GEQ (flippedack, s->high_seq)) 
	    {
	      /* We're transitioning out of Fast Recovery */
	      /* Give ourselves a full (1/2 of previous) snd_cwnd bucket of credit. */
	      /* Since ssthresh gets cut later in this function we have to fake it */
              /* If you clip tmp_prevcwnd to the CURRENT window, then if, when exiting the
               * congestion eopoch the offered window is small, you get no prevcwnd credit
               * and essentially go into very slow growth.  --KS 8/19/1999
               */

	/*
         * Behavior on exiting fast retransmit
	 */

#ifdef OLD_WAY
	/* Set cwnd to the new halved value of ssthresh (already done on entry to
	 * fast retransmit epoch)
	 *
	 * To prevent busts here we do not give ourselves cwnd credit for incoming
	 * acks until s->high_congestion_seq is acked.
	 *
	 */
#else /* OLD_WAY */
	/*
	 * If the number of packets in flight is less than prevcwnd, (which is the
         * maximum number of packets you may have when exiting a congestion epoch)
         * then you may emit as many packets as necessary so the number of packets
         * in flight equal to the prevcwnd.
         */
        
//	 logEventv(s, xplot, "pink\natext %s %lu\n", stringNow2 (), s->high_seq);
//	 logEventv(s, xplot, "%d %u %u %d\n", s->snd_prevcwnd, s->seqsent, flippedack, s->snd_cwnd);
	 s->snd_cwnd = max (0, s->snd_prevcwnd - (s->seqsent - flippedack));
	 s->funct_flags &= ~FUNCT_HIGH_CONGESTION_SEQ;
	 s->high_congestion_seq = 0;
#endif /* OLD_WAY */
 
	      LOGCWND(s);
#ifdef DEBUG_LOG
	      logEventv(s, SCPS_log, "%s out1 %lu %ld %ld %u %ld\n",
			stringNow2 (),
			flippedack,
			s->snd_prevcwnd,
			s->snd_ssthresh,
			diff,
			s->snd_cwnd);
#endif	/* DEBUG_LOG */

#ifdef DEBUG_PRINT
	      printf
		("%s out of FR, snd_cwnd(%ld) relative flippedack (%ld) prevcwnd (%ld) \n",
		 stringNow (), s->snd_cwnd, flippedack -
		 s->initial_seqnum, s->snd_prevcwnd);
	      fflush (stdout);
#endif	/* DEBUG_PRINT */

#ifdef DEBUG_XPLOT
	      if (s->funct_flags & FUNCT_HIGH_SEQ)
		{
		  logEventv(s, xplot, "pink\natext %s %lu\n",
			    stringNow2 (), s->high_seq);
		  logEventv(s, xplot, "!FR VJ\nline %s %lu %s %lu\n",
			    FR_START, s->high_seq,
			    stringNow2 (), s->high_seq);
		  logEventv(s, xplot, "line %s %lu %s %lu\n",
			    stringNow2 (), s->snduna,
			    stringNow2 (), s->high_seq);
		}
#endif	/* DEBUG_XPLOT */

              s->funct_flags = s->funct_flags & (~FUNCT_HIGH_SEQ);
	      s->high_seq = 0;

#ifdef CWND_INFLATE_THROTTLE
	      s->pkts_ack_in_epoch = 0;
#ifdef DEBUG_XPLOT
	  logEventv(s, xplot, "magenta\natext %s %u\n",
	  stringNow2(), flippedack);
	  logEventv(s,xplot,"0 %d\n",s->pkts_ack_in_epoch);
#endif /* DEBUG_XPLOT */
#endif /* CWND_INFLATE_THROTTLE */

	    }
          else if (!(s->funct_flags & FUNCT_HIGH_SEQ))

	    {
	      /*
	       * Get snd_cwnd credit 
	       */

	      if (s->snd_prevcwnd < s->snd_ssthresh)
		{
		  /* We're in exponential VJ mode */
		  s->snd_prevcwnd += s->maxdata;
		  s->snd_cwnd += s->maxdata;
#ifdef DEBUG_LOG
		  logEventv(s, SCPS_log, "%s ack %lu %ld %ld %u %ld %u\n",
			    stringNow2 (),
			    flippedack,
			    s->snd_prevcwnd,
			    s->snd_ssthresh,
			    diff,
			    s->snd_cwnd,
			    s->maxdata);
#endif	/* DEBUG_LOG */
		}
	      else
		{
		  /* Linear VJ mode */
		  /* We give ourselves credit here IF flippedack is greater than high_congestion_seq. */
		  /* See the rationale comment in tp_output.c */
		  if ( (!(s->funct_flags & FUNCT_HIGH_CONGESTION_SEQ)) ||
                      ((s->funct_flags & FUNCT_HIGH_CONGESTION_SEQ) && SEQ_GT (flippedack,
							s->high_congestion_seq)))
		    {
                      if (!s->snd_prevcwnd) {
		          s->snd_prevcwnd += ((s->maxdata * s->maxdata) / s->snd_prevcwnd);
		          s->snd_cwnd += ((s->maxdata * s->maxdata) / s->snd_prevcwnd);
		      } else {
		          s->snd_prevcwnd += s->maxdata;
		          s->snd_cwnd += ((s->maxdata * s->maxdata) / s->snd_prevcwnd);
		      }
		    } else {
		    }
#ifdef DEBUG_LOG
		  logEventv(s, SCPS_log, "%s elseack %lu %ld %ld %u %ld %lu %d %lu\n",
			    stringNow2 (),
			    flippedack,
			    s->snd_prevcwnd,
			    s->snd_ssthresh,
			    diff,
			    s->snd_cwnd,
			    ((s->maxdata * s->maxdata) / s->snd_prevcwnd),
			    (s->high_congestion_seq && SEQ_GT (flippedack, s->high_congestion_seq)),
			    s->high_congestion_seq);
#endif	/* DEBUG_LOG */
		}
	      /* Clip s->snd_prevcwnd to the offered window. */
#ifdef OLD
	      s->snd_prevcwnd = min(s->snd_prevcwnd, s->snd_awnd);
#else /* OLD */
	      s->snd_prevcwnd = min(s->snd_prevcwnd, TP_MAXWIN << s->snd_scale);
#endif /* OLD */
	      LOGCWND(s);
	    }
#ifdef CWND_INFLATE_THROTTLE
	    if (s->funct_flags & FUNCT_HIGH_SEQ) {
    	      s->pkts_ack_in_epoch = diff / s->maxdata;
            }
#endif /* CWND_INFLATE_THROTTLE */

	}
#endif /* VJ_CONGEST */

      /* Need to clear the VEGAS equivalent of cwnd inflation */
      /* 98_11_09 --KS  deflate_amt is never used... */
      if (s->dup_ack_cnt > 0)
	{
	  deflate_amt = (s->dup_ack_cnt * s->maxdata);
	}
      s->dup_ack_cnt = 0;	/* Clear running count of duplicate acks */

      /* Release all the acknowledged data from the send_buffer */

      VERIFY_BUFFER_HOLES (s->send_buff);
      SCRUB_HOLES (s);

      VERIFY_BUFFER_HOLES (s->send_buff);
      SCRUB_HOLES (s);

#ifdef DEBUG_MEMORY
      /* printf("%s %s About to trim to byte %u\n",
       * stringNow(), printPorts(s), ((s->snduna)-1)-(s->initial_seqnum));
       * fflush(stdout);
       */
     #endif /* DEBUG_MEMORY */
      BUG_HUNT (s);     
      ts_val = mb_trim (s->send_buff, (s->snduna) - 1, &ts1, &rexmit_bytes);
      BUG_HUNT (s);     

      VERIFY_BUFFER_HOLES (s->send_buff);
      SCRUB_HOLES (s);

      if ( diff>0 ) {
	      /* If we exit a congestion epoch and a hole exists, then make sure
               * the embargo timer will expire no later than srtt from now
               * Dec 01 2000
               */
	      if ((s->send_buff->holes) && (s->t_srtt)) {
		uint32_t hole_len;
		hole_len = (s->send_buff->holes->hole_end_seq-s->send_buff->holes->hole_start_seq);
              	if ((SEQ_LT (tp_now + (s->t_srtt >> TP_RTT_SHIFT), s->send_buff->holes->Embargo_Time)) &&
                    (s->send_buff->holes->Embargo_Time != 0)) {
#ifdef DEBUG_XPLOT
			{
			  
			  /*
			   * The ((tp_now%20)+1) stuff randomizes the position (height) of the
			   * embargo timer line within the sequence space of the SNACK.  We need
			   * the +1 to keep from getting the occasional floating point exception...
			   */
			  int hole_len = s->send_buff->holes->hole_end_seq - 
			    s->send_buff->holes->hole_start_seq;
			  uint32_t yValue = s->send_buff->holes->hole_start_seq+hole_len/((tp_now%20)+1);
			  logEventv(s, xplot, "; EMBARGO TIMER 1\n");
			  logEventv(s, xplot, "orange\nline %s %lu %s %lu\n",
				    stringNow2(),
				    yValue,
				    stringNow3(((double) s->send_buff->holes->Embargo_Time-tp_now)/1000000),
				    yValue);
			  logEventv(s, xplot, "dtick %s %lu\n",
				    stringNow3(((double) (s->t_srtt>>TP_RTT_SHIFT))/1000000),
				    yValue);
			}
#endif /* DEBUG_XPLOT */
		}
	      }
      }

      /* Rexmit_bytes contains the number of bytes of retransmissions that
       * were acked.  The retransmissions have been deducted from snd_cwnd
       * when the packet was sent.  If we're not doing VJ_CONGEST, these
       * need to be added back.
       */
#ifdef CONGEST
      if (s->cong_algorithm == VEGAS_CONGESTION_CONTROL)
	{
	  /* On the theory that no changes to the cwnd were being made
	   * while rexmits were outstanding, when rexmits are cleared up,
	   * just set snd_cwnd to snd_prevcwnd
	   */

#ifdef DEBUG_LOG
	  logEventv(s, SCPS_log, "%s vegas %lu %ld %ld %u %ld\n",
		   stringNow2 (),
		   flippedack,
		   s->snd_prevcwnd,
		   s->snd_ssthresh,
		   diff,
		   s->snd_cwnd);
#endif	/* DEBUG_LOG */
	  if ((s->funct_flags & FUNCT_HIGH_SEQ) && SEQ_GEQ (flippedack, s->high_seq))
	    {
#ifdef DEBUG_XPLOT
	      logEventv(s, xplot, "pink\natext %s %lu\n",
		       stringNow2 (), s->high_seq);
	      logEventv(s, xplot, "!FR Vegas\nline %s %lu %s %lu\n",
			FR_START, s->high_seq,
			stringNow2 (), s->high_seq);
	      logEventv(s, xplot, "line %s %lu %s %lu\n",
			stringNow2 (), s->snduna,
			stringNow2 (), s->high_seq);
#endif	/* DEBUG_XPLOT */
              s->funct_flags = s->funct_flags & (~FUNCT_HIGH_SEQ);
	      s->high_seq = 0;

	      s->snd_prevcwnd = max (s->maxseg, s->snd_prevcwnd);
	      s->snd_cwnd = s->snd_prevcwnd;
#ifdef CWND_INFLATE_THROTTLE
	      s->pkts_ack_in_epoch = 0;
#endif /* CWND_INFLATE_THROTTLE */

	    }
	}
#endif	/* CONGEST */

      /* SCPS thread-scheduler stuff begins here:
       * If the thread is blocked, and it is waiting on a write
       * and we now have enough space available for him to perform
       * that write, unblock the thread.
       */
#ifdef GATEWAY_SELECT
      if ((s->thread->status == Blocked) &&
	  ((s->write) &&
	   ((s->send_buff->max_size - (s->send_buff->data_size +
				       s->app_sbuff->size)) >= s->write)))

	{
	  /* 
	   * The thread is ready to run, increment the number
	   * of viable threads available to the scheduler.
	   * clear the socket's blocking on write conditional
	   */

	  s->thread->status = Ready;
	  scheduler.num_runable++;
	  s->write = 0;
	}
#else /* GATEWAY_SELECT */
      if ((s->thread->status == Blocked) &&
	  ((scheduler.sockets[s->sockid].write)
	   && ((s->send_buff->max_size - (s->send_buff->data_size +
					  s->app_sbuff->size)) >=
	       scheduler.sockets[s->sockid].write)))
	{
	  s->thread->status = Ready;
	  scheduler.num_runable++;
	  scheduler.sockets[s->sockid].write = 0;
	}
#endif /* GATEWAY_SELECT */

      /* SCPS thread-scheduler stuff ends here */

      /* Calculate the new value of last upper-window edge */

      temp = (int) flippedack + (ntohs (tp->window) << s->snd_scale);

      s->lastuwein = temp;
#ifdef DEBUG_PERSIST
      if (s->otimers[Persist]->set)
	{
	  printf
	    ("%s %s Persist set A, ack(abs=%u rel=%u) window(%u) lastuwein(%u) seqsent(%u)\n",
	     stringNow (), printPorts (s),
	     flippedack, flippedack - s->initial_seqnum,
	     ntohs (tp->window) << s->snd_scale,
	     s->lastuwein, s->seqsent);
	  printf
	    ("    snd_next(%u) snd_una(%u) RT_AVAIL(%d), snd_awnd(%u)\n",
	     (s->send_buff->send) ? (s->send_buff->send->m_seq) : 0,
	     (s->send_buff->snd_una) ? (s->send_buff->snd_una->m_seq) : 0,
	     s->rt_route->flags & RT_LINK_AVAIL != 0, temp - (int) s->seqsent);
	  fflush (stdout);
	}
#endif /* DEBUG_PERSIST */

      /*
       * Calculate the new value of space remaining in advertised window:
       * seqsent is the sequence number of the last octet sent, subtracting
       * this from the current upper-window edge provides us with the
       * remaining advertised window we have available
       */

      temp -= (int) s->max_seqsent;
      s->snd_awnd = (temp < 0) ? 0 : temp;

      /*
       * If we are currently in persist mode (persist timer is set)
       * and the resulting snd_awnd is greater than a maximum segment
       * in length, we transition out of persist.
       */
      if ((s->otimers[Persist]->set) && ((int) s->snd_awnd > s->maxseg))
	{
	  /* Should that be a >= instead of a >? */

	  /*
	   * Clear the persist timer, toggle the links availability
	   * flag and kick-start the retransmission timer.
	   */
          s->persist_shift = 0;
	  s->maxpersist_ctr = 0;
	  clear_timer (s->otimers[Persist], 1);

	  if (!(s->rt_route->flags & RT_LINK_AVAIL)) {
#ifdef GATEWAY_ROUTER
	        route_rt_avail (s->rt_route);
#endif /* GATEWAY_ROUTER */
	  }

	  s->rt_route->flags |= RT_LINK_AVAIL;

          /* When we use the rttvar in calculating the rxtcur, we need to make
           * sure the var is at least 0.5 seconds.  Rational is the following.
           * with implementation of TCP, the unit of variance is 1/4 of a tick
           * and a tick is 0.5 seconds.  The smallest value of the variable
           * is 0.125 seconds.  Therefore when you multiply it by 4, the minimum
           * value of the variance term is 500000 microseconds.  - PDF 
           */
          mytime.tv_usec = (s->t_srtt>>TP_RTT_SHIFT) + max (500000, ((s->t_rttvar>>TP_RTTVAR_SHIFT) << 2));
          mytime.tv_usec = max (mytime.tv_usec, s->RTOMIN);
          mytime.tv_usec = min(mytime.tv_usec, s->RTOMAX);
          if (!s->otimers[Rexmit]->expired) {
	     set_timer (&mytime, s->otimers[Rexmit], 1);
	  } 
#ifdef DEBUG_XPLOT
	  /* Plot a pink line to the right of and slightly above
	   * the segment that
	   * stops where the retransmission timer for that segment
	   * would expire.
	   */
	  if ((s->otimers[Rexmit]->set)) {
	    logEventv(s, xplot, "pink\nline %s %u %s %u\n",
		      stringNow2(),
		      flippedack + 5,
		      stringNow3((double) mytime.tv_usec/1000000),
		      flippedack + 5);
	    logEventv(s, xplot, "larrow %s %u\n",
		      stringNow2(),
		      flippedack+5);
	    logEventv(s, xplot, "rarrow %s %u\n",
		      stringNow3((double) mytime.tv_usec/1000000),
		      flippedack+5);
	  }
#endif /* DEBUG_XPLOT  */
	}

      if (!(s->capabilities & CAP_CONGEST)) {
	/*
	 * If we've disabled congestion control, set the available
	 * cwnd equal to the available flow-control window.
	 */
	s->snd_cwnd = s->snd_awnd;
	LOGCWND(s);
      }

      /* s->sndwin = min (s->snd_cwnd, (s->snd_awnd - (s->seqsent - */
      /* s->snduna))); */
      s->timeout = s->TIMEOUT;	/* should be rt_route specific */

    }

  /*
   * An ugly if statement;
   *
   * If this is a duplicate Ack:
   *     and
   * This is not an ack which is piggy-backed onto a data segment
   *     and
   * The Ack is for the segment that we are attempting to time
   *     and
   * There is a segment currently being timed
   *     and
   * ??? This Ack anchor's the last upper-window-edge update ???
   *
   * Then:
   *   We want to use the original stashed timestamp as the basis for
   *   calculating temp2 instead of the echoed timestamp ts_val.
   *
   * Why? I dunno anymore, but it hurts us badly in errored environments!
   */
  temp2 = (ts_val) ? (uint32_t) ((abs) ((int) tp_now - (int) ts_val)) : 0;

  if ((diff == 0) && (data_len == 0) && (flippedack == s->rtseq) && (s->rtt) &&
      (s->lastuwein == ((int) flippedack + (ntohs (tp->window) << s->snd_scale))))
    {
      /*
       * if for some reason there is no stashed timestamp value tucked
       * away in the socket, we will use the timestamp located in the
       * mbuffer of the segment at snd_una.
       */
      if (!(ts_val = s->rt_prev_ts_val))
	ts_val = s->send_buff->snd_una->m_ts;

      /* Don't let Vegas GROW the cwnd, but don't shrink it more either. */
      s->rtseq = 0;
      temp2 = (ts_val) ? (uint32_t) ((abs) ((int) tp_now - (int) ts_val)) : 0;
    }

  /*
   * If there is an echoed timestamp then
   * temp2 is the elapsed time from when the
   * timestamp was originally generated to now.
   */

  temp2 = (ts_val) ? (uint32_t) ((abs) ((int) tp_now - (int) ts_val)) : 0;

  if (ts_val)
    {
      /*
       * Another in the series of ugly if-statements:
       *
       * If we did NOT receive a timestamp
       *   and
       * We are currently attempting to time a segment
       *   and
       * The segment Acked is greater than to the
       * segment we are attempting to time or we've got
       * dup-acks ( rtseq is null)
       *   and
       * we've got either a timestamp for the oldest segment
       * trimmed (ts1) or an echo-reply timestamp (ts_val)
       *
       * Then:
       *
       * if there is a value for ts1:
       *    temp1 is set to be the elapsed time between
       *    ts1's generation and now,
       * otherwise temp1 is set to 0;
       *
       * tp_xmit timer is called to:
       *   1) update Vegas congestion window (if applicable)
       *   2) update round-trip-timming estimates
       */

      if (!(s->sockFlags & TF_RCVD_TSTMP) &&
	  ((s->rtt) &&
	   ((SEQ_GT (flippedack, s->rtseq)) || (s->rtseq == 0))) &&
	  ((ts1) || (ts_val)))
	{
	  temp1 = (ts1) ? (uint32_t) ((abs) ((int) tp_now - (int) ts1)) : 0;
	  /*
	   * ts1 represents when the first packet was sent, and should
	   * be used for RTO
	   * ts_val represents when the LAST packet was sent, and is
	   * used for Vegas throughput calculations
	   */
	  {
#ifdef DEBUG_XPLOT
	    if (s->rtt && s->rtseq > 0)
	      {
		/* Done timing segment. */
		if ( s->rtseq>0 ) {
		  char curTime[50];
		  sprintf(curTime, stringNow2());
		  logEventv(s, xplot, "; Done timing segment.\nyellow\ndiamond %s %lu\nline %s %lu %s %lu\n",
			    curTime, s->rtseq,
			    timingStartString, s->rtseq,
			    curTime, s->rtseq);
		}
	      }
#endif	/* DEBUG_XPLOT */
	    /*  s->snd_cwnd -= min(diff, s->maxseg_perm); */
	    tp_xmit_timer (s, temp1, temp2);
	    s->rtt = 0;
#ifdef DEBUG_TIMING
	    logEventv(s, timing,  TIMING_FORMAT, 
		      stringNow (),
		      "ts_val1",
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
	  }
	}

      /* Otherwise:
       * if we DID receive a timestamp
       *   and
       * the incoming Ack covers the timed segement or this is in
       * response to a duplicate ack
       *   and
       * we've got an elapsed time (a rtt measurement) in temp2,
       *
       * Then:
       *
       * tp_xmit timer is called to:
       *   1) update Vegas congestion window (if applicable)
       *   2) update round-trip-timming estimates
       */

      else if ((s->rtt) && (s->sockFlags & TF_RCVD_TSTMP) &&
	       (SEQ_GT (flippedack, s->rtseq) || (s->rtseq == 0)) && temp2)
	{
	  tp_xmit_timer (s, 0, temp2);
	  s->rtt = 0;		/* We are no longer timing a segment */

#ifdef DEBUG_TIMING
	  logEventv(s, timing, TIMING_FORMAT,
		    stringNow (),
		    "ts_val2",
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

#ifdef DEBUG_XPLOT
	  if (s->rtseq > 0)
	    {
	      logEventv(s, xplot, "yellow\ndiamond %s %lu\nline %s %lu %s %lu\n",
			stringNow2(), s->rtseq,
			timingStartString, s->rtseq,
			stringNow2(), s->rtseq);
	    }
#endif	/* DEBUG_XPLOT */
	}
    }
  else
    {
#ifdef DEBUG_TIMING
      logEventv(s, timing, TIMING_FORMAT,
		stringNow (),
		"!ts_val",
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
    }

  SCRUB_HOLES (s);
#ifdef OPT_SNACK1
  /* The below assumes that a SNACK contains at most a single hole; */

  if (s->capabilities & CAP_SNACK)
    {

      if ( (s->SNACK1_Send_Hole > 0) && (SEQ_LEQ (flippedack, s->seqsent)) )
	{
	  uint32_t highest_snacked_byte;
	  /*
	   * Find the mbuff(s) associated with this hole;
	   * ptr will provide the appropriate handle for
	   * retransmission.
	   */

      VERIFY_BUFFER_HOLES (s->send_buff);
      SCRUB_HOLES (s);

	  for (ptr = s->send_buff->snd_una;
	       ((s->SNACK1_Send_Offset > 0) && (ptr));
	       ptr = ptr->m_next)
	    s->SNACK1_Send_Offset -= ptr->m_ext.len;

	  if (s->SNACK1_Send_Offset < 0)
	    s->SNACK1_Send_Offset = 0;

	  /* If we're in a congestion epoch, record the highest SNACKed byte.  If we
	   * later receive a re-snack for things lower than the recorded value, do
	   * not cut the congestion window again.
	   */
	  highest_snacked_byte = flippedack + s->SNACK1_Send_Offset + s->SNACK1_Send_Hole;

	  if ((s->flags & FUNCT_HIGH_SEQ) && SEQ_GT (highest_snacked_byte,
				     s->high_hole_seq))
	    {
	      s->high_hole_seq = highest_snacked_byte;

#ifdef DEBUG_XPLOT
	      logEventv(s, xplot, "blue\nline %s %lu %s %lu\n",
			stringNow2 (), s->high_hole_seq,
			stringNow3 (0.05), s->high_hole_seq);
#endif	/* DEBUG_XPLOT */

	    }

	  /*
	   * Make sure that there's enough snd_cwnd credit to push out
	   * all of the packets covered by this SNACK and do it.
           * This logic allow:  1)  Makes sure you will call tp_NewSend
           * only if there is a snacked packet whose embargo timer will
           * permit the packet to be emitted and 2)  only increment CWND
           * if required to emit the packets and finally 3) make sure
           * these retransmitted packets consume cwnd.  -- PDF
	   */
	  {
	     struct _hole_element *local_hole;

	     local_hole = s->send_buff->holes;
	     while ((local_hole) && (local_hole->Embargo_Time !=0 ) &&
	            (SEQ_GT (local_hole->Embargo_Time, tp_now)) &&
	            (highest_snacked_byte != local_hole->hole_start-> m_seq)) {
	                 local_hole = local_hole->next;
	     }

	     if ( (local_hole) && (s->snack_delay != 0) ) {
		local_hole->Embargo_Time = tp_now + s->snack_delay;
  	     }

	     if (local_hole) {
	         if (s->SNACK1_Send_Hole > s->snd_cwnd) {
	             s->snd_cwnd = s->SNACK1_Send_Hole;
	         }

	         tp_NewSend (s, NULL, false);
	     }
             s->SNACK1_Send_Hole = 0;
	    
	  }

	  /*
	   * Halve the congestion window, if appropriate
	   */
	  if (!(s->funct_flags & FUNCT_HIGH_SEQ)
	      && SEQ_LT (s->high_hole_seq, highest_snacked_byte)
	      && ((s->cong_algorithm == VJ_CONGESTION_CONTROL) || 
                  (s->rt_route->flags & (RT_CONGESTED | RT_ASSUME_CONGEST))))
	    {
	      if (s->cong_algorithm == VJ_CONGESTION_CONTROL)
		{
		  /* PDF clip CWND to the amount of data in flight first */
		  s->snd_prevcwnd = min(s->snd_prevcwnd, s->seqsent - s->snduna);
                  s->snd_prevcwnd = min (s->snd_prevcwnd, (ntohs
                                         (tp->window) << s->snd_scale));
                  s->snd_ssthresh = max ((s->maxdata << 1), (s->snd_prevcwnd
                                                             >> 1));
		

          /* I'm rounding down prevcwnd to a multiple of maxdata.  This allows
           * VJ congestion control algorithm to perform a bit better. -- PDF
           */
		  if (s->snd_ssthresh == ((int) ((s->snd_ssthresh) / s->maxdata)) * s->maxdata) {
			s->snd_prevcwnd = (((int) ((s->snd_ssthresh) / s->maxdata)) *
                                              s->maxdata);
		  } else {
                      s->snd_prevcwnd = (((int) ((s->snd_ssthresh) / s->maxdata)) *
                                              s->maxdata) + s->maxdata;
		  }
                  s->snd_ssthresh = min (s->snd_ssthresh, s->snd_prevcwnd);
		  /* When we enter a congestion epoch, we sut ssthresh in half
                   * AND set cwnd to 1 packet.  If this dup ack does not increase the
                   * advertised window then we will set cwnd to 1 packet.  If
                   * this is a pure dup ack, then the cwnd will be incremented
                   * a little later.
		   *    WAS:  s->snd_cwnd = s->maxdata;
                   */
		 if (((s->lastuwein != ((int) flippedack +
                                       (ntohs (tp->window) << s->snd_scale))) ||
                    (diff > 0) ) &&
                     (data_len == 0)) {

		  	s->snd_cwnd =  s->maxdata;
	 	 } else {
		  	s->snd_cwnd =  0;

		 } 

		}
	      else if (s->cong_algorithm == VEGAS_CONGESTION_CONTROL)
		{
		  s->sockFlags |= TF_CC_LINEAR;
		  s->snd_cwnd = max (s->maxdata, (s->snd_cwnd >> 1));
		  s->snd_prevcwnd = max (s->maxdata, (s->snd_prevcwnd >> 1));
		}

#ifdef CWND_INFLATE_THROTTLE
	      s->pkts_ack_in_epoch = (s->seqsent - s->snduna) / s->maxdata;
#endif /* CWND_INFLATE_THROTTLE */

              s->snd_cwnd = min (s->snd_cwnd, s->snd_prevcwnd);

	      LOGCWND(s);
#ifdef DEBUG_LOG
	      logEventv(s, SCPS_log, "%s snackHalf %lu %lu %lu %u %ld\n",
			stringNow2 (),
			flippedack,
			s->snd_prevcwnd,
			s->snd_ssthresh,
			diff,
			s->snd_cwnd);
#endif	/* DEBUG_LOG */

	      /* clamp at one segment, minimum */
	      /* if ((int) s->snd_cwnd <= (int) s->maxseg_perm) */
	      if ((int) s->snd_prevcwnd <= (int) s->maxseg_perm)
		{
		  s->sockFlags &= ~TF_CC_LINEAR;	/* hit bottom-go exponential */
		  s->snd_prevcwnd = s->maxseg_perm;
		}

	      /* Begin NewReno Fast retransmit epoch if not already there. */
	      s->high_seq = s->max_seqsent;
              s->funct_flags = s->funct_flags | FUNCT_HIGH_SEQ;

#ifdef DEBUG_PRINT
	      printf
		      ("%s into FR, high_seq(%lu) snd_una(%lu) cwnd(%lu) ssthresh(%lu) prevcwnd(%lu)\n",
		      stringNow (), s->high_seq - s->initial_seqnum,
		      s->snduna - s->initial_seqnum, s->snd_cwnd,
		      s->snd_ssthresh, s->snd_prevcwnd);
	      fflush (stdout);
#endif	/* DEBUG_PRINT */

#ifdef DEBUG_XPLOT
	      logEventv(s, xplot, "pink\natext %s %lu\n",
			stringNow2(), s->high_seq);
	      logEventv(s, xplot, "FR SNACK\nline %s %lu %s %lu\n",
			stringNow2(), s->snduna, stringNow2(), s->high_seq);
	      sprintf (FR_START, stringNow2 ());
#endif	/* DEBUG_XPLOT */
	    }
	  /* Was here
	   * s->SNACK1_Send_Hole = 0;
	   * tp_NewSend (s, NULL, false);
	   */
	}
      else
	s->SNACK1_Send_Hole = 0;
    }
#endif /* OPT_SNACK1 */

      VERIFY_BUFFER_HOLES (s->send_buff);
      SCRUB_HOLES (s);

  SCRUB_HOLES (s);

  /* Whether we have Timestamps or not, do vegas fast rexmit */
  if (s->vegas_ack_check > 0)
    {
      if (s->send_buff->snd_una &&
	  s->send_buff->snd_una->m_rt &&
	  !(s->otimers[Persist]->set) &&
	  (SEQ_GEQ (tp_now, s->send_buff->snd_una->m_rt)))
	{
	  s->sockFlags |= TF_VEGAS_FAST_REXMIT;

	  /* 
	   * If this segment is not already on the 
	   * Pending Retransmission queue, insert it;
	   * 
	   * If it is already on the Pending queue, check
	   * the elements "Embargo Time" as compared to the
	   * current notion of system time (tp_now):
	   *
	   * if ((Embargo Time) && (tp_now >= Embargo Time))
	   *    clear Embargo Time
	   * else
	   *    do nothing;
	   */

	  /* 
	   * As above, calling tp_TFRetransmit() here is wrong;
	   */
	  VERIFY_BUFFER_HOLES (s->send_buff);
	  SCRUB_HOLES (s);

          BUG_HUNT (s);
	  s->send_buff->holes =
	    add_hole (s->send_buff->holes, s->send_buff->snd_una,
		      s->send_buff->snd_una->m_ext.len, tp_now, 0, s->max_seqsent,
		      s->snack_delay);
          BUG_HUNT (s);
	  VERIFY_BUFFER_HOLES (s->send_buff);
	  SCRUB_HOLES (s);

	  tp_NewSend (s, NULL, false);
	  VERIFY_BUFFER_HOLES (s->send_buff);
	  SCRUB_HOLES (s);
	}
      s->vegas_ack_check--;
    }

  SCRUB_HOLES (s);
  if (diff == 0)
    {

      /* 
       * Increment cwnd by one mss regardless, a segment has left
       * the network! But, if this has a window update, it is *not*
       * a duplicate ACK!
       */

      if ((s->lastuwein == ((int) flippedack +
			    (ntohs (tp->window) << s->snd_scale))) &&
	  (data_len == 0))
	{
	  s->dup_ack_cnt++;	/* Up the duplicate ack count */
#ifdef DEBUG_XPLOT
	  logEventv(s, xplot, "magenta\nuarrow %s %u\n",
		    stringNow2(), flippedack);
#endif /* DEBUG_XPLOT */

#ifdef EXPERIMENTAL
	  /* This is trying to really cut the transmission rate on loss
	   * (added specifically for Vegas)  This seems imprudent since
	   * it can lead to an exponential decay of the congestion window
	   * (for both).
	   *
	   * The idea is that if we're running vegas and assuming
	   * congestion, then we want to inject packets more slowly after
	   * detecting congestion (1/2 packet per dupack).  If we're
 	   * running VJ, just give ourselves one MSS of credit and keep
	   * going.  This needs to be integrated with cwnd inflation is
           * it becomes defined */
	   */
	  if (s->cong_algorithm == VEGAS_CONGESTION_CONTROL
	      && (s->rt_route->flags & (RT_CONGESTED | RT_ASSUME_CONGEST)))
	    {
	      s->snd_cwnd += s->maxdata >> 1;
	    }
	  else
	    {
	      s->snd_cwnd += s->maxdata;
	    }
#endif /* EXPERIMENTAL */

#ifdef DEBUG_XPLOT
	  //	  logEventv(s, xplot, "magenta\natext %s %u\n",
	  //		    stringNow2(), flippedack);
	  //	  logEventv(s,xplot,"%d %d\n",s->snd_cwnd, s->snd_cwnd + s->maxdata);
#endif /* DEBUG_XPLOT */

	  /*
	   * CWND INFLATION
	   */
#if 1
	  /* 
	   * Don't clip s->snd_cwnd tp s->snd_prevcwnd.  Chances of
	   * this actually being a problem are low.
	   */

#ifdef CWND_INFLATE_THROTTLE 
	  if (s->cong_algorithm == VJ_CONGESTION_CONTROL) {
            s->pkts_ack_in_epoch --;
            if ((s->pkts_ack_in_epoch * s->maxdata < s-> snd_ssthresh + (DUPACK_THRESH * s->maxdata)) ||
              (s->dup_ack_cnt < DUPACK_THRESH)) {
               s->pkts_ack_in_epoch ++;
  	       s->snd_cwnd += s->maxdata;
            }
          } else if (s->cong_algorithm == VEGAS_CONGESTION_CONTROL) {
		if (s->rt_route->flags & (RT_CONGESTED | RT_ASSUME_CONGEST)) {
#ifdef DEBUG_XPLOT
  	           logEventv(s, xplot, "magenta\natext %s %u\n",
	           stringNow2(), flippedack);
	           logEventv(s,xplot,"%d %d %d \n",s->pkts_ack_in_epoch * s->maxdata, s->snd_cwnd , s->snd_prevcwnd);
#endif /* DEBUG_XPLOT */
                     s->pkts_ack_in_epoch --;  /* Got an ack so we assume one has left the network */
	             if (((s->pkts_ack_in_epoch * s->maxdata) +  s->snd_cwnd) < s->snd_prevcwnd) {
	               s->pkts_ack_in_epoch ++;
	               s->snd_cwnd += s->maxdata;
                     }
		} else {
	          s->snd_cwnd += s->maxdata;
                }
	  }
#else  /* CWND_INFLATE_THROTTLE */
    	    s->snd_cwnd += s->maxdata;
#endif /* CWND_INFLATE_THROTTLE */


#else /* 0 */
	  /*
	   * This is cwnd inflation clipped to the value of
	   * prev_cwnd.  Clipping keeps us legal when in a
	   * congestion epoch by limiting our transmission rate to 1/2
	   * of that when we entered. 
	   */
	  s->snd_cwnd = min(s->snd_cwnd+s->maxdata, s->snd_prevcwnd);
#endif /* 0 */
	  LOGCWND(s);
#ifdef DEBUG_LOG
	  logEventv(s, SCPS_log, "%s dupack %lu %lu %lu %u %ld %u\n",
		    stringNow2 (),
		    flippedack,
		    s->snd_prevcwnd,
		    s->snd_ssthresh,
		    diff,
		    s->snd_cwnd,
		    s->maxdata);
#endif	/* DEBUG_LOG */
	}

#define  LINUX_STYLE_EPOCH 1
#ifdef LINUX_STYLE_EPOCH
	  if ((s->cong_algorithm == VJ_CONGESTION_CONTROL) && (s->funct_flags & FUNCT_HIGH_SEQ) &&
             (s->dup_ack_cnt <= DUPACK_THRESH) && (s->send_buff->snd_una)) {
          /* I'm rounding down prevcwnd to a multiple of maxdata.  This allows
           * VJ congestion control algorithm to perform a bit better. -- PDF
           */
	      	s->snd_ssthresh = max (s->snd_ssthresh, (s->seqsent - s->snduna + s->maxdata) >> 1);
		if (s->snd_ssthresh == ((int) ((s->snd_ssthresh) / s->maxdata)) * s->maxdata) {
			s->snd_prevcwnd = (((int) ((s->snd_ssthresh) / s->maxdata)) *
                                              s->maxdata);
		} else {
                      s->snd_prevcwnd = (((int) ((s->snd_ssthresh) / s->maxdata)) *
                                              s->maxdata) + s->maxdata;
		}
		s->snd_ssthresh = max (s->snd_ssthresh, s->snd_prevcwnd);
	  }
#endif /* LINUX_STYLE_EPOCH */
      if ((s->send_buff->snd_una) &&
	  (s->dup_ack_cnt >= DUPACK_THRESH))
	{
	  /* Need to modify this so that we only send a single 
	   * Fast-Retransmit per rtt, otherwise noisy channels 
	   * will really guber us up!
	   * How to do this?
	   * Add a rxmit_last value to the tpcb structure (ugh!) 
	   * that has the clock value for the last retrans of
	   * this packet. This is set to 0 when snduna moves 
	   * forward and dup_ack_cnt is cleared; When the nth
	   * duplicate ack arrives and 
	   * current_time  > (rtt_curr + rxmit_last) we do a 
	   * fast retransmit, clear the dup_ack_cnt and that's that. 
	   */

#ifdef CWND_INFLATE_THROTTLE
	  if (!(s->funct_flags & FUNCT_HIGH_SEQ)) {
	      s->pkts_ack_in_epoch = (s->seqsent - s->snduna) / s->maxdata;
          }
#endif /* CWND_INFLATE_THROTTLE */

#ifdef VJ_CONGEST
	  if (s->cong_algorithm == VJ_CONGESTION_CONTROL)
	    {
	      if (!(s->funct_flags & FUNCT_HIGH_SEQ))
		{
		  enter_fr_from_da = 1;
                  s->funct_flags = s->funct_flags | FUNCT_HIGH_SEQ;
		  s->high_seq = s->max_seqsent;	/* --KS */
		  s->snd_cwnd = s->snd_prevcwnd + flippedack - s->max_seqsent;
		  s->snd_prevcwnd = min (s->snd_prevcwnd, (ntohs
					 (tp->window) << s->snd_scale));
		  s->snd_ssthresh = max ((s->maxdata << 1), (s->snd_prevcwnd
							     >> 1));
          /* I'm rounding down prevcwnd to a multiple of maxdata.  This allows
           * VJ congestion control algorithm to perform a bit better. -- PDF
           */
		  if (s->snd_ssthresh == ((int) ((s->snd_ssthresh) / s->maxdata)) * s->maxdata) {
			s->snd_prevcwnd = (((int) ((s->snd_ssthresh) / s->maxdata)) *
                                              s->maxdata);
		  } else {
                      s->snd_prevcwnd = (((int) ((s->snd_ssthresh) / s->maxdata)) *
                                              s->maxdata) + s->maxdata;
		  }
		  s->snd_ssthresh = min (s->snd_ssthresh, s->snd_prevcwnd);
		  LOGCWND(s);
#ifdef DEBUG_LOG
		  logEventv(s, SCPS_log, "%s third_dupack(VJ) %lu %lu %lu %u %ld\n",
			    stringNow2 (),
			    flippedack,
			    s->snd_prevcwnd,
			    s->snd_ssthresh,
			    diff,
			    s->snd_cwnd);
#endif	/* DEBUG_LOG */
#ifdef DEBUG_PRINT
		  printf
		    ("%s into FR, high_seq(%lu) snduna(%lu) cwnd(%lu) ssthresh(%lu), prevcwnd(%lu)\n",
		     stringNow (), s->high_seq - s->initial_seqnum,
		     s->snduna - s->initial_seqnum, s->snd_cwnd,
		     s->snd_ssthresh, s->snd_prevcwnd);
		  fflush (stdout);
#endif /* DEBUG_PRINT */
#ifdef DEBUG_XPLOT
		  logEventv(s, xplot, "pink\natext %s %lu\n",
			    stringNow2(), flippedack);
		  logEventv(s, xplot, "FR VJ 3\nline %s %lu %s %lu\n",
			    stringNow2 (), s->snduna, stringNow2 (), s->high_seq);
		  sprintf (FR_START, stringNow2 ());
#endif	/* DEBUG_XPLOT */
		} else {
#ifdef EXPERIMENTAL
		   /* If your are in a congestion epoch and have not already emitted
                      the packet referred to by the DUP ACKS, then you must emit
                      that packet now
                    */
		   if ((s->dup_ack_cnt == DUPACK_THRESH) &&
                       (s->send_buff->holes) &&
                       (s->send_buff->holes->rx_ctr == 0)) {
			s->send_buff->holes->Embargo_Time = tp_now;
		   }
#endif /* EXPERIMENTAL */
		} 
	    }
#endif /* VJ_CONGEST */

#ifndef NEW_CODE
            if ((s->cong_algorithm == VEGAS_CONGESTION_CONTROL) &&
                (!(s->funct_flags & FUNCT_HIGH_SEQ)) &&
	        (s->rt_route->flags & (RT_CONGESTED | RT_ASSUME_CONGEST))) {
		  enter_fr_from_da = 1;
                  s->sockFlags |= TF_CC_LINEAR;
                  s->snd_cwnd = max (s->maxdata, (s->snd_cwnd >> 1));
                  s->snd_prevcwnd = max (s->maxdata, (s->snd_prevcwnd >> 1));
                  s->snd_cwnd = min (s->snd_cwnd, s->snd_prevcwnd);
            }
#endif /* NEW_CODE */


	  /*
	   * Force out the retransmission by making it a hole and calling tp_NewSend
	   */
	  VERIFY_BUFFER_HOLES (s->send_buff);
	  SCRUB_HOLES (s);
	  {
                int snack_delay = 0;
 
		if (s->dup_ack_cnt <= DUPACK_THRESH)
		  snack_delay = s->snack_delay;

          BUG_HUNT (s);
	  	s->send_buff->holes =
		    add_hole (s->send_buff->holes, s->send_buff->snd_una,
			      s->send_buff->snd_una->m_ext.len, tp_now, 0, s->max_seqsent,
			      snack_delay);
          BUG_HUNT (s);
	  }
	  VERIFY_BUFFER_HOLES (s->send_buff);
	  SCRUB_HOLES (s);

	  /*
	   * On the thirdt dupack, force out the retransmission.
	   * Make sure that we have enough snd_cwnd credit to send the packet.
	   */
	  if ((s->dup_ack_cnt == DUPACK_THRESH)  && (enter_fr_from_da) && ((s->funct_flags & FUNCT_HIGH_SEQ)))
	    {
   	
	      int old_cwnd = s->snd_cwnd;
	      s->snd_cwnd = s->maxdata;
	      tp_NewSend (s, NULL, false);
	      s->snd_cwnd = old_cwnd;
#ifdef OLD_CODE
	      if (s->snd_cwnd < s->maxdata) {
		  s->snd_cwnd = s->maxdata;
	      }
	      tp_NewSend (s, NULL, false);
#endif /* OLD_CODE */

	    }

	  VERIFY_BUFFER_HOLES (s->send_buff);
	  SCRUB_HOLES (s);

	  if ((s->cong_algorithm == VEGAS_CONGESTION_CONTROL) &&
	      (s->rt_route->flags & (RT_CONGESTED | RT_ASSUME_CONGEST)))
	    {
	      if (!(s->funct_flags & FUNCT_HIGH_SEQ))
		{
		  /* This congestion epoch will end when high_seq is acked. */
		  s->high_seq = s->max_seqsent;
                  s->funct_flags = s->funct_flags | FUNCT_HIGH_SEQ;

		  /* Cut congestion window in 1/2 */
		  s->snd_prevcwnd = max (s->maxdata, (s->snd_prevcwnd >> 1));
		  s->snd_cwnd = max (s->maxdata, (s->snd_cwnd >> 1));
		  s->snd_cwnd = min (s->snd_cwnd, s->snd_prevcwnd);

		  if ((int) s->snd_prevcwnd <= (int) s->maxseg_perm)
		    {
		      s->sockFlags &= ~TF_CC_LINEAR;	/* hit bottom-go exponential */
		      s->snd_prevcwnd = s->maxseg_perm;
		    }

		  LOGCWND(s);
#ifdef DEBUG_LOG
		  logEventv(s, SCPS_log, 
			    "%s third_dupack(Vegas) %lu %lu %lu %u %ld\n",
			    stringNow2 (),
			    flippedack,
			    s->snd_prevcwnd,
			    s->snd_ssthresh,
			    diff,
			    s->snd_cwnd);
#endif	/* DEBUG_LOG */
#ifdef DEBUG_PRINT
		  printf
			  ("%s into FR, high_seq(%lu) snduna(%lu) cwnd(%lu) ssthresh(%lu), prevcwnd(%lu)\n",
			  stringNow (), s->high_seq - s->initial_seqnum,
			  s->snduna - s->initial_seqnum, s->snd_cwnd,
			  s->snd_ssthresh, s->snd_prevcwnd);
		  fflush (stdout);
#endif	/* DEBUG_PRINT */
#ifdef DEBUG_XPLOT
		  logEventv(s, xplot, "pink\natext %s %lu\n",
			    stringNow2(), flippedack);
		  logEventv(s, xplot, "FR 3 Vegas\nline %s %lu %s %lu\n",
			    stringNow2 (), s->snduna, stringNow2 (), s->high_seq);
		  sprintf (FR_START, stringNow2 ());
#endif	/* DEBUG_XPLOT */
		}
	      fflush (stdout);
	    }

#ifdef DEBUG_XPLOT
	  if (SEQ_LT (flippedack - 2000, flippedack))
	    {
	      logEventv(s, xplot, "pink\nline %s %lu %s %lu\n",
			stringNow2 (), flippedack - 2000,
			stringNow2 (), flippedack - 1000);
	    }
#endif	/* DEBUG_XPLOT */

	}

      else if ((s->cong_algorithm == VEGAS_CONGESTION_CONTROL) &&
	       (s->send_buff->snd_una &&
		s->send_buff->snd_una->m_rt) &&
	       !(s->otimers[Persist]->set) &&
	       (SEQ_GEQ (tp_now, s->send_buff->snd_una->m_rt)))
	{
          /* We should onlt enter a VEGAS fast retransmit if we assume loss
             is due to congestion. -- PDF */

	  if (s->rt_route->flags & (RT_CONGESTED | RT_ASSUME_CONGEST)) {
	  	s->sockFlags |= TF_VEGAS_FAST_REXMIT;
	  }

	  /* 
	   * If this segment is not already on the 
	   * Pending Retransmission queue, insert it;
	   * 
	   * If it is already on the Pending queue, check
	   * the elements "Embargo Time" as compared to the
	   * current notion of system time (tp_now):
	   *
	   * if ((Embargo Time) && (tp_now >= Embargo Time))
	   *    clear Embargo Time
	   * else
	   *    do nothing;
	   */

	  /* 
	   * As above, calling tp_TFRetransmit() here is wrong;
	   */

	  VERIFY_BUFFER_HOLES (s->send_buff);
	  SCRUB_HOLES (s);
	  s->send_buff->holes =
	    add_hole (s->send_buff->holes, s->send_buff->snd_una,
		      s->send_buff->snd_una->m_ext.len, tp_now, 0, s->max_seqsent,
		      s->snack_delay);
	  VERIFY_BUFFER_HOLES (s->send_buff);
	  SCRUB_HOLES (s);

	  tp_NewSend (s, NULL, false);
	  VERIFY_BUFFER_HOLES (s->send_buff);
	  SCRUB_HOLES (s);
	}

      /* this may be increasing our window size */
      s->snd_awnd = ntohs (tp->window) << s->snd_scale;
      temp = (int) flippedack + (ntohs (tp->window) << s->snd_scale);

      s->lastuwein = temp;
#ifdef DEBUG_PERSIST
      if (s->otimers[Persist]->set)
	{
	  printf
	    ("%s %s Persist set B, ack(abs=%u rel=%u) window(%u) lastuwein(%u)\n",
	     stringNow (), printPorts (s),
	     flippedack, flippedack - s->initial_seqnum,
	     ntohs (tp->window) << s->snd_scale,
	     s->lastuwein);
	  printf ("    snd_next(%u) snd_una(%u) RT_AVAIL(%d) snd_awnd(%u)\n",
		  (s->send_buff->send) ? (s->send_buff->send->m_seq) : 0,
		  (s->send_buff->snd_una) ? (s->send_buff->snd_una->m_seq) : 0,
		  s->rt_route->flags & RT_LINK_AVAIL != 0, s->snd_awnd);
	  fflush (stdout);
	}
#endif /* DEBUG_PERSIST */

      temp -= (int) s->max_seqsent;
      if (temp < 0)
	temp = 0;

      if (!(s->capabilities & CAP_CONGEST)) {
	s->snd_cwnd = s->snd_awnd;
	LOGCWND(s);
      }

      s->sndwin = min (s->snd_cwnd, temp);
    }

  /*
   * In merging the gateway back into the release branch, this
   * showed up.  Note that tp_RTTSLOP no longer exists.
   */
  if ((s->otimers[Persist]->set) && ((int) s->snd_awnd > s->maxseg))
    {
      /* Should that be a >= instead of a >?  XXX PDF KLS*/
#ifdef DEBUG_LOG
      logEventv(s, SCPS_log, "%s %s Would have left persist state TRY_WITHOUT.\n",
		stringNow(), printPorts(s));
#endif /* DEBUG_LOG */
    }
#ifdef TRY_WITHOUT
  /*
   * If we are currently in persist mode (persist timer is set)
   * and the resulting snd_awnd is greater than a maximum segment
   * in length, we transition out of persist.
   */
  if ((s->otimers[Persist]->set) && ((int) s->snd_awnd > s->maxseg))
    {
      /* Should that be a >= instead of a >? */
#ifdef DEBUG_LOG
      logEventv(s, SCPS_log, "%s %s Would have left persist state TRY_WITHOUT.\n",
		stringNow(), printPorts(s));
#endif /* DEBUG_LOG */

      /*
       * Clear the persist timer, toggle the links availability
       * flag and kick-start the retransmission timer.
       */
      s->persist_shift = 0;
      s->maxpersist_ctr = 0;
      clear_timer (s->otimers[Persist], 1);

      if (!(s->rt_route->flags & RT_LINK_AVAIL)) {
#ifdef GATEWAY_ROUTER
	    route_rt_avail (s->rt_route);
#endif /* GATEWAY_ROUTER */
      }

      s->rt_route->flags |= RT_LINK_AVAIL;
      mytime.tv_usec =
	max (((s->t_srtt >> (TP_RTT_SHIFT - 1)) + (tp_RTTSLOP << 2)),
	     s->RTOMIN);
      mytime.tv_usec = max (mytime.tv_usec, s->RTOMIN);
      mytime.tv_usec = min (mytime.tv_usec, s->RTOMAX);
#ifdef DEBUG_PERSIST
      printf ("%s %s Transitioning out of persist C\n",
#ifdef DEBUG_MEMORY
	      stringNow (), printPorts (s));
#else /* DEBUG_MEMORY */
	      "00:00:00.000000", "m(?) h(?)");
#endif /* DEBUG_PERSIST */
      if (s->otimers[Rexmit]->set)
	{
	  printf ("        And retransmit timer SET.\n");
	}
#endif /* DEBUG_PERSIST */
    if (!s->otimers[Rexmit]->expired) {
        set_timer (&mytime, s->otimers[Rexmit], 1);
     }
    }
  /* End of stuff I copied from above 10/14/98 --KS */
#endif /* TRY_WITHOUT */

  if (!(s->sockFlags & TF_RCVD_TSTMP) &&
      ((s->rtt) && SEQ_GT (flippedack, s->rtseq))
      && ((ts1) || (ts_val)))
    {
      temp1 = (ts1) ? (uint32_t) ((abs) (tp_now - ts1)) : 0;
      temp2 = (ts_val) ? (uint32_t) ((abs) (tp_now - ts_val)) : 0;

      /*
       * ts1 represents when the first packet was sent, and should
       * be used for RTO
       * ts_val represents when the LAST packet was sent, and is
       * used for Vegas throughput calculations
       */
      tp_xmit_timer (s, temp1, temp2);
      s->rtt = 0;
#ifdef DEBUG_TIMING
      logEventv(s, timing, TIMING_FORMAT,
		stringNow (),
		"!ts",
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
    }

#ifdef GATEWAY

 if (s->gateway_flags & GATEWAY_HAS_RUNT) {
    s->gateway_runt_ack_ctr++;
  }

  if (sys_memory.clust_in_use + 10 < sys_memory.fclist.max_size) {
    if ( (s->gateway_runt_ack_ctr >= 2) || (s->state > 4) ) {
      s->gateway_flags &= ~GATEWAY_HAS_RUNT;
      s->gateway_runt_ack_ctr = 0;
      s->gateway_runt_ctr= 0;
      tp_Flush (s);
    }
  }

#endif /* GATEWAY */

  if (sys_memory.clust_in_use + 10 < sys_memory.fclist.max_size) {
    if ((!(s->sockFlags & SOCK_NDELAY)) && (!(s->send_buff->snd_una))
        && (s->app_sbuff->size))
      {
        /* 
         * We've just gotten ACKed up, so we if had a tiny_gram outstanding,
         * we don't anymore; If we've got more outstanding data in
         * app_sbuff it's less than a full-segment's worth, so call 
         * tp_flush to push this tinygram out;
         * I'm uneasy about this since tp_Flush() calls tp_NewSend();
         */
        tp_Flush (s);  
      }
  }

#ifdef GATEWAY
#ifdef GATEWAY_DEBUG
  printf ("Calling move data from process ACK\n");
#endif /* GATEWAY_DEBUG */
  if ( (s) && (s->peer_socket) )
    {
      gateway_move_data (s->peer_socket, s);
    }
#endif /* GATEWAY */

  /* 
   * If we're all Acked up, clear the Rexmit timer that we reset 
   */
  if (flippedack == s->seqsent)
    {
      clear_timer (s->otimers[Rexmit], 1);
      if (s->snd_cwnd <= s->maxdata)
	{
	  s->snd_cwnd = s->maxdata;
	  /* s->snd_cwnd = max (s->snd_prevcwnd, s->maxdata); */
	  LOGCWND(s);
#ifdef DEBUG_LOG
	  logEventv(s, SCPS_log, "%s acked_up %lu %lu %lu %u %ld\n",
		    stringNow2 (),
		    flippedack,
		    s->snd_prevcwnd,
		    s->snd_ssthresh,
		    diff,
		    s->snd_cwnd);
#endif	/* DEBUG_LOG */
	}
    }
#ifdef DEBUG_XPLOT
  /* Plot a pink line to the right of and slightly above
   * the segment that
   * stops where the retransmission timer for that segment
   * would expire.
   */
  if ((s->otimers[Rexmit]->set)) {
    uint32_t yval = flippedack + ((tp_now%10)+1)*20;
    logEventv(s, xplot, "; RTO and SRTT Indicator\npink\nline %s %u %s %u\n",
	      stringNow2(),
	      yval,
	      stringNow3((double) mytime.tv_usec/1000000),
	      yval);
    logEventv(s, xplot, "rarrow %s %u\n",
	      stringNow3((double) mytime.tv_usec/1000000),
	      yval);
    logEventv(s, xplot, "dtick %s %u\n",
	      stringNow3((double) (s->t_srtt>>TP_RTT_SHIFT)/1000000),
	      yval);
  }
#endif /* DEBUG_XPLOT  */
  VERIFY_BUFFER_HOLES (s->send_buff);
  SCRUB_HOLES (s);
}

/*
 * Process the data in an incoming packet. 
 * Called from all states where incoming 
 * data can be received: 
 * established, fin-wait-1, fin-wait-2
 */

void
tp_ProcessData (tp_Socket * s, tp_Header * tp, byte * data, int len)
{
  int x;
  uint32_t uwe;
  word flags;
  byte *dp;
  struct mbuff *mbuffer;
  struct mbcluster *old_write_head;
  int old_write_off, temp_len;
  int ack_now = 0;
  uint32_t flippedseq;
  struct timeval mytime =
  {0, s->ACKDELAY};

  flags = tp->flags;
  /*
   * determine if there is any data we've already 
   * seen in this segment. If s->acknum (what we've 
   * acked is bigger than tp->seqnum (the starting 
   * sequence number in this segment), then we've 
   * seen some or all of the data before.  We don't 
   * want to give that data to the application again.
   */

  x = tp->th_off << 2;
  dp = (byte *) data;

  /*
   * If this segment had ANY data associated with it, 
   * valid or not, bump the delayed ack counter.  
   * The test being here makes sure we still ack out 
   * of sequence data (albeit delayed), but we don't 
   * ack acks.
   */
#define MAX_UNACKED_SEGS 2

  if ((len != 0) && (sys_memory.clust_in_use + 10 >= sys_memory.fclist.max_size)) {
     return; 
  }

  if ((len > 0) && (s->state != tp_StateSYNREC))
    {
      s->ack_delay++;
      s->unacked_segs++;
      if ((s->ack_freq == 1) ||
	  ((s->ack_freq == 2) && (s->unacked_segs >= MAX_UNACKED_SEGS)))
	ack_now = 1;
      else
	{
	  if (!(s->otimers[Del_Ack]->set))
	    {
	      mytime.tv_sec = 0;
	      mytime.tv_usec = s->ACKDELAY;
	      set_timer (&mytime, s->otimers[Del_Ack], 1);
	      s->sockFlags |= SOCK_DELACK;
	    }
	}
    }

  /* Establish the upper window edge */
  uwe = s->lastuwe;

  /*
   * If any data is to the right of the upper window edge, discard it
   */

  flippedseq = ntohl (tp->seqnum);
  if (SEQ_GT (flippedseq + len, uwe))
    {
      len = (uwe - flippedseq);
      if (len < 0)
	len = 0;
      flags &= ~tp_FlagFIN;
      flags &= ~tp_FlagEOR;
    }

  /*
   * When we move acknum forward, snack the guy at the new
   * acknum multiple times.
   */
  if (flippedseq == s->acknum)
    s->advance_hole = 0;

  if (flippedseq != s->acknum)
    {
      /* skip stuff if it's in the right place */

      if (flippedseq < uwe)
	{
	  /* is any of the packet lower than uwe? */

	  if (((s->state == tp_StateESTAB) &&
	       flippedseq < s->acknum))
	    {
	      /* is it a rexmit? */
	      dp += (s->acknum - flippedseq);
	      len -= (s->acknum - flippedseq);

	      if (s->ack_freq)
		{
#ifndef MPF
		  ack_now = 1;	/* let him know */
#endif /* MPF */
		}
	      else
		{
#ifndef MPF
		  s->sockFlags |= SOCK_DELACK;
#endif /* MPF */
		}
	    }
	  else
	    {
	      /* 
	       * It's not in sequence, it's in the 
	       * window, and at least some of it's 
	       * new... Enqueue an out of sequence segment 
	       */
	      if ((len > 0) || (flags & tp_FlagFIN))
		{
		  /*
		   * Don't call tp_OutSeq with packets which have already been acked.
		   * _DO_ call it if the packet is a FIN with 0 length.
		   * 
		   * This test really should go at the top of tp_OutSeq soon (10/12/98)
		   * --KS
		   */
		  if ((ntohl (tp->seqnum) + len > s->acknum) ||
		      ((flags & tp_FlagFIN) && (ntohl (tp->seqnum) ==
						s->acknum)))
		    {
		      if (tp_OutSeq (s, tp, x, dp, len) < 1)
			printf ("tp_OutSeq failed: ");
		    }

		  /* Always immediately ACK for an 
		   * out-of-sequence segment 
		   * if we are NOT doing massively 
		   * delayed ACKS
		   */

		  /* Eric was here 4/22/97 (was was not happy about it)
		   * This melts down in the case of burst errors;
		   * I know that is the intent (Ack *every* out_seq
		   * packet), but it causes a spike of ACK traffic!
		   * There needs to be a better way...
		   */
		  if (s->ack_freq)
		    ack_now = 1;
		  /* s->sockFlags |= SOCK_CANACK; */
		  else
		    s->sockFlags |= SOCK_CANACK;

		  if (((s->Out_Seq->last) &&
		       SEQ_GEQ ((s->Out_Seq->last->m_seq +
				 s->Out_Seq->last->m_plen),
				s->lastuwe)) ||
		      (flags & tp_FlagFIN))
		    {
		      s->SNACK1_Receive_Hole = s->acknum;
		      s->SNACK1_Flags |= SEND_SNACK1;
		      ack_now = 1;
		    }
		  len = 0;
		  flags &= ~tp_FlagFIN;
		}
	      if (ack_now)
		goto ACKNOW;
	      else
		return;
	    }			/* Else enqueue out of sequence segment */
	}			/* If any of packet is below uwe */
    }

  /* 
   * Place the data into the receive buffers cluster chain!    
   * Just like tp_Write, but backwards. First, put the header 
   * into an mbuff, then copy the data into a cluster. We'll   
   * worry about out of sequence stuff shortly.                
   */

  if (len > 0)
    {
      if ((mbuffer = alloc_mbuff (MT_HEADER)))
	{
	  mbuffer->m_seq = flippedseq;

	  /* Copy the TP header into the mbuff */
	  memcpy (mbuffer->m_pktdat, tp, x);
	  mbuffer->m_len = x;

	  /* Copy the data into the receive_buffer */

	  old_write_head = s->app_rbuff->write_head;
	  old_write_off = s->app_rbuff->write_off;
	  cb_cpdatin (s->app_rbuff, dp, len, 0, 0);

	  if (old_write_head == NULL)
	    {
	      /* 
	       * We entered cb_cpdatin w/o a write_head, and one
	       * was provided to us. Figure out where it was since
	       * we might have done a write > SMCLBYTES. write_off
	       * will always have started at 0 in this case.
	       */
	      if (!(old_write_head = s->app_rbuff->write_head))
		old_write_head = s->app_rbuff->last;
	      temp_len = len - s->app_rbuff->write_off;
	      while (temp_len > 0)
		{
		  old_write_head = old_write_head->c_prev;
		  temp_len -= SMCLBYTES;
		}
	    }

	  s->acknum += len;
	  LOGCWND(s);

	  mcput (mbuffer, old_write_head, old_write_off, len, 0);

	  if (tp->flags & tp_FlagEOR)
	    {
	      /* Build and insert the Record Boundary */
	      Process_EOR (s, mbuffer, 0);
	      tp->flags &= htons (~tp_FlagEOR);
	    }

	  /* Place the new segment into the receive queue */
	  enq_mbuff (mbuffer, s->receive_buff);

#ifndef GATEWAY
	  /* Wake up the receiver */

	  /*
	   * Make sure that the socket is
	   * on the list of readable sockets.
	   */

#ifdef GATEWAY_SELECT
	  ADD_READ (s);

	  if ((s->thread->status == Blocked) &&
	      (((s->read) &&
		(s->app_rbuff->size >= s->read))))
	    {
	      s->read = 0;
	      s->thread->status = Ready;
	      scheduler.num_runable++;
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

	  /*
	   * This is the proper place to check the 
	   * out-of-sequence queue for the next expected 
	   * segment. If it is what we're looking for, all 
	   * we need to do is increment the s->acknum, dequeue 
	   * it from Out_Seq and enqueue in s->receive_buff.
	   *
	   * This is a one-shot deal (no looping required) 
	   * since we have been coalescing the out-of-sequence 
	   * space as it builds.
	   */
#else /* GATEWAY */
	  if ( (s) && (s->peer_socket) )
	    {
	      gateway_move_data (s, s->peer_socket);
	    }

#endif /* GATEWAY */

	  if ((s->Out_Seq->start) &&
	      (s->Out_Seq->start->m_seq <= s->acknum))
	    {			/* Here */
#ifdef OPT_BETS
	      if (s->capabilities & CAP_BETS)
		{
		  /*
		   *  We've closed a hole, disable the BE_Recv timer if 
		   * it is running. Should probably add a check to see 
		   * whether or not BETS is allowed at all; then again, 
		   * this might be covered by the BETS timer itself...
		   */

		  if (s->otimers[BE_Recv]->set)
		    clear_timer (s->otimers[BE_Recv], 1);
		}
#endif /* OPT_BETS */

		/* TOP PART */
	      mbuffer = deq_mbuff (s->Out_Seq);

              /*
               * Set flags here in case the only thing on the out-of-sequence queue is
               * the FIN, in which case, mbuffer is the FIN and we want to close out
               * the connection below.  Note that the processing between here and where
               * we check for the FIN bit will not happen since it's looking for something
               * ELSE on the out-of-sequence queue.
               */
	      flags =
	        ((tp_Header *) (mbuffer->m_pktdat))->flags;

	      if (s->acknum == mbuffer->m_seq)
		{
		  s->acknum += mbuffer->m_plen;
		}
	      else
		{
		  if (s->acknum > mbuffer->m_seq)
		    {
		      uint32_t length_to_trim;
		      uint32_t amount_to_ack;
		      struct mbcluster *mbcluster;

		      length_to_trim = (s->acknum - mbuffer->m_seq);
		      amount_to_ack = mbuffer->m_plen - (s->acknum - mbuffer->m_seq);
		      mbuffer->m_plen -= length_to_trim;
		      mbuffer->m_ext.len -= length_to_trim;
		      mbuffer->m_seq += length_to_trim;
		      mbuffer->m_ext.offset += length_to_trim;
		      while (mbuffer->m_ext.offset >= SMCLBYTES)
			{
			  mbuffer->m_ext.offset -= SMCLBYTES;
			  mbcluster = (struct mbcluster *) mbuffer->m_ext.ext_buf;
			  mbuffer->m_ext.ext_buf = (caddr_t) mbcluster->c_next;
			  free_mclus (mbcluster);
			}
		      s->acknum += amount_to_ack;

	      LOGCWND(s);
		    }
		}

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

	      ack_now = 1;

#ifdef GATEWAY
#ifdef GATEWAY_DEBUG
	      printf ("Calling move data from process DATA\n");
#endif /* GATEWAY_DEBUG */
	      if ( (s) && (s->peer_socket) )
		gateway_move_data (s, s->peer_socket);
#endif /* GATEWAY */

	      /* 
	       * If the *next* outseq element is the FIN, we 
	       * must pull it off here.
	       */

	      if ((s->Out_Seq->start) &&
		  (s->acknum == s->Out_Seq->start->m_seq) &&
		  (((tp_Header *) (s->Out_Seq->start->m_pktdat))->flags & tp_FlagFIN))
		{
		  mbuffer = deq_mbuff (s->Out_Seq);

		  flags =
		    ((tp_Header *) (mbuffer->m_pktdat))->flags;
		  s->acknum += mbuffer->m_plen;
		  LOGCWND(s);

		  /* 
		   * Forget about diddling with the write-head, 
		   * This connection is about to close.
		   */

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

                  ack_now = 1;
		}
	    }
	}
      else
	{
	  len = 0;
	  flags &= ~tp_FlagFIN;
	}
    }
  s->rcvwin = s->app_rbuff->max_size - s->app_rbuff->size;

  if (flags & tp_FlagFIN)
    {
      x = s->state;

      /* Make sure that the socket is NOT blocked on a read */
#ifdef GATEWAY_SELECT
      if ((s->read) && (s->thread->status == Blocked))
	{
	  /* 
	   * Make sure the socket is on the
	   * list of the readable sockets
	   */
	  /* s->thread->read_socks |= (1 << s->sockid); */
	  ADD_READ (s);
	  s->read = 0;
	  s->thread->status = Ready;
	  scheduler.num_runable++;
	}
#else /* GATEWAY_SELECT */
      if ((scheduler.sockets[s->sockid].read) &&
	  (s->thread->status == Blocked))
	{
	  s->thread->read_socks |= (1 << s->sockid);
	  scheduler.sockets[s->sockid].read = 0;

	  s->thread->status = Ready;
	  scheduler.num_runable++;
	}
#endif /* GATEWAY_SELECT */

      switch (s->state)
	{
	case tp_StateESTAB:

	  /*
	   * note: skip state CLOSEWT by automatically closing
	   * conn
	   */

	  /*
	   * Check the segment for window violations here,
	   * trimming excess, and then copy the valid data into
	   * a cluster and stick the header in an mbuff until
	   * we decide that this is really unnecessary... After
	   * all, who else needs to look at the TP header?
	   */
	  /*
	   *  x = tp_StateLASTACKPEND;
	   *  
	   *  s->flags |= tp_FlagFIN;
	   *  if (mbuffer = alloc_mbuff (MT_HEADER))
	   *  {
	   *  (void) tp_BuildHdr (s, mbuffer, 0);
	   *  enq_mbuff (mbuffer, s->send_buff);
	   *  if (!(s->send_buff->send))
	   *  s->send_buff->send = s->send_buff->last;
	   *  }
	   *  tp_NewSend (s, NULL, false);
	   */

	  s->acknum++;
	  x = tp_StateCLOSEWT;
	  s->sockFlags |= SOCK_ACKNOW;
	  LOGCWND(s);

	  /*
	   *  If the socket is currently blocked on a read, we need to 
	   * unblock it,  as no more input will be coming over this 
	   * connection after we've processed his FIN 
	   */

#ifdef GATEWAY_SELECT
	  if ((s->thread->status == Blocked) &&
	      (s->read))
	    {
	      /*
	       * Make sure that this socket is
	       * on the list of readable sockets.
	       */
	      /* s->thread->read_socks |= (1 << s->sockid); */
	      ADD_READ (s);
	      s->thread->status = Ready;
	      scheduler.num_runable++;
	      s->read = 0;
	    }
#else /* GATEWAY_SELECT */
	  if ((s->thread->status == Blocked)
	      && (scheduler.sockets[s->sockid].read))
	    {
	      s->thread->read_socks |= (1 << s->sockid);
	      s->thread->status = Ready;
	      scheduler.num_runable++;
	      scheduler.sockets[s->sockid].read = 0;
	    }
#endif /* GATEWAY_SELECT */

	  /*
	   * If we sent the fin immediately, skip the Pending
	   * state
	   */
	  break;

	case tp_StateFINWT1PEND:
	  x = tp_StateFINWTDETOUR;
	  s->acknum++;
	  s->flags = tp_FlagACK;
	  s->sockFlags |= SOCK_ACKNOW;
	  break;

	case tp_StateFINWT1:
	  x = tp_StateCLOSING;
	  s->acknum++;
	  s->flags = tp_FlagACK;
	  s->sockFlags |= SOCK_ACKNOW;
	  break;

	case tp_StateFINWT2:
	  x = tp_StateTIMEWT;
	  s->send_buff->holes = 0x0; 
	  s->acknum++;
	  s->timeout = s->TWOMSLTIMEOUT;
	  mytime.tv_sec = s->TWOMSLTIMEOUT; 
	  mytime.tv_usec = 0;
	  set_timer (&mytime, s->otimers[TW], 1);
	  s->flags = tp_FlagACK;
	  s->sockFlags |= SOCK_ACKNOW;
	  /* build a pure ack in an mbuffer and send it */
	  clear_timer (s->otimers[Del_Ack], 1);
	  clear_timer (s->otimers[Rexmit], 1);
	  break;

	case tp_StateWANTTOCLOSE:
	  x = tp_StateWANTTOLAST;
	  s->acknum++;
	  s->flags = tp_FlagACK;
	  s->sockFlags |= SOCK_ACKNOW;
	  break;
	}
      s->state_prev = s->state;
      s->state = x;
#ifdef GATEWAY
      if (s->peer_socket)
	{
	  if ((s->peer_socket->state >= tp_StateFINWT1))
	    {
	    }
	  else
	    {
	      if ((!(s->app_rbuff->size)) && (!(s->Out_Seq->start)))
		{
		  tp_Close (s->peer_socket->sockid);
		}
	      else
		{
#define GATEWAY_DELAY_FIN
#ifdef GATEWAY_DELAY_FIN
		  s->peer_socket->gateway_flags |= GATEWAY_SEND_FIN;
#else /* GATEWAY_DELAY_FIN */
		  tp_Close (s->peer_socket->sockid);
#endif /* GATEWAY_DELAY_FIN */
		}
	    }
	}
#endif /* GATEWAY */
      PRINT_STATE (x, s);
    }
  LOGCWND(s);
  /*
   * Setting a flag here and checking it when we check the timers
   * accomplishes the RFC1122 requirement of not sending any ACKS until
   * the receive queue has been exhausted (so as not to send a bunch of
   * acks in a row.  We know that the input queue has been exhausted
   * when we're checking the timers, because we only check them when a
   * ll_nbreceive  returns NIL.
   */
  if ((ack_now) || ((s->ack_delay) && (s->state < tp_StateCLOSING)))
    {

    ACKNOW:
      if (ack_now)
	{
	  s->sockFlags |= SOCK_ACKNOW;
	  /* send an immediate ack */
	  if ((mbuffer = tp_BuildHdr (s, NULL, 0)))
	    {
	      s->flags = tp_FlagACK;
#ifdef GATEWAY
	      if ((s) &&
		  (s->gateway_flags & GATEWAY_PEER_WIN_NOT_OPENED))
		{
#ifdef GATEWAY_DEBUG
		  printf ("In tp_process.c must ACKNOW\n");
#endif /* GATEWAY_DEBUG */
		}
#endif /* GATEWAY */
	      if (tp_NewSend (s, mbuffer, false) > 0)
		{
		  s->unacked_segs = 0;
		  s->lastuwe = s->acknum + s->rcvwin;
		  s->lastack = s->acknum;
		  s->ack_delay = 0;
		  clear_timer (s->otimers[Del_Ack], 1);
		  s->sockFlags &= ~(SOCK_ACKNOW | SOCK_DELACK | SOCK_CANACK);
		  s->ack_delay = 0;
		}
	      free_mbuff (mbuffer);
	    }
	}
    }
  LOGCWND(s);
}

void
Process_EOR (tp_Socket * s, struct mbuff *mbuffer, int Out_Seq)
{
  struct record_boundary *Rec_Bound, *temp_RB;

  mbuffer->m_flags |= M_EOR;
  Rec_Bound =
    (struct record_boundary *) malloc (sizeof (struct record_boundary));
  Rec_Bound->seq_num = mbuffer->m_seq;
  Rec_Bound->next = Rec_Bound->prev = NULL;

  if (s->app_rbuff->RB)
    {
      temp_RB = s->app_rbuff->RB;
      if (temp_RB->seq_num > Rec_Bound->seq_num)
	{
	  Rec_Bound->offset = s->app_rbuff->RB->offset -
	    (s->app_rbuff->RB->seq_num - Rec_Bound->seq_num);
	  Rec_Bound->next = s->app_rbuff->RB;
	  s->app_rbuff->RB->prev = Rec_Bound;
	  s->app_rbuff->RB = Rec_Bound;

	}
      else
	{
	  for (;;)
	    {
	      if (temp_RB->next)
		{
		  if (temp_RB->next->seq_num > Rec_Bound->seq_num)
		    {
		      Rec_Bound->next = temp_RB->next;
		      Rec_Bound->prev = temp_RB;
		      Rec_Bound->next->prev = Rec_Bound;
		      temp_RB->next = Rec_Bound;
		      Rec_Bound->offset = Rec_Bound->seq_num -
			temp_RB->seq_num;
		      Rec_Bound->next->offset -= Rec_Bound->offset;
		      break;
		    }
		  temp_RB = temp_RB->next;
		}
	      else
		{
		  temp_RB->next = Rec_Bound;
		  Rec_Bound->offset =
		    Rec_Bound->seq_num - temp_RB->seq_num;
		  Rec_Bound->prev = temp_RB;
		  break;
		}
	    }
	}
    }
  else
    {
      /*
       * This is the first/only Record Boundary on the list, so we
       * need to calculate the offset. If we are in sequence, then
       * the offset is exactly equal to the size of the buffer -
       * Otherwise it gets even uglier!
       */
      if (!(Out_Seq))
	Rec_Bound->offset = s->app_rbuff->size;
      else if (!(s->receive_buff->last))
	Rec_Bound->offset = Rec_Bound->seq_num - s->acknum;
      /*
       * The offset will be equal to the size (all in-sequence
       * data) plus the difference in sequence numbers of the
       * record-boundary and the last octet of the in-sequence
       * data...
       */
      else
	Rec_Bound->offset = Rec_Bound->seq_num -
	  (s->receive_buff->last->m_seq + s->receive_buff->last->m_len);
      s->app_rbuff->RB = Rec_Bound;
    }
}

