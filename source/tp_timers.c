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
#include <stdio.h>
#include "tp_debug.h"

#ifdef SP
#include "scps_sp.h"
int
  sp_trequest (tp_Socket * s, route * nroute, int *bytes_sent,
	       struct mbuff *m, int th_off);
#endif /* SP */

int
  scps_np_trequest (tp_Socket * s, scps_ts * ts, route * nproute, uint32_t
		    length, struct mbuff *m, u_char th_off);
#include "scps_ip.h"

#ifdef Sparc
#ifndef SOLARIS
extern int gettimeofday (struct timeval *tp, struct timezone *tzp);
#endif /* SOLARIS */
#endif /* Sparc */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_timers.c,v $ -- $Revision: 1.57 $\n";
#endif /* NO_CVS_IDENTIFY */

extern tp_Socket *tp_allsocs;
extern struct _timer rate_timer;
extern uint32_t tp_now;
extern procref timer_fn[];
extern route *route_list_head;
extern int delayed_requested;

extern int persist_time_outs [TP_MAX_PERSIST_SHIFT];


extern int TS_ARRAY_LEN;

extern struct _times
  {
    struct timeval t;
    uint32_t rtt;
  }
ts_array[1];

extern int ts_index;

#ifdef FAIRER_GATEWAY
extern int rate_condition;
#endif /* FAIRER_GATEWAY */

extern int reset_rate_condition;
/*
 * Walk through all the timers for all the sockets. This may not scale well
 * for ground systems, but it's better for onboard systems that don't have
 * many sockets open at one time
 */

void
tp_Timers ()
{
  tp_Socket *s;
  struct timeval mytime;
  route *r;

  tp_now = clock_ValueRough ();	/* for UDP when no TP socks are open */
  mytime.tv_sec = 0;

  for (s = tp_allsocs; s != NIL; s = s->next)
    {

      if (s && s->rt_route && (s->rt_route->flags & RT_LINK_TRANSITION))
	{
	  if (s->rt_route->flags & RT_LINK_AVAIL)
	    {
              s->persist_shift = 0;
	      s->maxpersist_ctr = 0;
	      clear_timer (s->otimers[Persist], 1);

      	      /* When we use the rttvar in calculating the rxtcur, we need to make
	       * sure the var is at least 0.5 seconds.  Rational is the following.
	       * with implementation of TCP, the unit of variance is 1/4 of a tick
	       * and a tick is 0.5 seconds.  The smallest value of the variable
	       * is 0.125 seconds.  Therefore when you multiply it by 4, the minimum
	       * value of the variance term is 500000 microseconds.  - PDF 
	       */

	      mytime.tv_usec = ((s->t_srtt>>TP_RTT_SHIFT) +
				max (500000, ((s->t_rttvar>>TP_RTTVAR_SHIFT)<< 2)));
	      mytime.tv_usec = max (mytime.tv_usec, s->RTOMIN);
	      mytime.tv_usec = min (mytime.tv_usec, s->RTOMAX);
              if (!s->otimers[Rexmit]->expired) {
	         set_timer (&mytime, s->otimers[Rexmit], 1);
   	      }

	      s->timeout = s->TIMEOUT;

	      s->sockFlags |= SOCK_DELACK;

#ifndef GLOBAL_VEGAS
#else /* GLOBAL_VEGAS */
#endif /* GLOBAL_VEGAS */
#ifndef GLOBAL_VEGAS
	      s->rttbest = 0;
#else /* GLOBAL_VEGAS */
	      s->rt_route-> rttbest = 0;
#endif /* GLOBAL_VEGAS */
	    }
	  else if ( !(s->otimers[Rexmit]->set) && !(s->otimers[Rexmit]->expired))
	    {
	      /* Transition into persist state */
	      mytime.tv_sec = 0;
	      mytime.tv_usec = s->PERSISTTIME;
	      set_timer (&mytime, s->otimers[Persist], 1);
	      clear_timer (s->otimers[Rexmit], 1);
	      s->timeout = s->LONGTIMEOUT;
	    }
	}
      if (s->send_buff->send)
	tp_NewSend (s, NULL, (BOOL) false);
    }

  for (r = route_list_head; r != NIL; r = r->next)
    {
      /*
       * At this point, all tp sockets have seen the link
       * transition
       */
      if (r->flags & RT_LINK_TRANSITION)
	r->flags &= ~RT_LINK_TRANSITION;
    }
}

void
tp_CancelTimers (tp_Socket * s)
{
  int t;
  for (t = 0; t < TIMER_COUNT; t++)
    {
      s->timers[t] = 0;
      clear_timer (s->otimers[t], 1);
    }
}

void
tp_TFDelayedAck (tp_Socket * s)
{
  if (s->sockFlags & SOCK_DELACK)
    {
      s->sockFlags &= ~SOCK_DELACK;
      s->sockFlags |= SOCK_ACKNOW;
      delayed_requested++;
      s->unacked_segs = 0;
    }
}

/*
 * Retransmitter - called periodically to perform tp retransmissions
 */
extern int tp_mssmin;

void
tp_TFRetransmit (tp_Socket * s)
{
  BOOL x;
  struct timeval mytime;
  /* struct _hole_element *temp; */

  int failed = 0;
  uint32_t ts1 = 0;
  x = false;

  mytime.tv_sec = 0;

  tp_now = clock_ValueRough ();
  if ((!(s->send_buff)) || (s->state == tp_StateFINWT2))
    {
      return;
    }

  if (s->state == tp_StateCLOSED)
    return;

  if (s->send_buff->snd_una)
    {
#ifdef RTO_ROLLBACK
      /* This is really experimental.  Move snd_next back down to the max of snd_una
       * and high_hole on rto.  */
       if ( (temp = find_hole(s->send_buff->holes, s->high_hole_seq)) ) {
	s->send_buff->send = temp->hole_start;
       } else {
        s->send_buff->send = s->send_buff->snd_una;
       }
       s->seqsent = s->send_buff->send->m_seq;
       printf("RTO rollback\n");
       /* End of experiment. */
#endif /* RTO_ROLLBACK */

      /*  This portion of code rolls back ->send back to ->snd_una
       *  on an RTO -  Other portions of the RI had to be modified to
       *  complete the functionality. -- PDF
       */

#ifdef DEBUG_XPLOT
	logEventv(s, xplot, "red\natext %s %lu\n", stringNow2 (), s->send_buff->snd_una->m_seq);
	logEventv(s, xplot, "RTO\n");
#endif /* DEBUG_XPLOT */
      s->send_buff->send = s->send_buff->snd_una;
      s->seqsent = s->send_buff->send->m_seq + s->send_buff->send->m_ext.len;
      s->snduna = s->send_buff->send->m_seq;
      s->funct_flags = s->funct_flags & (~FUNCT_HIGH_SEQ);
      s->funct_flags = s->funct_flags & (~FUNCT_HIGH_CONGESTION_SEQ);
      s->high_seq = 0;
      s->high_congestion_seq = 0;
      s->snd_cwnd = s->maxseg;

#ifdef CWND_INFLATE_THROTTLE
      s->pkts_ack_in_epoch = 0;
#endif /* CWND_INFLATE_THROTTLE */

      if (tp_NewSend (s, s->send_buff->snd_una, (BOOL) true))
	{
	  /* It's now a retranmission, we can't time this */
	  if (s->send_buff->snd_una->m_ts)
	    {
	      s->send_buff->snd_una->m_ts = tp_now;
	      s->rtt = 0;
#ifdef DEBUG_TIMING
	      logEventv(s, timing, TIMING_FORMAT,
			stringNow (),
			"RTO",
			(uint32_t) 0,
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
	  if (!s->vegas_ack_check)
	    s->vegas_ack_check = 0;	/* 2; */

	  x = true;
	  s->send_buff->snd_una->m_rt
	    = tp_now + s->t_rxtcur + (s->t_rttvar << 2);

	  /*
	   * The congestion stuff should go BEFORE the
	   * retransmission!
	   */
#ifdef CONGEST
	  if (s->capabilities & CAP_CONGEST)
	    {
	      if (s->cong_algorithm == VJ_CONGESTION_CONTROL)
		{
		  /*
		   * We had a retransmission timeout,
		   * so knock down ssthresh and reenter
		   * slow-start
		   */

#ifdef DEBUG_XPLOT
	logEventv(s, xplot, "red\natext %s %lu\n", stringNow2 (), s->send_buff->snd_una->m_seq);
	logEventv(s, xplot, "  XXXXX\n");
#endif /* DEBUG_XPLOT */
		 /* PDF on an RTO set snd_ssthresh to the max of half the congestion window
                    snd_prevcwnd (for VJ) and 2 segments */
		  s->snd_ssthresh = max((s->snd_prevcwnd >> 1), (s->maxdata << 1)); 
		  s->snd_cwnd = 0;	/* Will be reloaded on ack */
		  s->snd_prevcwnd = s->maxdata;
#ifdef DEBUG_LOG
		  logEventv(s, SCPS_log, "%s retrans1 %lu %lu %lu %lu %lu\n",
			    stringNow2 (),
			    s->snduna == 0 ? s->initial_seqnum : s->snduna,
			    s->snd_prevcwnd,
			    s->snd_ssthresh,
			    (int32_t) 0 /* diff placeholder */ ,
			    s->snd_cwnd);
#endif	/* DEBUG_LOG */
		}
	      else
		{		/* VEGAS (since we're inside CAP_CONGEST) */
		  /*
		   * If it was a fast retransmit, we
		   * should consider congestion
		   * avoidance, but probably not slow
		   * start  - with Vegas, we're there
		   */
		  if (s->sockFlags & TF_VEGAS_FAST_REXMIT)
		    {
		      s->sockFlags &= ~TF_VEGAS_FAST_REXMIT;
		      s->snd_cwnd = max (s->maxdata, (s->snd_cwnd >> 1));
		      LOGCWND(s);
#ifdef DEBUG_LOG
		      logEventv(s, SCPS_log, "%s retrans2 %lu %lu %lu %lu %lu\n",
				stringNow2 (),
				s->snduna == 0 ? s->initial_seqnum : s->snduna,
				s->snd_prevcwnd,
				s->snd_ssthresh,
				(int32_t) 0 /* diff placeholder */ ,
				s->snd_cwnd);
#endif	/* DEBUG_LOG */
		      if ((int) s->snd_cwnd <= (int) s->maxdata)
			{
			  s->sockFlags &= ~TF_CC_LINEAR;
			  /*
			   * hit bottom - go
			   * exponential
			   */
			  /* I don't think we should give ourselves this cwnd. --KS
			   * Let the ack start us up again.
			   */
#ifdef OLD_CODE
			  s->snd_cwnd = s->maxdata;
#endif /* OLD_CODE */
			  LOGCWND(s);
#ifdef DEBUG_LOG
			  logEventv(s, SCPS_log, 
				    "%s vegas_bottom %lu %lu %lu %lu %lu\n",
				    stringNow2 (),
				    s->snduna == 0 ? s->initial_seqnum : s->snduna,
				    s->snd_prevcwnd,
				    s->snd_ssthresh,
				    (int32_t) 0 /* diff placeholder */ ,
				    s->snd_cwnd);
#endif	/* DEBUG_LOG */
			}
		    }
		  else
		    {
		      /* Vegas timeout. */
		      if (s->rt_route->flags & (RT_CONGESTED |
					     RT_ASSUME_CONGEST))
			{
			  s->snd_ssthresh = max (s->maxdata << 1,
						 s->snd_prevcwnd >> 1);
			  s->snd_prevcwnd = s->maxdata;
			  /* I don't think we should give ourselves this cwnd. --KS
			   * Let the ack start us up again.
			   */
			  s->snd_cwnd = 0;
			  LOGCWND(s);
#ifdef DEBUG_LOG
			  logEventv(s, SCPS_log, 
				    "%s vegas_timeout %lu %lu %lu %lu %lu\n",
				    stringNow2 (),
				    s->snduna == 0 ? s->initial_seqnum : s->snduna,
				    s->snd_prevcwnd,
				    s->snd_ssthresh,
				    (int32_t) 0 /* diff placeholder */ ,
				    s->snd_cwnd);
#endif	/* DEBUG_LOG */

			  s->sockFlags &= ~TF_CC_LINEAR;	/* hit bottom-go exponential */

			}
#ifdef DYNAMIC_MSS
		      else if ((s->timeout < s->TIMEOUT) &&
			       (s->rt_route->flags &
				(RT_CORRUPTED | RT_ASSUME_CORRUPT)))
			{
			  /*
			   * Reduce the maximum
			   * segment size
			   * Increase it when
			   * we toss rttbest
			   */
			  s->maxseg = (s->maxseg - (s->maxseg >> 3)) & 0xfffe;
			  if (s->maxseg < tp_mssmin)
			    s->maxseg = tp_mssmin;
			  s->sndwin =
			    max (min (s->snd_cwnd, s->snd_awnd), s->maxdata);
#ifdef DEBUG_LOG
			  logEventv(s, SCPS_log, 
				    "%s vegas_timeout %lu %lu %lu %lu %lu\n",
				    stringNow2 (),
				    s->snduna == 0 ? s->initial_seqnum : s->snduna,
				    s->snd_prevcwnd,
				    s->snd_ssthresh,
				    0 /* diff placeholder */ ,
				    s->snd_cwnd);
#endif	/* DEBUG_LOG */
			}
#endif /* DYNAMIC_MSS */
		    }
		}
	      /* Abort fast retransmit */
	      if (s->funct_flags & FUNCT_HIGH_SEQ)
		{
#ifdef DEBUG_PRINT
		  printf
		    ("%s RTO out of FR, snd_cwnd(%lu) relative snduna(%lu)\n",
		     stringNow (), s->snd_cwnd,
		     s->snduna - s->initial_seqnum);
		  fflush (stdout);
#endif	/* DEBUG_PRINT */
#ifdef DEBUG_XPLOT
		  logEventv(s, xplot, "red\natext %s %lu\n", stringNow2 (), s->high_seq);
		  logEventv(s, xplot, "!RTO\nline %s %lu %s %lu\n",
			    stringNow2 (), s->snduna, stringNow2 (), s->high_seq);
#endif	/* DEBUG_XPLOT */
		  s->high_seq = 0;
                  s->funct_flags = s->funct_flags & (~FUNCT_HIGH_SEQ);

#ifndef CWND_INFLATE_THROTTLE
       	          s->pkts_ack_in_epoch = 0;
#endif /* CWND_INFLATE_THROTTLE */

		}
              s->funct_flags = s->funct_flags & (~FUNCT_HIGH_CONGESTION_SEQ);
	      s->high_congestion_seq = 0;
	    }
#endif /* CONGEST */
	}
      else
	failed = 1;
    } else {
	if (((int) s->snd_cwnd) < s->maxdata) {
                s->snd_prevcwnd = s->snd_cwnd = s->maxdata;
          if (!(s->otimers[Rexmit]->set))
            {
              s->t_rxtshift++;
              if (s->t_rxtshift > TP_MAXRXTSHIFT)
                s->t_rxtshift = TP_MAXRXTSHIFT;
              mytime.tv_usec =((s->t_srtt>>TP_RTT_SHIFT) +
                               max (500000,((s->t_rttvar>>TP_RTTVAR_SHIFT) << 2)));
              mytime.tv_usec = max (s->RTOMIN, mytime.tv_usec) << s->t_rxtshift;         /* Scale the rtt */
              mytime.tv_usec = min (mytime.tv_usec, s->RTOMAX);
              if (!s->otimers[Rexmit]->expired) {
                 set_timer (&mytime, s->otimers[Rexmit], 1);
	      }
            }
        }

    }

  if ((x == true) || (s->state > tp_StateLASTACKPEND) ||
      (s->state == tp_StateLISTEN))
    {
      s->timeout--;
    }
  if (s->timeout <= 0)
    {
      if (s->state == tp_StateTIMEWT)
	{
	  s->state_prev = 0;
	  s->state = tp_StateCLOSED;
#ifdef GATEWAY
	  {
            if ( (s->peer_socket) && (s->peer_socket->peer_socket == s) ) {
	       tp_Abort (s->peer_socket->sockid);
            }
	  }
#endif /* GATEWAY */
	  PRINT_STATE (s->state, s);
	  SET_ERR (SCPS_ENOTCONN);
	  tp_Unthread (s);
          return;
	}
#ifdef OPT_BETS
      else if (((s->BETS.Flags & BF_BETS_OK) == BF_BETS_OK) &&
	       (s->send_buff->snd_una) && (s->send_buff->snd_una->m_next))
	{
	  /*
	   * Give up on this segment, just advance the snd_una
	   * and move on
	   */
	  s->BETS.Flags |= BF_BETS_SEND;

	  /*
	   * This currently ignorant implementation can just
	   * report the first n holes; This is fine for right
	   * now, but it needs to be fixed so that it treats
	   * the buffer as a circular queue of the n most
	   * recent holes. It is up to the application to query
	   * the state of holes in the case of wrap-around.
	   * This is a trade-off between the application and
	   * the amount of socket space to be allocated to
	   * this.
	   */
	  if (s->BETS.num_send_holes < s->BETS.max_send_holes)
	    {
	      if (s->snduna ==
		  (s->BETS.Send_Holes[(s->BETS.num_send_holes - 1)].Finish +
		   1))
		{		/* Grow the most recent
				 * hole */
		  s->BETS.Send_Holes[s->BETS.num_send_holes - 1].Finish
		    += s->send_buff->snd_una->m_plen;
		}
	      else
		{
		  s->BETS.Send_Holes[s->BETS.num_send_holes].Start =
		    s->BETS.Send_Holes[s->BETS.num_send_holes].Finish = s->snduna;
		  s->BETS.Send_Holes[s->BETS.num_send_holes].Finish +=
		    (s->send_buff->snd_una->m_plen - 1);
		  s->BETS.num_send_holes++;
		}
	    }
	  s->snduna += s->send_buff->snd_una->m_plen;
	  /*
	   * We need to think about doing something to update
	   * s->snd_awnd
	   */
	  s->lastuwein += s->send_buff->snd_una->m_plen;
	  s->snd_awnd += s->send_buff->snd_una->m_plen;

	  mb_trim (s->send_buff, (s->snduna) - 1, &ts1, (uint32_t *) NULL);
	  if ((((tp_Socket *)
		scheduler.sockets[s->sockid].ptr)->thread->status == Blocked)
	      && (scheduler.sockets[s->sockid].write) &&
	      ((s->send_buff->max_size - s->send_buff->b_size) >=
	       scheduler.sockets[s->sockid].write))
	    {
	      ((tp_Socket *)
	       scheduler.sockets[s->sockid].ptr)->thread->status = Ready;
	      scheduler.sockets[s->sockid].write = 0;
	    }
	  s->timeout = s->TIMEOUT;	/* should be route
					 * specific */

	  s->dup_ack_cnt = 0;
	  s->BETS.Flags &= ~BF_BETS_SEND;
	  return;
	}
      else if ((s->BETS.Flags & BF_BETS_OK) == BF_BETS_OK)
	{
	  /* If this is a FIN, we'd better deal with it... */
	  return;		/* Do a newsend? */
	}
#endif /* OPT_BETS */
      else
	{
#ifdef GATEWAY
	  {
            if ( (s->peer_socket) && (s->peer_socket->peer_socket == s) ) {
	       tp_Abort (s->peer_socket->sockid);
            }
	  }
#endif /* GATEWAY */
	  SET_ERR (SCPS_ETIMEDOUT);
	  tp_Abort (s->sockid);
	  return;
	}
    }
  if (s->send_buff->snd_una)
    {
      /*
       * If you don't reset the retransmission timer then it is possible to get
       * into a situation where you have outstanding data to be retransmitted
       * and the retransmission timer is the ONLY thing that's going to kick it
       * out (like at the end of a file e.g.).
       * We're testing this without the && (!failed) condition --KS  10/4/98
       */
/*      if ((s->state != tp_StateFINWT2) && (!failed)) */
      if (s->state != tp_StateFINWT2)
	/*
	 * if ((s->state != tp_StateFINWT2) && (!failed)) PDF
	 * changed this.  Retrofitting corrections back to
	 * 1.1.4
	 */
	{
	  if ((!(s->otimers[Rexmit]->set)) && (!(s->otimers[Rexmit]->expired)))
	    {
	      s->t_rxtshift++;
	      if (s->t_rxtshift > TP_MAXRXTSHIFT)
		s->t_rxtshift = TP_MAXRXTSHIFT;
	      mytime.tv_usec =((s->t_srtt>>TP_RTT_SHIFT) +
			       max (500000,((s->t_rttvar>>TP_RTTVAR_SHIFT) << 2)));
	      mytime.tv_usec = max (s->RTOMIN, mytime.tv_usec) << s->t_rxtshift;		/* Scale the rtt */
	      mytime.tv_usec = min (mytime.tv_usec, s->RTOMAX);
#ifdef DEBUG_PRINT
	      printf ("%s  RTO - rxtshift = %ld\n", stringNow (), s->t_rxtshift);
	      printf ("    Before shift tv_sec(%lu), tv_usec(%lu)\n",
		      mytime.tv_sec, mytime.tv_usec);
	      fflush (stdout);
#endif	/* DEBUG_PRINT */
#ifdef DEBUG_PRINT
	      printf ("RTO:    After shift(%ld) tv_sec(%lu), tv_usec(%lu)\n",
		      s->t_rxtshift,
		      mytime.tv_sec, mytime.tv_usec);
	      fflush (stdout);
#endif /* DEBUG_PRINT */

	      set_timer (&mytime, s->otimers[Rexmit], 1);
#ifdef DEBUG_XPLOT
	      /* Plot a pink line to the right of and slightly above
	       * the segment that
	       * stops where the retransmission timer for that segment
	       * would expire.
	       */
	      if ((s->otimers[Rexmit]->set)) {
		logEventv(s, xplot, "pink\nline %s %u %s %u\n",
			  stringNow2(),
			  s->send_buff->snd_una->m_seq + 15,
			  stringNow3((double) mytime.tv_usec/1000000),
			  s->send_buff->snd_una->m_seq + 15);
		logEventv(s, xplot, "rarrow %s %u\n",
			  stringNow2(),
			  s->send_buff->snd_una->m_seq+15);
		logEventv(s, xplot, "larrow %s %u\n",
			  stringNow3((double) mytime.tv_usec/1000000),
			  s->send_buff->snd_una->m_seq+15);
	      }
#endif /* DEBUG_XPLOT  */
	    }
	}
    }

/*
 * This feature RTO_TO_PESIST_CTR is specified in the rfile. This value
 * refers to the Nth time the RTO timer will fire for a particular packet
 * requiring retransmission.  Essentially, instead of the Nth RTO timer
 * resulting in another retransmission of lost packets, the link will be
 * considered unavailable and perist mode will be entered.
 */
    if ((s->otimers[Rexmit]->set)) {
	if (s->RTO_TO_PERSIST_CTR && ((s->TIMEOUT - s->timeout) >= s->RTO_TO_PERSIST_CTR)) {
        	struct timeval persist_time;

		clear_timer (s->otimers[Rexmit],1);
     		persist_time.tv_sec = 0;
     		persist_time.tv_usec = mytime.tv_usec;
                set_timer (&persist_time, s->otimers[Persist], 1);
		s->rt_route->flags &= ~(RT_LINK_AVAIL);
   	}
    }
		
}

/*
 * Find a convenient segment, copy its headers and 
 * one octet of its data to form a probe segment and 
 * send it.
 *
 * We make sure that snd_una points to (or before) the original
 * segment so that if the probe is acknowledged, mb_trim will
 * snip it off correctly.
 *
 * Remember to set s->seqsent correctly!
 */

void
tp_TFPersist (tp_Socket * s)
{
  struct mbuff *buf, *mbuffer;
  struct timeval mytime;
  word th_len;
  tp_Header *th;
  uint32_t bytes_sent = 0;
  struct _hole_element *hole = 0x0;
  uint32_t flippedack;
  int diff;
  int rc;


/*
  if (!(s->send_buff->send)) {
      clear_timer (s->otimers[Rexmit], 1);
       s->persist_shift = 0;
       s->maxpersist_ctr = 0;
       return;
  }

*/

  if ( (s->otimers[Rexmit]->set) || (s->otimers[Rexmit]->expired)) {
	return;
  }

  if ((sys_memory.clust_in_use + 10 >= sys_memory.fclist.max_size) ||
      (!(s->send_buff->send))) {
     mytime.tv_sec = 0;
     if (s->persist_shift == TP_MAX_PERSIST_SHIFT) {
         s->persist_shift = TP_MAX_PERSIST_SHIFT - 1;
     }   
      
     if (s->rt_route->flags & RT_LINK_AVAIL) {
     	mytime.tv_sec = 0;
     	mytime.tv_usec = persist_time_outs [s->persist_shift] * 1000 * 1000; 
        mytime.tv_usec = min (mytime.tv_usec, s->RTOPERSIST_MAX);
     } else {
     	mytime.tv_sec = 1;
     	mytime.tv_usec = 0;
     	mytime.tv_sec = 0;
     	mytime.tv_usec = persist_time_outs [s->persist_shift] * 1000 * 1000; 
        mytime.tv_usec = min (mytime.tv_usec, s->RTOPERSIST_MAX);
     }

     set_timer (&mytime, s->otimers[Persist], 1);
     clear_timer (s->otimers[Rexmit], 1);
     s->timeout = s->LONGTIMEOUT;

     if (!(s->send_buff->send)) {
         clear_timer (s->otimers[Rexmit], 1);
         clear_timer (s->otimers[Persist], 1);
         s->rt_route->flags |= RT_LINK_AVAIL;
     }

     return;
  }

  if ((s->state == tp_StateFINWT2) || (s->state == tp_StateLASTACK) ||
      (s->state == tp_StateTIMEWT) || (s->state == tp_StateCLOSED))
    {
      return;
    }

  flippedack = s->lastuwein - s->snd_awnd;
  diff = flippedack - s->snduna;

  /* find a segment */
  if (s->send_buff->snd_una)
    {
      buf = s->send_buff->snd_una;
#ifdef DEBUG_PERSIST
      printf ("%s %s Persist grabbed buffer (%p) from send_buffer->snd_una\n",
	      stringNow (), printPorts (s), buf);
#endif /* DEBUG_PERSIST */
    }
  else
    {
      buf = tp_next_to_send (s, &hole);
#ifdef DEBUG_PERSIST
      printf ("%s %s Persist grabbed buffer (%p) from send_buffer->send\n",
	      stringNow (), printPorts (s), buf);
#endif /* DEBUG_PERSIST */
    }

  if ((buf) && (buf->m_ext.len))
    {
      /* OK, this segment has data, use it */

      mbuffer = alloc_mbuff (MT_HEADER);

      copy_mbuff (mbuffer, buf);
      th = (tp_Header *) (mbuffer->m_pktdat + s->th_off);
      th_len = th->th_off;
      th->seqnum = htonl (buf->m_seq);

      /* Stuff in a single byte of data after the transport header */
      memcpy (((mbuffer->m_pktdat + s->th_off) + (th_len << 2)),
	      (buf->m_ext.ext_buf + buf->m_ext.offset), 1);
      mbuffer->m_ext.ext_buf = 0x0;
      mbuffer->m_ext.len = 0x0;
      mbuffer->m_len += 1;

#ifdef DEBUG_PERSIST
      s->display_now |= 0x04;
      printf ("%s %s %s %d Shipping probe with mbuffer->m_plen(%d)\n",
	      stringNow (), printPorts (s), __FILE__, __LINE__, mbuffer->m_plen);
#endif /* DEBUG_PERSIST */
      if ((mbuffer)
	  || ((s->sockFlags & (TF_RCVD_TSTMP | TF_REQ_TSTMP)) ==
	      (TF_RCVD_TSTMP | TF_REQ_TSTMP)))
	{
	  /* update window and ack fields */
	  tp_WinAck (s, th);

#ifdef OPT_TSTMP
	  if (s->capabilities & CAP_TIMESTAMP)
	    {
	      if ((th_len > 22) &&
		  (((u_char *) th)[22] == TPOPT_TIMESTAMP))
		{
		  uint32_t *lp;

		  lp = (uint32_t *) (((u_char *) th) + 24);
		  *lp++ = htonl (tp_now);
		  *lp = htonl (s->ts_recent);
		}
	    }
#endif /* OPT_TSTMP */
	}

      s->ph.nl_head.ipv4.length = htons ((th_len << 2) + 1);
      th->checksum = 0;
      /* Make sure the checksum includes the single byte of data */
      s->ph.nl_head.ipv4.checksum = checksum ((word *) th, ((th_len << 2) + 1));
      th->checksum = ~checksum ((word *) & (s->ph), 14);

      /* Ship the probe */
      rc = tp_iovCoalesce (s, mbuffer, &bytes_sent);
#ifdef DEBUG_PERSIST
      if (rc <=0) {
	printf ("Tried to probe on %s and failed %d\n", printPorts (s), rc);
      }
#endif /* DEBUG_PERSIST */

      if (mbuffer->m_seq + 1 > (s->seqsent))
	{
	  (s->seqsent) = mbuffer->m_seq + 1;

	  if (SEQ_GT (s->seqsent, s->max_seqsent)) { /* PDF XXX PDF XX PDF XXX */
		  s->max_seqsent = s->seqsent;
	  }

	}
      /* USED to have an additional if ;;    if ((buf) && (mbuffer->m_seq == buf->m_seq) ) {} */
      /*
       * Make sure that snd_una points to buf if appropriate.  This is required
       * in order for mb_trim to snip off the probe byte when it is acknowledged.
       * I'm going to assume that if snd_una is not NULL then the buffer we got
       * is such that mb_trim will get to it.
       */
      if (s->send_buff->snd_una == NULL)
	{
	  s->send_buff->snd_una = buf;
	}
      else
	{
	  /*   s->send_buff->send = s->send_buff->send->m_hdr.mh_next;  */
	}
      /* Got a core dump here once when s->send_buff->send was NULL --KS XXX */
      if (!(s->send_buff->send == NULL) &&
          (s->send_buff->send->M_dat.MH.MH_ext.len == 1)) {
           s->send_buff->send = NULL; 
      }
#ifdef DEBUG_PERSIST
      /* This is only required to make the check at the beginning
       * of free_mbuff not complain about broken chains. */
      mbuffer->m_next = NULL;
#endif /* DEBUG_PERSIST */
      free_mbuff (mbuffer);
    }
  else
    {
#ifdef DEBUG_PERSIST
      printf ("%s  %s In persist but can't find data to send.\n", stringNow
	      (), printPorts (s));
#endif /* DEBUG_PERSIST */
      s->sockFlags |= SOCK_DELACK;
    }

  mytime.tv_sec = 0;
  s->persist_shift ++;    
  s->maxpersist_ctr ++;
  if (s->persist_shift == TP_MAX_PERSIST_SHIFT) {    
    s->persist_shift = TP_MAX_PERSIST_SHIFT - 1;    
  }    

  if (s->maxpersist_ctr > s->MAXPERSIST_CTR) { 
#ifdef GATEWAY
	  {
	    s->rt_route->flags |= RT_LINK_AVAIL;
            if ( (s->peer_socket) && (s->peer_socket->peer_socket == s) ) {
	       s->peer_socket->rt_route->flags |= RT_LINK_AVAIL;
	       tp_Abort (s->peer_socket->sockid);
            }
	  }
#endif /* GATEWAY */
	  SET_ERR (SCPS_ETIMEDOUT);
	  tp_Abort (s->sockid);
	  return;
  }

  if (s->rt_route->flags & RT_LINK_AVAIL) {
     	mytime.tv_sec = 0;
     	mytime.tv_usec = persist_time_outs [s->persist_shift] * 1000 * 1000; 
        mytime.tv_usec = min (mytime.tv_usec, s->RTOPERSIST_MAX);
  } else {
     	mytime.tv_sec = 1;
     	mytime.tv_usec = 0;
     	mytime.tv_sec = 0;
     	mytime.tv_usec = persist_time_outs [s->persist_shift] * 1000 * 1000; 
        mytime.tv_usec = min (mytime.tv_usec, s->RTOPERSIST_MAX);
  }

  set_timer (&mytime, s->otimers[Persist], 1);
  clear_timer (s->otimers[Rexmit], 1);
  s->timeout = s->LONGTIMEOUT;

}


#ifdef CONGEST
void
tp_TFVegas (tp_Socket * s)
{
  int cwinsegs;
  int diff;
  uint32_t new_cwnd;
  struct timeval mytime;
  int old_state;

#ifdef DEBUG_TIMING
  logEventv(s, timing, TIMING_FORMAT,
	    stringNow (),
	    "vegas_in",
	    (uint32_t) 0,
	    s->lastuwein,
	    s->snd_cwnd,
	    s->snd_prevcwnd,
	    s->snd_ssthresh,
	    s->rtt,
	    s->rtseq,
	    s->snduna,
	    s->seqsent);
#endif	/* DEBUG_TIMING */
  mytime.tv_sec = mytime.tv_usec = 0;


#ifndef GLOBAL_VEGAS
  if ((s->rttcur) && (s->rttbest))
#else /* GLOBAL_VEGAS */
  if ((s->rt_route-> rttcur) && (s->rt_route-> rttbest))
#endif /* GLOBAL_VEGAS */
    {

      cwinsegs =
	min ((s->snd_prevcwnd / s->maxseg), max ((s->snd_prevcwnd -
						  (s->snduna -
						   s->rtseq)) / s->maxseg, 1));

#ifndef GLOBAL_VEGAS
      diff = cwinsegs - ((cwinsegs * s->rttbest) / s->rttcur);
#else /* GLOBAL_VEGAS */
      diff = cwinsegs - ((cwinsegs * s->rt_route->rttbest) / s->rttcur);
#endif /* GLOBAL_VEGAS */
      diff = max (diff, 0);

      new_cwnd = s->snd_prevcwnd;

      old_state = (s->sockFlags & TF_CC_LINEAR);
      if (s->sockFlags & TF_CC_LINEAR)
	{
	  if (diff < s->VEGAS_ALPHA)
	    {
	      new_cwnd += s->maxdata;
	      /* s->snd_cwnd += s->maxdata; */
	      if (new_cwnd > 0x7fffffff)
		{
		  new_cwnd = 0x7fffffff;
		}
	    }
	  if (diff > s->VEGAS_BETA)
	    {
#define VEGAS_BACKOFF 0
	      switch ( VEGAS_BACKOFF ) {
	      case 0: /* Experimental */
		/*
		 * Thought:  If we get above VEGAS_BETA, we could ratchet down cwnd
		 * by (diff-VEGAS_BETA) to get back on track.  The min and the /2
		 * dampen this to try to keep things stable.
		 */
		new_cwnd -= min((new_cwnd/2), (((diff-s->VEGAS_BETA)*s->maxdata)/2));
	      case 1: /* Vegas spec. */
		/* int xx = new_cwnd; */
		new_cwnd -= s->maxdata;
	      default:
		new_cwnd = new_cwnd;
	      }
#undef VEGAS_BACKOFF 
	      if ((int) new_cwnd <= (int) s->maxdata)
		{
		  s->sockFlags &= ~TF_CC_LINEAR;
		  /* hit bottom - go exponential */
		  new_cwnd = s->maxdata;
		}
	    }
#ifdef DEBUG_XPLOT
	  /*
	   */
	  if ( s->rtseq > 0 ) {
	    char curTime[50];
	    sprintf(curTime, stringNow2());
	    logEventv(s, xplot, "yellow\nline %s %lu %s %lu\n",
		      curTime, s->rtseq, curTime, s->rtseq + (diff * s->maxdata));
	    logEventv(s, xplot, "diamond %s %lu\n", curTime, s->rtseq +
		      (diff * s->maxdata));
	    logEventv(s, xplot, "uarrow %s %lu\n",
		      curTime, s->rtseq + (s->VEGAS_ALPHA * s->maxdata));
	    logEventv(s, xplot, "darrow %s %lu\n",
		      curTime, s->rtseq + (s->VEGAS_BETA * s->maxdata));
	  }
#endif	/* DEBUG_XPLOT */
	}
      /* linear */
      else
	/* exponential */
	{
          if ( (s->VEGAS_SS == 0) || ( (s->VEGAS_SS |= 0) && (new_cwnd == s->snd_ssthresh) ))
	    {
	      if (diff > s->VEGAS_GAMMA)
		{
		  s->sockFlags |= TF_CC_LINEAR;
		}
	      else if (new_cwnd < 0x7fffffff)
		{
		  new_cwnd = (new_cwnd << 1);
		}
              if (s->VEGAS_SS == 0) {
	        s->snd_ssthresh = new_cwnd;
 	      }
	    }
	  else
	    s->snd_ssthresh = new_cwnd;

	  /* Help new connections "get off the ground"! */
	  if (new_cwnd == s->maxdata)
	    new_cwnd = (new_cwnd << 1);

	  if ((s->rt_route->sendpipe) && (s->rt_route->sendpipe < new_cwnd))
	    {
	      new_cwnd = s->rt_route->sendpipe;
	      s->sockFlags |= TF_CC_LINEAR;
	    }
	  else if (s->app_sbuff->max_size < new_cwnd)
	    {
	      /*
	       * Durst 11/24/97 - this looks like it should
	       * be max_size, not sendpipe
	       */
	      /* new_cwnd = s->rt_route->sendpipe; */
	      new_cwnd = s->app_sbuff->max_size;
	      s->sockFlags |= TF_CC_LINEAR;
	    }
#ifdef DEBUG_XPLOT
	  if ( s->rtseq >0 ) {
	    logEventv(s, xplot, "yellow\nline %s %lu %s %lu\n",
		      stringNow2 (), s->rtseq, stringNow2 (),
		      s->rtseq + (diff * s->maxdata));
	    logEventv(s, xplot, "diamond %s %lu\n", stringNow2 (), s->rtseq +
		      (diff * s->maxdata));
	    logEventv(s, xplot, "ltick %s %lu\n",
		      stringNow2 (), s->rtseq + (s->VEGAS_GAMMA * s->maxdata));
	    logEventv(s, xplot, "rtick %s %lu\n",
		      stringNow2 (), s->rtseq + (s->VEGAS_GAMMA * s->maxdata));
	  }
#endif	/* DEBUG_XPLOT */
	}

      if ((int) new_cwnd <= (int) s->maxdata)
	{
	  s->sockFlags &= ~TF_CC_LINEAR;	/* hit bottom - go
						 * exponential */
	  new_cwnd = s->maxdata;
	}
      s->snd_cwnd += (new_cwnd - s->snd_prevcwnd);
     
      if ((int) (s->snd_cwnd) < 0)
	{
	  s->snd_cwnd = 0;
	}
      s->snd_prevcwnd = max (new_cwnd, s->maxseg);
//	if ((s->seqsent - s->snduna) + s->snd_cwnd > s->snd_prevcwnd) {
//           s->snd_cwnd =  max (s->snd_prevcwnd - (s->seqsent - s->snduna), 0);
//      }
       s->snd_cwnd =  max ((int) (s->snd_prevcwnd - (s->seqsent - s->snduna)), 0);

#ifndef GLOBAL_VEGAS
      mytime.tv_usec = s->rttcur;
      s->rttcur = 0;
#else /* GLOBAL_VEGAS */
      mytime.tv_usec = s->rt_route->rttcur;
      s->rt_route->rttcur = 0;
#endif /* GLOBAL_VEGAS */

      LOGCWND(s);
#ifdef DEBUG_LOG
      logEventv(s, SCPS_log, "%s TFVegas %lu %lu %lu %lu %lu\n",
		stringNow2 (),
		(s->snduna == 0) ? s->initial_seqnum : s->snduna,
		s->snd_prevcwnd,
		s->snd_ssthresh,
		(uint32_t) 0 /* diff placeholder */ ,
		s->snd_cwnd);
#endif	/* DEBUG_LOG */
    }
#ifdef DEBUG_TIMING
  logEventv(s, timing, TIMING_FORMAT,
	    stringNow (),
	    "vegas_out",
	    (uint32_t) 0,
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
#endif /* CONGEST */

void
tp_TFRate (route *r)
{

  struct timeval mytime;
  route *tmp = r;
  static uint32_t old_value = 0;
  double variance_factor;

  mytime.tv_sec = 0;
  mytime.tv_usec = 10000;
  set_timer (&mytime, &rate_timer, 1);

  tp_now = clock_ValueRough ();	/* for UDP when no TP socks are open */
  if ((!old_value || (old_value == tp_now) )) {
	variance_factor = 1;
  } else {
	variance_factor = ((double) (tp_now-old_value)/(double) mytime.tv_usec);
  }
  old_value = tp_now;

#ifdef SCPS_RI_CONSOLE
  r = route_list_head;
#endif /* SCPS_RI_CONSOLE */
#ifdef FAIRER_GATEWAY
     if (rate_condition == GW_LOST_RATE)  {
        rate_condition = GW_LOST_AND_REGAINED_RATE;
     }
#endif /* FAIRER_GATEWAY */
    reset_rate_condition = RESET_LOST_AND_REGAINED_RATE;
  while (r) {
    if (((route *) r)->current_credit < (((route *) r)->max_credit))
      {
  	if (((route *) r)->bytes_per_interval == 0) {
  		((route *) r)->shifted_rate_bucket +=
  			((route *) r)->shifted_bytes_per_interval *
                        variance_factor;

  		if ((((route *) r)->shifted_rate_bucket) >
  			 1 << LOW_RATE_SCALE_FACTOR) {
  			uint32_t  temp ;
  
  			temp = ((route *) r)->shifted_rate_bucket >> LOW_RATE_SCALE_FACTOR;
  			((route *) r)->current_credit += temp;
  			((route *) r)->shifted_rate_bucket -= (temp << LOW_RATE_SCALE_FACTOR);
  		}
/*	printf ("Current_credit (%lu) double_bucket (%d)\n", 
  		((route *) r)->current_credit,
  		((route *) r)->shifted_rate_bucket); 
  		printf ("bpi (%d) shifted_rate_bucket (%d) ",
  		 ((route *) r)->shifted_bytes_per_interval,
  		 ((route *) r)->shifted_rate_bucket); */
  	} else {
  		uint32_t  temp = ((route *) r)->bytes_per_interval;
			temp = temp * variance_factor;
        		((route *) r)->current_credit += temp;
  	}
  
        if ((((route *) r)->current_credit) > (((route *) r)->max_credit))
  	(((route *) r)->current_credit) = (((route *) r)->max_credit);
      }
#ifdef MIN_RATE_THRESH
    if (((route *) r)->min_current_credit < (((route *) r)->max_credit))
      {
  	if (((route *) r)->min_bytes_per_interval == 0) {
  		((route *) r)->min_shifted_rate_bucket +=
  			((route *) r)->min_shifted_bytes_per_interval;
  		if ((((route *) r)->min_shifted_rate_bucket) >
  			 1 << LOW_RATE_SCALE_FACTOR) {
  			uint32_t  temp ;
  
  			temp = ((route *) r)->min_shifted_rate_bucket >> LOW_RATE_SCALE_FACTOR;
			temp = temp * variance_factor;
  			((route *) r)->min_current_credit += temp;
  			((route *) r)->min_shifted_rate_bucket -= (temp << LOW_RATE_SCALE_FACTOR);
  		}
/*	printf ("min_Current_credit (%lu) double_bucket (%d)\n", 
  		((route *) r)->min_current_credit,
  		((route *) r)->min_shifted_rate_bucket); 
  		printf ("bpi (%d) shifted_rate_bucket (%d) ",
  		 ((route *) r)->min_shifted_bytes_per_interval,
  		 ((route *) r)->min_shifted_rate_bucket); */
  	} else {
        		((route *) r)->min_current_credit +=
  		((route *) r)->min_bytes_per_interval;
  	}
  
        if ((((route *) r)->min_current_credit) > (((route *) r)->max_credit))
  	(((route *) r)->min_current_credit) = (((route *) r)->max_credit);
      }
#endif /* MIN_RATE_THRESH */
     r = ((route *) r) -> next;
  }
  r = tmp;

#ifndef SOLARIS
#ifdef ASYNC_IO
  if (scheduler.service_interface_now)
    service_interface (scheduler.interface);
#endif /* ASYNC_IO */
#endif /* SOLARIS */
  /* If the appropriate debugging switches are set, SCPS_LOGRATE will
   * cause rate information to show up in an xplottable file, otherwise
   * SCPS_LOGRATE is completely removed by the precompiler.
   */
  LOGRATE(r);
  set_timer (&mytime, &rate_timer, 1);
}

/* Handle a BE_Recv timeout */
void
tp_TFBERecv (tp_Socket * s)
{
  struct mbuff *mbuffer;
  /*
   * Clear the BETS timer, set the BETS_RECEIVE flag. Next, define the
   * size and boundaries of the BETS Receive Hole and increase the size
   * of receive buffer.
   */
  clear_timer (s->otimers[BE_Recv], 1);

  if (!s->Out_Seq->start) {
	return;
  }

  s->BETS.Flags |= BF_BETS_RECEIVE;
  s->BETS.Hole_Size = (s->Out_Seq->start->m_seq - s->acknum);
  s->BETS.Receive_Hole.Start = s->acknum;
  s->BETS.Receive_Hole.Finish = s->Out_Seq->start->m_seq - 1;
  s->app_rbuff->size += s->BETS.Hole_Size;

  s->acknum += s->BETS.Hole_Size;

  /*
   * Now, put the head of the Out-of-Sequence queue into the
   * in-sequence data stream immediately following the BETS hole.
   * tp_Read will not actually touch this data until it has read past
   * the BETS_Hole - This gives any straggling data located in the
   * BETS_Hole arrive and be consumed if it gets here before the
   * reading process consumes the sequence space.
   */
  mbuffer = deq_mbuff (s->Out_Seq);
if (!mbuffer) printf ("%s %d in BETS 1 temp = NIL\n", __FILE__, __LINE__);


  s->app_rbuff->Out_Seq_size -= mbuffer->m_plen;
  s->app_rbuff->size += mbuffer->m_plen;
  enq_mbuff (mbuffer, s->receive_buff);
  s->acknum += mbuffer->m_plen;

#ifdef OPT_SNACK1
  if (s->capabilities & CAP_SNACK)
    {
      if (s->Out_Seq->start)
	s->SNACK1_Flags |= SEND_SNACK1;
    }
#endif /* OPT_SNACK1 */

  write_align (s->app_rbuff,
	       (s->BETS.Hole_Size +
		mbuffer->m_plen), 0);
  s->rcvwin =
    s->app_rbuff->max_size - s->app_rbuff->size;

  if (s->app_rbuff->size > s->app_rbuff->biggest)
    s->app_rbuff->biggest = s->app_rbuff->size;

  /* Send an immediate ACK for the BETS hole */
  s->sockFlags |= SOCK_ACKNOW;
}

/*
 * Following code taken from BSD, and should reflect the BSD copyright.
 */
void
tp_xmit_timer (tp_Socket * s, uint32_t rttrto, uint32_t rttvegas)
{
  int delta;
  struct timeval mytime;

  mytime.tv_sec = 0;
#ifdef DEBUG_TIMING_VERBOSE
  printf("%s %s RTO update top: rttrto(%f) srtt(%f) rttvar(%f) RTO(%f)(%f)\n",
	 stringNow(), printPorts(s),
	 (float) rttrto/1000000,
	 (float) (s->t_srtt >> TP_RTT_SHIFT)/1000000,
	 (float) (s->t_rttvar >> TP_RTTVAR_SHIFT)/1000000,
	 (float) ((s->t_srtt>>TP_RTT_SHIFT) + ((s->t_rttvar>>TP_RTTVAR_SHIFT)<<2))/1000000,
	 (float) ((float) s->t_rxtcur/1000000) );
#endif /* DEBUG_TIMING_VERBOSE */
#ifdef CONGEST
  if (s->cong_algorithm == VEGAS_CONGESTION_CONTROL)
    {
      /*
       * Initialization code: wait a few round trips before
       * establishing rttbest
       */
      if (s->rttcnt < 0)
	{			/* ("A few" is defined in tp_Common,
				 * I think) */
#ifndef GLOBAL_VEGAS
	  s->rttbest = 0;
#else /* GLOBAL_VEGAS */
	  s->rt_route->rttbest = 0;
#endif /* GLOBAL_VEGAS */
	  s->rttcnt++;
	}
      /*
       * If rttcnt has decremented to zero, reset it and toss
       * rttbest
       */
      else if (s->rttcnt == 0)
	{
	  s->rttcnt = 1000;
/* s->rttbest = 0; *//* We should smooth, not replace */
	  s->maxseg = s->maxseg_perm;	/* undo any shrinkage of
					 * mss */
	}
      else
	s->rttcnt--;		/* Otherwise, decrement rttcnt every
				 * round trip */

      /*  Only update the rttbest if the packet has not been retransmitted -- PDF */
      if (rttvegas)
	{
          if ((s->max_seqsent == s->seqsent) &&
              ((!(s->funct_flags & FUNCT_HIGH_SEQ)) ||
              ((s->funct_flags & FUNCT_HIGH_SEQ) && SEQ_GEQ (s->rtseq, s->high_seq)) ) &&
#ifndef GLOBAL_VEGAS
              (((s->rtseq) && (rttvegas < s->rttbest)) || (!(s->rttbest))))
#else /* GLOBAL_VEGAS */
              (((s->rtseq) && (rttvegas < s->rt_route->rttbest)) || (!(s->rt_route->rttbest))))
#endif /* GLOBAL_VEGAS */
	    {
#ifndef GLOBAL_VEGAS
	      s->rttbest = rttvegas;
#else /* GLOBAL_VEGAS */
	      s->rt_route->rttbest = rttvegas;
#endif /* GLOBAL_VEGAS */
	    }
#ifndef GLOBAL_VEGAS
	  s->rttcur = rttvegas;
#else /* GLOBAL_VEGAS */
	  s->rt_route->rttcur = rttvegas;
#endif /* GLOBAL_VEGAS */

	  if ((s->capabilities & CAP_CONGEST) && (s->rtt))
	    tp_TFVegas (s);
	}
    }
#endif /* CONGEST */


  /*  Only update the rttbest if the packet has not been retransmitted -- PDF */
  if ((rttrto) &&
      (s->max_seqsent == s->seqsent) &&
      ((!(s->funct_flags & FUNCT_HIGH_SEQ)) ||
      ((s->funct_flags & FUNCT_HIGH_SEQ) && SEQ_GEQ (s->rtseq, s->high_seq)) )) {

      gettimeofday (&(ts_array[ts_index].t), NULL);
      ts_array[ts_index].rtt = rttrto;
      ts_index = (ts_index + 1) % TS_ARRAY_LEN;

        /*  If you have to RTO a packet at least 4 times, then the rtt is
         *  probably bogus, so you should obtain a new sample.  While we
         *  are at it, we might as well change rttbest as well. -- PDF
         */

	if (s->t_rxtshift >= 4) {
		s->t_srtt = 0;
#ifndef GLOBAL_VEGAS
		s->rttbest = 0;
#else /* GLOBAL_VEGAS */
		s->rt_route->rttbest = 0;
#endif /* GLOBAL_VEGAS */
	}

      if (s->t_srtt != 0)
	{
	  /*
	   * srtt is stored as fixed point with 3 bits after
	   * the binary point.  The following magic is
	   * equivalent to the smoothing algorithm in rfc793
	   * with an alpha of .875 (srtt = rtt/8 + srtt*7/8 in
	   * fixed point.
	   */

	  delta = rttrto - (s->t_srtt >> TP_RTT_SHIFT);
	  if ((s->t_srtt += delta) <= 0)
	    s->t_srtt = 1;

	  /*
	   * Accumulate smoothed rtt variance (smoothed mean
	   * difference), then set retransmit timer to smoothed
	   * rtt + 4xsmoothed variance. rttvar is stored as
	   * fixed points, with 2 bits after the binary point
	   * (i.e., scaled by 4).  The following is equivalent
	   * to RFC793 smoothing with alpha=0.75 rttvar =
	   * rttvar*3/4 + |delta|/4.  This replaces RFC793's
	   * wired-in beta.
	   */
	  if (delta < 0)
	    delta = -delta;
	  delta -= (s->t_rttvar >> TP_RTTVAR_SHIFT);
	  if ((s->t_rttvar += delta) <= 0)
	    s->t_rttvar = 1;
#ifdef DEBUG_XPLOT
//	logEventv(s, xplot, "red\natext %s %lu\n", stringNow2 (), s->snduna-50);
//	logEventv(s, xplot, "RTO %f %f %f %f\n", (float) s->t_srtt/1000000, (float) s->t_rttvar/1000000, (float) ((s->t_srtt >> TP_RTT_SHIFT) + s->t_rttvar)/1000000, (float) rttrto/1000000);
#endif /* DEBUG_XPLOT */
	}
      else
	{
	  /*
	   * No rtt measurement yet - use unsmoothed rtt. Set
	   * variance to half the RTT (so our first rexmit
	   * happens at 3*rtt).
	   */
	  s->t_srtt = rttrto << TP_RTT_SHIFT;
	  s->t_rttvar = rttrto << (TP_RTTVAR_SHIFT - 1);
	}

      s->t_rxtshift = 0; 
     
      /* When we use the rttvar in calculating the rxtcur, we need to make
       * sure the var is at least 0.5 seconds.  Rational is the following.
       * with implementation of TCP, the unit of variance is 1/4 of a tick
       * and a tick is 0.5 seconds.  The smallest value of the variable
       * is 0.125 seconds.  Therefore when you multiply it by 4, the minimum
       * value of the variance term is 500000 microseconds.  - PDF 
       */
      s->t_rxtcur = (s->t_srtt >> TP_RTT_SHIFT) + max (s->t_rttvar, 500000);
#ifdef DEBUG_TIMING_VERBOSE
	  printf("RTT:  s->t_rxtcur = %u, s->t_srtt %u rttvar = %u, rxtshift = %d rttcur %d\n", 
		s->t_rxtcur, s->t_srtt, s->t_rttvar, s->t_rxtshift, s->t_rxtcur);
#endif /* DEBUG_TIMING_VERBOSE */
#ifndef GLOBAL_VEGAS
      if (s->rttcur && (s->t_rxtcur > (s->rttcur << 1)))
	{
	  s->t_rxtcur = max (s->rttcur << 1, 500000);
#else /* GLOBAL_VEGAS */
      if (s->rt_route->rttcur && (s->t_rxtcur > (s->rt_route->rttcur << 1)))
	{
	  s->t_rxtcur = max (s->rt_route->rttcur << 1, 500000);
#endif /* GLOBAL_VEGAS */
#ifdef DEBUG_TIMING_VERBOSE
	  printf("RTT2:  s->t_rxtcur = %u, s->rttcur = %u\n", s->t_rxtcur, s->rttcur);
#endif /* DEBUG_TIMING_VERBOSE */

	}

      s->t_rxtcur = max (s->t_rxtcur, s->RTOMIN);
      s->t_rxtcur = min (s->t_rxtcur, s->RTOMAX);
#ifdef DEBUG_TIMING_VERBOSE
	  printf("%s %s RTO update bottom: rttrto(%f) srtt(%f) rttvar(%f) RTO(%f)(%f)\n",
		 stringNow(), printPorts(s),
	         (float) rttrto/1000000,
		 (float) (s->t_srtt >> TP_RTT_SHIFT)/1000000,
		 (float) (s->t_rttvar >> TP_RTTVAR_SHIFT)/1000000,
		 (float) ((s->t_srtt>>TP_RTT_SHIFT) +
		 ((s->t_rttvar>>TP_RTTVAR_SHIFT)<<2))/1000000,
	         (float) ((float) s->t_rxtcur/1000000) );
#endif /* DEBUG_TIMING_VERBOSE  */
    }
}

void
tp_TFSelect (tp_Socket * s)
{
  /* The select timer has gone off, just unblock the socket's thread */
  if (s->thread->status != Ready)
    {
      if (s->thread->status == Blocked)
	scheduler.num_runable++;
      s->thread->status = Ready;
    }
}


void
tp_TFKeepAlive (tp_Socket * s)
{
  struct timeval mytime;
  if ( (s) && (s->state >= tp_StateSYNSENT)  &&
      (s->state <=tp_StateLASTACK)) {
      s->sockFlags |= SOCK_ACKNOW;
  }
  mytime.tv_usec = 0;
  mytime.tv_sec = s->KATIMEOUT;
  set_timer (&mytime, s->otimers[KA], 1);
}

void
tp_TFTimeWT (tp_Socket * s)
{
  if ( (s->state == tp_StateTIMEWT) || (s->state == tp_StateLASTACK) ||
       (s->state == tp_StateWANTTOLAST))
    {
      s->state_prev = 0;
      s->state = tp_StateCLOSED;
      PRINT_STATE (s->state, s);
      SET_ERR (SCPS_ENOTCONN);
      tp_Unthread (s);
    }
}
