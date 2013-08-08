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


/*
 * scpstp.c - Space Communications Protocol Standards Transport Protocol
 */
#include "scps.h"
#include "scpstp.h"
#include "scpsudp.h"
#include "scps_constants.h"
/* #include "scpserrno.h" */
#include <stdio.h>		/* temporary */
#include <sys/types.h>
#include "thread.h"
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "tp_debug.h"

#include "np_scmp.h"
int scps_np_ind (scps_np_rqts * rqts, short length, int *data_offset);

#include "scps_ip.h"

#ifdef SCPSSP
#include "scps_sp.h"
int sp_ind (scps_sp_rqts * sp_rqts, short length, int *offset);
#endif /* SCPSSP */

#ifdef Sparc
#include <sys/mman.h>
#ifndef SOLARIS
void fflush (FILE * fp);
#endif /* ndef fflush */
#endif /* Sparc */

#ifdef GATEWAY
#include "rs_config.h"
extern GW_ifs gw_ifs;
#endif /* GATEWAY */

#ifdef TAP_INTERFACE
#include "other_proto_handler.h"
#endif /* TAP_INTERFACE */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp.c,v $ -- $Revision: 1.47 $\n";
#endif

int abs (int i);		/* test function prototype */

extern char config_span_name[];

tp_Socket *tp_allsocs;		/* Pointer to first TP socket */
udp_Socket *udp_allsocs;	/* Pointer to first UDP socket */
reset_Socket *socs_to_reset = NULL;	/* Pointer to first TP socket */
struct _timer rate_timer;	/* Rate Control timer */
procref timer_fn[TIMER_COUNT];	/* Array of timer functions */

struct _ll_queue_element *in_data;	/* packet buffer */
byte out_data[MAX_MTU];		/* packet buffer */
struct msghdr out_msg;		/* the message for sndmsg */
struct iovec out_iov[20];	/* Handle up to 19 segments + 1 raw header */

extern struct _interface *sock_interface; 
extern struct _interface *divert_interface;

#ifdef FAIRER_GATEWAY
  tp_Socket *start_s = NIL;
  tp_Socket *init_s  = NIL;
  tp_Socket *current_s = NIL;
  int num_loops = 0;
#endif /* FAIRER_GATEWAY */

#ifdef GATEWAY_ROUTER
#include "rt_alloc.h"
#endif /* GATEWAY_ROUTER */

/*
 * Local IP address
 */
scps_np_addr local_addr;

int receives, max_receives;
int tp_is_running = 0;

/*
 * IP identification numbers
 */
unsigned short tp_id;
unsigned short udp_id;

/* TP's concept of current time */
uint32_t tp_now;
uint32_t last_cluster_check;

#ifdef UDP_GATEWAY
int gateway_mega_udp_socket = -1;
#endif /* UDP_GATEWAY */

/* inbound packet's requirements structure */
scps_np_rqts rqts_in;

/* Timer definitions */

int ls;
int ll_read_avail;		/* Lower layer socket id */

struct timeval end_time;	/* For throughput calculations */
float elapsed_time;		/* For final throughput calculations */
short global_conn_ID;		/* Connection identifier for compression -
				 * each socket uses an ID unique to this
				 * machine */

int write_count;
int send_count;
int udp_write_count;
int udp_send_count;

int delayed_requested = 0;
int delayed_sent = 0;

int TS_ARRAY_LEN = 1;
struct _times
  {
    struct timeval t;
    uint32_t rtt;
  }
ts_array[1];

int ts_index = 0;

#ifdef FAIRER_GATEWAY
int rate_condition = GW_LOST_AND_REGAINED_RATE;
#endif /* FAIRER_GATEWAY */
int reset_rate_condition = RESET_LOST_AND_REGAINED_RATE;

#ifdef GATEWAY
#ifdef LOW_CPU_IDLE
int gw_no_delay = 0;
#endif /* LOW_CPU_IDLE */
#endif /* GATEWAY */

extern int print_list_now;
extern struct _clust_mem_map clust_mem_map;
/*
 * busy-wait loop for tp.
 */
void
tp ()
{
  in_Header *ip;
  uint32_t start;
  BOOL x = false;		/* Determines whether ack is piggybacked or not */
  byte proto;
  static uint32_t timeout = 0;
  static int send_delay = 0;
  static int max_send_delay = 40;
  tp_Socket *s = NULL;
  udp_Socket *us;
  int cc;
  uint32_t bytes_sent;
  tp_Header *tp;
  scps_np_rqts rqts_in;
#ifdef SCPSSP
  scps_sp_rqts rqts_sp;
#endif /* SCPSSP */
  struct mbuff *mbuffer;
  int offset = 0;
  struct timeval mytime;
  int already_freed;

#define GATEWAY_MEM_POOL_CLEAN_UP 1
#ifdef GATEWAY_MEM_POOL_CLEAN_UP
  int  clust_check = 0;
#endif /* GATEWAY_MEM_POOL_CLEAN_UP */

#ifdef GATEWAY
#ifdef GATEWAY_MANY
  max_receives = 1;
#ifdef LOW_CPU_IDLE
  max_receives = 150;
#endif /* LOW_CPU_IDLE */
#else /* GATEWAY_MANY */
  max_receives = 5;
#endif /* GATEWAY_MANY */
#else /* GATEWAY */
  max_receives = 1;
#ifdef LOW_CPU_IDLE
  max_receives = 150;
#endif /* LOW_CPU_IDLE */
#endif  /* GATEWAY */

  mytime.tv_sec = 0;

  while (1)
    {
#ifdef GATEWAY_SINGLE_THREAD
      while (1)
#else /* GATEWAY_SINGLE_THREAD */
      while (tp_allsocs || udp_allsocs)
#endif /* GATEWAY_SINGLE_THREAD */
	{
	  start = tp_now;	/* clock_ValueRough (); */
	  if (!timeout)
	    timeout = start + tp_TICK;
	  ip = NIL;
	  receives = 0;

	  /* This needs to loop through interfaces and pull data off them */
	  while ((receives < max_receives) && (scheduler.interface_data) &&
#ifdef SECURE_GATEWAY
		 ((cc = sp_ind (&rqts_sp, MAX_MTU, &offset)) > 0))
#else /* SECURE_GATEWAY */

#ifdef SCPSSP
		 ((cc = sp_ind (&rqts_sp, MAX_MTU, &offset)) > 0))
#else /* SCPSSP */
	    ((cc = nl_ind (&rqts_in, MAX_MTU, &offset)) > 0))
#endif /* SCPSSP */
#endif /* SECURE_GATEWAY */
	  {

#ifdef SCPSSP
	    rqts_in =  rqts_sp.np_rqts;
#endif /* SCPSSP */

	    tp = (tp_Header *) ((void *) in_data->data + offset);

#ifndef GATEWAY
	    if (rqts_in.dst_addr == htonl (local_addr))
#endif /* GATEWAY */
	      {
		proto = rqts_in.tpid;

#ifdef SCPSSP
		proto = rqts_sp.tpid;

#ifdef SECURE_GATEWAY
		if (rqts_sp.secure_gateway_rqts== SECURE_GATEWAY_NO_SECURITY) {
			proto = rqts_in.tpid;
		}
#endif /* SECURE_GATEWAY */

#endif /* SCPSSP */

#ifdef ENCAP_DIVERT
		rqts_in.divert_port_number = in_data->divert_port_number;
#ifdef SECURE_GATEWAY
		if ((proto == SCPSTP) && (!(
                    ((tp->flags & tp_FlagSYN) && (ntohl (tp->acknum) == 0))))) {
			in_data->divert_port_number = gw_ifs.c_divport;
			rqts_in.divert_port_number = gw_ifs.c_divport;
			rqts_in.secure_gateway_rqts = rqts_sp.secure_gateway_rqts;
		}
#endif /* SECURE_GATEWAY */
#ifdef GATEWAY_DEBUG
		printf ("The divert port number = %d\n", rqts_in.divert_port_number);
#endif /* GATEWAY_DEBUG */
#endif /* ENCAP_DIVERT */

		already_freed = 0;
		switch (proto)
		  {
		  case SCPSTP:
		    tp_Handler (&rqts_in, cc, tp);
		    break;
		  case SCPSCTP:
		    tp_CompressedHandler (&rqts_in, cc, tp);
		    break;
		  case SCPSUDP:
		    udp_Handler (&rqts_in, cc, tp);
		    break;
		  case ICMP:
                    tp = (tp_Header *) ((void *) in_data->data);
		    icmp_Handler (&rqts_in, cc, (ip_template *) tp, offset);
#ifdef TAP_INTERFACE
                    already_freed = 1; 
#endif /* TAP_INTERFACE */
		    break;
		  default:
		    break;
		  }
	      }
	    receives++;

	    /* Free the buffer */
            if (!already_freed) {
                free_ll_queue_element (rqts_in.interface, in_data);
            }
	  }

#ifdef DEBUG_MEMORY
if (print_list_now) {
    logMemoryInfo ();
    print_list_now = 0;
}
#endif /* DEBUG_MEMORY */

	  /*
	   * If there is nothing in the receive queue, check 
	   * timers and issue delayed acks for all sockets.
	   *
	   * Check timers and issue delayed acks for each socket
	   */

	  if (scheduler.timers.expired_queue.head)
	    {
	      service_timers ();
	    }

	  if (SEQ_GT (start, timeout))
	    {
	      tp_now = start;
	      /* service_timers(); */
	      tp_Timers ();
	      timeout = start + tp_TICK;
	      if (!timeout)
		timeout++;	/* reserve 0 value timeout */
	    }

          /*
           *  If we have gained rate, we need to send probes is the
           *  failed to be sent (either rate of mbuf reasons
           */
          if ((reset_rate_condition == RESET_LOST_AND_REGAINED_RATE) && (socs_to_reset)) {
             reset_Socket * tmp = socs_to_reset;
             int  rc = 0;
             while ((tmp) && (tmp->s)) {
                 rc = tp_Abort (tmp->s->sockid);
                 if (tmp)
                    tmp = tmp -> next;
             }

          /* Walk down the list */
             reset_rate_condition = RESET_USING_RATE;
	  }
   
#ifdef FAIRER_GATEWAY
          if (!init_s) {
	      init_s = tp_allsocs;
	  }
          if (!start_s) {
	      start_s = tp_allsocs;
	  }
         
          if (!s) {
	      s = tp_allsocs;
	  }

          s = start_s;

          if (rate_condition == GW_LOST_AND_REGAINED_RATE) {
	     s = init_s;
             rate_condition = GW_USING_RATE;
	  } else {
	     s = init_s;
	  }
   
	  if (!s) {
            s = tp_allsocs;
#ifdef NOT_YET
          } else {
		tp_Socket * s_tmp = s;
		tp_Socket * s_tmp2 = s -> next;

		if ((s_tmp) && (s_tmp2)) {
		  s_tmp -> next = s_tmp -> next -> next;
                  if (s_tmp2 -> next) s_tmp2 -> next ->prev = s_tmp;
		  s_tmp2 -> next = tp_allsocs;
		  s_tmp2 -> prev = NIL;
		  tp_allsocs ->prev = s_tmp2;
		  tp_allsocs = s_tmp2;
            	  s = tp_allsocs;
		}
		  
		tp_Socket * s_tmp = tp_allsocs -> next;

		if ((s_tmp) && (s->next) && (s->prev)) {
		  tp_allsocs ->prev = s -> prev;
		  tp_allsocs ->next = s->next;
       		  s->prev ->next = tp_allsocs;
		  s->next->prev = tp_allsocs;

		  tp_allsocs = s;
		  tp_allsocs -> next = s_tmp;
	  	  tp_allsocs -> prev = NIL;
		  s_tmp -> prev = tp_allsocs;
                }
#endif /* NOT_YET */

	  }


          start_s = s;
          if (num_loops == 2) {
              s = tp_allsocs;
              init_s = tp_allsocs;
              start_s = tp_allsocs;
          }
          num_loops = 0;
#endif /* FAIRER_GATEWAY */
#ifndef FAIRER_GATEWAY
	  for (s = tp_allsocs; s != NIL; s = s->next)
#else /* FAIRER_GATEWAY */
	  do 
#endif /* FAIRER_GATEWAY */
	    {
		if (s) {
		DEBUG_INTERACTIVE_SERVICE();
#ifdef GATEWAY_ROUTER
              if (!s->rt_route) {
                 s->rt_route = route_rt_lookup_s (s);
              }
#endif  /* GATEWAY_ROUTER */

	      if (s->sockFlags & (SOCK_ACKNOW | SOCK_CANACK))
		{
		  s->flags = tp_FlagACK;

		  BUG_HUNT (s);
		  if (!(mbuffer = tp_BuildHdr (s, NULL, 0)))
		    {
		      return;
		    }

		  if ((s->sockFlags & TF_COMPRESSING) == TF_COMPRESSING)
		    {
		      x = true;
		    }
		  if ((tp_NewSend (s, mbuffer, false)) > 0)
		    {
		      delayed_sent++;
		      s->sockFlags &=
			~(SOCK_ACKNOW | SOCK_CANACK | SOCK_DELACK);
		      s->unacked_segs = 0;
		      s->lastack = s->acknum;
		      clear_timer (s->otimers[Del_Ack], 1);
		      s->lastuwe = s->acknum + s->rcvwin;
		      s->ack_delay = 0;
		    }		/* If NewSend returned non-zero */
		  free_mbuff (mbuffer);
		}		/* If SOCK_ACKNOW set */
	      if (s->send_buff->snd_una || s->send_buff->send)
		{
		  tp_NewSend (s, NULL, false);

		}

	      if (send_delay >= max_send_delay)
		{
		  send_delay = 0;
		  if (s->send_buff->send)
		    {
		      tp_NewSend (s, NULL, false);

		    }
		}
	      else
		{
		  send_delay++;
		}

	      /* Need to do this to push out final data holding
	       * up a FIN because of lack of mbuffs
	       */
	      if (sys_memory.clust_in_use + 10 < sys_memory.fclist.max_size) {
	          if ((s->state == tp_StateWANTTOCLOSE) ||
		      (s->state == tp_StateWANTTOLAST))
			tp_Flush (s);
              }

#ifdef GATEWAY
          {     
                if ( (gw_ifs.c_netstat_interval)  && 
                      ((tp_now - last_cluster_check) >
                       (gw_ifs.c_netstat_interval * 1000 * 1000))) {

                int i; 
                int cluster_count = 0;
                int socket_count  = 0;

                last_cluster_check = tp_now;
                for (i = 0; i < MAX_CLUST; i++) {
                    if (clust_mem_map.clust_list [i].used == 1) {
                         cluster_count ++;
                    }
                }
                syslog (LOG_ERR, "Gateway: cluster allocation: %d\n", cluster_count);

                for (i = 0; i < MAX_SCPS_SOCKET; i++) {
                  if (scheduler.sockets[i].ptr != NULL) {
                    socket_count ++;
                  }
                }
                syslog (LOG_ERR, "Gateway: socket allocation: %d\n", socket_count);

     		if (sock_interface)
	                syslog (LOG_ERR, "Gateway: interface buffers available : %d\n", sock_interface->available.size);
       		if (divert_interface)
                	syslog (LOG_ERR, "Gateway: divert interface buffers available : %d\n", divert_interface->available.size);
           }
          }
#endif /* GATEWAY */

	  if (!s->otimers[Persist]->set) {
	      if ((!s->otimers[Rexmit]->set) && ( (s->send_buff->snd_una) ||
SEQ_GT (s->max_seqsent, s->snduna)) &&
                  (s->state != tp_StateCLOSED) &&
                  (s->otimers[Rexmit]->expired == 0) ) {
       	          struct timeval mytime;
	          mytime.tv_sec = 0x0;
	          mytime.tv_usec =((s->t_srtt>>TP_RTT_SHIFT) +
    			       max (500000,((s->t_rttvar>>TP_RTTVAR_SHIFT) << 2)));
	          mytime.tv_usec = max (mytime.tv_usec, s->RTOMIN);
	          mytime.tv_usec = min (mytime.tv_usec, s->RTOMAX);
	          set_timer (&mytime, s->otimers[Rexmit], 1);
	      }
          }

         if ((!s->otimers[TW]->set) && (s->state ==tp_StateTIMEWT)) {
              s->timeout = s->TWOMSLTIMEOUT;
              mytime.tv_sec = s->TWOMSLTIMEOUT;
              mytime.tv_usec = 0;
              set_timer (&mytime, s->otimers[TW], 1);
         }
#ifdef GATEWAY_MEM_POOL_CLEAN_UP
	  {
		int i;
		clust_check ++;
		if (clust_check > 50000) {
			clust_check = 0;

			for (i = 0; i < MAX_CLUST; i++) {
				if ((clust_mem_map.clust_list [i].clust) && 
				    (clust_mem_map.clust_list [i].used == 1) && 
       		                     (clust_mem_map.clust_list [i].clust->parent == 0x0) &&
       		                     (clust_mem_map.clust_list [i].clust->c_next == 0x0) &&
       		                     (clust_mem_map.clust_list [i].clust->c_prev == 0x0)) {
						free_mclus (clust_mem_map.clust_list [i].clust);	
				}
			}
		}
	  }
#endif /* GATEWAY_MEM_POOL_CLEAN_UP */

#ifdef GATEWAY
	      if ((s) && (s->peer_socket) && 
                  (s->gateway_flags & (GATEWAY_MORE_TO_WRITE)))
		{
		  gateway_move_data (s, s->peer_socket);
		}
	      else
		{
		}

	      if ((s) && (s->gateway_flags & (GATEWAY_ABORT_NOW))) {
		tp_Socket *ttmp;
		if (s->peer_socket) {
			tp_Abort (s->peer_socket->sockid);
	 	}

		ttmp = s->next;
		tp_Abort (s->sockid);
		s = ttmp;
	      }

		
#endif /* GATEWAY */
#ifdef GATEWAY
#ifdef LOW_CPU_IDLE
	      if (s->gateway_flags & (GATEWAY_MORE_TO_WRITE)) {
                  gw_no_delay = 1;
              }
#endif /* LOW_CPU_IDLE */
#endif /* GATEWAY */

	     }
#ifdef FAIRER_GATEWAY
	      current_s = s;
              if (s)  s = s -> next;
	      if (!s) {
                  s = tp_allsocs;
                  num_loops ++;
              }

              if ((current_s) && (current_s->rt_route) &&
		  (current_s->rt_route->current_credit <= current_s->rt_route->MTU) &&  
                  (rate_condition == GW_USING_RATE) ) {

		  if (((current_s->send_buff->send) || (current_s->send_buff->holes) ) &&
		       (!current_s->gateway_fairness_ctr)) {
		    init_s = current_s;
                    rate_condition = GW_LOST_RATE;
		  } else {
		    init_s = s;
                    rate_condition = GW_LOST_RATE;
		  }
		  current_s->gateway_fairness_ctr = 0;
	      }

              } while ((s != start_s) && (num_loops != 2));
#else /* FAIRER_GATEWAY */
	    }			/* For all sockets */
#endif /* FAIRER_GATEWAY */

	  /* See if any UDP datagrams need to be kicked out the door */
	  for (us = udp_allsocs; us != NIL; us = us->next)
	    {
	      if ((us->select_timer) && (SEQ_GEQ (tp_now, us->select_timer)))
		{
		  us->select_timer = 0;
		  us->thread->status = Ready;
		}

	      if ((us->buff_full) &&
		  (us->rt_route && us->rt_route->flags & RT_LINK_AVAIL) &&
		  (us->rt_route->current_credit >=
		   ((int) us->send_buff->start->m_ext.len +
		    UDP_HDR_LEN + us->sp_size + 20)))
		{		/* this is hard-coded for IP! */
		  udp_Coalesce (us, &bytes_sent);
		  us->buff_full = FALSE;
		}
	    }

#ifdef TAP_INTERFACE
	other_proto_emit ();
	other_proto_non_ip_emit ();
	other_proto_ipv6_emit ();
#endif /* TAP_INTERFACE */

	  /* 
	   * Servicing the interface every 10ms just doesn't
	   * cut if for running faster than ~7Mbps; So we need
	   * to do it here too :o(
	   *
	   * If you are running at slower speeds, there is no
	   * need to service the interface here!
	   *
	   * We need a dedicated thread that will select() on
	   * the interfaces and drain them as data becomes 
	   * available; This is not possible with our tiny 
	   * threads because I have no way of letting the 
	   * select() block waiting for input without *all* the 
	   * threads blocking too; POSIX threads are probably 
	   * the portable way to do this, but they aren't 
	   * necessarily available (or stable) on all platforms.
	   * 
	   *    Solaris     ~yes;
	   *    SunOS       No (but LWP do exist)
	   *    Linux       ~yes;
	   *    Irix        ~yes(?)
	   *    {Foo}BSD    ???
	   *    NT          No (but there is Win32 threads)
	   *    OS/2        No (but there is some threading capability)
	   *
	   * I'm working on a more acceptable solution than this,
	   * but it's requiring thought...
	   *
	   */

	  /* if (scheduler.service_interface_now) */
          if (sock_interface)
                service_interface (sock_interface);
          if (divert_interface)
                service_interface (divert_interface);

#ifdef GATEWAY
#ifdef LOW_CPU_IDLE
	  gw_no_delay = 0;
#endif /* LOW_CPU_IDLE */
#endif /* GATEWAY */

	  /*
	   * Allow application to run 
	   */

	  if (scheduler.num_runable > 1)
	    sched ();
	}			/* while allsocs */
      fflush (stdout);
      timeout = 0;
#ifndef GATEWAY_SINGLE_THREAD
      scheduler.current->status = Blocked;	/* block self until socket opened */
      sched ();
#endif /* GATEWAY_SINGLE_THREAD */
    }				/* while(1) */
}
