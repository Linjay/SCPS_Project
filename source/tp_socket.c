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
#include "scpserrno.h"
#include "tp_debug.h"
#include "gateway.h"
#include <stdio.h>		/* temporary  - for udp_WriteTo() */
#include <netinet/in.h>
#include <netdb.h>		/* For scps_getprotobyname */

#include <stdlib.h>

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_socket.c,v $ -- $Revision: 1.40 $\n";
#endif

extern void free (void *ptr);
extern void *malloc (size_t size);
//extern void *memset (void *s, int c, size_t n);
extern int printf (const char *format, /* args */ ...);



#ifdef SCPSSP
#include "scps_sp.h"
#endif /* SCPSSP */

#include "scps_ip.h"
int scps_np_get_template (scps_np_rqts * rqts,
			  scps_np_template * templ);

extern uint32_t tp_now;
extern struct timeval end_time;
extern float elapsed_time;
extern short global_conn_ID;

extern tp_Socket *tp_allsocs;
extern reset_Socket *socs_to_reset;
extern unsigned short tp_id;
extern route *def_route;

tp_Socket *
clone_socket (tp_Socket * socket)
{
  int temp, i;
  struct timeval mytime;
  int sock_buff_size = socket->receive_buff->max_size;
  int app_sbuff_size = socket->app_sbuff->max_size;
  int app_rbuff_size = socket->app_rbuff->max_size;
  struct mbcluster *mbcluster;

  tp_Socket *new_socket = (tp_Socket *) malloc (sizeof (tp_Socket));

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);           
  if (!(new_socket))
    {
      SET_ERR (SCPS_ENOMEM);
          sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);           
      return (0x0);
    }

   memcpy (new_socket, socket, sizeof (tp_Socket));  

  /* Get a pseudo-file descriptor for our socket */
  for (temp = 0; temp < MAX_SCPS_SOCKET; temp++)
    {
      if (scheduler.sockets[temp].ptr == NULL)
	{
	  scheduler.sockets[temp].ptr = (caddr_t) new_socket;
	  new_socket->sockid = temp;
	  break;
	}
    }

  if (temp == MAX_SCPS_SOCKET)
    {
          sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);           
      free (new_socket);
      return (NULL);
    }

  new_socket->thread = socket->thread;

  new_socket->total_data = new_socket->last_total_data = 0;

  new_socket->scratch_buff = 0x0;
  new_socket->receive_buff = 0x0;
  new_socket->Out_Seq = 0x0;
  new_socket->send_buff = 0x0;
  new_socket->app_sbuff = 0x0;
  new_socket->app_rbuff = 0x0;

  new_socket->send_buff = buff_init (sock_buff_size, new_socket);
  new_socket->receive_buff = buff_init (sock_buff_size, new_socket);
  new_socket->Out_Seq = buff_init (sock_buff_size, new_socket);

  if ((!(new_socket->receive_buff)) || (!(new_socket->Out_Seq)) ||
      (!(new_socket->send_buff)))
    {
          sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);           
      goto SockAlloc_Failure;
    }

  new_socket->app_sbuff = chain_init (app_sbuff_size);
  new_socket->app_rbuff = chain_init (app_rbuff_size);

  if ((!(new_socket->app_rbuff)) || (!(new_socket->app_sbuff)))
    {
          sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);           
      goto SockAlloc_Failure;
    }

  new_socket->scratch_buff = alloc_mbuff (MT_HEADER);

  if (!new_socket->scratch_buff)
    {
      goto SockAlloc_Failure;
    }

  tp_now = clock_ValueRough ();

  mytime.tv_sec = 0;
  mytime.tv_usec = new_socket->ACKDELAY;

  /* Create our timers */
  for (i = 0; i < TIMER_COUNT; i++)
    {
      if (!(new_socket->otimers[i] =
	    create_timer (socket->otimers[i]->function,
			  (void *) new_socket,
			   socket->otimers[i]->immediate,
			   NULL, NULL, i)))
	{
          sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);           
	  SET_ERR (SCPS_ENOBUFS);
	  goto SockAlloc_Failure;
	}
    }
  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);           

  new_socket->next = tp_allsocs;
  tp_allsocs->prev = new_socket;

  if (new_socket->next)
    new_socket->next->prev = new_socket;
  new_socket->prev = NULL;

  tp_allsocs = new_socket;
  return (new_socket);

SockAlloc_Failure:
  /*
   * Give back any dynamic memory we grabbed so far...
   */
  if (new_socket->scratch_buff)
    free_mbuff (new_socket->scratch_buff);
  if (new_socket->receive_buff)
    free (new_socket->receive_buff);
  if (new_socket->Out_Seq)
    free (new_socket->Out_Seq);
  if (new_socket->send_buff)
    free (new_socket->send_buff);

  if (new_socket->app_sbuff) {
    while ((mbcluster = deq_mclus (new_socket->app_sbuff))) {
      mbcluster ->c_count = 1;
      free_mclus (mbcluster);
    }
    free (new_socket->app_sbuff);
  }

  if (new_socket->app_rbuff) {
    while ((mbcluster = deq_mclus (new_socket->app_rbuff))) {
      mbcluster ->c_count = 1;
      free_mclus (mbcluster);
    }
    free (new_socket->app_rbuff);
  }

  free (new_socket);
  scheduler.sockets[new_socket->sockid].ptr = 0x0;
  SET_ERR (SCPS_ENOMEM);
  return (NULL);
}

int
scps_socket (int family, int type, int flags)
{
  void *socket = NULL;
  int retval = -1;


  SET_ERR (0);
  if (type != SOCK_ROUTE)
    sched ();

  switch (type)
    {
    case SOCK_STREAM:
    case SOCK_SEQPACKET:
    case SOCK_ROUTE:
      socket = (void *) malloc (sizeof (tp_Socket));

      if (!socket) {
        return (retval);
      }

      memset (socket, 0, sizeof (tp_Socket));

#ifdef GATEWAY
      ((tp_Socket *) socket) ->nl_protocol_id = NL_PROTOCOL_IPV4;
      ((tp_Socket *) socket) ->np_rqts.nl_protocol = NL_PROTOCOL_IPV4;

      if (family == AF_INET6) {
           ((tp_Socket *) socket) ->nl_protocol_id = NL_PROTOCOL_IPV6;
           ((tp_Socket *) socket) ->np_rqts.nl_protocol = NL_PROTOCOL_IPV6;
      }
#endif /*  GATEWAY */

      retval = tp_Common ((tp_Socket *) socket);

      if (retval == -1) {
        /* If you can complete the scps_socket you must not place the socket on tp_allsocs */
        if (socket) {
          free (socket);
        }
        return (retval);
      }

      /* 
       * This is really sleazy and broken, but 
       * it's just for this busted implementation 
       */

      if (type == SOCK_SEQPACKET)
	((tp_Socket *) socket)->sockFlags |= SOCK_ATOMIC;

      if (type == SOCK_ROUTE)
	{
	  ((tp_Socket *) socket)->Initialized = SCPSROUTE;
	  tp_mss (socket, 0);	/* Attach to the default rt_route */

	  /* Ughhh... */
	  if ((tp_allsocs = socket))
	    tp_allsocs = ((tp_Socket *) socket)->next;
	  if (tp_allsocs)
	    tp_allsocs->prev = NULL;
	}
      break;

    case SOCK_DGRAM:
      socket = (void *) malloc (sizeof (udp_Socket));
      memset (socket, 0, sizeof (udp_Socket));
      retval = udp_Common ((udp_Socket *) socket);
      break;
    }
  if (retval == -1)
    {
      if (socket)
	{
	  free (socket);
	}
    }
  return (retval);
}

int
scps_bind (int sockid, void *ina, int addrlen)
{
  void *socket = scheduler.sockets[sockid].ptr;
  struct _interface *index = 0x0;
  uint32_t address;
  int errval = 0;
  int retval = 0;

  SET_ERR (0);
  if ((!(socket)) || (((tp_Socket *) socket)->thread != scheduler.current))
    errval = SCPS_EBADF;

#ifdef DELETE_LATER_PDF
  else if (addrlen != sizeof (struct sockaddr_in))
    errval = SCPS_EINVAL;
#endif /* DELETE_LATER_PDF  */

  else
    {
      switch (((tp_Socket *) socket)->Initialized)
	{
	case SCPSTP:
	case SCPSUDP:
	  {

	    /*
	     * We can get away from this because the headers of
	     * the socket definitions are identical in memory.
	     */
#ifndef IPV6
            memcpy (&(((tp_Socket *) socket)->my_ipv4_addr),
                    &(((struct sockaddr_in *) ina)->sin_addr),
                    sizeof ((((struct sockaddr_in *) ina)->sin_addr)));
            if (!(((tp_Socket *) socket)->my_ipv4_addr))
              {
                ((tp_Socket *) socket)->my_ipv4_addr = htonl (local_addr);
              }
#else /* IPV6 */
         if (((tp_Socket *) socket) ->nl_protocol_id == NL_PROTOCOL_IPV4) {
            memcpy (&(((tp_Socket *) socket)->my_ipv4_addr),
                    &(((struct sockaddr_in *) ina)->sin_addr),
                    sizeof ((((struct sockaddr_in *) ina)->sin_addr)));
            if (!(((tp_Socket *) socket)->my_ipv4_addr))
              {
                ((tp_Socket *) socket)->my_ipv4_addr = htonl (local_addr);
              }

         } else if (((tp_Socket *) socket) ->nl_protocol_id == NL_PROTOCOL_IPV6) {

            memcpy (&(((tp_Socket *) socket)->my_ipv6_addr),
                    &(((struct sockaddr_in6 *) ina)->sin6_addr),
                    sizeof ((((struct sockaddr_in6 *) ina)->sin6_addr)));
            if (!(((tp_Socket *) socket)->my_ipv6_addr.addr[0] == 0))
              {
                ((tp_Socket *) socket)->my_ipv6_addr.addr[0] = /* XXXX htonl (local_addr); */ 0;
              }

         } else {
                errval = SCPS_EINVAL;
         }

#endif /* IPV6 */

	    if (!(((tp_Socket *) socket)->myport =
		  (u_short) (((struct sockaddr_in *) ina)->sin_port)))
	      ((tp_Socket *) socket)->myport = htons
		(scheduler.tp_ephemeral_next++);

            if (scheduler.tp_ephemeral_next > 64000) {
                scheduler.tp_ephemeral_next = 5001;
            }

            /* Worst Case scenario */
            ((tp_Socket *) socket)->np_size = MIN_IP_HDR;    /* Bad! Evil! */

#ifdef SCPSSP
	    ((tp_Socket *) socket)->sp_size = 30;
#endif /* SCPSSP */
	    break;
	  }
	default:
	  errval = SCPS_ENOTSOCK;
	}
      /* 
       * We need to bind this to an interface 
       */

      memcpy (&address,
	      &(((struct sockaddr_in *) ina)->sin_addr), sizeof (uint32_t));
      if (address)
	index = scheduler.interface;

#ifdef NOT_YET
      while (index)
	{
	  if (index->address == address)
	    break;
	}
#endif /* NOT_YET */

      if (index)
	((tp_Socket *) socket)->np_rqts.interface = (void *) index;

      else
	/* Bind to a default interface */
	((tp_Socket *) socket)->np_rqts.interface =
	  (void *) scheduler.interface;
    }

  if (errval)
    {
      SET_ERR (errval);
      retval = -1;
    }
  return (retval);
}

#ifdef GATEWAY_SELECT
int
scps_select (int sockid, scps_fd_set * readset,
	     scps_fd_set * writeset, scps_fd_set * nullval, struct timeval *time)
{
  tp_Socket *socket;
  scps_fd_set temp_read, temp_write;
  int timer, timer_index, temp;
  int value = 0;
  int offset, inner, outer;
  uint32_t timer_value = 0;

  SET_ERR (0);
  sched ();

  timer_index = -1;		/* No timer currently set */
  timer = 1;			/* Flag to indicate whether a timer is to be used */

  /* If time == NULL, we don't use a timer, we block indefinately */

  if (time)
    {
      /*
       * We need to know if we have play the timer game or not
       */

      if ((timer_value = (time->tv_sec * 1000000) + (time->tv_usec)))
	timer_value += clock_ValueRough ();
    }
  else
    timer = 0;


  if (readset)
    memcpy (&temp_read, readset, sizeof (scps_fd_set));

  if (writeset)
    memcpy (&temp_write, writeset, sizeof (scps_fd_set));

  /*
   * A Truly vile hack here until I screw my head on better - this
   * needs to go out the door! - I'm terribly ashamed...
   *
   * We get wrapped up on sockets in CLOSEWT that are trying to do a read!
   */
  if (readset)
    {
      for (temp = 1; temp < (sizeof (scps_fd_set) << 3); temp++)
	{
	  socket = (tp_Socket *) scheduler.sockets[temp].ptr;

	  if (SCPS_FD_ISSET (temp, &temp_read))
	    {
	      if ((socket->Initialized == SCPSTP) &&
		  (socket->state > tp_StateESTAB))
		{
		  memset (readset, 0, sizeof (scps_fd_set));
		  SCPS_FD_SET (temp, readset);
		  return (1);
		}
	    }
	}
    }

  /*
   * Jump in here if there is a readset or writeset specified
   */

  if (temp_read || temp_write)
    {
      /* 
       * Mask in the current readable/writeable sockets
       */

      /*
       * Build the list of readable sockets
       */
      if (readset)
	{
	  if ((socket = (tp_Socket *) scheduler.current->read_socks))
	    {
	      while (socket)
		{
		  if (socket->app_rbuff->size)
		    {
		      ADD_READ (socket);
		      ((int32_t *) readset)[(socket->sockid) / (sizeof (int32_t) *
							     8)] |=
		        (1 << ((socket->sockid) % (sizeof (int32_t) * 8)));
		    }
		  else
		    ((int32_t *) readset)[(socket->sockid) / (sizeof (int32_t) *
							   8)] &=
		      ~(1 << ((socket->sockid) % (sizeof (int32_t) * 8)));
		  socket = socket->read_next;
		}
	    }
	  else			/* No readable sockets, clear readset */
	    memset (readset, 0, sizeof (scps_fd_set));

	  /*  
	   * Walk through designated sockets and if we are selecting on a
	   * listening socket, then make sure we tell the socket code to
	   * wake us upon connection establishment.
	   */

	  /* Walk through all the bytes of readset */
	  for (outer = 0; (outer < 8); outer++)
	    {
	      offset = (outer << 5);
	      for (inner = 0; (inner < (sizeof (int32_t) << 3)); inner++)
		{
		  if (((*(int *) readset[outer]) & (1 << inner)) &&
		      (socket = (tp_Socket *) (scheduler.sockets[(offset +
								  inner)].ptr)) &&
		      (socket->state == tp_StateLISTEN))
		    socket->read = 1;
		}
	    }
	}

      /*
       * Build the list of writeable sockets
       */

      if (writeset)
	{
	  if ((socket = (tp_Socket *) (scheduler.current->write_socks)))
	    {
	      while (socket)
		{
		  if (!(socket->write))
		    ((int32_t *) writeset)[(socket->sockid) / (sizeof (int32_t) *
							    8)] |=
		      (1 << ((socket->sockid) % (sizeof (int32_t) * 8)));
		  else
		    ((int32_t *) writeset)[(socket->sockid) / (sizeof (int32_t) *
							    8)] &=
		      ~(1 << ((socket->sockid) % (sizeof (int32_t) * 8)));
		  socket = socket->write_next;
		}
	    }
	  else			/* No readable sockets, clear readset */
	    memset (writeset, 0, sizeof (scps_fd_set));

	  /*  
	   * Walk through designated sockets and if we are selecting on a
	   * listening socket, then make sure we tell the socket code to
	   * wake us upon connection establishment.
	   */

	  /* Walk through all the bytes of readset */
	  for (outer = 0; (outer < 8); outer++)
	    {
	      offset = (outer << 5);
	      for (inner = 0; (inner < (sizeof (int32_t) << 3)); inner++)
		{
		  if (((*(int *) writeset[outer]) & inner) &&
		      (socket = (tp_Socket *) (scheduler.sockets[(offset +
								  inner)].ptr)) &&
		      (socket->state == tp_StateLISTEN))
		    socket->write = 1;
		}
	    }
	}

      /*
       * If the timer is set and:
       *    there is no readset defined
       *        or
       *    there is a readset defined, but no readable sockets
       * and
       *    there is no writeset defined
       *        or
       *    there is a writeset defined, but no writeable sockets
       *        
       * We block the thread and prepare to continue with the select
       *
       */

      if (timer && ((!(readset)) || ((readset) && (!(tp_Socket *)
						   (scheduler.current->read_socks))))
	  && ((!(writeset)) ||
	      ((writeset) &&
	       (!((tp_Socket
		   *) (scheduler.current->write_socks))))))
	{

	  /*
	   * Set the current threads runable status to Blocked
	   * Decrement the number of runable processes 
	   */
	  scheduler.current->status = Blocked;
	  scheduler.num_runable--;

	  /* 
	   * Cycle through all the sockets (shouldn't be!) and
	   * for each socket:
	   * 
	   * If the socket is defined in temp_read or temp_write
	   * set the socket to be waiting to read/write (whatever
	   * is appropriate) at least 1 byte;
	   *  
	   * If we are looking for a socket to attach the select_timer
	   * to (timer_index == -1) then attach it to the first socket
	   * that comes along.
	   */
	  if (timer_index == -1)
	    {
	      for (temp = 0; temp < (sizeof (scps_fd_set) << 3); temp++)
		{
		  if (((readset) && (SCPS_FD_ISSET (temp, readset))) ||
		      ((writeset) && (SCPS_FD_ISSET (temp, writeset))))
		    {
		      timer_index = temp;
		      break;
		    }
		}
	    }

	  /*    
	   * If we are running a select_timer, then set the timer
	   * for the socket we "attached" to above
	   * (specified by timer_index); This timer might be a
	   * tp_socket, but it also might be a udp_socket.
	   */

	  if (timer_value)
	    {
	      socket = ((tp_Socket *) scheduler.sockets[timer_index].ptr);
	      if (socket->Initialized == SCPSTP)
		{
		  /* socket->timers[Select] = time; */
		  set_timer (time, socket->otimers[Select], 1);
		}
	      else
		{
		  /* (udp_Socket *)socket->select_timer = timer_value; */
		  set_timer (time, socket->otimers[Select], 1);
		}
	    }

	  /* 
	   * Value represents the number of sockets specified in
	   * the union of the specified read/write sets that are
	   * available for reading/writing.
	   * 
	   * We walk through each readable and writeable socket  
	   * and check if the socket is specified in the mask, if
	   * so, there is no need to be waiting on a timer.
	   */
	  value = 0;

	  for ((socket = (tp_Socket *) scheduler.current->read_socks);
	       (socket); socket = socket->read_next)
	    {
	      if ((readset) && (SCPS_FD_ISSET (socket->sockid, readset)))
		value++;
	    }

	  for (socket = ((tp_Socket *) scheduler.current->write_socks);
	       (socket); socket = socket->write_next)
	    {
	      if ((writeset) && (SCPS_FD_ISSET (socket->sockid, writeset)))
		value++;
	    }

	}

      /*   
       * If there are no specified sockets available
       * and there is a timer_value (zero is acceptable)  
       * then put the thread to sleep until scheduler       
       * wakes us up again
       */

      if (!(value) && (timer_value))
	sched ();

      /*          
       * Otherwise, we're not waiting around; There was
       * either a non-blocking select or there was at
       * least one specified socket available (value >= 1)
       */

      else
	{
	  if (scheduler.current->status != Ready)
	    {
	      scheduler.current->status = Ready;
	      scheduler.num_runable++;
	    }
	}

      /*   
       * This is the return from the scheduler (if we slept at all)
       */

      /*  
       * Clear the Select timer...
       */

      if (timer_index != -1)
	{
	  socket = (tp_Socket *) scheduler.sockets[timer_index].ptr;

	  if (socket->Initialized == SCPSTP)
	    {
	      socket->timers[Select] = 0;
	      clear_timer (socket->otimers[Select], 1);
	    }
	  else
	    {
	      ((udp_Socket *) socket)->select_timer = 0;
	      clear_timer (socket->otimers[Select], 1);
	    }
	}
      /* 
       * Realign the currently available read/write socket sets
       */

#ifdef FIX_ME			/* - What the heck is this?!? */
      /*    
       * Rebuild the list of readable sockets
       */
      if (readset)
	*readset = (temp_read & scheduler.current->read_socks);

      /* 
       * Rebuild the list of writeable sockets
       */
      if (writeset)
	*writeset = (temp_write & scheduler.current->write_socks);
#endif /* FIX_ME */

      /*    
       * Determine the number of available sockets
       */

      value = 0;

      for (socket = (tp_Socket *) scheduler.current->read_socks; (socket);
	   socket = socket->read_next)
	{
	  socket->read = 0;
	  /* If the socket is in the original mask, increment count */
	  if ((readset) && (SCPS_FD_ISSET (socket->sockid, &temp_read)))
	    {
	      ((int32_t *) readset)[(socket->sockid) / (sizeof (int32_t) * 8)] |=
	        (1 << ((socket->sockid) % (sizeof (int32_t) * 8)));
	      value++;
	    }
	}

      for (socket = (tp_Socket *) scheduler.current->write_socks; (socket);
	   socket = socket->write_next)
	{
	  socket->write = 0;
	  if ((writeset) && (SCPS_FD_ISSET (socket->sockid, &temp_write)))
	    {
	      ((int32_t *) writeset)[(socket->sockid) / (sizeof (int32_t) * 8)] |=
	        (1 << ((socket->sockid) % (sizeof (int32_t) * 8)));
	      value++;
	    }
	}

      return (value);
    }
  /* Otherwise, we've got an error */
  SET_ERR (SCPS_EINVAL);
  return (-1);
}
#else /* GATEWAY_SELECT */
int
scps_select (int sockid, scps_fd_set * readset,
	     scps_fd_set * writeset, scps_fd_set * nullval, struct timeval *time)
{
  unsigned int temp_read = 0, temp_write = 0;
  int timer, timer_index, temp;
  uint32_t timer_value = 0;
  int value = 0;

  SET_ERR (0);
  sched ();

  timer_index = -1;		/* No timer currently set */
  timer = 1;			/* Flag to indicate whether a timer is to be used */

  /* If time == NULL, we don't use a timer, we block indefinately */

  if (time)
    {
      if ((timer_value = (time->tv_sec * 1000000) + (time->tv_usec)))
	timer_value += clock_ValueRough ();
    }
  else
    timer = 0;

  if (readset)
    temp_read = *readset;
  if (writeset)
    temp_write = *writeset;

  /*    
   * A Truly vile hack here until I screw my head on better - this
   * needs to go out the door! - I'm terribly ashamed...
   *        
   * We get wrapped up on sockets in CLOSEWT that are trying to do a read!  
   */
  if (readset)
    {
      for (temp = 1; temp < MAX_SCPS_SOCKET; temp++)
	{
	  if (temp_read & (1 << temp))
	    {
	      if ((((tp_Socket *) scheduler.sockets[temp].ptr)->Initialized
		   == SCPSTP)
		  && (((tp_Socket *) scheduler.sockets[temp].ptr)->state > tp_StateESTAB))
		{
		  *readset = (1 << temp);
		  return (1);
		}
	    }
	}
    }

  for (temp = 1; temp < MAX_SCPS_SOCKET; temp++)
    {
      if (temp_read & (1 << temp))
	scheduler.sockets[temp].read = 0;
      if (temp_write & (1 << temp))
	scheduler.sockets[temp].write = 0;
      if ((readset) && (*readset & (1 << temp)))
	value++;
      if ((writeset) && (*writeset & (1 << temp)))
	value++;
    }

  if (temp_read || temp_write)
    {
      if (readset)
	*readset &= scheduler.current->read_socks;
      if (writeset)
	*writeset &= scheduler.current->write_socks;

      if (timer && ((!(readset)) || ((readset) && (!(*readset))))
	  && ((!(writeset)) || ((writeset) && (!(*writeset)))))
	{
	  scheduler.current->status = Blocked;
	  scheduler.num_runable--;

	  for (temp = 0; temp < MAX_SCPS_SOCKET; temp++)
	    {
	      if (temp_read & (1 << temp))
		{
		  scheduler.sockets[temp].read = 1;
		  if (timer_index == -1)
		    timer_index = temp;
		}
	      if (temp_write & (1 << temp))
		{
		  scheduler.sockets[temp].write = 1;
		  if (timer_index == -1)
		    timer_index = temp;
		}
	    }

	  /*      
	   * Something hideous... but it'll get us a select-timer:
	   * (1) We set a "select-timer" on the first socket in the list;
	   * (2) When we return from sched(), if this timer's value is now
	   *     zero, we've hit the end, set SET_ERR();
	   * (3) Otherwise, reset the timer's value to 0 to avoid confusion.
	   */

	  if (timer_value)
	    {
	      if (((tp_Socket *)
		   scheduler.sockets[timer_index].ptr)->Initialized == SCPSTP)
		{
		  ((tp_Socket *) scheduler.sockets[timer_index].ptr)->timers[Select]
		    = timer_value;
		  set_timer (time, ((tp_Socket
				     *)
				    scheduler.sockets[timer_index].ptr)->otimers[Select], 1);
		}
	      else
		((udp_Socket *) scheduler.sockets[timer_index].ptr)->select_timer
		  = timer_value;
	    }

	  value = 0;

	  for (temp = 1; temp < MAX_SCPS_SOCKET; temp++)
	    {
	      if (temp_read & ((1 << temp) ||
			       (((tp_Socket *)
				 scheduler.sockets[temp].ptr)->app_rbuff->size
				>= scheduler.sockets[temp].read)))
		{
		  scheduler.sockets[temp].read = 0;
		  temp_read |= (1 << temp);
		  value++;
		}
	      if (temp_write & ((1 << temp) ||
				((((tp_Socket *)
				   scheduler.sockets[temp].ptr)->send_buff->max_size
				  - (((tp_Socket *)
				      scheduler.sockets[temp].ptr)->seqnum -
				     ((tp_Socket
				       *)
				      scheduler.sockets[temp].ptr)->snduna)) >=
				 scheduler.sockets[temp].write)))
		{
		  scheduler.sockets[temp].write = 0;
		  temp_write |= (1 << temp);
		  value++;
		}
	      if ((readset) && (*readset & (1 << temp)))
		value++;
	      if ((writeset) && (*writeset & (1 << temp)))
		value++;
	    }

	  if (!(value) && (timer_value))
	    sched ();
	  else
	    {
	      if (scheduler.current->status != Ready)
		{
		  scheduler.current->status = Ready;
		  scheduler.num_runable++;
		}
	    }

	  if (((tp_Socket *)
	       scheduler.sockets[timer_index].ptr)->Initialized == SCPSTP)
	    {
	      ((tp_Socket *)
	       scheduler.sockets[timer_index].ptr)->timers[Select] = 0;
	      clear_timer (((tp_Socket
			     *)
			    scheduler.sockets[timer_index].ptr)->otimers[Select], 1);
	    }
	  else
	    ((udp_Socket *)
	     scheduler.sockets[timer_index].ptr)->select_timer = 0;

	  if (readset)
	    *readset = (temp_read & scheduler.current->read_socks);
	  if (writeset)
	    *writeset = (temp_write & scheduler.current->write_socks);
	}

      value = 0;

      for (temp = 1; temp < MAX_SCPS_SOCKET; temp++)
	{
	  if (temp_read & (1 << temp))
	    scheduler.sockets[temp].read = 0;
	  if (temp_write & (1 << temp))
	    scheduler.sockets[temp].write = 0;
	  if ((readset) && (*readset & (1 << temp)))
	    value++;
	  if ((writeset) && (*writeset & (1 << temp)))
	    value++;
	}
      return (value);
    }
  /* Otherwise, we've got an error */
  SET_ERR (SCPS_EINVAL);
  return (-1);
}
#endif /* GATEWAY_SELECT */

/*
 * Send a FIN on a particular port -- only works if it is open
 */
int
scps_close (int sockid)
{
  int retval = 0;

  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;

  SET_ERR (0);
  sched ();

  if ((sockid < 0) || (!(s)) || (s->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      retval = -1;
    }
  else
    {
      switch (s->Initialized)
	{
	case SCPSTP:
	  retval = tp_Close (sockid);
	  break;
	case SCPSUDP:
	  retval = udp_Close (sockid);
	  break;
	default:
	  SET_ERR (SCPS_EBADF);
	  retval = -1;
	}
    }
  return (retval);
}

int
scps_read (int sockid, void *data, int size)
{
  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;
  int retval = 0;
  SET_ERR (0);

  sched ();

  if ((!(s)) || (s->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      retval = -1;
    }

  else
    {
      switch (s->Initialized)
	{
	case SCPSTP:
	  retval = tp_Read (sockid, data, size);
	  break;
	case SCPSUDP:
	  retval = udp_Read (sockid, data, size);
	  break;
	default:
	  SET_ERR (SCPS_EBADF);
	  retval = -1;
	}
    }
  return (retval);
}

int
scps_write (int sockid, void *dp, int len)
{
  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;
  int push = 0;
  int retval = 0;

  SET_ERR (0);
  sched ();

  if ((!(s)) || (s->thread != scheduler.current))
    {
#ifdef SOCKET_DEBUG
      printf ("In scps_write bad socket %d %x\n", sockid, s);
#endif /* SOCKET_DEBUG */
      SET_ERR (SCPS_EBADF);
      retval = -1;
    }

  else
    {
      switch (s->Initialized)
	{
	case SCPSTP:
	  if (s->sockFlags & SOCK_NDELAY)
	    push = 1;

	  if (s->sockFlags & SOCK_ATOMIC)
	    push = 2;

	  retval = tp_Write (sockid, dp, len, push);
	  break;

	case SCPSUDP:
#ifndef IPV6
          if ((((udp_Socket *) s)->his_ipv4_addr) && (((udp_Socket *) s)->hisport))
            retval =
              (udp_WriteTo (sockid, dp, len, ((udp_Socket *) s)->his_ipv4_addr,
                            ((udp_Socket *) s)->hisport));
#else /* IPV6 */
         if (((tp_Socket *) s) ->nl_protocol_id == NL_PROTOCOL_IPV4) {
          if ((((udp_Socket *) s)->his_ipv4_addr) && (((udp_Socket *) s)->hisport))
            retval =
              (udp_WriteTo (sockid, dp, len, ((udp_Socket *) s)->his_ipv4_addr,
                            ((udp_Socket *) s)->hisport));
         }

         if (((tp_Socket *) s) ->nl_protocol_id == NL_PROTOCOL_IPV6) {
//        if ((((udp_Socket *) s)->his_ipv6_addr.addr[0]) && (((udp_Socket *) s)->hisport))
//          retval =
//            (udp_WriteTo (sockid, dp, len, ((udp_Socket *) s)->his_ipv6_addr,
//                          ((udp_Socket *) s)->hisport));
         }
#endif /* IPV6 */
	  else
	    {
	      SET_ERR (SCPS_EINVAL);
	      retval = -1;
	    }
	  break;

	default:
	  SET_ERR (SCPS_EBADF);
	  retval = -1;
	}
    }
  return (retval);
}

int
scps_connect (int sockid, void *ina, int addrlen)
{
  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;
  udp_Socket *u = (udp_Socket *) scheduler.sockets[sockid].ptr;
  int retval = 0;
  SET_ERR (0);

  sched ();

  if ((!(s)) || (s->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      retval = -1;
    }
  else
    {
      switch (s->Initialized)
	{
	case SCPSTP:
	  retval = tp_Connect (sockid, ina, addrlen);
	  break;

	case SCPSUDP:
#ifndef IPV6
          memcpy (&(u->his_ipv4_addr), &(((struct sockaddr_in *) ina)->sin_addr),
                  sizeof (uint32_t));
          memcpy (&(u->hisport), &(((struct sockaddr_in *) ina)->sin_port),
                  sizeof (u_short));
#else /* IPV6 */
         if (((tp_Socket *) socket) ->nl_protocol_id == NL_PROTOCOL_IPV4) {
             memcpy (&(u->his_ipv4_addr), &(((struct sockaddr_in *) ina)->sin_addr),
                  sizeof (uint32_t));
             memcpy (&(u->hisport), &(((struct sockaddr_in *) ina)->sin_port),
                  sizeof (u_short));
         }

         if (((tp_Socket *) socket) ->nl_protocol_id == NL_PROTOCOL_IPV6) {
             memcpy (&(u->his_ipv6_addr), &(((struct sockaddr_in6 *) ina)->sin6_addr),
                  sizeof (struct ipv6_addr));
             memcpy (&(u->hisport), &(((struct sockaddr_in6 *) ina)->sin6_port),
                  sizeof (u_short));
         }
#endif /* IPV6 */

	  break;

	default:
	  SET_ERR (SCPS_EBADF);
	  retval = -1;
	}
    }
  return (retval);
}

int
scps_getpeername (int sockid, void *ina, int *addrlen)
{
  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;
  unsigned int intarg;
  uint32_t longarg;
  int retval = 0;
  SET_ERR (0);

  sched ();

  if ((!(s)) || (s->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  else
    {
      *addrlen = sizeof (struct sockaddr_in);

      switch (s->Initialized)
	{
	case SCPSTP:
	case SCPSUDP:
	  {
	    if (((s->state > tp_StateSYNREC) && (s->state < tp_StateCLOSED))
		|| (s->Initialized == SCPSUDP))
	      {
		intarg = htons (s->hisport);
		longarg = s->his_ipv4_addr;
		memcpy (&(((struct sockaddr_in *) ina)->sin_addr), &longarg,
			sizeof (uint32_t));
		memcpy (&(((struct sockaddr_in *) ina)->sin_port), &intarg,
			sizeof (u_short));
	      }
	    else
	      {
		SET_ERR (SCPS_ENOTCONN);
		retval = -1;
	      }
	    break;
	  }

	default:
	  {
	    SET_ERR (SCPS_ENOTSOCK);
	    retval = -1;
	  }
	}
    }
  return (retval);
}

int
scps_getsockname (int sockid, void *ina, int *addrlen)
{
  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;
  int retval = 0;
  SET_ERR (0);

  sched ();

  if ((!(s)) || (s->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      retval = -1;
    }

  else
    {
      switch (s->Initialized)
	{
	case SCPSTP:
	case SCPSUDP:
	  {
	    memcpy (&(((struct sockaddr_in *) ina)->sin_addr), &(s->my_ipv4_addr),
		    sizeof (uint32_t));
	    memcpy (&(((struct sockaddr_in *) ina)->sin_port), &(s->myport),
		    sizeof (u_short));
	    break;
	  }

	default:
	  SET_ERR (SCPS_ENOTSOCK);
	  retval = -1;
	}
    }
  return (retval);
}

struct protoent *
scps_getprotobyname (char *name)
{
  struct protoent *entity =
    (struct protoent *) malloc (sizeof (struct protoent));
  SET_ERR (0);

  if (!(strcmp ("scpstp", name)))
    {
      entity->p_name = "scpstp" "\0";
      entity->p_aliases = NULL;
      entity->p_proto = PROTO_SCPSTP;
    }
  else if (!(strcmp ("scpsudp", name)))
    {
      entity->p_name = "scpsudp" "\0";
      entity->p_aliases = NULL;
      entity->p_proto = PROTO_SCPSUDP;
    }
  else
    entity = getprotobyname (name);

  return (entity);
}

/*
 * Actively open a TP connection to a particular destination.
 */
int
tp_Connect (int sockid, void *ina, int addrlen)
{

  struct mbuff *mbuffer;
  struct timeval mytime;
  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;
  SET_ERR (0);

  /* If tp_common returns a value of -1, the socket
   * is otherwise unavailable for use (see resulting 
   * errno value), so let the caller know there is a
   * problem.
   */

  sched ();

  if ((!(s)) || (s->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  if (addrlen != sizeof (struct sockaddr_in))
    {
      SET_ERR (SCPS_EFAULT);
    }

  if (tp_Common (s) < 0) {
      return (-1);
  }

  s->state_prev = tp_StateCLOSED;	/* Might have been tp_StateNASCENT */
  s->state = tp_StateSYNSENT;

  s->np_rqts.tpid = SCPSTP;
  s->nl_protocol_id = s->np_rqts.nl_protocol;
#ifndef IPV6
  memcpy (&(s->np_rqts.ipv4_dst_addr), &(((struct sockaddr_in *) ina)->sin_addr),
          sizeof (uint32_t));
  s->np_rqts.ipv4_dst_addr = ntohl (s->np_rqts.ipv4_dst_addr);
#else /* IPV6 */
         if (((tp_Socket *) s) ->nl_protocol_id == NL_PROTOCOL_IPV4) {
                memcpy (&(s->np_rqts.ipv4_dst_addr), &(((struct sockaddr_in *) ina)->sin_addr),
                  sizeof (u_long));
                s->np_rqts.ipv4_dst_addr = ntohl (s->np_rqts.ipv4_dst_addr);
         }

         if (((tp_Socket *) s) ->nl_protocol_id == NL_PROTOCOL_IPV6) {

                memcpy (&(s->np_rqts.ipv6_dst_addr), &(((struct sockaddr_in6 *) ina)->sin6_addr),
                  sizeof (struct ipv6_addr));
                ntoh16 (s->np_rqts.ipv6_dst_addr.addr, s->np_rqts.ipv6_dst_addr.addr);

         }

#endif /* IPV6 */

#ifdef GATEWAY

  s->nl_protocol_id = s->np_rqts.nl_protocol;

#ifndef IPV6
  if (s->np_rqts.ipv4_src_addr)
    {
      s->np_rqts.ipv4_src_addr = ntohl (s->np_rqts.ipv4_src_addr);
      s->ph.nl_head.ipv4.src = htonl (s->np_rqts.ipv4_src_addr);
    }
  else
    {
      s->np_rqts.ipv4_src_addr = ntohl (local_addr);
      s->ph.nl_head.ipv4.src = htonl (s->np_rqts.ipv4_src_addr);
    }
#else /* IPV6 */
         if (((tp_Socket *) s) ->nl_protocol_id == NL_PROTOCOL_IPV4) {
          if (s->np_rqts.ipv4_src_addr) {
              s->np_rqts.ipv4_src_addr = ntohl (s->np_rqts.ipv4_src_addr);
              s->ph.nl_head.ipv4.src = htonl (s->np_rqts.ipv4_src_addr);
            } else {
              s->np_rqts.ipv4_src_addr = ntohl (local_addr);
              s->ph.nl_head.ipv4.src = htonl (s->np_rqts.ipv4_src_addr);
            }
         }

         if (((tp_Socket *) s) ->nl_protocol_id == NL_PROTOCOL_IPV6) {
          if (s->np_rqts.ipv6_src_addr.addr[0]) {
              ntoh16 (s->np_rqts.ipv6_src_addr.addr, s->np_rqts.ipv6_src_addr.addr);
              ntoh16 (s->ph.nl_head.ipv6.src.addr, s->np_rqts.ipv6_src_addr.addr);
            } else { /* PDF NEED TO FIX LATER XXX PDF XXX */
              s->np_rqts.ipv4_src_addr = ntohl (local_addr);
            }
         }
#endif /* IPV6 */

#else /* GATEWAY */

#ifndef IPV6
  s->np_rqts.ipv4_src_addr = ntohl (local_addr);
#else /* IPV6 */
// PDF NEED TO FIX LATER XXX PDF XXX
#endif /* IPV6 */

#endif /* GATEWAY */
  if (s->myport == 0)
    s->myport = htons (scheduler.tp_ephemeral_next++);

    if (scheduler.tp_ephemeral_next > 64000) {
        scheduler.tp_ephemeral_next = 5001;
    }

#ifdef SCPSSP
  /* Fill in the SP requirements structure */
  /* PDF Changed this around to set deafult parameters when the socket
     is opened */
  s->sp_rqts.np_rqts.tpid = SP;


#ifndef IPV6
  s->sp_rqts.np_rqts.ipv4_dst_addr = (s->np_rqts.ipv4_dst_addr);
#else /* IPV6 */
         if (((tp_Socket *) s) ->nl_protocol_id == NL_PROTOCOL_IPV4) {
          s->sp_rqts.np_rqts.ipv4_dst_addr = (s->np_rqts.ipv4_dst_addr);
         }
         if (((tp_Socket *) s) ->nl_protocol_id == NL_PROTOCOL_IPV6) {
          memcpy (s->sp_rqts.np_rqts.ipv6_dst_addr.addr, s->np_rqts.ipv6_dst_addr.addr, sizeof (struct ipv6_addr));
	 }
#endif /* IPV6 */

  s->sp_rqts.np_rqts.bqos.precedence = s->np_rqts.bqos.precedence;
#ifndef IPV6

#ifdef GATEWAY
  s->sp_rqts.np_rqts.ipv4_src_addr = (s->np_rqts.ipv4_src_addr);
#else /* GATEWAY */
  s->sp_rqts.np_rqts.ipv4_src_addr = ntohl (local_addr);
#endif /* GATEWAY */
  s->np_rqts.tpid = SP;

#else /* IPV6 */

         if (((tp_Socket *) socket) ->nl_protocol_id == NL_PROTOCOL_IPV4) {
#ifdef GATEWAY
          s->sp_rqts.np_rqts.ipv4_src_addr = (s->np_rqts.ipv4_src_addr);
#else /* GATEWAY */
          s->sp_rqts.np_rqts.ipv4_src_addr = ntohl (local_addr);
#endif /* GATEWAY */
          s->np_rqts.tpid = SP;
         }

         if (((tp_Socket *) socket) ->nl_protocol_id == NL_PROTOCOL_IPV6) {
#ifdef GATEWAY
          memcpy (s->sp_rqts.np_rqts.ipv6_src_addr.addr, s->np_rqts.ipv6_src_addr.addr, sizeof (struct ipv6_addr));
#else /* GATEWAY */
// PDF XXX HELP
          s->sp_rqts.np_rqts.ipv4_src_addr = ntohl (local_addr);
#endif /* GATEWAY */
          s->np_rqts.tpid = SP;
         }
#endif /* IPV6 */

#endif /* SCPSSP */

#ifdef SCPSSP
  s->sp_size = sp_hdr_size (s->sp_rqts);
#endif /* SCPSSP */

  switch (s->np_rqts.nl_protocol) { 
        case NL_PROTOCOL_IPV4:
                s->np_size = ip_get_template (&(s->np_rqts), &(s->ip_templ));
                s->ip_templ.nl_head.ipv4.identification = htons (tp_id++);
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

#ifndef IPV6
  memcpy (&(s->his_ipv4_addr), &(((struct sockaddr_in *) ina)->sin_addr),
          sizeof (uint32_t));
  memcpy (&(s->hisport), &(((struct sockaddr_in *) ina)->sin_port),
          sizeof (u_short));
  memcpy (&(s->ph.nl_head.ipv4.dst), &(((struct sockaddr_in *) ina)->sin_addr),
          sizeof (uint32_t));
#else /* IPV6 */
  switch (s->np_rqts.nl_protocol) {
        case NL_PROTOCOL_IPV4:
        case NL_PROTOCOL_NP:
                  memcpy (&(s->his_ipv4_addr), &(((struct sockaddr_in *) ina)->sin_addr),
                        sizeof (uint32_t));
                  memcpy (&(s->hisport), &(((struct sockaddr_in *) ina)->sin_port),
                        sizeof (u_short));
                  memcpy (&(s->ph.nl_head.ipv4.dst), &(((struct sockaddr_in *) ina)->sin_addr),
                        sizeof (uint32_t));
                break;
        case NL_PROTOCOL_IPV6:
                  memcpy (&(s->his_ipv6_addr), &(((struct sockaddr_in6 *) ina)->sin6_addr), 16);
                  memcpy (&(s->hisport), &(((struct sockaddr_in6 *) ina)->sin6_port), sizeof (u_short));
                  memcpy (&(s->ph.nl_head.ipv6.dst), &(((struct sockaddr_in6 *) ina)->sin6_addr), 16);
                break;
  }
#endif /* IPV6 */

  tp_mss (s, 0);		/* set the maximum segment size */

  if (s->rt_route->SMTU) { 
    s->maxdata = min (s->maxdata, s->rt_route->SMTU - tp_hdr_size () - s->np_size - s->sp_size - TP_HDR_LEN);
  }

  mytime.tv_sec = 0;
#ifdef OLD_CODE
  mytime.tv_usec =
    max (((s->t_srtt >> (TP_RTT_SHIFT - 1)) + ((s->t_rttvar>>TP_RTTVAR_SHIFT) << 2)),
	 s->RTOMIN);
  mytime.tv_usec = min(mytime.tv_usec, s->RTOMAX);
#endif /* OLD_CODE */
  mytime.tv_usec = s->rt_route->initial_RTO;
  s->t_rxtcur = mytime.tv_usec;
  mytime.tv_usec = min(mytime.tv_usec, s->RTOMAX);
  /* Intentionally don't clamp against RTOMAX here;  If you set the initial RTO
   * specifically very large, so be it.
   */

  if (!s->otimers[Rexmit]->expired) {
    set_timer (&mytime, s->otimers[Rexmit], 1);
  }

  /* Debug print RTO value after call to tp_BuildHdr, which sets the
   * initial seqnum
   */

#ifdef OPT_COMPRESS
  if (s->capabilities & CAP_COMPRESS)
    {
      if (s->rt_route->flags & RT_COMPRESS)
	{
	  s->sockFlags |= TF_REQ_COMPRESS;	/* compression request */
	  s->local_conn_id = (global_conn_ID++ & 0xff);
	  if (!s->local_conn_id)
	    {
	      global_conn_ID++;
	      s->local_conn_id++;
	    }
	}
    }
#endif /* OPT_COMPRESS */

  PRINT_STATE (s->state, s);
  if (s->sockFlags & SOCK_BL)
    {
      /* Block the application until the socket is writable. */
      s->thread->status = Blocked;
      scheduler.num_runable--;
#ifdef GATEWAY_SELECT
      ((tp_Socket *) scheduler.sockets[sockid].ptr)->write = 1;
#else /* GATEWAY_SELECT */
      scheduler.sockets[sockid].write = 1;
#endif /* GATEWAY_SELECT */
    }

  if ((s->send_buff->b_size < s->send_buff->max_size) &&
      (mbuffer = tp_BuildHdr (s, NULL, 0)))
    {
      enq_mbuff (mbuffer, s->send_buff);
      if (!(s->send_buff->send))
	s->send_buff->send = s->send_buff->last;

      if (s->send_buff->send)
	tp_NewSend (s, NULL, false);
      if (s->sockFlags & SOCK_BL)
	{
	  sched ();		/* Hang around until we've connected... */
#ifdef GATEWAY_SELECT
	  ((tp_Socket *) scheduler.sockets[sockid].ptr)->write = 0;
#else /* GATEWAY_SELECT */
	  scheduler.sockets[sockid].write = 0;
#endif /* GATEWAY_SELECT */
	  /* We might have lost the connection while sleeping... */
	  if (s->state == tp_StateCLOSED)
	    {
	      SET_ERR (SCPS_ECONNABORTED);
	      return (-1);
	    }
	}
      else
	{
	  SET_ERR (SCPS_EINPROGRESS);
	  return (-1);
	}
#ifdef DEBUG_XPLOT
      /* Plot a pink line to the right of and slightly above
       * the segment that
       * stops where the retransmission timer for that segment
       * would expire.
       */
      logEventv(s, xplot, "pink\nline %s %u %s %u\n",
		stringNow2(),
		s->initial_seqnum+7,
		stringNow3((double) mytime.tv_usec/1000000),
		s->initial_seqnum+7);
      logEventv(s, xplot, "rarrow %s %u\n",
		stringNow2(),
		s->initial_seqnum+7);
      logEventv(s, xplot, "larrow %s %u\n",
		stringNow3((double) mytime.tv_usec/1000000),
		s->initial_seqnum+7);
#endif /* DEBUG_XPLOT  */
      return (0);
    }
  else
    {
      SET_ERR (SCPS_ENOMEM);
      return (-1);
    }
}

/*
 * Passive open: listen for a connection on a particular port
 */
int
scps_listen (int sockid, int backlog)
{
  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;
  SET_ERR (0);

  /* If tp_common returns a value of -1, the socket
   * is otherwise unavailable for use (see resulting 
   * errno value), so let the caller know there is a
   * problem.
   */

  sched ();

  if ((!(s)) || (s->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  if (s->myport == 0)
    return (-1);

  tp_mss (s, 0);		/* provisional mss setup */
  s->state_prev = tp_StateCLOSED;	/* Might have been tp_StateNASCENT */
  s->state = tp_StateLISTEN;
  PRINT_STATE (s->state, s);

  s->timeout = 0x7ffffff;	/* forever... */

  clear_timer (s->otimers[Rexmit], 1);
  s->hisport = 0;
#ifndef IPV6
  s->ph.nl_head.ipv4.dst = 0;
#endif /* IPV6 */
  s->link_outage = 0;		/* forced for now */
  return (0);
}

/*
 * Send a FIN on a particular port -- only works if it is open
 */
int
tp_Close (int sockid)
{
  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;
  SET_ERR (0);

  sched ();

  if ((!(s)) || (s->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  switch (s->state)
    {
    case tp_StateLISTEN:
    case tp_StateNASCENT:
    case tp_StateSYNSENT:
      {
	tp_Unthread (s);
	return (0);

	break;
      }

    case tp_StateCLOSEWT:
    case tp_StateESTAB:
    case tp_StateSYNREC:
      {

       if (s->state == tp_StateCLOSEWT)
          {
            struct timeval mytime;
            s->state_prev = s->state;
            s->state = tp_StateWANTTOLAST;
                  
            /* PDF We are setting the Time Wait timer.  If the original ACK
               for the FIN gets lost, the remote side process may terminate
               and only timing-out after many RTOs will terminate the
               socket. */
            s->timeout = s->TWOMSLTIMEOUT;
            mytime.tv_sec = s->TWOMSLTIMEOUT;
            mytime.tv_usec = 0;
            set_timer (&mytime, s->otimers[TW], 1);
            PRINT_STATE (s->state, s);
          }
	else
          {
	    s->state_prev = s->state;
	    s->state = tp_StateWANTTOCLOSE;
	    PRINT_STATE (s->state, s);
	  }

	tp_Flush (s);

	return (0);
      }
    }
  SET_ERR (SCPS_EBADF);
#ifdef GATEWAY
  s->gateway_flags |= GATEWAY_SEND_FIN;
#endif /* GATEWAY */
  return (-1);
}

/*
 * Abort a tp connection
 */
int
tp_Abort (int sockid)
{
  struct mbuff *mbuffer;
  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;
  int bytes_sent  = 0;
  int rc = 0;

#ifdef RESET_NOT_YET
  int failed = 0;
  reset_Socket *tmp = socs_to_reset;
  reset_Socket *prev = socs_to_reset;
  reset_Socket *new = NULL;
#endif /* RESET_NOT_YET */
  SET_ERR (0);

  sched ();

#ifndef GATEWAY_SINGLE_THREAD
  if ((!(s)) || ((scheduler.current->pid != 1) && (s->thread != scheduler.current)))
    {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }
#endif /* GATEWAY_SINGLE_THREAD */

  if (!s) { /* PDF XXX */
	return (-1);
  }

  if (!s->rt_route) { printf ("%s %d abort no rt_route %d\n",__FILE__, __LINE__, s->sockid); s->rt_route = def_route;}
  if ((s->state != tp_StateLISTEN) && (s->state != tp_StateCLOSED) &&
      (s->state != tp_StateTIMEWT))
    {
      s->flags = tp_FlagRST | tp_FlagACK;
      s->lastack = s->acknum;
      s->lastuwe = s->acknum + s->rcvwin;
      /* Create a packet in an mbuffer before calling tp_Send */
      /*
       * NOTE:  need to not fail due to unavailability of an
       * mbuffer
       */
      if ((mbuffer = tp_BuildHdr (s, NULL, 0)))
	{
	  bytes_sent = tp_NewSend (s, mbuffer, true);
          if (bytes_sent <= 0) {
#ifdef RESET_NOT_YET
                failed = 1;
#endif /* RESET_NOT_YET */
          }
	  free_mbuff (mbuffer);
	} else {
#ifdef RESET_NOT_YET
          failed = 1;
	  printf("Can't sent RST due to unavailablity of mbuffer!\n");
#endif /* RESET_NOT_YET */
	}

#ifdef RESET_NOT_YET
      if (failed) {
          int found = 0;

      /* Check to see if s is on socs_to_reset */
          while (tmp) {
              if (tmp->s == s) {
                  found = 1;
              }
              tmp = tmp -> next;
          }

          if (found) {
              return(0);
          } else {
              new  = (reset_Socket*) malloc (sizeof (reset_Socket));
              new ->s = s;
              new ->next = NULL;
              if (socs_to_reset) {
                  new->next = socs_to_reset;
                  socs_to_reset = new;
              } else {
                  socs_to_reset = new;
              }
          }
          s->state = tp_StateCLOSED;
          return (0);
      }
#endif /* RESET_NOT_YET */
    }


#ifdef RESET_NOT_YET
  tmp = socs_to_reset;
  if (tmp) {
      if (tmp ->s == s) {
          socs_to_reset = tmp ->next;
          free (tmp);
          tmp = NULL;
          rc = 1;
      } else {
          prev = tmp;
          tmp = tmp ->next;
          while (tmp) {
              if (tmp->s == s) {
                  prev->next = tmp ->next;
                  free (tmp);
                  tmp = NULL;
                  rc = 1;
              } else {
                 tmp = tmp -> next;
                 prev = prev ->next;
              }
          }
       }
  }
#endif /* RESET_NOT_YET */

  s->state_prev = 0;
  s->state = tp_StateCLOSED;
  PRINT_STATE (s->state, s);
  clear_timer (s->otimers[Rexmit], 1);
  clear_timer (s->otimers[TW], 1); /* PDF XXX */

  /* If there is a process sleeping on this socket, wake it up */

#ifndef GATEWAY_SINGLE_THREAD
  if (s->thread->status == Blocked)
    {
      s->thread->status = Ready;
      scheduler.num_runable++;
      sched ();
    }
#endif  /* GATEAWAY_SINGLE_THREAD */

  s->state_prev = 0;
  s->state = tp_StateCLOSED;

  tp_Unthread (s);
  return (rc);
}

int
scps_shutdown (int sockid, int how)
{
  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;
  int ret_val = 0, err_val = 0;
  SET_ERR (0);

  sched ();

  if ((!(s)) || (s->thread != scheduler.current))
    {
      err_val = SCPS_EBADF;
      ret_val = -1;
    }
  else
    {
      switch (s->Initialized)
	{
	case SCPSTP:
	  {
	    if (how == 2)
	      ret_val = tp_Abort (sockid);
	    else		/* We really should handle 0 & 1 properly... eventually */
	      ret_val = tp_Close (sockid);
	    break;
	  }
	case SCPSUDP:
	  ret_val = udp_Close (sockid);
	  break;
	default:
	  SET_ERR (SCPS_EBADF);
	  ret_val = -1;
	}
    }
  if (err_val)
    SET_ERR (err_val);
  return (ret_val);
}

/*
 * Write data to a connection. Returns number of bytes written, 
 * == 0 when connection is not in established state.
 */
int
tp_Write (int sockid, void *dp, int len, int push)
{
  int count = 0, value;
  int ret_val = 0, err_val = 0;
  struct mbuff *mbuffer = NULL;
  int blen;
  int is_rec_bound = 0;

  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;

  SET_ERR (0);
  sched ();

  /*
   * tp_Write() is obviously going to be dealing with 
   * the socket's app_sbuff, so let's keep that in mind.
   */

  /*
   * Philosphical thing here, why not allow data 
   * to queue on a pending connection?
   */

  if ((!(s)) || (s->thread != scheduler.current))
    {
      err_val = SCPS_EBADF;
      ret_val = -1;
      goto Write_Done;
    }

  switch (s->state)
    {
    case tp_StateNASCENT:
    case tp_StateCLOSED:
      {
	err_val = SCPS_EBADF;
	ret_val = -1;
	goto Write_Done;
      }
    case tp_StateLISTEN:
    case tp_StateSYNREC:
    case tp_StateSYNSENT:	/* This REALLY should enqueue the data */
      {
	err_val = SCPS_EWOULDBLOCK;
	ret_val = -1;
	goto Write_Done;
      }

    case tp_StateWANTTOCLOSE:
    case tp_StateFINWT1PEND:
    case tp_StateFINWT1:
    case tp_StateFINWT2:
    case tp_StateLASTACKPEND:
    case tp_StateLASTACK:
    case tp_StateCLOSING:
    case tp_StateTIMEWT:
      {
	return (0);
      }
    }

  /*
   * We've got a valid connection, lets start putting data into it.
   */

#ifdef OPT_RECORD_BOUNDRY
  is_rec_bound = mbuffer->m_flags & M_EOR;
#endif /* OPT_RECORD_BOUNDRY */

  /* Called with a bad len, let the caller know! */
  if (len <= 0)
    return (len);

  /* Warning! TP_HDR_LEN Macro generates run-time code! Caution */
  /* maxdata = s->maxseg - TP_HDR_LEN; */

  blen = len;

  /* If there isn't buffer space, we can't write the data! */

  if (((s->app_sbuff->size + s->send_buff->data_size + len) >
       s->app_sbuff->max_size) || (!((len = cb_cpdatin (s->app_sbuff, dp,
							len, 0, s->maxdata))
				     > 0)))
    {
      if (s->sockFlags & SOCK_BL)
	{
	  ((tp_Socket *) scheduler.sockets[sockid].ptr)->thread->status = Blocked;
	  scheduler.num_runable--;
#ifdef GATEWAY_SELECT
	  ((tp_Socket *) scheduler.sockets[sockid].ptr)->write = blen;
#else /* GATEWAY_SELECT */
	  scheduler.sockets[sockid].write = blen;
#endif /* GATEWAY_SELECT */

#ifdef DEBUG_XPLOT
	  logEventv(s, xplot, "; Send buffer full.\nyellow\nltick %s %u\nrtick %s %u\nuarrow %s %u\n",
		    stringNow2(), s->snduna+s->send_buff->data_size,
		    stringNow2(), s->snduna+s->send_buff->data_size,
		    stringNow2(), s->snduna+s->send_buff->data_size);
	  //	  logEventv(s, xplot, "yellow\natext %s %lu\nBuf Full\n",
	  //		    stringNow2 (), s->snduna + s->send_buff->data_size);
#endif /* DEBUG_XPLOT */

	  while ((len > (s->app_sbuff->max_size - (s->app_sbuff->size +
						   s->send_buff->data_size))) ||
		 (!((len = cb_cpdatin (s->app_sbuff, dp, blen, 0,
				       s->maxdata)) > 0)))
	    {
	      sched ();
	      /* We might have lost the connection while sleeping... */
	      if (s->state == tp_StateCLOSED)
		{
		  SET_ERR (SCPS_ECONNABORTED);
		  return (-1);
		}
	    }
	}
      else
	{
	  err_val = SCPS_ENOMEM;
	  ret_val = -1;
	  len = s->app_sbuff->size;
#ifdef GATEWAY_DEBUG
	  printf
	    ("in tp_Write sbuf size = %d sbuf datasize %d len %d sbuf maxsize %d len  %d\n",
	     s->app_sbuff->size, s->send_buff->data_size, blen,
	     s->app_sbuff->max_size, len);
#endif /* GATEWAY_DEBUG */
	}
    }

  if ((push) && (!(ret_val)))
    write_align (s->app_sbuff, 0, 1);

  /* Build them packets! */

  /*
   * Starting from chain->read_head, start building 
   * full sized segments and add then to the send_buffer. 
   * If a full sized segment can't be built, let the 
   * data sit there until next time.
   */

  /* Need to recognize *LAST* segment of a write for EOR! */

  count = len;

  /* 
   * If we're all ACKed up for packets we've BUILT, make sure that
   * PUSH flag is set to knock out a potential tiny_gram.
   *
   *
   * if (s->snduna >= s->seqnum)
   *  push = 1;
   */

  while (count > 0)
    {
      /*
       * All within this cluster, build an mbuff for this segment;
       * the reference count for this cluster is updated in the
       * mcput() routine.
       */

      if ((s->send_buff->b_size >= s->send_buff->max_size) ||
	  (!(mbuffer = alloc_mbuff (MT_HEADER))))
	{
	  if (s->sockFlags & SOCK_BL)
	    {
	      /* 
	       * Pseudo-Block here waiting for an mbuff... 
	       * 
	       * There is a better way to wake up processes waiting
	       * on resources, the daemon handles things better...
	       */

	      while (!(mbuffer = alloc_mbuff (MT_HEADER)))
		{
		  sched ();
		  /* We might have lost the connection while sleeping... */
		  if (s->state == tp_StateCLOSED)
		    {
		      SET_ERR (SCPS_ECONNABORTED);
		      return (-1);
		    }
		}
	    }
	  else
	    {
	      s->mbuff_fails++;

	      /* Need to back out the rest of the cp_datin! */
	      if (!(push))
		count = 0;	/* Let user know all data was written */
	      goto Backout;
	    }
	}

      /*
       *  Try and build all the full-sized segments that we can;
       *  If the only segment we can build on this write is a runt, 
       * and we are all ACKed-up, go ahead and build it; 
       * Otherwise, if the runt is at the end of a larger write, we'll
       * hold off building it until either:
       *   (a) More data arrives on the next write - we'll coalesce
       *   (b) We get all ACKed-up and tp_processAck() will force
       *         the building and transmission of the new runt.
       */


      if (!s->send_buff->snd_una) {
	s->send_buff->flags &= (~M_RUNT);
      }
      value = mcput (mbuffer, s->app_sbuff->read_head,
		     s->app_sbuff->read_off, s->maxdata, push);
      if ((value <= 0) && (!(s->send_buff->snd_una)) &&
	  (!(s->send_buff->flags
	     & M_RUNT)))
	{
	  value = mcput (mbuffer, s->app_sbuff->read_head,
			 s->app_sbuff->read_off, s->maxdata, 1);
	  mbuffer->m_flags |= M_RUNT;
#ifdef GATEWAY
          s->gateway_runt_ctr ++;
          s->gateway_flags |=GATEWAY_HAS_RUNT;
#endif /* GATEWAY */

	}
      if (value > 0)
	/* Add mbuff to send-buffer here */
	{
#ifdef OPT_RECORD_BOUNDARY
	  if ((count == value) && (push == 2))
	    mbuffer->m_flags |= M_EOR;
#endif /* OPT_RECORD_BOUNDARY */
	  tp_BuildHdr (s, mbuffer, push);

	  if (!(enq_mbuff (mbuffer, s->send_buff)))
	    {
              s->seqnum -= mbuffer->m_ext.len;
	      goto Backout;
	    }
	  else if (mbuffer->m_flags & M_RUNT)
	    s->send_buff->flags |= M_RUNT;

	  count -= value;

	  if ((push) || (value < s->maxdata))
	    write_align (s->app_sbuff, 0, 1);
	  read_align (s->app_sbuff, value, 1);

	  s->app_sbuff->run_length -= value;
	  s->app_sbuff->size -= value;

	  if (!(s->send_buff->send))
	    s->send_buff->send = s->send_buff->last;

	}
      else
	{
	  free_mbuff (mbuffer);
	  if (!(push))
	    count = 0;
	  goto Backout;
	}
    }

  /*
   * Revise this:  If there is a record boundary, call Flush, 
   * otherwise just call NewSend(s, NULL, false) to push out 
   * the headers that have been built
   */

  if (s->send_buff->start)
    {
#ifdef OPT_RECORD_BOUNDARY
      if ((is_rec_bound) && (!(ret_val)))	/* Check for an edge condition */
	tp_Flush (s);
      else
#endif /* OPT_RECORD_BOUNDARY */
	{
	  if (s->send_buff->send)
	    tp_NewSend (s, NULL, false);
	}
    }

  count = 0;
  goto Write_Done;		/* Skip the Backout code, harmless but extra work */

Backout:
  if ((push) && (!(ret_val)))
    {
      s->app_sbuff->write_head =
	(struct mbcluster *) (s->send_buff->last->m_ext.ext_buf);
      s->app_sbuff->write_off = s->send_buff->last->m_ext.offset +
	s->send_buff->last->m_ext.len;
      while (s->app_sbuff->write_off >= SMCLBYTES)
	{
	  s->app_sbuff->write_head = s->app_sbuff->write_head->c_next;
	  s->app_sbuff->write_off -= SMCLBYTES;
	  s->app_sbuff->bytes_beyond += SMCLBYTES;
	}

      /* Use old write-head to give back any more clusters */
      if ((count > 0) && (!(ret_val)))
	{
	  s->app_sbuff->size -= count;
	  s->mbuff_overage += count;
	}
      err_val = SCPS_ENOMEM;
    }

Write_Done:
  /* Let them know how much data we actually wrote to the transport */
  if (ret_val >= 0)
    {
      ret_val = (len - count);
      s->user_data += ret_val;
    }

  if (err_val)
    SET_ERR (err_val);

  sched ();
  return (ret_val);
}

/*
 * Read data from a socket receive buffer for the 
 * application This read routine doesn't handle data 
 * as contiguous clusters of data - I *think* I
 * want it to, but that means that the tp_ProcessData 
 * needs to put data there when it receives it. Sleep 
 * on it a little bit so figure out how to handle 
 * INCOMING data.
 */

int
tp_Read (int sockid, void *data, int size)
{
  int read, temp;
  struct timeval mytime;

  tp_Socket *sock = (tp_Socket *) scheduler.sockets[sockid].ptr;
  uint32_t old_win, rcv_diff;
  SET_ERR (0);

  sched ();

  /* 
   * Make sure the socket is connected
   * before trying to read off of it.
   */

  if ((!(sock)) || (sock->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  if (((sock->state < tp_StateESTAB) || sock->state == tp_StateCLOSED))
    {
      SET_ERR (SCPS_ENOTCONN);
      return (-1);
    }

  /*
   * Make sure the size request is less than or equal to the amount of
   * memory we have available to this connection
   */
  if (size > sock->app_rbuff->max_size)
    size = sock->app_rbuff->max_size;

  /*
   * For now, disregard minimum size of buffer 
   * We won't do a read across a record boundary 
   * regardless! 
   */

  switch (sock->state)
    {				/* switch */
    case tp_StateCLOSED:
    case tp_StateNASCENT:
      {
	if (sock->state_prev != 0)
	  SET_ERR (SCPS_ECONNRESET);
	else
	  SET_ERR (SCPS_EBADF);
	return (-1);
      }
    case tp_StateLISTEN:
    case tp_StateSYNSENT:
      {
	SET_ERR (SCPS_EWOULDBLOCK);
	return (-1);
      }

    case tp_StateLASTACK:
    case tp_StateCLOSING:
    case tp_StateTIMEWT:
      {
	return (0);
      }

    case tp_StateCLOSEWT:
    case tp_StateSYNREC:
    case tp_StateESTAB:
    case tp_StateFINWT1:
    case tp_StateFINWT2:
    case tp_StateFINWT1PEND:
      {
	/* 
	 * Prior to doing a "normal" read, 
	 * check to see if we've in BETS 
	 * mode for receiving side;
	 */
#ifdef OPT_BETS
	/*
	 * If we are BETS capable and we are in BETS mode
	 * on the receiving end of a connection (we've got
	 * a hole at the begining of consumable sequence space)
	 */
	if ((sock->capabilities & CAP_BETS) &&
	    (sock->BETS.Flags & BF_BETS_RECEIVE))
	  {

	  BETS_NOTIFY:
	    /*
	     * Figure out how big a hole we are dealing with:
	     *
	     * If the size of the existing gap in consumable
	     *   data is larger than the requested read, we report
	     *   a hole the size of the read request;
	     *
	     * If the gap in consumable sequence space is less than
	     *   the size of the read request, we report the actual
	     *   size of the gap;
	     *
	     * No real data will be provided to the user process regardless.
	     */

	    sock->BETS.Reported_Hole = min (sock->BETS.Hole_Size, size);

	    /*
	     * Shrink the size of the remaining hole;
	     *
	     * This involves reducing the magnitude of the reported
	     * hole as well as bumping up the starting sequence for
	     * the hole.
	     *
	     * If we've reported the entire hole (read >= hole size)
	     * then we take the socket out of BETS mode for reception.
	     * The next socket call for a read will return at least
	     * one byte of (now in sequence) data.
	     */

	    if (!(sock->BETS.Hole_Size -= sock->BETS.Reported_Hole))
	      {
		sock->BETS.Flags &= ~BF_BETS_RECEIVE;
		sock->BETS.Receive_Hole.Start = sock->BETS.Receive_Hole.Finish;
	      }
	    else
	      {
		sock->BETS.Receive_Hole.Start += sock->BETS.Reported_Hole;
	      }

	    if ( sock->BETS.Receive_Hole.Start > sock->BETS.Receive_Hole.Finish ) {
#ifdef DEBUG_LOG
	      logEventv(sock, SCPS_log, "BETS Receive_Hole.Start > Receive_Hole.Finish.  Fixing...\n");
#endif /* DEBUG_LOG */
	      sock->BETS.Receive_Hole.Start = sock->BETS.Receive_Hole.Finish;
	    }

	    /* Balance the books on the amount of "data" space occupied
	     * or (in the case of a BETS hole) reserved in the receive
	     * cluster chain. We've reported the hole to the user process
	     * so we can free the space in the buffers we were reserving
	     * for the missing data.
	     */

	    sock->app_rbuff->size -= sock->BETS.Reported_Hole;

	    /* Now advance the read_off and read_head accordingly. */
	    write_align (sock->app_rbuff, 0, 0);
	    read_align (sock->app_rbuff, sock->BETS.Reported_Hole, 0);

	    /*
	     * Report the BETS error to the application.
	     * Upon receiving an EBETS error to a read call, the
	     * user application should immediately make the (misnamed)
	     * scps_getsockopt() call to be informed of the magnitude
	     * of the BETS hole just reported.
	     */
	    SET_ERR (SCPS_EBETS);
	    return (-1);
	  }
#endif /* OPT_BETS */

	/*
	 * If this socket is capable of blocking on a read request (default)
	 *   and
	 * There is no data in the socket's receive buffer to consume
	 *   and
	 * We're not in a situation where we have consumed the FIN, but
	 * we are draining off any remaining data left in the buffer
	 *
	 * Then we will block the calling user "process" until this
	 * socket once again has data to consume (or possibly a BETS
	 * hole to report)
	 *
	 */
	if ((sock->sockFlags & SOCK_BL) && (!(sock->app_rbuff->size)) &&
	    (sock->state != tp_StateCLOSEWT))
	  {

	    /*
	     * The owning thread is blocked by the scheduler, and the
	     * number of currently runnable threads managed by the
	     * scheduler is decremented.
	     */

	    ((tp_Socket *) scheduler.sockets[sockid].ptr)->thread->status = Blocked;
	    scheduler.num_runable--;

	    /*
	     * Mark the socket as blocked on a read of AT LEAST one
	     * byte of data.
	     */

#ifdef GATEWAY_SELECT
	    ((tp_Socket *) scheduler.sockets[sockid].ptr)->read = 1;
#else /* GATEWAY_SELECT */
	    scheduler.sockets[sockid].read = 1;
#endif /* GATEWAY_SELECT */
	    /*
	     * Turn over the cpu to the next runnable thread;
	     * When this sched() call returns, the thread owning
	     * this socket will once again be runnable - and there
	     * will be some data to consume, or a BETS error to report.
	     *
	     * To handle the latter case, we need the GOTO call;
	     */

	    sched ();

#ifdef OPT_BETS
	    if ((sock->capabilities & CAP_BETS) &&
		(sock->BETS.Flags & BF_BETS_RECEIVE))
	      goto BETS_NOTIFY;
#endif /* OPT_BETS */
	  }

	/*   
	 * In the interest of minimizing the chance of a "user" thread  
	 * starving out the transport/network operations, we give the
	 * other threads a chance to run. This is analogous to the
	 * "rescheduling penalty" you get with a real OS for making a
	 * system-call.
	 */

	sched ();

	/*       
	 * Verify that there is indeed data available in the socket
	 * buffer for potential consumption  
	 *
	 */

	if (sock->app_rbuff->size)
	  {
	    /*  
	     * There is data, if the size of the read is going to
	     * straddle a record boundary, we truncate the size of
	     * the read to the amount left in the current record.
	     * If the data stream does not utilize record boundaries,
	     * this test will be short-circuited on the first chunk
	     * of the if-statement by definition.
	     *   
	     * The test is as follows:
	     *   
	     * If the receive_buffer has head to it's list of record-bound.
	     *   and
	     * The size of the current read request is greater than the
	     * length of the pending record
	     *
	     * Then
	     * The trim the size of the read request to the length of the
	     * pending record (marked by the record-boundaries offset).
	     */

	    if ((sock->app_rbuff->RB) && (size > sock->app_rbuff->RB->offset))
	      size = sock->app_rbuff->RB->offset;

	    /*
	     * Regardless of whether there is a pending record boundary
	     * or not, we need to make sure that we trim the size of a
	     * read to reflect the amount of data available in the socket
	     * buffer.
	     * For the cases where there is at least enough data available
	     * to satify the request, or there is a record boundary
	     * pending, this test should fail, and we'll skip this chunk
	     * of code.
	     */

	    if (size > sock->app_rbuff->size)
	      {

		/* 
		 * Trim the effective size of the read request
		 */

		size = sock->app_rbuff->size;

		/*
		 * Determine if it is necessary to begin a BETS timer
		 */
#ifdef OPT_BETS
		/*
		 * If we've truncated the effective size of the read,
		 * but there *is* also out-of-sequence data in the
		 * receive buffer beyond the truncated read request,
		 * then we want to start the BETS Receive Timer for
		 * this socket.
		 *
		 * If the out-of-sequence data corresponding
		 * to the FIRST hole in the receive sequence space
		 * has not been enqueued by the receiver before the
		 * timer goes off, then the next read request
		 * following timer expiration will return an EBETS
		 * error as handled at the begining of this routine.
		 */

		/*
		 * If the socket/connection allows for BETS operation;
		 *   and
		 * There is out-of-sequence data pending in the receiving
		 * reassembly queue;
		 *   and
		 * The BETS Receive Timer is not already running;
		 *
		 * Then:
		 *
		 * Initialize the BETS Receive Timer to the socket's
		 * BETS Receive Timeout value and begin the timer.
		 *
		 */

		if (((sock->BETS.Flags & BF_BETS_OK) == BF_BETS_OK) &&
		    (sock->Out_Seq->start) &&
		    (!(sock->otimers[BE_Recv]->set)))
		  {
		    mytime.tv_sec = 0;
		    mytime.tv_usec = sock->BETS.Receive_Timeout;
		    set_timer (&mytime, sock->otimers[BE_Recv], 1);
		  }
#endif /* OPT_BETS */
	      }
	  }
	else if (sock->state != tp_StateCLOSEWT)
	  {
#ifdef OPT_BETS
	    if (sock->capabilities & CAP_BETS)
	      {
		/* 
		 * We've read all the in-sequence data and we have 
		 * out-of-sequence data so start the BETS Receive 
		 * timer now.
		 */
		if (((sock->BETS.Flags & BF_BETS_OK) == BF_BETS_OK) &&
		    (sock->Out_Seq->start) &&
		    (!(sock->otimers[BE_Recv]->set)))
		  {
		    mytime.tv_usec = sock->BETS.Receive_Timeout;
		    set_timer (&mytime, sock->otimers[BE_Recv], 1);
		  }
	      }
#endif /* OPT_BETS */
	    SET_ERR (SCPS_EWOULDBLOCK);
	    return (-1);
	  }
	else
	  {
	    return (0);
	  }
      }

    }
  /*
   * At this point, it should just be a matter of doing 
   * a cb_cpdatout() into the data pointer...
   */

  sched ();

  size = read = cb_cpdatout (sock->app_rbuff, data, size);

  /*
   * This socket has no more data to read right now, 
   * clear it's read_socks bit 
   *
   * Take the socket off the list of readable sockets.
   */
  if (!(sock->app_rbuff->size))
    {
#ifdef GATEWAY_SELECT
      REMOVE_READ (sock);
#else /* GATEWAY_SELECT */
      sock->thread->read_socks &= ~(1 << sock->sockid);
#endif /* GATEWAY_SELECT */
    }

  /* 
   * Keep in mind here that it is now possible for 
   * read < size, so ammend size accordingly or we 
   * might get ourselves into trouble...
   */

  if (read == 0)
    {
      SET_ERR (SCPS_EWOULDBLOCK);
      return (-1);
    }

#ifdef OPT_RECORD
  if (sock->app_rbuff->RB)
    {
      /*
       * Decrement the offset of the next record 
       * boundary (if there is one)
       *
       * Do this on EVERY read, not just ones that 
       * hit a record boundary.
       */
      if (!(sock->app_rbuff->RB->offset -= size))
	{			/* should that be read? */
	  if (sock->app_rbuff->RB->next)
	    {
	      sock->app_rbuff->RB = sock->app_rbuff->RB->next;
	      free (sock->app_rbuff->RB->prev);
	    }
	  else
	    {
	      free (sock->app_rbuff->RB);
	      sock->app_rbuff->RB = NULL;
	    }
	}
    }
#endif /* OPT_RECORD */

  mb_rtrim (sock->receive_buff, size);
  /* At this point all of the mbuff & mbcluster structures should be
   * consistant.
   */
  BUG_HUNT (sock);

  temp = sock->app_rbuff->max_size - sock->app_rbuff->size;

  old_win = sock->rcvwin;
  sock->rcvwin = (temp < 0) ? 0 : temp;
  rcv_diff = sock->rcvwin - old_win;

  sock->ack_delay++;

  /* Update the rcvwin if appropriate */
  if (				/* (size >= (sock->maxdata << 1)) || */
      ((old_win < sock->my_mss_offer) && (sock->rcvwin >= sock->my_mss_offer)))
    {
      sock->sockFlags |= SOCK_ACKNOW;

      if (!(sock->otimers[Del_Ack]->set))
	{
	  mytime.tv_sec = 0;
	  mytime.tv_usec = sock->ACKDELAY;
	  set_timer (&mytime, sock->otimers[Del_Ack], 1);
	}
    }

  sock->sockFlags |= SOCK_DELACK;

  sched ();
  return (read);
}

/* Do an honest Berkeley accept() */
int
scps_accept (int sockid, void *peer, int *addrlen)
{
  int retval;
  u_short intarg;
  uint32_t longarg;

  tp_Socket *sock = (tp_Socket *) scheduler.sockets[sockid].ptr;
  SET_ERR (0);

  sched ();

  if ((!(sock)) || (sock->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  while (!(sock->q))
    {
#ifdef GATEWAY_SELECT
#ifndef GATEWAY
      ((tp_Socket *) scheduler.sockets[sockid].ptr)->thread->status =
	Blocked;
      ((tp_Socket *) scheduler.sockets[sockid].ptr)->write = 1;
      /* If we're a gateway, we called accept from tp and don't want to do this. */
      scheduler.num_runable--;
#endif /* GATEWAY */
      sched ();
#else /* GATEWAY_SELECT */
      ((tp_Socket *) scheduler.sockets[sockid].ptr)->thread->status = Blocked;
      scheduler.sockets[sockid].write = 1;
      scheduler.num_runable--;
      sched ();
#endif /* GATEWAY_SELECT */
    }

  if (sock->q)
    {
#ifndef IPV6
      retval = sock->q->sockid;
      intarg = htons (((tp_Socket *) scheduler.sockets[retval].ptr)->hisport);
      longarg = ((tp_Socket *) scheduler.sockets[retval].ptr)->his_ipv4_addr;

      if ( (!peer) || !addrlen || (*addrlen == 0)) {
        /* Do nothing. */
      } else {
        ((struct sockaddr_in *) peer)->sin_port = intarg;
        memcpy (&(((struct sockaddr_in *) peer)->sin_addr), &longarg,
                sizeof (uint32_t));
        *addrlen = sizeof (struct sockaddr_in);
      }
#else /* IPV6 */
         if (((tp_Socket *) socket) ->nl_protocol_id == NL_PROTOCOL_IPV4) {
                retval = sock->q->sockid;
                intarg = htons (((tp_Socket *) scheduler.sockets[retval].ptr)->hisport);
                longarg = ((tp_Socket *) scheduler.sockets[retval].ptr)->his_ipv4_addr;

                if ( (!peer) || !addrlen || (*addrlen == 0)) {
                        /* Do nothing. */
                } else {
                        ((struct sockaddr_in *) peer)->sin_port = intarg;
                        memcpy (&(((struct sockaddr_in *) peer)->sin_addr), &longarg,
                                sizeof (uint32_t));
                        *addrlen = sizeof (struct sockaddr_in);
                  }
         }

         if (((tp_Socket *) socket) ->nl_protocol_id == NL_PROTOCOL_IPV6) {
              struct ipv6_addr addr;
              retval = sock->q->sockid;
              intarg = htons (((tp_Socket *) scheduler.sockets[retval].ptr)->hisport);
              memcpy (&addr,  &((tp_Socket *) scheduler.sockets[retval].ptr)->his_ipv6_addr, sizeof (addr));

              if ( (!peer) || !addrlen || (*addrlen == 0)) {
                /* Do nothing. */
              } else {
                ((struct sockaddr_in6 *) peer)->sin6_port = intarg;
                memcpy (&(((struct sockaddr_in6 *) peer)->sin6_addr), &addr,
                        sizeof (struct ipv6_addr));
                *addrlen = sizeof (struct sockaddr_in6);
          }
         }
#endif /* IPV6 */

      sock->q = sock->q->q;	/* Bump to the next socket in the queue */
      if (sock->q)
	{
	  sock->q->qhead = NULL;
	  sock->q->q = NULL;
	  sock->q->q0 = NULL;
	  /*
	   * Take the socket off the list of writeable sockets.
	   */
#ifdef GATEWAY_SELECT
	  REMOVE_WRITE (sock);
#else /* GATEWAY_SELECT */
	  sock->thread->write_socks &= ~(1 << sock->sockid);
#endif /* GATEWAY_SELECT */
	}
      return (retval);
    }
  /* Should never get here */
  SET_ERR (SCPS_EWOULDBLOCK);
  return (-1);
}

/*
 * Return status as to whether a socket has an established connection on it.
 */
int
tp_connect (int sockid)
{
  tp_Socket *sock = (tp_Socket *) scheduler.sockets[sockid].ptr;
  SET_ERR (0);

  sched ();

  if ((!(sock)) || (sock->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  if ((sock->state >= tp_StateESTAB) && (sock->state < tp_StateCLOSING))
    {
      return (1);
    }
  else
    {
      return (0);
    }
}

/*
 * No reason to duplicate code which does the same thing!
 */
#define tp_accept(s) (tp_connect(s))

/*
 * Return status as to whether a socket is completely unused.
 */
int
tp_closed (int sockid)
{
  tp_Socket *sock = (tp_Socket *) scheduler.sockets[sockid].ptr;
  SET_ERR (0);

  sched ();

  if ((!(sock)) || (sock->thread != scheduler.current))
    {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  if ((sock->state == tp_StateNASCENT) || (sock->state == tp_StateCLOSED))
    {
      return (0);
    }
  else
    {
      SET_ERR (SCPS_ESOCKOUTSTATE);
      return (-1);
    }
}
