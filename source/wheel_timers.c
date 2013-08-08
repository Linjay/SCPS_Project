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
#include <sys/types.h>
#include <signal.h>

#include "thread.h"
#include "../include/scps.h"
#include "scpstp.h"


#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: wheel_timers.c,v $ -- $Revision: 1.13 $\n";
#endif

extern void free (void *ptr);
extern void *malloc (size_t size);
extern void *memset (void *s, int c, size_t n);

extern uint32_t tp_now;
#ifndef SOLARIS
#ifdef ASYNC_IO
extern void toggle_iostatus (int status);
#endif /* ASYNC_IO */
#endif /* SOLARIS */
int off = 0;

/*
 * Change this to a run-time configurable value determined at timer
 * intialization time.
 */
#define NUM_TICKS 100		/* Basically HZ of OS we are working on */

/* This needs to be sized to 1 second's worth of clock ticks... */
/*
 * The best way to do this is to oversize this array to support
 * platforms that tick most often. This is slightly wasteful for
 * other platforms, but it's only a pair of pointers per wasted 
 * tick - big deal...
 *
 * At this point the biggest ticks/sec I've found is BSD's 125;
 *     for reference:   
 *			SunOS 4.1	 60 ticks/sec
 *			Linux 		100 ticks/sec
 *			Solaris 2.x	100 ticks/sec
 *			IRIX		100 ticks/sec (???)
 *			FreeBSD		125 ticks/sec
 *			OpenBSD		???
 */

struct
  {
    int current;
    struct _timer_queue *current_queue;
    struct _timer_queue queue[NUM_TICKS];
    int dirty;
  }
timer_wheel;

int32_t timer_interval;

#ifdef XXX
int
check_qs (fn, ln)
char *fn;
int ln;

{
	int i;

	for (i = 0; i < NUM_TICKS; i++) {
		if ((timer_wheel.queue[i].head == NULL)  && (timer_wheel.queue[i].tail == NULL) ) 
			continue;

		if ((timer_wheel.queue[i].head != NULL)  && (timer_wheel.queue[i].tail != NULL) ) 
			continue;

		printf ("%s %d QC %s %d %i %p %p\n", __FILE__, __LINE__, fn, ln, i, timer_wheel.queue[i].head, timer_wheel.queue[i].tail);

	}

	for (i = 0; i < NUM_TICKS; i++) {
	      struct _timer *te = timer_wheel.queue[i].head;

		while (te) {
		
			if (te->prev) {
				if (te != te->prev->next) {
					printf ("%s %d QC prev %s %d %i\n",__FILE__, __LINE__,   fn, ln, i);

				}
			}

			if (te->next) {
				if (te->next->prev != te) {
					printf ("%s %d QC next %s %d %i\n",__FILE__, __LINE__,   fn, ln, i);

				}
			}

			if (!te->queue) {
				printf ("%s %d QC queue %s %d %i\n", __FILE__, __LINE__,fn, ln, i);
			}

			te = te->next;
		}
	}

	if ((timer_wheel.current_queue->head == NULL)  && (timer_wheel.current_queue->tail == NULL) ) 
		return (1);

	if ((timer_wheel.current_queue->head != NULL)  && (timer_wheel.current_queue->tail != NULL) ) 
		return (1);

	printf ("%s %d QC %s %d current_q %p %p\n", __FILE__, __LINE__, fn, ln, timer_wheel.current_queue->head, timer_wheel.current_queue->tail);

}
#endif /* XXX */

uint32_t
clock_ValueRough (void)
{
  uint32_t timenow;
  struct timeval mytime;

  gettimeofday (&mytime, NULL);

  timenow = (mytime.tv_sec * 1000000) + (mytime.tv_usec);
  timer_wheel.dirty = 1;

  return (timenow);
}

/* 
 * New Timer handling routines to remove the do_timers loop in tp.c
 * The goal here is to reduce the overhead used for checking for timers.
 * 
 *
 */

/* 
 * Initialize the timer-wheel and give it a bit of momentum
 */

void
timer_wheel_init ()
{
  struct itimerval value;
  struct itimerval ovalue;

  timer_interval = 1000000 / NUM_TICKS;

  value.it_interval.tv_sec = value.it_value.tv_sec = 0;
  value.it_interval.tv_usec = value.it_value.tv_usec = timer_interval;


  /* Make sure the wheel is pristine */

  memset (&timer_wheel, 0, sizeof (timer_wheel));

  /* A little syntatic sugar */
  timer_wheel.current_queue = &(timer_wheel.queue[0]);

#ifdef ENABLE_GDB
  setitimer (ITIMER_VIRTUAL, &value, &ovalue);
#else /* ENABLE_GDB */
  setitimer (ITIMER_REAL, &value, &ovalue);
#endif /* ENABLE_GDB */

  timer_wheel.dirty = 0;
}

/* 
 * Create a new timer, initialize it and return it's 
 * pointer back to the caller.
 */

struct _timer *
create_timer (void (*handler_fcn) (void *), void *socket,
	      int immediate,
	      struct timeval *expiration,
	      struct _timer *timer_element, int type)
{

  struct _timer *ltimer_element;

  if (!(timer_element)) {
    ltimer_element = (struct _timer *) malloc (sizeof (struct _timer));
    memset (ltimer_element, 0, sizeof (struct _timer));
  } else {
    ltimer_element = timer_element;
  }

  ltimer_element->function = handler_fcn;
  ltimer_element->socket = socket;
  ltimer_element->immediate = immediate;
  ltimer_element->type = type;

  if (expiration) {
    set_timer (expiration, ltimer_element, 0);
  }

  return (ltimer_element);
}

/* 
 * Delete a timer, clear it's current expiration time from the
 * global timer queue if it running and then free the memory 
 * occupied by the timer_element itself;
 */

int
delete_timer (struct _timer *timer_element, int mask)
{

  if (timer_element)
    {
      if (mask)
        sigprocmask (SIG_BLOCK, &alarmset, 0x0);

      clear_timer (timer_element, 0); /* PDF set this to 0 12/18/01 */

      free (timer_element);

      if (mask)
        sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);

    }
  return (0);
}

/* 
 * Set a timer by adding it to the timer_wheel. This is significantly
 * different than what we used to do, since we don't really maintain the 
 * timers due to fire within a particular bin. At best, we enqueue timers
 * with at least a cycle to go at the end of the bin list, but thats all.
 */

uint32_t
set_timer (struct timeval *expiration, struct _timer *timer_element, int mask)
{
  struct itimerval till_next_tick;
  unsigned int index = 0;

  if (!(timer_element))
    return (0);

  if (mask)
    sigprocmask (SIG_BLOCK, &alarmset, 0x0);

  /* If the timer element is on a queue (including expired), clear_it. */

  if (timer_element->queue) {
    dequeue_timer (timer_element, 0);
  }

  /* 
   * If the usec is greater than 1000000 (1 sec), make 
   * sure that we wrap that into the spins element. We 
   * need to protect against this as it is not illegal
   * for someone to do that. :o(
   */

  timer_element->spins = expiration->tv_sec;
  if (expiration->tv_usec >= 1000000)
    timer_element->spins += (expiration->tv_usec / 1000000);

  /*
   * Calculate the index offset and check for the edge 
   * condition when (index == NUM_TICKS); If this happens, we've 
   * assigned 1 spin to many above, and we must knock it off.
   */

  if ((index = (unsigned int) ((int32_t) expiration->tv_usec / timer_interval))
      == NUM_TICKS)
    timer_element->spins--;

  /* If we're less than a tick away, make sure we don't fire prematurely */
  if (!(index))
    {
      index++;
#ifdef ENABLE_GDB
      getitimer (ITIMER_VIRTUAL, &till_next_tick);
#else /* ENABLE_GDB */
      getitimer (ITIMER_REAL, &till_next_tick);
#endif /* ENABLE_GDB */
      if (expiration->tv_usec > till_next_tick.it_value.tv_usec)
	index++;
    }

  /* Place the timer in the correct spot on the wheel */
  timer_element->index = (index + timer_wheel.current) % NUM_TICKS;
  timer_element->expired = 0;

  timer_element->next_tobe_sched =
    scheduler.timers.to_be_sched.head;
  scheduler.timers.to_be_sched.head = timer_element;

  /* Enqueue the timer directly */
  if (!(timer_wheel.queue[timer_element->index].head))
    {
      timer_wheel.queue[timer_element->index].head = timer_element;
      timer_wheel.queue[timer_element->index].tail = timer_element;
      timer_element->prev = timer_element->next = 0x0;
    }
  else if (!(timer_element->spins))
    {
      timer_element->prev = 0x0;
      timer_element->next =
	timer_wheel.queue[timer_element->index].head;
      timer_wheel.queue[timer_element->index].head->prev = timer_element;
      timer_wheel.queue[timer_element->index].head = timer_element;
    }
  else
    {
      timer_element->next = 0x0;
      timer_element->prev =
	timer_wheel.queue[timer_element->index].tail;
      timer_wheel.queue[timer_element->index].tail->next = timer_element;
      timer_wheel.queue[timer_element->index].tail = timer_element;
    }

  timer_element->queue = &(timer_wheel.queue[timer_element->index]);
  timer_element->set = 1;
  timer_element->flags |= TIMER_VALID;

  if (mask)
    sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);

  return (0);
}

void
dequeue_timer (struct _timer *timer_element, int mask)
{

  int is_head, is_tail, is_queued;


  if (mask)
    sigprocmask (SIG_BLOCK, &alarmset, 0x0);
  /* 
   * Simple operation, so simple rules should apply...
   *
   *  If the timer is not set and timer_element->queue = 0x0,
   *      we can exit immediately.
   *  If the timer element is not set, but timer_element->queue != 0x0
   *      we are (hopefully) on the expired queue, treat it like a set timer.
   *  If the timer is set:
   *     - if timer_element->prev = 0x0, then I'm the head of this queue.
   *     - if timer_element->next = 0x0, then I'm the tail of this queue.
   */

  is_head = (timer_element->prev == 0x0);
  is_tail = (timer_element->next == 0x0);
  is_queued = (!(timer_element->queue == 0x0));

  /* If the timer is not queued */
  if (!(is_queued)) {
	printf ("%s %d XXXXXXXX not on queue\n", __FILE__, __LINE__);
    if (mask)
      sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
    return;
  }

  /* At this point, we should be enqueued */

  if ((is_head) && (is_tail))
    timer_element->queue->head = timer_element->queue->tail = 0x0;

  else if (is_head)
    {
      timer_element->queue->head = timer_element->next;
      timer_element->queue->head->prev = 0x0;
    }
  else if (is_tail)
    {
      timer_element->queue->tail = timer_element->prev;
      timer_element->queue->tail->next = 0x0;
    }
  else
    {
      timer_element->prev->next = timer_element->next;
      timer_element->next->prev = timer_element->prev;
    }

  timer_element->prev = timer_element->next = 0x0;
  timer_element->queue = 0x0;
  timer_element->set = 0;

  if (mask)
    sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
  return;
}

int
clear_timer (struct _timer *timer_element, int mask)
{
  timer_element->next_tobe_sched =
    scheduler.timers.to_be_sched.head;
  scheduler.timers.to_be_sched.head = timer_element;

  if (mask)
    sigprocmask (SIG_BLOCK, &alarmset, 0x0);

  if (timer_element->queue) {
    dequeue_timer (timer_element, 0);
  }

  timer_element->ticks = 0;
  timer_element->expired = 0;
  timer_element->spins = 0;
  timer_element->index = 0;
  timer_element->set = 0;
  timer_element->prev = 0;
  timer_element->next = 0;
  timer_element->queue = 0x00;

  if (mask)
    sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
  return (0);
}

void
alarm_handler (void)
{
  struct _timer *p, *element, *prev;

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);
  /* 
   * This routine should be relatively simple...
   *
   * First, we increment timer_wheel.current, and 
   * we do a soft update to tp_now (we give this
   * a HARD update upon receipt of any packet).
   * We then move any pending timers (with a spin 
   * of 0) to the expired queue. We decrement the 
   * spin count of others.
   * That's all there is too it (in theory) 
   */

  if (timer_wheel.dirty)
    {
      timer_wheel.dirty = 0;
    }
  else
    {
      tp_now += timer_interval;
    }

  timer_wheel.current = (++timer_wheel.current % NUM_TICKS);
  timer_wheel.current_queue = &(timer_wheel.queue[timer_wheel.current]);

  /* Now do the shuffling of timers */
  /* Really simple/stupid right now */

  if ((p = timer_wheel.current_queue->head))
    {
      while (p)
	{
	  element = p;
	  prev = p->prev;
	  p = p->next;
	  if (element->spins > 0)
	    element->spins--;
	  else
	    {
	      if (element->queue) {
		dequeue_timer (element, 0);
 	      }

	      if (element->immediate)
		{
		  /* was: clear_timer(element, 0); */
		  /* element->set = 0; */
                  if (element->function) {
		     element->function (element->socket);
   sigprocmask (SIG_UNBLOCK, &alarmset, 0x0); /* PDF 12/18/01 */
  sigprocmask (SIG_BLOCK, &alarmset, 0x0);
                  }
		}
	      else
		{ if (element->socket != NULL) {
		  if ((element->prev = scheduler.timers.expired_queue.tail))
		    scheduler.timers.expired_queue.tail->next = element;
		  else
		    scheduler.timers.expired_queue.head = element;
		  scheduler.timers.expired_queue.tail = element;
		  if (scheduler.timers.expired_queue.tail)
  		  	scheduler.timers.expired_queue.tail->next = NULL;
		  element->queue = &(scheduler.timers.expired_queue);
		  element->expired = 1;
		}
		}
	    }
	}
    }
   sigprocmask (SIG_UNBLOCK, &alarmset, 0x0); /* PDF 12/18/01 */
}

#ifndef SOLARIS
#ifdef ASYNC_IO
/*
 * We received a notification that data is available 
 * on a socket (any of our sockets), so we want to 
 * set the global flag telling us to service the
 * interface and turn-off Asynchronous notification
 * on our sockets until we handle this one. This 
 * should reduce the overhead associated with this
 * scheme, as we won't spend all our time servicing
 * interrupts.
 */

void
sigio_handler (void)
{
  sigprocmask (SIG_BLOCK, &alarmset, 0x0);
  toggle_iostatus (0);
  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
}
#endif /* ASYNC_IO */
#endif /* SOLARIS */

/* 
 * Main routine should execute this to 
 * walk the expired timer queue servicing 
 * the timers.
 */

void
service_timers ()
{
  struct _timer *p;
  struct _timer *next;
  struct _timer *prev;

  sigprocmask (SIG_BLOCK, &alarmset, 0x0);

  p = scheduler.timers.expired_queue.head;
  while (p)
    {
      next = p->next;
      prev = p->prev;
      p->expired = 0;

      if (!next) {
	scheduler.timers.expired_queue.tail = 0x0;
      }

	
      /* was: clear_timer(p, 0); */
      if (p->queue) {
	dequeue_timer (p, 0);
      }
      else {
	dequeue_timer (p, 0);
      }
      /* p->set = 0; */

      if (p->function) {
         p->function (p->socket);
      }
      sigprocmask (SIG_BLOCK, &alarmset, 0x0); /* 12/18/01 PDF - something
                                                  in the functioned called
                                                  may unblock the mask */

      p = next;
      if (p) p->prev = 0x0;
      scheduler.timers.expired_queue.head = p;
    }
  sigprocmask (SIG_UNBLOCK, &alarmset, 0x0);
}
