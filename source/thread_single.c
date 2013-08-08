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

#ifdef Sparc
#ifdef SOLARIS
#include <sys/asm_linkage.h>
#include <sys/trap.h>
#elif defined (NETBSD) || defined (__OpenBSD__)
#include <machine/asm.h>
#include <machine/trap.h>
#else /* (NETBSD) || (__OpenBSD__) */
#include <sparc/asm_linkage.h>
#include <sparc/trap.h>
#endif				/* SOLARIS */
#endif				/* Sparc */

#include <signal.h>
#include "thread.h"

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: thread_single.c,v $ -- $Revision: 1.1 $\n";
#endif

// extern int      printf(char *format, /* args */ ...);
extern void    *malloc(size_t size);
extern void    *memset(void *s, int c, size_t n);


/* Globals */

#if defined (NETBSD) || defined (__OpenBSD__)
#define WINDOWSIZE  (16*4)
#define ARGPUSHSIZE (6*4)
#define MINFRAME  (WINDOWSIZE+ARGPUSHSIZE+4)	/* min frame */
#define STACK_ALIGN       8
#define ST_FLUSH_WINDOWS 0x03

#define SA(X)     (((X)+(STACK_ALIGN-1)) & ~(STACK_ALIGN-1))
#endif  /* NETBSD || OpenBSD */

#define THREAD_C 1

struct _scheduler scheduler;

struct threads  dummyStartupThread;

sigset_t        alarmset;
int             read_lower;

extern void     timer_wheel_init();

#ifdef SCPSSP
extern int      SADB_init();
#endif				/* SCPSSP */

void
init_scheduler()
{
	struct sigaction sa;

	scheduler.num_procs = 0;
	scheduler.num_runable = 0;
	scheduler.last_alloc = 0;
	scheduler.head = NULL;
	scheduler.tail = NULL;
	scheduler.current = NULL;
	memset(scheduler.sockets, 0, sizeof(scheduler.sockets));
	scheduler.run_index = 0;/* Start with first process in the run queue */
	memset(scheduler.run_queue, 0, sizeof(scheduler.run_queue));
	scheduler.switch_time = 0;	/* Really should be current time, but
					 * I'm lazy */
	scheduler.timers.queue.head = scheduler.timers.queue.tail = NULL;
	scheduler.timers.expired_queue.head =
		scheduler.timers.expired_queue.tail = NULL;
	scheduler.timers.queue.reset = 1;
	scheduler.timers.expired_queue.reset = 0;
	scheduler.tp_ephemeral_next = 5001;
	scheduler.udp_ephemeral_next = 5001;
	scheduler.service_interface_now = 0;
	scheduler.interface_data = 0;
	scheduler.interface = 0x0;
	sigemptyset(&alarmset);
#ifdef ENABLE_GDB 
  sigaddset (&alarmset, SIGVTALRM);
#else   /* ENABLE_GDB */ 
  sigaddset (&alarmset, SIGALRM);
#endif /* ENABLE_GDB */

#ifndef SOLARIS
#ifdef ASYNC_IO
	sigaddset(&alarmset, SIGIO);
#endif				/* ASYNC_IO */
#endif				/* SOLARIS */

	/* Catch SIGALRM */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;	/* SA_INTERRUPT; *//* Don't restart system
				 * calls... */
	sa.sa_handler = (void *) &alarm_handler;
#ifdef ENABLE_GDB
  if (sigaction (SIGVTALRM, &sa, NULL) < 0)
#else   /* ENABLE_GDB */
  if (sigaction (SIGALRM, &sa, NULL) < 0)
#endif  /* ENABLE_GDB */
	{
		printf("Error installing SIGALM signal handler\n");
		exit(2);
	}
#ifndef SOLARIS
#ifdef ASYNC_IO
	/* Catch SIGIO */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;	/* SA_INTERRUPT; *//* Don't restart system
				 * calls... */
	sa.sa_handler = (void *) &sigio_handler;
	if (sigaction(SIGIO, &sa, NULL) < 0)
	{
		printf("Error installing SIGIO signal handler\n");
		exit(2);
	}
#endif				/* ASYNC_IO */
#endif				/* SOLARIS */
	timer_wheel_init();
#ifdef SCPSSP
	(void) SADB_init();
#endif				/* SCPSSP */


}

struct threads *
                create_thread(void (*program) (void),...)
{
	static struct threads *threadp;

	/*
	 * create a new thread, and place it in the process queue. New
	 * threads always go on the tail of the process queue.
	 */

	threadp = (struct threads *) malloc(sizeof(struct threads));
	threadp->pid = ++scheduler.last_alloc;
	threadp->status = Created;
	threadp->function = program;
	threadp->stack_size = 1024;
	threadp->stack = (char *) malloc(THREAD_SWAP_STACK_SIZE);
	threadp->stack = &(threadp->stack[THREAD_SWAP_STACK_SIZE - 32]);
	threadp->last_run = threadp->last_wait = threadp->switch_time
		= threadp->avg_run = threadp->avg_wait = 0;
	threadp->read_socks = 0;
	threadp->write_socks = 0;

	/* Now, add the new task to the tail of the circular process queue */
	if (!scheduler.head)
	{
		scheduler.head = threadp;
		threadp->prev_thread = threadp;
	} else
	{
		scheduler.tail->next_thread = threadp;
		threadp->prev_thread = scheduler.tail;
	}
	scheduler.tail = threadp;
	scheduler.tail->next_thread = scheduler.head;
	scheduler.head->prev_thread = scheduler.tail;
	scheduler.num_procs++;
	scheduler.num_runable++;

	return (threadp);
}

void
start_threads()
{
	dummyStartupThread.next_thread = scheduler.run_queue[0];
	scheduler.current = &dummyStartupThread;
	threadHandoffCPU(scheduler.run_queue[0], Defunct);
}

void
setup_thread_globals()
{
}

void
sched()
{
}

/*
 * NewThreads context switching implementation for the following
 * architectures done  by Josef Burger (bolo@cs.wisc.edu) Sparc 68000 HP
 * Precision Architecture IBM RS/6000
 * 
 * Notes: I also changed the existing implementation of the MIPS context switch
 * routine to be interrupt (signal) safe.
 * 
 * 9/13/93  Josef Burger (bolo@cs.wisc.edu) Created a new version of the I860
 * context switching code;  It is now interrupt safe, and it also tries to
 * generate a stack frame for the debugger.
 * 
 * The 386 version was already signal safe.
 * 
 * (The new context switchers that I wrote are all interrupt safe.  bolo)
 */

/*****************************************************************************
 *
 *  hand off the CPU to another thread
 *
 *  don't mess with this code unless you know what you're doing!
 */


void
threadHandoffCPU(struct threads * t, Th_Status status)
{

}

void
threadExit()
{
}

