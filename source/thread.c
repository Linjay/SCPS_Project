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
static char CVSID[] = "$RCSfile: thread.c,v $ -- $Revision: 1.14 $\n";
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

/* Returns a pointer to the thread associated with program */
struct threads *
get_thread(void (*program) (void))
{
	struct threads *current;

	current = scheduler.head;
	do
	{
		if ((caddr_t) current->function == (caddr_t) program)
			return (current);
		current = current->next_thread;
	}
	while (current != scheduler.head);
	return (NULL);
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

struct threads *
next_runnable()
{
	struct threads *current;
	int             starting_point;
	/* Move to next process in run queue */

	/*
	 * Mark the current process where we start off, cycle through the
	 * run-queue until we find a process that is runnable, return it if
	 * found, otherwise, when we reach our starting point, if this
	 * process is runnable, return it - otherwise return a NULL pointer.
	 */

	starting_point = scheduler.run_index;
	do
	{
		if (scheduler.run_queue[++scheduler.run_index] == NULL)
		{
			current = scheduler.run_queue[0];
			scheduler.run_index = 0;
		}
		if (scheduler.run_queue[scheduler.run_index]->status <= Ready)
			return (scheduler.run_queue[scheduler.run_index]);
	} while (scheduler.run_index != starting_point);

	/*
	 * If we made it here, run_index == starting_point, so let's see if
	 * we can re-run the calling process
	 */
	if (scheduler.run_queue[scheduler.run_index]->status <= Ready)
		return (scheduler.run_queue[scheduler.run_index]);
	else
		return (NULL);
}

void
sched()
{
#ifndef GATEWAY_SINGLE_THREAD
	struct threads *next_thread;

	/* We might be comming off of a transition to Block or Preemption */

	if ( scheduler.num_runable==0 ) {
//	  printf("No runnable threads.  Goodbye.\n"); fflush(stdout);
	}
	if ((scheduler.current->status == Running) && (scheduler.num_runable == 1))
		return;

	if (scheduler.current->status == Running)
		scheduler.current->status = Ready;

	next_thread = next_runnable();

	if (next_thread == scheduler.current)
	{
		/* Don't bother to do a context switch */
		return;
	}
	if (next_thread) {
	  threadHandoffCPU(next_thread, scheduler.current->status);
	} else {
	  threadExit();
	}
#endif  /* GATEWAY_SINGLE_THREAD */
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
	static struct threads *oldThread;
	static Th_Status stat;

	oldThread = scheduler.current;
	scheduler.current = t;
	stat = status;

	/* save registers */

#ifdef Mips
	asm             volatile("subu  $sp, 100");
	asm             volatile("sw $17,4($sp); \
				                 sw $18, 8($sp); \
	sw $19, 12($sp); \
	sw $20, 16($sp); \
	sw $21, 20($sp); \
	sw $22, 24($sp); \
	sw $23, 28($sp); \
	sw $fp, 32($sp); \
	sw $16, 36($sp) ");
#endif /* Mips */

#ifdef I386
		asm volatile("pushl %ebp; \
			     pushl % ebx; \
			     pushl % edi; \
			     pushl % esi; \
			     leal - 108(%esp), %esp ");
#endif /* I386 */

#ifdef Sparc
	/* most of the context is saved courtesy of the reg. windows */

	/*
	 * the floating point registers are caller-save, so we ignore them
	 * However, we want to terminate all fp. activity, so the trap
	 * doesn't occur in the wrong process.  We do this by storing the
	 * floating point status register to memory (I use the arg passing
	 * area of the save area for this scratch)
	 */

	/*
	 * if (oldThread->usesFloatingPoint) { asm volatile("st %%fsr, [%%sp
	 * + %0]" : : "i" (SA(WINDOWSIZE))); }
	 */

	/*
	 * on the sparcs, the current "register window save area", pointed to
	 * by the SP, can pretty much be over-written ANYTIME by traps,
	 * interrupts, etc
	 * 
	 * When we start to restore the new thread's context, if we setup SP
	 * immediately, the machine could wipe out any saved values before we
	 * have a chance to restore them. And, if we left it pointed at the
	 * old area, the activity would wipe out the context we had just
	 * saved.
	 * 
	 * So,... we create a new register save area on the old thread's stack
	 * to use in the interim.
	 * 
	 * (we use o7 because the compiler doesn't; a better solution would be
	 * to use a register variable)
	 */
asm volatile(" mov %%sp, %0;":"=r"(oldThread->stack));

	/* Flush register windows to the thread stack */
	asm             volatile(" \
        t %0; \
	sub %%sp, %1, %%sp; \
	mov %2, %%o7 " \
		: :"i" (ST_FLUSH_WINDOWS), \
		"i" (SA(WINDOWSIZE)), \
		"r" (scheduler.current->stack));
#endif /* Sparc */
#ifdef Mc68000
#ifdef Mc68020
	asm             volatile("moveml #0x3f3e, sp@-");
#else /* Mc68020 */
	asm             volatile(" \
				                 movl a6, sp @ -; \
	movl            a5, sp @ -; \
	movl            a4, sp @ -; \
	movl            a3, sp @ -; \
	movl            a2, sp @ -; \
	movl            d7, sp @ -; \
	movl            d6, sp @ -; \
	movl            d5, sp @ -; \
	movl            d4, sp @ -; \
	movl            d3, sp @ -; \
	movl            d2, sp @ -; \
	");
#endif /* Mc68020 */
#endif				/* Mc68000 */

	/* switch stack-pointers */

#ifdef Mips
		asm volatile("add %0, $sp, $0" \
:	     "=r"(oldThread->stack));
	asm             volatile("add $sp, %0, $0" \
			     ::              "r"(scheduler.current->stack));
#endif /* Mips */

#ifdef I386
	asm             volatile("movl %%esp, %0; \
			movl %1, %%esp " \
			:"=&r"(oldThread->stack) \
			:"r"(scheduler.current->stack));
#endif	/* i386 */
#ifdef Sparc
	/* done above */
#endif /* Sparc */
#ifdef Mc68000
	asm             volatile("movl sp, %0;":"=r"(oldThread->stack));
	asm             volatile("movl %0, sp;"::"r"(scheduler.current->stack));
#endif /* Mc68000 */

	oldThread->status = stat;

	if (scheduler.current->status == Created)
	{
		/* first time --- call procedure directly */

#ifdef Mips
		/* create a "mips" stackframe (room for arg regs) */
		asm             volatile("subu $sp, 24");
#endif /* Mips */

#ifdef Sparc
		/*
		 * Ok, so we don't restore anything -- just setup the SP,
		 * which needs to have a register save  + args area! Also,
		 * set the FP for the new stack
		 */
		asm             volatile(" \
					                 sub %%o7, %0, %%sp; \
		mov %%o7, %%fp " \
: :			"i"(SA(MINFRAME)));
#endif /* Sparc */
#ifdef Mc68000
		/* setup a frame and a frame pointer */
		asm             volatile("movl sp, a6; subl #32, sp");
#endif /* Mc68000 */

		/* scheduler.current->startFunc(scheduler->startArg); */
		scheduler.current->status = Running;
		scheduler.current->switch_time =
			oldThread->switch_time = scheduler.switch_time;
		scheduler.current->function();
		threadExit();
	} else
	{
		/* restore registers */

#ifdef Mips
		asm             volatile("lw $17,4($sp); \
					                 lw $18, 8($sp); \
		lw $19, 12($sp); \
		lw $20, 16($sp); \
		lw $21, 20($sp); \
		lw $22, 24($sp); \
		lw $23, 28($sp); \
		lw $fp, 32($sp); \
		lw $16, 36($sp) ");
			asm volatile("addu $sp, 100");
#endif /* Mips */

#ifdef I386
		asm             volatile("leal 108(%esp), %esp; \
					                 popl % esi; \
					                 popl % edi; \
					                 popl % ebx; \
					                 popl % ebp ");
#endif /* I386 */
#ifdef Sparc
		/*
		 * Ok, %o7 == &register save area, %sp==old threads save area
		 * 
		 * Now, restore all registers (except the SP) from the new
		 * thread's save area
		 */
	      asm volatile(" \
	        ldd [%o7], %l0; \
		ldd [%o7 + 0x8], %l2; \
		ldd [%o7 + 0x10], %l4; \
		ldd [%o7 + 0x18], %l6; \
\
		ldd [%o7 + 0x20], %i0; \
		ldd [%o7 + 0x28], %i2; \
		ldd [%o7 + 0x30], %i4; \
		ldd [%o7 + 0x38], %i6; \
		"); 

		/*
		 * The registers are all valid, so traps won't wipe out info
		 * NOW, we can set the new sp
		 */
			asm volatile("nop; mov %o7, %sp; nop");


		/*
		 * floating point registers are caller-save, so we ignore
		 * them
		 */

#endif				/* Sparc */

#ifdef Mc68000
		/*
		 * if(scheduler.current->usesFloatingPoint){ asm volatile ("
		 * fmovem	sp@+,#0xff "); }
		 */
#if defined(Mc68020)
		asm             volatile("moveml sp@+, #0x7cfc");
#else /* defined(Mc68020) */
		asm             volatile(" \
					                 movl sp @ +, d2; \
		movl            sp @ +, d3; \
		movl            sp @ +, d4; \
		movl            sp @ +, d5; \
		movl            sp @ +, d6; \
		movl            sp @ +, d7; \
		movl            sp @ +, a2; \
		movl            sp @ +, a3; \
		movl            sp @ +, a4; \
		movl            sp @ +, a5; \
		movl            sp @ +, a6; \
		");
#endif /* defined(Mc68020) */
#endif				/* Mc68000 */
	}
}

void
threadExit()
{
	struct threads *next_thread;

	/*
	 * If this thread owns any sockets, we should unthread them, but we
	 * don't
	 */
	next_thread = next_runnable();
	if (next_thread)
		threadHandoffCPU(next_thread, Defunct);
	else
		exit(1);
}

