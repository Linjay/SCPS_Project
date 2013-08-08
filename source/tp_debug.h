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
#ifndef tp_debug_h
#define tp_debug_h

/*
 * The general interface to the debug routines is through
 * macros of the form VERIFY_XXXX where XXXX is a memory
 * structure (MBCLUSTER, MBUFF, CL_CHAIN, BUFFER).  
 *
 * There is also a (extremely general-purpose) macro, BUG_HUNT(s)
 * where s is a (tp_Socket *).  By placing calls to BUG_HUNT in the
 * code, it should be possible to detect and localize inconsistancies
 * in the memory management code.
 */

/*
 * DEBUG_HOLES defines.
 */
#ifdef DEBUG_HOLES
#define     VERIFY_BUFFER_HOLES(b) verify_buffer_holes((b), __FILE__, __LINE__)
#define     VERIFY_HOLE(h) verify_hole((h), __FILE__, __LINE__)
#define     SCRUB_HOLES(s) scrub_holes((s), __FILE__, __LINE__)
#else	/* DEBUG_HOLES */
#define     VERIFY_BUFFER_HOLES(b)
#define     VERIFY_HOLE(h)
#define     SCRUB_HOLES(s)
#endif	/* DEBUG_HOLES */

#if ( defined(DEBUG_RATE) && defined(DEBUG_XPLOT) )
#define	    LOGRATE(r) SCPS_logRate(r)
#else
#define     LOGRATE(r)
#endif

#if ( defined(DEBUG_CWND) && defined (DEBUG_XPLOT) )
#define     LOGCWND(s) logCWND(s, __FILE__, __LINE__)
#else
#define     LOGCWND(s)
#endif

#if ( defined(DEBUG_TCPTRACE) && defined (DEBUG_XPLOT) )
#define     LOGACK(s, acknum) logACK(s, acknum, __FILE__, __LINE__)
#else
#define     LOGACK(s, acknum)
#endif

#if ( defined(DEBUG_TCPTRACE) && defined (DEBUG_XPLOT) )
#define     LOGPACKET(s, start, len) logPACKET(s, __FILE__, __LINE__, start, len)
#else
#define     LOGPACKET(s, start, len)
#endif

#ifdef DEBUG_SEQNUM
#define		DEBUG_SEQNUM_CALL(s, b) debug_seqnum((s), (b))
#else	/* DEBUG_SEQNUM */
#define		DEBUG_SEQNUM_CALL(s, b)
#endif /* DEBUG_SEQNUM */

#define		DEBUG_INTERACTIVE_PORT	49987
#ifdef DEBUG_INTERACTIVE
#define		DEBUG_INTERACTIVE_SERVICE()		tp_debugPortService();
#else /* DEBUG_INTERACTIVE */
#define		DEBUG_INTERACTIVE_SERVICE()
#endif /* DEBUG_INTERACTIVE */

/*
 * This is globablly visible all the time.  We often want to print the
 * state in some extreme error conditions.
 */
typedef struct stateNamePair
  {
    int stateNumber;
    char stateName[50];
  }
stateNamePair;

extern stateNamePair stateNamePairs[];

#ifdef DEBUG_ERRORS
void SET_ERR_FUNCTION(int error, char *file, int line);
#endif /* DEBUG_ERRORS */

/*
 * Here we check to see if any of the DEBUG_XXX options
 * are defined.
 */
#if (    defined(TPDEBUG_C) \
      || defined(DEBUG_SUPPORT) \
      || defined(DEBUG_MEMORY) \
      || defined(DEBUG_XPLOT) \
      || defined(DEBUG_RATE) \
      || defined(DEBUG_TIMING) \
      || defined(DEBUG_HOLES) \
      || defined(DEBUG_LOG) \
      || defined(DEBUG_PRINT) \
      || defined(DEBUG_GATEWAY) \
      || defined(DEBUG_ERRORS) \
      || defined(DEBUG_SEQNUM) )

#include <stdio.h>
#include "scps.h"
#include "scpstp.h"
#include "buffer.h"

#define BAD_POINTER(x) badPointer((void *) (x), __FILE__, __LINE__)

/* These values are passed as parameters to verify_mbcluster and 
 * check against the status of the 'de_queued' value.
 */
extern const int CLUSTER_DE_QUEUED;
extern const int CLUSTER_QUEUED;
extern const int CLUSTER_UNKNOWN;
extern struct _tp_socket *G_SOCK;
extern int call_chain_depth;
extern int checkForEndHang;

/* Used for the logFile stuff. */
typedef enum {
  xplot,
  trim,
  SCPS_log,
  logRate,
  state,
  acknum,
  timing,
  sequence,
  e_gateway,
} LOGFILE_IDENT;
extern char tempLogString[];

/*
 * BUG_HUNT searches the system resource lists (the free cluster and
 * free mbuff lists) as well as the structures of the socket (if
 * non-NULL) looking for what it considers to be anomalies and prints
 * warning messages if anomalies are found.
 */
#ifdef DEBUG_MEMORY
#define BUG_HUNT(s) bug_hunt((s), __FILE__, __LINE__)
#else /* DEBUG_MEMORY */
#define BUG_HUNT(s)
#endif /* DEBUG_MEMORY */

/*
 * Due to the way mbclusters are linked together, it is possible to
 * have what appears to be a broken prev pointer.  VERIFY_MBCLUSTER
 * should do the right thing, and will do a better job if given a
 * socket pointer, otherwise it is more permissive of what it
 * considers valid.
 */
#define VERIFY_MBCLUSTER(m, status) verify_mbcluster(m, \
						     status, \
						     __FILE__, \
						     __LINE__, \
						     socket)

#define VERIFY_BUFFER(b) verify_buffer((b), \
				       __FILE__, \
				       __LINE__)

#define VERIFY_MBUFF(b) verify_mbuff((b), \
				     __FILE__, \
				     __LINE__)

#define VERIFY_CL_CHAIN(c, status) verify_cl_chain((c), \
						   (status), \
						   __FILE__, \
						   __LINE__)

#if ( defined(DEBUG_ACKNUM) )
#define PRINT_ACKNUM(a, s) printAcknum((a), (s), __FILE__, __LINE__)
#else
#define PRINT_ACKNUM(a,s)
#endif

#if ( defined(DEBUG_STATE) )
#define PRINT_STATE(state, s) printState((state), (s), __FILE__, __LINE__)
#else
#define PRINT_STATE(state, s)
#endif

/*
 * Function Prototypes.
 */
int isValidSocket(struct _tp_socket *s);
int bug_hunt (struct _tp_socket * s, char *file, int line);
void printState (int state, struct _tp_socket *s, char *file, int line);
void printAcknum (uint32_t a, struct _tp_socket *s, char *file, int line);
int verify_hole (struct _hole_element *h, char *file, int line);
int verify_buffer_holes (struct _buffer *b, char *file, int line);
int scrub_holes (struct _tp_socket *s, char *file, int line);
void logPACKET(struct _tp_socket *s, char *file, int line, uint32_t start, uint32_t len);
void logACK(struct _tp_socket *s, unsigned int acknum, char *file, int line);
void logCWND(struct _tp_socket *s, char *file, int line);
void SCPS_logRate(route *r);
void printHoleChain (struct _hole_element *list);
int mbuffIsOnList (struct mbuff *m, struct mbuff *mlist);
int verify_mbcluster (struct mbcluster *m,
		      int status,
		      char *file,
		      int line,
		      struct _tp_socket *s /* May be NULL */ );
void tp_buffer_report (int sockid);
void udp_buffer_report (int sockid);
int badPointer (void *foo, char *file, int line);
int verify_cl_chain (struct _cl_chain *chain,
		     int status,
		     char *file,
		     int line,
		     struct _tp_socket *s);
int verify_Receive_Buff (struct _buffer *b);
int verify_buffer (struct _buffer *b, char *file, int line);
int verify_mbuff (struct mbuff *m, char *file, int line);
int verify_Socket (struct _tp_socket *s);
int verify_sys_lists (char *file, int line);
int mbclusterIsInChain (struct mbcluster *m, struct _cl_chain *c);

int mbcluster_pointer_walk (struct mbcluster *c);
int mbuff_pointer_walk (struct mbuff *m, int max, char *file, int line);

int print_mbuf_chain (struct mbuff *m, char *file, int line);
int print_buffer (struct _buffer *b);
int print_check ();
int print_cluster_chain (struct _cl_chain *c);
int print_chain_from_cluster (struct mbcluster *c);

void ts_print (register const struct timeval *tvp);
void print_now ();

void debug_seqnum (struct _tp_socket *s, struct mbuff *mbuffer);

int fileExists (char *name);
char *stringNow ();
char *stringNow2 ();
char *stringNow3 (double offset);
char *printPorts (struct _tp_socket *s);

void logEvent(struct _tp_socket *s, LOGFILE_IDENT ident, char *string);
void logEventv(struct _tp_socket *s, LOGFILE_IDENT ident, char *string, ...);

extern int ohshithappened;

extern char timingStartString[];

#else /* No -DDEBUG_XXXs defined and not from tp_debug.c */

/*
 * If DEBUG_MEMORY is not defined, all of the macros do nothing.
 */
#define VERIFY_MBCLUSTER(m, status, socket)
#define VERIFY_BUFFER(b)
#define VERIFY_MBUFF(b)
#define VERIFY_CL_CHAIN(c, status)

#define PUSH_CALL_CHAIN
#define POP_CALL_CHAIN
#define RESET_CALL_CHAIN
#define PRINT_CALL_CHAIN
#define BUG_HUNT(s)
#define PRINT_STATE(state, s)
#define PRINT_ACKNUM(a, s)

#endif	/* DEBUG_FUNCTIONS */

#define TP_IOVCOALESCE(s, m, bytes) tp_iovCoalesce((s), (m), (bytes), \
						   __FILE__, __LINE__)

/* time comment acknum uwe snd_cwnd snd_prevcwnd snd_ssthresh rtt rttseq snduna seqsent 
   diff 
*/
#define TIMING_FORMAT "%s %s %lu %lu %ld %lu %lu %d %lu %lu %lu\n"


#endif	/* tp_debug_h */
