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
/* #include "scpserrno.h" */
#include <stdio.h>		/* temporary */
#include <sys/types.h>
#include "thread.h"
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "buffer.h"

#include "scps_ip.h"

#ifdef SCPSSP
#include "scps_sp.h"
int sp_ind (scps_sp_rqts * sp_rqts, short length, int *offset);
#endif /* SCPSSP */

#ifdef Sparc
#include <sys/mman.h>
#endif /* Sparc */

#define VERBOSE

#define TEST_1_FAIL 1
#define TEST_2_FAIL 2
#define TEST_3_FAIL 4
#define TEST_4_FAIL 8
#define TEST_5_FAIL 16
#define TEST_6_FAIL 32
#define TEST_7_FAIL 64
#define TEST_8_FAIL 128
#define TEST_9_FAIL 256

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: scrub_holes.c,v $ -- $Revision: 1.9 $\n";
#endif

int
scrub_holes (tp_Socket * s, char *file, int line)
{
  int retval = 0;
  int done = 0;
  int len = 0;
  int hole_idx = 0;
  struct _hole_element *hole;
  struct mbuff *mbuff;
  uint32_t prev_start_seq;
  uint32_t prev_end_seq;

  /* Is the starting sequence number in the hole equal to the starting 
   * sequence number in hole_start?
   */

  if ((s->send_buff->holes))
    {
      for (hole = s->send_buff->holes; hole; hole = hole->next)
	{
	  hole_idx++;

	  if (hole == s->send_buff->holes)
	    {
	      prev_start_seq = hole->hole_start_seq;
	      prev_end_seq = hole->hole_end_seq;
	    }
	  else
	    {
	      /* If the new one doesn't end after the old one, something
	       * is screwed up. */
	      if (!(SEQ_GT (hole->hole_start_seq, prev_end_seq)))
		{
		  retval |= TEST_9_FAIL;
#ifdef VERBOSE
		  printf ("HOLE SCRUB ERROR:  Hole overlap error\n");
		  printf ("hole index = %d\n", hole_idx);
#endif /* VERBOSE */
		  /* old ends after new, old starts after new 
		   *    -> misordered list */
		  if (SEQ_GT (prev_start_seq, hole->hole_start_seq))
		    {
#ifdef VERBOSE
		      printf ("HOLE SCRUB ERROR:  Misordered list\n");
		      printf ("hole = %x, hole->prev = %x\n", hole, hole->prev);
#endif /* VERBOSE */
		    }
		  if (prev_start_seq == hole->hole_start_seq)
		    {
#ifdef VERBOSE
		      printf ("HOLE SCRUB ERROR:  Duplicate hole\n");
		      printf ("hole = %x, hole->prev = %x\n", hole, hole->prev);
#endif /* VERBOSE */
		    }
		  if (prev_end_seq == hole->hole_end_seq)
		    {
#ifdef VERBOSE
		      printf ("HOLE SCRUB ERROR:  Holes end at same point\n");
		      printf ("hole = %x, hole->prev = %x\n");
#endif /* VERBOSE */
		    }

		}
	    }
	  if (hole->hole_start_seq != hole->hole_start->m_seq)
	    {
#ifdef VERBOSE
	      printf
		("HOLE SCRUB ERROR:  Starting sequence number mismatch\n");
	      printf ("hole = %x, mbuffer = %x\n", hole, hole->hole_start);
	      printf ("hole->hole_start_seq = %u, mbuffer->m_seq = %u\n",
		      hole->hole_start_seq, hole->hole_start->m_seq);
#endif /* VERBOSE */
	      retval |= TEST_1_FAIL;
	    }

/*  Is the calculated ending sequence number of the hole consistent with
 *  the recorded ending sequence number?
 */
	  if ((hole->hole_start_seq + hole->length) != hole->hole_end_seq)
	    {
#ifdef VERBOSE
	      printf ("HOLE SCRUB ERROR:  Ending sequence number mismatch\n");
	      printf ("hole = %x\n", hole);
	      printf ("Expected = %u, Got = %u\n",
		      hole->hole_start_seq + hole->length, hole->hole_end_seq);
	      printf
		("hole->hole_start_seq = %u, len = %d, hole_end_seq = %u\n",
		 hole->hole_start_seq, hole->length, hole->hole_end_seq);
	      printf ("hole_idx = %d\n", hole_idx);
#endif /* VERBOSE */
	      retval |= TEST_2_FAIL;
	    }
	  if (hole->hole_end_seq !=
	      (hole->hole_end->m_seq + hole->hole_end->m_ext.len))
	    {
#ifdef VERBOSE
	      printf
		("HOLE SCRUB ERROR:  Ending sequence number mismatch 2\n");
	      printf ("Expected %u, Got %u\n", hole->hole_end_seq,
		      (hole->hole_end->m_seq + hole->hole_end->m_ext.len));
	      printf ("hole_idx = %d\n", hole_idx);
#endif /* VERBOSE */
	      retval |= TEST_3_FAIL;
	    }

	  done = len = 0;
	  for (mbuff = hole->hole_start;
	       ((mbuff) && (done == 0) &&
		(SEQ_LT (mbuff->m_seq, hole->hole_end_seq)));
	       mbuff = mbuff->m_next)
	    {
	      if (mbuff == hole->hole_end)
		done = 1;

	      if (mbuff->parent != s->send_buff)
		{
#ifdef VERBOSE
		  printf ("HOLE SCRUB ERROR:  Hole parent mismatch\n");
		  printf ("hole = %x, mbuff = %x\n", hole, mbuff);
		  printf ("Expected = %x, Got = %x\n",
			  s->send_buff, mbuff->parent);
#endif /* VERBOSE */
		  retval |= TEST_4_FAIL;
		}
	      len += mbuff->m_ext.len;

/* Have all mbuffs in the chain been sent at least once? */
	      if (mbuff->m_ts == 1)
		{
#ifdef VERBOSE
		  printf ("HOLE SCRUB ERROR:  Unsent mbuffer in hole\n");
		  printf ("hole = %x, mbuff = %x\n", hole, mbuff);
#endif /* VERBOSE */
		  retval |= TEST_7_FAIL;

		}
	    }			/* for each mbuff in the hole */

/* Is the chain of mbuffs unbroken from hole_start to hole_end? */
	  if (done != 1)
	    {
#ifdef VERBOSE
	      printf ("HOLE SCRUB ERROR:  mbuff chain broken\n");
	      printf ("hole = %x, mbuff = %x\n", hole, mbuff);
#endif /* VERBOSE */
	      retval |= TEST_5_FAIL;
	    }
	  if (len != hole->length)
	    {
#ifdef VERBOSE
	      printf ("HOLE SCRUB ERROR:  mbuff chain length error\n");
	      printf ("hole = %x, mbuff = %x\n", hole, mbuff);
	      printf ("Expected = %d, Got = %d\n", hole->length, len);
#endif /* VERBOSE */
	      retval |= TEST_6_FAIL;

	    }
	  if (SEQ_GT (hole->hole_start_seq, s->max_seqsent))
	    {
#ifdef VERBOSE
	      printf ("HOLE SCRUB ERROR: hole_start_seq beyond max_seqsent\n");
	      printf ("hole = %x, mbuff = %x\n", hole, mbuff);
	      printf ("hole_start_seq = %u, max_seqsent = %u\n",
		      hole->hole_start_seq, s->max_seqsent);
#endif /* VERBOSE */
	      retval |= TEST_8_FAIL;

	    }
	}
    }
  if (retval)
    printf ("%d total holes checked\n", hole_idx);
  return (retval);
}
