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
 *      Compressor/decompressor software.
 *      
 */

#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include "scps_defines.h"
#include "scpstp.h"
#include "new_compress.h"
#include "scps.h"

#ifndef COMP_NO_STATS
#define INCR(counter) ++comp.counter;
#else /* COMP_NO_STATS */
#define INCR(counter)
#endif /* COMP_NO_STATS */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: new_compress.c,v $ -- $Revision: 1.4 $\n";
#endif

#ifdef OPT_NEW_COMPRESS
uint32_t
tp_Compress (tp_Socket * socket, struct mbuff *m, u_char * chp)
{
  /* NOTE:  The "segment" buffer passed to compress_tp
     MUST BE 32-bit ALIGNED!! */

  register tp_Header *old_th;	/* previous TP header */
  register tp_Header *th;	/* current TP header */
  short tp_len;			/* len of TP hdr in 32-bit words */
  short chl;			/* len of compressed header in bytes */
  register u_int changes = 0;	/* Two octet control field */
  u_char new_seq[20];		/* changes from last to current */
  register u_char *cp = new_seq;
  u_char new_opt[44];		/* for rebuilt options */
  u_char *op = new_opt;
  u_char opt;			/* current option */
  register int deltaS;		/* signed scratch variable */
  register u_int deltaA;	/* unsigned scratch variable */
  short opt_len;		/* len of options in compressed hdr */
  short cnt;			/* down counter for parsing options */
  short olen;			/* length of an individual option */
  u_char *op1;			/* pointer into option space of orig hdr */
  int data_only = 0;		/* If data, nothing else but TS and PUSH */
  th = (tp_Header *) (m->m_pktdat + socket->th_off);
  tp_len = th->th_off;

  if (m->m_ext.len)
    data_only = 1;

  /* 
   * Check to see what has changed 
   * and begin to construct the 
   * compressed header 
   */

  /* 
   * At this point, we assume that we're not doing a resync.  
   * The control flags are built in the variable called changes,
   * which was initialized to zero upon declaration.
   * Since we're not doing a resync, Urg, Win, Ack, and Sequence
   * numbers might change.  Check them.
   */

  old_th = &(socket->old_th);
  if (!data_only)
    {
      if (th->flags & tp_FlagURG)
	{
	  deltaS = (u_short) (th->urgentPointer);
	  ENCODE2 (deltaS);
	  changes |= COMP_URG;
	}

      /* if the window size or the ack number changed, encode both */
      {
	ENCODE2 (ntohs ((u_short) th->window));
	ENCODE4 (ntohl (th->acknum));

	changes |= COMP_A;
      }
    }

  if ((m->m_ext.len) || (th->seqnum != old_th->seqnum) ||
      (th->flags & tp_FlagFIN))
    {
      ENCODE4 (ntohl (th->seqnum));
      changes |= COMP_S;
    }

    {
  if ((opt_len = (tp_len - TP_NO_OPTS)))
    {
      opt_len <<= 2;		/* length in bytes */

      op1 = (u_char *) th + 20;	/* point to options */
      cnt = opt_len;
      for (; cnt > 0; cnt -= olen, op1 += olen) {

	  opt = op1[0];
	  switch (opt) {

	    case TPOPT_EOL:
	    case TPOPT_NOP:
	      olen = 1;
	      continue;

	    case TPOPT_EOR:
	      olen = 2;
	      continue;

	    case TPOPT_TIMESTAMP:
	    {
  	        memcpy (cp, &(op1[2]), 4);
	        cp += 4;
		changes |= COMP_TS1;

  	        memcpy (cp, &(op1[6]), 4);
	        cp += 4;
		changes |= COMP_TS2;
	      olen = 10;
	      continue;
	    }

	    default:
	      olen = op1[1];
	      continue;
	}
     }
    }
   }
  /* Fix the flags field, copy the changed fields, and handle the options. */
  if (th->flags & tp_FlagPUSH)
    changes |= COMP_PUSH;

  if (!data_only)
    {
      if (th->flags & tp_FlagFIN)
	changes |= COMP_FIN;
      if (th->flags & tp_FlagRST)
	changes |= COMP_RST;
      if (th->flags & tp_FlagRST)
	changes |= COMP_ACKR;
    }

  /* Do we have to deal with options?  */
  if ((opt_len = (tp_len - TP_NO_OPTS)))
    {
      opt_len <<= 2;		/* length in bytes */
      /* 
       * Wwe have options - determine if we can compress them 
       *
       * We compress options in the following manner:
       *  - NOP and EOL: discard
       *  - Record boundary: set bit in compressed header 
       *  - All others:  copy options without mods
       */
      op1 = (u_char *) th + 20;	/* point to options */
      cnt = opt_len;
      for (; cnt > 0; cnt -= olen, op1 += olen)
	{
	  opt = op1[0];

	  switch (opt)
	    {
	    default:
	      olen = op1[1];
	      memcpy (op, op1, olen);
	      op += olen;

	      continue;

	    case TPOPT_EOL:
	    case TPOPT_NOP:
	      olen = 1;
	      opt_len--;	/* delete these */
	      continue;

	    case TPOPT_EOR:
	      olen = 2;
	      opt_len -= olen;
	      changes |= COMP_RB;
	      continue;

	    case TPOPT_TIMESTAMP:
	      olen = 10;
	      opt_len -= olen;
	      continue;
	    }
	}
      if ((!data_only) && (opt_len > 0))
	changes |= COMP_OPTS;
    }				/* options */
  deltaS = (cp - new_seq);

  if ((!changes) && (!(th->flags & (tp_FlagFIN | tp_FlagRST))))
    {
      /* At this point, we really expect something to have
         changed.  If not, what we probably have is a 
         retransmit on an idle connection (i.e., there's 
         nothing else in the window, so when the retransmit
         occurred, the sequence number didn't "retreat"), a 
         retransmitted ack, or a window probe.  Let's resync 
         in those cases.   */
      {
	/* goto resync; */
	if (!data_only)
	  {
	    ENCODE2 ((u_short) (ntohs (th->window)));
	    ENCODE4 (ntohl (th->acknum));
	    changes |= COMP_A;
	  }
	deltaS = cp - new_seq;
      }
    }

  /* Do we have one or two octets of change data? */
  if (changes & 0xff)
    changes |= COMP_MORE;
  chl = ((changes & COMP_MORE) ? 5 : 4) + deltaS +
    ((changes & COMP_OPTS) ? (1 + opt_len) : 0);
  if (chl & 0x1)
    {
      /* 
       * if the compressed header is an odd number of bytes,
       * we MUST pad it with a zero value octet, so that the
       * user data starts on an even byte boundary (because
       * the user data checksum is computed assuming an even
       * byte boundary start 
       */
      if (changes & COMP_MORE)
	changes |= COMP_PAD;
      else
	changes |= COMP_MORE;
      chl++;
    }

  cp = chp;

  /* write the connection ID */
  *cp++ = (byte) socket->local_conn_id;

  /* write the control field(s) */
  *cp++ = (u_char) (changes >> 8);
  if (changes & COMP_MORE)
    *cp++ = (u_char) (changes & 0xff);

  /* write the changed fields */
  memcpy (cp, new_seq, deltaS);
  cp += deltaS;

  if (changes & COMP_OPTS)
    {
      *cp++ = opt_len;
      memcpy (cp, new_opt, opt_len);
      cp += opt_len;
    }

  if (changes & COMP_PAD)
    *cp++ = 0;

  socket->ph.nl_head.ipv4.length = htons (chl + m->m_ext.len);
  deltaA = checksum ((word *) chp, chl - 2) + m->m_ext.checksum;
  deltaA = ((deltaA >> 16) & 0xffff) + (deltaA & 0xffff);
  socket->ph.nl_head.ipv4.checksum = ((deltaA >> 16) & 0xffff) + (deltaA & 0xffff);
  deltaA = ~checksum ((word *) & (socket->ph), 14);
  deltaA = htons (deltaA);
  *cp++ = (char) ((deltaA >> 8) & 0xff);
  *cp++ = (char) ((deltaA) & 0xff);
  return (chl);
}

int
tp_Uncompress (tp_Socket * s, char *cp)
{
  /* 
     Inputs:   Compressed packet (in buf[])
     network layer info (in net_info) containing
     packet length, src, dst

     Calling conditions:  protocol number indicated compressed packet 

     Outputs:  Buffer containing uncompressed TP header (tp_header)
     and TP options; 
     Modified input buffer, containing user data (buf[]);
     Return value is offset into buf[], pointing
     to TP user data.
   */
  u_int hlen;
  word changes;
  tp_Header *th;
  int chl;
  u_char *op;

  u_char *p = cp - 1;		/* compressed header length */
  int opt_len = 0;

  th = &(s->in_th);
  changes = (word) (*cp++) << 8;	/* get first byte of field */

  if (changes & COMP_MORE) {
    changes |= (word) ((*cp++) & 0x00ff);
  }

  th->flags = tp_FlagACK;

  if (changes & COMP_PUSH)
    th->flags |= tp_FlagPUSH;

  if (changes & COMP_RST)
    th->flags |= tp_FlagRST;

  if (changes & COMP_FIN)
    th->flags |= tp_FlagFIN;

  if (changes & COMP_URG)
    {
      th->flags |= tp_FlagURG;
      DECODEW (th->urgentPointer);
    }

  if (changes & COMP_A)
    {
      DECODEW (th->window);
      DECODE4 (th->acknum);
    }
  if (changes & COMP_S)
    DECODE4 (th->seqnum);

  if (changes & COMP_ACKR)
    th->flags &= ~tp_FlagACK;

  hlen = TP_NO_OPTS << 2;
  th->th_off = TP_NO_OPTS;

  op = (u_char *) th + 20;
  if (changes & COMP_RB)
    {
      *((word *) op) = htons (TPOPT_EOR << 8 | TPOLEN_EOR);
      op += TPOLEN_EOR;
      hlen += TPOLEN_EOR;
    }
  if ( (changes & COMP_TS1) || (changes & COMP_TS2) )
    {
      *((word *) op) = htons (TPOPT_TIMESTAMP << 8 | TPOLEN_TIMESTAMP);
      if (changes & COMP_TS1) {
		memcpy ((op + 2), cp, 4);
      		cp += 4;
      }

      if (changes & COMP_TS2) {
		memcpy ((op + 6), cp, 4);
      		cp += 4;
      }

      op += TPOLEN_TIMESTAMP;
      hlen += TPOLEN_TIMESTAMP;
    }
  if (changes & COMP_OPTS)
    {
      opt_len = *cp++;
      memcpy (op, cp, opt_len);
      cp += opt_len;
      hlen += opt_len;
      op += opt_len;
    }

/* 
 * TP headers must begin and end on 32-bit boundaries.  
 * Pad with no-op options
 * if necessary.
 */
  if ((opt_len = (hlen % 4)))
    {
      for (; opt_len > 0; opt_len--)
	{
	  *op++ = TPOPT_NOP;
	  hlen++;
	}
    }

  th->th_off = hlen >> 2;

  if (changes & COMP_PAD)
    cp++;

  /* Compressed header length must take into account 2 octets of checksum */
   
  chl = (int) (cp) - (int) p + 2;

  return (chl);
}

#endif /* OPT_NEW_COMPRESS */
