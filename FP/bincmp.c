/*
  This is unclassified Government software.

  The SCPS File Protocol (SCPS-FP) software was developed under
  contract to the Jet Propulsion Laboratory, an operating division of
  the California Institute of Technology and is available for use by
  the public without need of a licence.

  DISCLAIMER:

  THE SCPS-FP SOFTWARE AND RELATED MATERIALS ARE PROVIDED "AS-IS"
  WITHOUT WARRANTY OR INDEMNITY OF ANY KIND INCLUDING ANY WARRANTIES
  OF USE, PEROFMRNACE, OR MERCHANTABILITY OR FITNESS FOR A PRTICULAR
  USE OR PURPOSE (as set forth in UCC section 2312-2313) OR FOR ANY
  PURPOSE WHATSOEVER.

  USER BEARS ALL RISK RELATING TO USE, QUALITY, AND PERFORMANCE OF THE
  SOFTWARE.

  The Jet Propulsion Laboratory, the California Institute of
  Technology, and the United States government retain a paid-up
  royalty free world wide license in this product.

  SAIC Disclaimer:
    (1) SAIC assumes no legal responsibility for the source code and
        its subsequent use.
    (2) No warranty or representation is expressed or implied.
    (3) Portions (e.g. Washington University FTP Replacement Daemon)
        are copyright (c) Regents of the University of California.
	All rights reserved.  Restrictions included in said copyright
	are also applicable to this release.

*/

/********************************************************************/
/*  Created by      :                                               */
/*                     Steven R. Sides                              */
/*                     steven.r.sides@cpmx.saic.com                 */
/*                     Tuesday, June 18, 1996 11:03 am              */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             bincmp.c                                     */
/*                                                                  */
/* Description:                                                     */
/*    Contains routines that perform a "diff" on binary files.      */
/*    It works by assuming that file1 and file2 are composed        */
/*    of records and that the majority of the records in file2      */
/*    are unchanged.                                                */
/*
 * $Id: bincmp.c,v 1.11 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/bincmp.c,v 1.11 2007/04/19 15:09:36 feighery Exp $
 * 
 *    Change History:
 * $Log: bincmp.c,v $
 * Revision 1.11  2007/04/19 15:09:36  feighery
 * This version makes the gateway code (and only the gateway code) safe for
 * 64 bit architectures.  Before we were very sloppy and use a long and int
 * interchangeable.  As part of this change, it was required to make the
 * gateway code single threaded;  therefore gateway_single_thread=yes is the
 * default.  -- PDF
 *
 * Revision 1.10  2002/09/23 19:52:14  scps
 * Added the following pieces of code for this rev
 *
 * 1)  Rewrote the readme tun based on user feedback
 *
 * 2)  Added ability to disable the rule generation for gateway operating
 *
 * 3)  Added support for OpenBSD based on user feedback.
 *
 *         PDF
 *
 * Revision 1.9  1999/11/22 16:14:32  scps
 * Removed disclaimer comment blocks from revision logs.
 *
 * Revision 1.8  1999/11/22 15:52:41  scps
 * Changed FP discaimers
 *
 * Revision 1.7  1999/03/23 20:24:33  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.6.2.2  1999/01/22 15:02:28  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:27  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:35  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.4  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.3  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 * 
 * Revision 1.2  1997/06/16 14:09:30  steven
 * Added size LARGE.
 * 
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *                                                                  */
/********************************************************************/

static char rcsid[] = "$Id: bincmp.c,v 1.11 2007/04/19 15:09:36 feighery Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bincmp.h"
#ifdef MSVC
#include <winsock.h>
#else
#if !defined(SYSV)
#ifndef memchr
extern void *memchr (const void *, int, __SIZE_TYPE__);
#endif
#include <unistd.h>
#endif
#endif


static char rbuf[RBUF_SIZE];
static int32_t foundat[FOUNDAT_SIZE];

#if !defined(SYSV) && !defined(__BSD__) && !defined(MSVC) && !defined(LINUX)
void bcopy (char *b1, char *b2, int length);

/* memmove -
 *   
 */
char *
memmove (char *s1, char *s2, size_t n)
{
  bcopy (s2, s1, (int) n);
  return s1;
}				/* memmove() */
#endif



/* foundone -
 *     Found an occurrance of the string in the file.
 *
 *     returns -1 if foundat[] is full, 0 otherwise.
 */
int
foundone (int32_t fileloc)
{
  if (foundat[0] + 1 == FOUNDAT_SIZE)
    {
      return (-1);
    }
  foundat[0] += 1;
  foundat[foundat[0]] = fileloc;
  return (0);
}				/* foundone() */


/* strsearch -
 *     Searches the file for the specified binary
 *     unsigned character string.  Searches for
 *     the first FOUNDAT_SIZE-1 matches.
 *
 *     Returns a pointer to an array of longs (if
 *     and matches were found) or NULL (if no
 *     matches were found).
 *
 *     If matches were found, the first element of
 *     the array contains the number of matches
 *     found.  The following elements contain the
 *     file positions of the matches.
 */
int32_t *
strsearch (FILE * f, char *str, int strlen)
{
  int rbuflen;
  int remaining;
  int32_t current_offset = 0;	/* offset in the file of rbuf[0] */
  char *where;
  char *startsearch;
  char *endadr;
  int32_t pos;
  int havelen;

  foundat[0] = 0;
  for (;;)
    {
      rbuflen = fread (rbuf, 1, RBUF_SIZE, f);
      if (rbuflen == 0 || rbuflen < strlen)
	break;
      startsearch = rbuf;
      endadr = rbuf + rbuflen;
      remaining = rbuflen;
      while ((where = memchr (startsearch, *str, remaining)))
	{
	  havelen = remaining - (int) (where - startsearch);
	  if (havelen < strlen)
	    {
	      /* end of buffer comes before end of search string 
	       * move the part to the beginning of rbuf, fill the
	       * rest of rbuf with the next bytes in the file, and
	       * compare the string.  The search string must be shorter
	       * than the size of rbuf.  */
	      memmove (rbuf, where, havelen);
	      /* update current_offset */
	      current_offset += (int32_t) (rbuflen - havelen);
	      rbuflen = fread (rbuf + havelen, 1, RBUF_SIZE - havelen, f);
	      if (0 == rbuflen || (rbuflen + havelen) < strlen)
		{
		  goto alldone;
		}
	      if (0 == memcmp (rbuf, str, strlen))
		{
		  if (foundone (current_offset) < 0)
		    goto alldone;
		}
	      rbuflen += havelen;	/* From now on, include the partial
					 * string in calculations.  */
	      where = rbuf;
	      endadr = rbuf + rbuflen;
	    }
	  else
	    {
	      if (0 == memcmp (where, str, strlen))
		{
		  /* Found a match. */
		  if (foundone ((int32_t) (where - rbuf) + current_offset) < 0)
		    goto alldone;
		}
	    }
	  startsearch = where + 1;
	  remaining = (int) (endadr - startsearch);
	}			/* while */
      current_offset += (int32_t) (rbuflen);
    }

alldone:
  pos = 0;
  fseek (f, pos, SEEK_SET);
  if (foundat[0])
    return (foundat);
  else
    return (NULL);
}				/* strsearch() */


/* freemall -
 *     Free a list of matches
 */
void
freemall (struct _matches *m)
{
  struct _matches *freemall;

  freemall = m;
  while (freemall)
    {
      freemall = m->next;
      free (m);
      m = freemall;
    }
}				/* freemall() */


/* freem -
 *     Free one match from the list.
 */
struct _matches *
freem (struct _matches **head, struct _matches *m)
{
  struct _matches *r;

  if (m->prev)
    (m->prev)->next = m->next;
  else
    *head = m->next;
  if (m->next)
    (m->next)->prev = m->prev;
  r = m->next;
  free (m);
  return (r);
}				/* freem() */


/* collectmatches -
 *   Grabs sort of 80 bytes every 4K or so in the original file
 *   and searches for them in the modified file.  Each
 *   80 byte string may occur 0, 1 or more times in the
 *   modified file.  strsearch() finds only the first
 *   FOUNDAT_SIZE-1 matches.
 * 
 *   collectmatches() builds a list of matches and
 *   stores them in the structure matches.
 */
struct _matches *
collectmatches (FILE * f1, FILE * f2, int32_t f1size)
{
  static struct _matches *mz = NULL;	/* list of matches */
  int32_t gotopos = 0;
  int32_t srchstrlen;
  int32_t interval;
  char *srchbuf;
  int32_t *matches;
  int32_t count;
  struct _matches *lastm = NULL;	/* last match      */


  /* keep the search string length <= 80 bytes. */
  srchstrlen = min ((int32_t) (STRLEN_MAP * f1size), 80L);
  /* keep the interval <= 10K bytes so that expandmatches()
   * never needs more than 20K of buffer space.  Some user
   * might be unlucky enough to have a change record at
   * the beginning of an interval, and another at the end
   * of an interval.  In that case, the just-less-than
   * 10K of unchanged data would be transmitted as updated.
   * limiting interval to 10K, attempts to set the limit of
   * the size of an update record. */
  interval = min ((int32_t) (INTERVAL_MAP * f1size), 10000L);
  srchbuf = malloc ((size_t) (srchstrlen));
#ifdef DEBUG
  printf ("Search string length: %ld  Interval: %ld\n", srchstrlen, interval);
#endif

  for (;;)
    {
      if (0 == fseek (f1, gotopos, SEEK_SET))
	{
	  fread (srchbuf, 1, (size_t) (srchstrlen), f1);
	  matches = strsearch (f2, srchbuf, (int) (srchstrlen));
	  if (matches)
	    {
	      /* found something. */
	      count = *matches++;
	      if (1 == count)
		{
		  /* if it matched more than one time, discard all the
		   * matches--they don't tell me anything. */
		  if (NULL == mz)
		    {
		      /* This is the first match entry. */
		      mz = lastm = malloc (sizeof (struct _matches));
		      mz->prev = NULL;
		      if (NULL == mz)
			goto rerror;
		    }
		  else
		    {
		      struct _matches *tmp;

		      tmp = malloc (sizeof (struct _matches));
		      if (NULL == tmp)
			goto rerror;
		      tmp->prev = lastm;
		      lastm->next = tmp;
		      lastm = tmp;
		    }
		  lastm->next = NULL;
		  lastm->f1loc = gotopos;
		  lastm->f2loc = *matches;
		  lastm->length = srchstrlen;
		  /* printf("here:%09lX  prev:%09lX  f1loc:%ld  f2loc:%ld  len:%ld\n", lastm, lastm->prev, lastm->f1loc, lastm->f2loc, lastm->length); */
		}		/* for */
	    }			/* if matches found */
	}
      else
	{
	  goto rerror;
	}
      gotopos += interval;
      if (gotopos + srchstrlen > f1size)
	break;
    }				/* for */

  free (srchbuf);
  return (mz);

rerror:
  free (srchbuf);
  freemall (mz);		/* If mz == NULL, freemall() does nothing--just returns */
  return (NULL);
}				/* collectmatches() */


/* removemoves -
 *   Currently, SCPS-FP record update does not
 *   support move.  Moves must be treated as
 *   inserts.
 * 
 *   Returns 1 if one or more moves was removed,
 *   0 if no moves were removed, and perhaps -1
 *   if there is an error.
 *     
 */
int
removemoves (struct _matches **m)
{
  struct _matches *tmp = *m;
  int32_t currf2loc = 0;

  while (tmp)
    {
      if (tmp->f2loc < currf2loc)
	{
	  /* f2 is supposed to be only slightly different
	   * than f1, so the f2 locations should generally
	   * be in order.  */
	  tmp = freem (m, tmp);
	}
      else
	{
	  currf2loc = tmp->f2loc;
	  tmp = tmp->next;
	}
    }
  return (0);
}				/* removemoves() */


/* removeoverlaps -
 *   Makes sure that none of the match strings in
 *   f2 overlap.  An overlap is where, for example,
 *   one match (m1) is at 25 in f2 for length 61, and
 *   another match (m2) is at 36 for length 61.  Here the
 *   first 50 bytes of m2 are the same bytes as the last 50
 *   of m1.  This routine would remove the match m2.
 * 
 *   This routine depends on moves having been removed,
 *   and f2locs being in ascending order.  Therefore if
 *   there is an overlap, it will be the very next match
 *   in the list.
 */
int
removeoverlaps (struct _matches **m)
{
  struct _matches *tmp = *m;

  while (tmp)
    {
      if (tmp->next)
	{
	  if ((tmp->next)->f2loc < (tmp->f2loc + tmp->length))
	    {
	      /* found an overlap.  Delete it.  It doesn't tell
	       * me how to generate change data.  */
	      tmp = freem (m, tmp->next);
	    }
	  else
	    {
	      tmp = tmp->next;
	    }
	}
      else
	{
	  tmp = NULL;
	}
    }				/* while */
  return (0);
}				/* removeoverlaps() */


/* memrcmp -
 *   Compares the string at s1 with the string at s2,
 *   each of length n.  Compares strings in reverse.
 * 
 *   Returns the index of the point where the
 *   strings differ. If the strings are identical,
 *   returns -1.
 * 
 * 
 *   PERFORMANCE:
 *   To improve performance dramatically, write this
 *   in assembler.
 */
int
memrcmp (char *s1, char *s2, size_t n)
{
  n--;
  if (NULL == s1 || NULL == s2)
    return (int) n;
  for (s1 += n, s2 += n; n && *s1 == *s2; s1--, s2--, n--);
  if (n == 0 && *s1 == *s2)
    return (int) (-1);
  else
    return (int) n;
}				/* memrcmp() */


/* memfcmp -
 *   Compares successive elements from two arrays
 *   of char, beginning at the addresses s1 and s2
 *   (both of size n), until it finds elements that
 *   are not equal.
 * 
 *   Returns the index of the point where the strings
 *   differ.  If the strings are identical, returns
 *   n.
 * 
 * 
 *   PERFORMANCE:
 *   To improve performance dramatically, write this
 *   in assembler.
 */
int
memfcmp (char *s1, char *s2, size_t n)
{
  size_t x;

  if (NULL == s1 || NULL == s2)
    return 0;
  for (x = 0; x < n && *s1 == *s2; s1++, s2++, x++);
  return (int) x;
}				/* memfcmp() */

/* expandmatches -
 *   Goes through the list of matches and tries to
 *   expand the length backward or forward.
 *   
 *   For example if the 80 byte string at location
 *   16K in the original file matches the 80 byte
 *   string at location 17K in the modified file,
 *   this routine compares the bytes before and after
 *   the 80 byte string to see if it is part of a
 *   larger block that matches.
 * 
 *   The struct _matches pointer is passed by reference
 *   because removemoves() or removeoverlaps() might
 *   need to remove the first match.
 * 
 *   expandmatches() finds the first byte that is different
 *   in both directions.  Updates the matches record
 *   to reflect the locations and length of the block
 *   that matches.
 * 
 *   Finally it goes through the list and merges multiple
 *   match records that refer to a contiguous file block
 *   into one match record.  For example, if there
 *   are three match records that refer to locations
 *   0-200, 201-300, and 301-500, respectively,
 *   expandmatches() frees the second and third
 *   match records and updates the first match record
 *   to refer to locations 0-500.
 * 
 *   Returns -1 if something went wrong i.e. couldn't
 *   malloc(), expand problems, etc.
 * 
 *   Returns 0 if everything went OK.
 *     
 */
int
expandmatches (struct _matches **m, FILE * f1, FILE * f2, int32_t f1size, int32_t f2size)
{
  struct _matches *tmp;
  int32_t prevf1loclen, prevf2loclen;
  int32_t nextf1loclen, nextf2loclen;
  char *cmpf1buf, *cmpf2buf;
  int result;
  int update;			/* update elements of this match. */
  int more;			/* expand this match more */
  int32_t rdsize;
  int32_t fpos;

  /* Remove matches that refer to blocks that have moved relative
   * to other blocks that match.  */
  removemoves (m);

  /* Remove overlapping match blocks. */
  removeoverlaps (m);

  cmpf1buf = malloc (RBUF_SIZE);
  if (NULL == cmpf1buf)
    {
      printf ("Unable to allocate memory near %d of %s\n", __LINE__, __FILE__);
      return (-1);
    }

  cmpf2buf = malloc (RBUF_SIZE);
  if (NULL == cmpf2buf)
    {
      printf ("Unable to allocate memory near %d of %s\n", __LINE__, __FILE__);
      return (-1);
    }

  /* expand backward */
  tmp = *m;
  while (tmp)
    {
      for (more = 1; more;)
	{
	  /* Only expand this block back as far as the end
	   * of the previous match (or beginning of file if there
	   * is no previous match). */
	  if (tmp->prev)
	    {
	      prevf1loclen = (tmp->prev)->f1loc + (tmp->prev)->length;
	      prevf2loclen = (tmp->prev)->f2loc + (tmp->prev)->length;
	    }
	  else
	    {
	      /* Set expand back limit to beginning-of-file. */
	      prevf1loclen = 0;
	      prevf2loclen = 0;
	    }			/* if */
	  if (tmp->f1loc == prevf1loclen ||
	      tmp->f2loc == prevf2loclen)
	    {
	      /* Expanded to the limit.  Quit */
	      more = 0;
	    }
	  else
	    {
	      rdsize = min (RBUF_SIZE, tmp->f1loc - prevf1loclen);
	      rdsize = min (rdsize, tmp->f2loc - prevf2loclen);
	      fpos = tmp->f1loc - rdsize;
	      result = fseek (f1, fpos, SEEK_SET);
	      fpos = tmp->f2loc - rdsize;
	      result |= fseek (f2, fpos, SEEK_SET);
	      if (result)
		{
		  /* panic */
		  printf ("Invalid file position near %d of %s\n", __LINE__, __FILE__);
		  return (-1);
		}
	      result = fread (cmpf1buf, 1, (size_t) rdsize, f1);
	      if (result != rdsize)
		{
		  printf ("Invalid read near %d of %s\n", __LINE__, __FILE__);
		  return (-1);
		}
	      result = fread (cmpf2buf, 1, (size_t) rdsize, f2);
	      if (result != rdsize)
		{
		  printf ("Invalid read near %d of %s\n", __LINE__, __FILE__);
		  return (-1);
		}
	      result = memrcmp (cmpf1buf, cmpf2buf, (size_t) rdsize);
	      update = (int) (rdsize) - (result + 1);
	      if (update)
		{
		  tmp->f1loc -= update;
		  tmp->f2loc -= update;
		  tmp->length += update;
		  if (update < rdsize)
		    {
		      /* some bytes did not match */
		      more = 0;
		    }
		}
	      else
		{
		  /* no bytes matched */
		  more = 0;
		}
	    }			/* if */
	}			/* for */
      tmp = tmp->next;
    }

  /* expand forward */
  tmp = *m;
  while (tmp)
    {
      for (more = 1; more;)
	{
	  /* Only expand this block forward as far as the beginning
	   * of the next match (or end of file if there is no
	   * next match). */
	  if (tmp->next)
	    {
	      nextf1loclen = (tmp->next)->f1loc;
	      nextf2loclen = (tmp->next)->f2loc;
	    }
	  else
	    {
	      /* Set expand forward limit to end-of-file. */
	      nextf1loclen = f1size;
	      nextf2loclen = f2size;
	    }			/* if */
	  if (tmp->f1loc == nextf1loclen ||
	      tmp->f2loc == nextf2loclen)
	    {
	      /* Expanded to the limit.  Quit */
	      more = 0;
	    }
	  else
	    {
	      rdsize = min (RBUF_SIZE, nextf1loclen - (tmp->f1loc + tmp->length));
	      rdsize = min (rdsize, nextf2loclen - (tmp->f2loc + tmp->length));
	      fpos = tmp->f1loc + tmp->length;
	      result = fseek (f1, fpos, SEEK_SET);
	      fpos = tmp->f2loc + tmp->length;
	      result |= fseek (f2, fpos, SEEK_SET);
	      if (result)
		{
		  /* panic */
		  printf ("Invalid file position near %d of %s\n", __LINE__, __FILE__);
		  return (-1);
		}
	      result = fread (cmpf1buf, 1, (size_t) rdsize, f1);
	      if (result != rdsize)
		{
		  printf ("Invalid read near %d of %s\n", __LINE__, __FILE__);
		  return (-1);
		}
	      result = fread (cmpf2buf, 1, (size_t) rdsize, f2);
	      if (result != rdsize)
		{
		  printf ("Invalid read near %d of %s\n", __LINE__, __FILE__);
		  return (-1);
		}
	      update = memfcmp (cmpf1buf, cmpf2buf, (size_t) rdsize);
	      if (update > 0)
		{
		  tmp->length += update;
		  if (update < rdsize)
		    {
		      /* some bytes did not match */
		      more = 0;
		    }
		}
	      else
		{
		  /* no bytes matched */
		  more = 0;
		}
	    }			/* if */
	}			/* for */
      tmp = tmp->next;
    }

  /* combine matches */
  tmp = *m;
  while (tmp)
    {
      if (tmp->next)
	{
	  if (tmp->f1loc + tmp->length == (tmp->next)->f1loc &&
	      tmp->f2loc + tmp->length == (tmp->next)->f2loc)
	    {
	      tmp->length += (tmp->next)->length;
	      freem (m, tmp->next);
	    }
	  else
	    {
	      tmp = tmp->next;
	    }
	}
      else
	{
	  tmp = NULL;
	}
    }
  return (0);
}				/* expandmatches() */
