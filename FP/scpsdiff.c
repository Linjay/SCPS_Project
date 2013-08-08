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
/*                     Wednesday, June 19, 1996 1:02 pm             */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             scpsdiff.c                                   */
/*                                                                  */
/* Description:                                                     */
/*    Tool to create the record update commands to convert f1       */
/*    into f2.                                                      */
/*
 * $Id: scpsdiff.c,v 1.10 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/scpsdiff.c,v 1.10 2007/04/19 15:09:36 feighery Exp $
 * 
 *    Change History:
 * $Log: scpsdiff.c,v $
 * Revision 1.10  2007/04/19 15:09:36  feighery
 * This version makes the gateway code (and only the gateway code) safe for
 * 64 bit architectures.  Before we were very sloppy and use a long and int
 * interchangeable.  As part of this change, it was required to make the
 * gateway code single threaded;  therefore gateway_single_thread=yes is the
 * default.  -- PDF
 *
 * Revision 1.9  1999/11/22 16:14:34  scps
 * Removed disclaimer comment blocks from revision logs.
 *
 * Revision 1.8  1999/11/22 15:52:44  scps
 * Changed FP discaimers
 *
 * Revision 1.7  1999/03/23 20:24:37  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.6.2.2  1999/01/22 15:02:35  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:34  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:38  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.4  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.3  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 * 
 * Revision 1.2  1997/06/16 14:09:30  steven
 * Added sizes MEDIUM and LARGE.
 * 
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *                                                                  */
/********************************************************************/

static char rcsid[] = "$Id: scpsdiff.c,v 1.10 2007/04/19 15:09:36 feighery Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "bincmp.h"
#ifdef MSVC
#include <winsock.h>
#else
#include <netinet/in.h>		/* for hton macros/routines */
#include <unistd.h>
#endif


/* usage -
 *     Display usage
 */
void
usage (void)
{
  printf ("Usage:\n");
  printf ("   scpsdiff f1 f2 update_control_file\n");
  printf ("\n");
  printf
    ("   Requires three filename arguments.  Uses a special compare algorithm\n");
  printf
    ("   to compare binary file f1 with binary file f2.  Writes SCPS-FP record\n");
  printf
    ("   update commands to update_control_file.  The record update commands\n");
  printf ("   convert f1 into f2.\n");
}				/* usage() */


/* wl -
 *     write long.
 *     Returns 1 on success, 0 on failure.
 */
int
wl (int32_t what, FILE * f)
{
  what = htonl (what);
  return (fwrite (&what, 4, 1, f));
}				/* wl() */


/* ws -
 *     write short.
 *     Returns 1 on success, 0 on failure.
 */
int
ws (short what, FILE * f)
{
  what = htons (what);
  return (fwrite (&what, 2, 1, f));
}				/* ws() */


/* wblk -
 *     write block.
 *     Returns 1 on success, 0 on failure.
 */
int
wblk (int32_t loc, short n, FILE * f2, FILE * outf)
{
  char *rdbuf;
  int result;

  rdbuf = malloc ((size_t) n);
  if (rdbuf)
    {
      if (fseek (f2, loc, SEEK_SET))
	{
	  printf ("Invalid seek near %d of %s (location:%ld)\n", __LINE__,
		  __FILE__, loc);
	  free (rdbuf);
	  exit (2);
	}
      result = fread (rdbuf, 1, (size_t) n, f2);
      if (result != n)
	{
	  printf ("Invalid read near %d of %s (size:%d)\n", __LINE__,
		  __FILE__, n);
	  free (rdbuf);
	  exit (2);
	}
      result = fwrite (rdbuf, 1, (size_t) n, outf);
      if (result != n)
	{
	  printf ("Invalid write near %d of %s\n", __LINE__, __FILE__);
	  free (rdbuf);
	  exit (2);
	}
      free (rdbuf);
      return 1;
    }
  else
    {
      printf ("Couldn't malloc near %d of %s\n", __LINE__, __FILE__);
      exit (2);
    }
}				/* wblk() */


/* write_updt_rec -
 *     Write one or two update commands to effect a change for a single
 *     block that is different in f2 than in f1.
 */
void
write_updt_rec (struct _matches *m, int32_t currf1, int32_t currf2, FILE * f2,
		FILE * outf)
{
  /*  scpsdiff assumes that the changes are small.
   *  So m->fnloc - currfn should always fit in a short. 
   *  If the block is too large, it would have been caught
   *  before now.  */
  short f1blk = (short) (m->f1loc - currf1);
  short f2blk = (short) (m->f2loc - currf2);

  /* The case of 0 == f1blk && 0 == f2blk is checked by the caller.
   * in that case, this routine should do nothing--it should not
   * even be called. */

  if (0 == f1blk && 0 != f2blk)
    {
      fwrite ("i", 1, 1, outf);
      wl (currf1, outf);
      ws (f2blk, outf);
      wblk (currf2, f2blk, f2, outf);
    }
  else if (0 != f1blk && 0 == f2blk)
    {
      fwrite ("d", 1, 1, outf);
      wl (currf1, outf);
      ws (f1blk, outf);
    }
  else if (f1blk > f2blk)
    {
      fwrite ("w", 1, 1, outf);
      wl (currf1, outf);
      ws (f2blk, outf);
      wblk (currf2, f2blk, f2, outf);

      fwrite ("d", 1, 1, outf);
      wl ((int32_t) (currf1 + f2blk), outf);
      ws ((short) (f1blk - f2blk), outf);
    }
  else if (f1blk == f2blk)
    {
      fwrite ("w", 1, 1, outf);
      wl (currf1, outf);
      ws (f2blk, outf);
      wblk (currf2, f2blk, f2, outf);
    }
  else if (f1blk < f2blk)
    {
      fwrite ("w", 1, 1, outf);
      wl (currf1, outf);
      ws (f1blk, outf);
      wblk (currf2, f1blk, f2, outf);

      fwrite ("i", 1, 1, outf);
      wl ((int32_t) (currf1 + f1blk), outf);
      ws ((short) (f2blk - f1blk), outf);
      wblk ((int32_t) (currf2 + f1blk), (short) (f2blk - f1blk), f2, outf);
    }
}				/* write_updt_rec() */


/* main -
 *     Returns 0 if everything went OK, non-zero otherwise.
 */
int
main (int argc, char *argv[])
{
  FILE *f1, *f2, *outf;
  struct stat st1;
  struct stat st2;
  struct _matches *m;
  struct _matches *tmp = m;


  if (argc != 4)
    {
      usage ();
      return 1;
    }
  outf = fopen (argv[3], "r+");
  if (outf)
    {
      char reply[256];

      fclose (outf);
      printf ("Overwrite %s? [yn](y): ", argv[3]);
      gets (reply);
      if ((reply[0] != 'Y') &&
	  (reply[0] != 'y') &&
	  (reply[0] != '\0'))
	{
	  printf ("Aborted\n");
	  return 1;
	}			/* if */
    }				/* if a writeable file exists */
  outf = fopen (argv[3], "w");
  if (outf == NULL)
    {
      printf ("Couldn't write to %s\n", argv[3]);
      return 1;
    }				/* if couldn't open outf */

  f1 = fopen (argv[1], "r");
  if (f1 == NULL)
    {
      printf ("Could not open '%s' for reading\n", argv[1]);
      return 1;
    }

  f2 = fopen (argv[2], "r");
  if (f2 == NULL)
    {
      fclose (f1);
      printf ("Could not open '%s' for reading\n", argv[2]);
      return 1;
    }
  if (0 == stat (argv[1], &st1) && 0 == stat (argv[2], &st2))
    {
      m = collectmatches (f1, f2, st1.st_size);
      if (NULL == m)
	{
	  printf ("Search blocks from %s were not found in %s or\n"
		  "did not match unique locations in %s.\n"
		  "Cannot continue.\n",
		  argv[1], argv[2], argv[2]);
	}
      else
	{

	  if (0 == expandmatches (&m, f1, f2, st1.st_size, st2.st_size))
	    {
	      struct _matches *last = NULL;
	      int32_t currf1 = 0;
	      int32_t currf2 = 0;

#ifdef DEBUG
	      for (tmp = m; tmp; tmp = tmp->next)
		{
#ifdef DECIMAL
		  printf ("%09lX\t%09lX\t%5ld\t%5ld\t%5ld\n",
			  (uint32_t) (tmp),
			  (uint32_t) (tmp->prev),
			  tmp->f1loc,
			  tmp->f2loc,
			  tmp->length);
#else
		  printf ("%09lX\t%09lX\t%5lX\t%5lX\t%5lX\n",
			  (uint32_t) (tmp),
			  (uint32_t) (tmp->prev),
			  tmp->f1loc,
			  tmp->f2loc,
			  tmp->length);
#endif
		}		/* for */
#endif
	      tmp = m;
	      while (tmp)
		{
		  if (currf1 != tmp->f1loc || currf2 != tmp->f2loc)
		    {
		      write_updt_rec (tmp, currf1, currf2, f2, outf);
		    }		/* if one or the other */
		  currf1 = tmp->f1loc + tmp->length;
		  currf2 = tmp->f2loc + tmp->length;
		  if (NULL == tmp->next)
		    last = tmp;
		  tmp = tmp->next;
		}		/* while */
	      if (last)
		{
		  if (currf1 != st1.st_size || currf2 != st2.st_size)
		    {
		      /* I want to pass the same parameters in both calls
		       * to write_updt_rec(), so I blow away last->locations.
		       * Those locations are already accounted for in
		       * currf1 and currf2, so I don't need them anymore. */
		      last->f1loc = st1.st_size;
		      last->f2loc = st2.st_size;
		      write_updt_rec (last, currf1, currf2, f2, outf);
		    }
		}
	      else
		{
		  printf ("No last pointer near %d of %s\n", __LINE__, __FILE__);
		}
	    }			/* if */

	  freemall (m);
	}
    }
  else
    {
      perror ("stat");
    }

  return 0;
}				/* main() */
