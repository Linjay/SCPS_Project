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
/*                     Thursday, November 7, 1996 2:17 pm           */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             sortupdt.c                                   */
/*                                                                  */
/* Description:                                                     */
/*    Sorts the update data before sending them to the server
 *    as arguments in an raupdt command.
 * $Id: sortupdt.c,v 1.10 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/sortupdt.c,v 1.10 2007/04/19 15:09:36 feighery Exp $
 * 
 *    Change History:
 * $Log: sortupdt.c,v $
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
 * Revision 1.8  1999/11/22 15:52:45  scps
 * Changed FP discaimers
 *
 * Revision 1.7  1999/03/23 20:24:38  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.6.2.2  1999/01/22 15:02:36  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:35  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:39  scps
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


/* sort update signals */
#include <stdio.h>
#include <stdlib.h>
#ifdef MSVC
#include <winsock.h>
#else
#include <unistd.h>
#endif
#include "edit.h"
#include "libc.h"

static char rcsid[] = "$Id: sortupdt.c,v 1.10 2007/04/19 15:09:36 feighery Exp $";

#define MAXSIGNALS 1000

struct update_sig
  {
    char ch;
    int32_t file_pos;		/* position of signal in delta file */
    int32_t sig_fofs;		/* offset parameter in signal */
  };

struct update_sig allsignals[MAXSIGNALS];

/* sortupdt_cmp - Compares sig_fofss.  Used by qsort() */
int sortupdt_cmp (const void *seg1, const void *seg2);

/* sortupdt - Sorts update signals
 *
 * Takes the name of the update file as an
 * argument.  Writes output to a new file
 * deletes the original, and renames
 * the new file, the original file name.
 *
 * Returns 0 if all OK
 *         1 if anything went wrong
 */
int
sortupdt (char *filename)
{
  int32_t dfilepos = 0;
  char ch;
  FILE *rf;
  FILE *wf;
  struct change_cmd chrec;
  int i = 0;
  int j;
  char newfile[SCPS_L_tmpnam];
  char lastch;
  u_long lastofs;

  rf = Lfopen (filename, "r");
  if (rf == NULL)
    return 1;

  while (get_ch_rec (&chrec, rf))
    {
      /* printf("i: %d ch: %c ofs: %lu len: %hi\n", i, chrec.ch, chrec.foffset, chrec.len); */
      allsignals[i].file_pos = dfilepos;
      allsignals[i].ch = chrec.ch;
      allsignals[i++].sig_fofs = chrec.foffset;
      if (i == MAXSIGNALS)
	goto sortupdtabort;
      if (chrec.ch != 'd')
	while (chrec.len--)
	  {
	    if (1 != fread (&ch, 1, 1, rf))
	      goto sortupdtabort;
	  }			/* while */
      dfilepos = ftell (rf);
    }				/* while */

  if (i == 0)
    /* oops.  No records. */
    goto sortupdtabort;

  /* sort by the foffset field in the signal records  */
  qsort (allsignals, i, sizeof (struct update_sig), sortupdt_cmp);

  /*
   * for (j=0; j<i; j++)
   *   printf("j: %d   pos: %lu   ofs: %lu\n", j, allsignals[j].file_pos, allsignals[j].sig_fofs);
   */
  if (NULL == Ltmpnam (newfile))
    goto sortcopyabort;

  wf = Lfopen (newfile, "w");
  if (wf == NULL)
    goto sortupdtabort;

  /* copy the records to the new file in sorted order 
   * While writing them, check to make sure they are
   * valid.  If they aren't, abort.  */
  lastofs = 0;
  lastch = 0;
  for (j = 0; j < i; j++)
    {
      int32_t ltemp;
      short stemp;

      fseek (rf, allsignals[j].file_pos, SEEK_SET);
      if (0 == get_ch_rec (&chrec, rf))
	goto sortcopyabort;
      if (lastofs)
	{
	  if (chrec.foffset == lastofs &&
	      lastch != 'i')
	    {
	      /* duplicate offset numbers */
	      goto sortcopyabort;
	    }
	}
      lastofs = chrec.foffset;
      lastch = chrec.ch;
      fwrite (&(chrec.ch), 1, 1, wf);
      ltemp = htonl (chrec.foffset);
      fwrite (&ltemp, 4, 1, wf);
      stemp = htons (chrec.len);
      fwrite (&stemp, 2, 1, wf);
      if (chrec.ch != 'd')
	{
	  while (chrec.len--)
	    {
	      fread (&(chrec.ch), 1, 1, rf);
	      fwrite (&(chrec.ch), 1, 1, wf);
	    }
	}
    }				/* while */

  Lfclose (wf);
  Lfclose (rf);

  if (rename (newfile, filename))
    {
      if (fcopy (newfile, filename))
	return 1;
      remove (newfile);
      return 0;
    }
  return 0;

sortcopyabort:
  if (wf)
    Lfclose (wf);
sortupdtabort:
  if (rf)
    Lfclose (rf);
  return 1;
}				/* sortupdt */


/* sortupdt_cmp - Compares the low part of seg1 with that of seg2.
 *                Returns a negative value if seg1.low is less than
 *                seg2.low, 0 if they are equal, and a positive
 *                value if seg1.low is greater than seg2.low.
 *                If the offsets are equal, this routine considers
 *                the segment that is an 'i' command (if either)
 *                to be less.
 */
int
sortupdt_cmp (const void *seg1, const void *seg2)
{
  if (((struct update_sig *) seg1)->sig_fofs ==
      ((struct update_sig *) seg2)->sig_fofs)
    {
      if ((((struct update_sig *) seg1)->ch == 'i') ||
	  (((struct update_sig *) seg2)->ch == 'i'))
	{
	  if (((struct update_sig *) seg2)->ch == 'i')
	    {
	      return 1;
	    }
	  else
	    {
	      return -1;
	    }
	}
      else
	{
	  /* they are equal, and there are no 'i' commands */
	  return 0;
	}
    }
  else
    {
      return ((struct update_sig *) seg1)->sig_fofs - ((struct update_sig *)
						       seg2)->sig_fofs;
    }
}				/* sortupdt_cmp */
