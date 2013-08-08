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
/*                     Friday, April 25, 1997 1:41 pm               */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************
 *   This is unclassified Government software.
 *
 *   The SCPS File Protocol (SCPS-FP) software was developed under
 *   contract to the Jet Propulsion Laboratory, an operating division of
 *   the California Institute of Technology and is available for use by
 *   the public without need of a licence.
 *
 *   DISCLAIMER:
 *
 *   THE SCPS-FP SOFTWARE AND RELATED MATERIALS ARE PROVIDED "AS-IS"
 *   WITHOUT WARRANTY OR INDEMNITY OF ANY KIND INCLUDING ANY WARRANTIES
 *   OF USE, PEROFMRNACE, OR MERCHANTABILITY OR FITNESS FOR A PRTICULAR
 *   USE OR PURPOSE (as set forth in UCC section 2312-2313) OR FOR ANY
 *   PURPOSE WHATSOEVER.
 *
 *   USER BEARS ALL RISK RELATING TO USE, QUALITY, AND PERFORMANCE OF THE
 *   SOFTWARE.
 *
 *   The Jet Propulsion Laboratory, the California Institute of
 *   Technology, and the United States government retain a paid-up
 *   royalty free world wide license in this product.
 *
 *   SAIC Disclaimer:
 *     (1) SAIC assumes no legal responsibility for the source code and
 *         its subsequent use.
 *     (2) No warranty or representation is expressed or implied.
 *     (3) Portions (e.g. Washington University FTP Replacement Daemon)
 *         are copyright (c) Regents of the University of California.
 *         All rights reserved.  Restrictions included in said copyright
 *         are also applicable to this release.
 *
 */

/******************************************************************** 
 * Module:             rp.c  (restart_point)                        * 
 *                                                                  * 
 * Description:                                                     * 
 *    Find and set the restart point when type==ASCII.              * 
 *                                                                  * 
 *
 * $Id: rp.c,v 1.8 2000/10/23 14:02:36 scps Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/rp.c,v 1.8 2000/10/23 14:02:36 scps Exp $
 * 
 *    Change History:
 * $Log: rp.c,v $
 * Revision 1.8  2000/10/23 14:02:36  scps
 * Cleaned to the FP directory so it would compile cleanly  -- PDF
 *
 * Revision 1.7  1999/11/22 15:52:44  scps
 * Changed FP discaimers to read as follows:
 *
 * 		--keith
 *
 * Revision 1.6  1999/03/23 20:24:37  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.5.2.2  1999/01/22 15:02:35  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.5.2.1  1998/12/29 14:27:33  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:38  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.3  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.2  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 *
 * Revision 1.1  1997/06/16 14:09:30  steven
 * Initial revision
 *
 */

static char rcsid[] = "$Id: rp.c,v 1.8 2000/10/23 14:02:36 scps Exp $";

#include <stdio.h>
#include <sys/types.h>
#include "rp.h"
#include "fileio.h"

#ifdef SUNOS
#define SEEK_SET 0
#define SEEK_END 2
#endif

/* These buffers are used by asciicopy, but asciicopy.c and rp.c are
 * never used concurrently.  */

extern char acinput[ACBUFSIZE + 1];
extern char acoutput[ACBUFSIZE + 1];


/* srp -
 *     Set restart_point.  This file does not have \r characters.
 *     Its transmission was interrupted.  Now the remote FP issued
 *     REST n.  What location do I set for the file?
 *
 *     The routine assumes that the file contains no \0 characters.
 *
 *     Returns 0 if the location was successfully calculated and set
 *     Returns 1 otherwise.
 *     Also returns 1 if the file contains \r characters.
 */
int
srp (FILE * outf, u_long requested_rp, u_long * new_offset)
{
  char *srch;
  u_long myloc, hisloc;
  int c;

  if (new_offset)
    *new_offset = 0;
  if (requested_rp == 0)
    return (fseek (outf, 0, SEEK_SET));
  myloc = hisloc = 0;
  while ((c = fread (acinput, 1, ACBUFSIZE, outf)) != 0)
    {
      acinput[c] = '\0';
      for (srch = acinput; *srch && hisloc != requested_rp; srch++, myloc++,
	   hisloc++)
	{
	  if (*srch == '\r')
	    /* No '\r' characters allowed. */
	    return 1;
	  if (*srch == '\n')
	    hisloc++;
	  if (hisloc > requested_rp)
	    /* Invalid requested restart point.  It falls between a
	     * '\r' and '\n'.  */
	    return 1;
	}			/* for */
    }				/* while */
  if (hisloc == requested_rp)
    {
      if (new_offset)
	*new_offset = myloc;
      return (fseek (outf, myloc, SEEK_SET));
    }
  else
    return 1;
}				/* srp() */


/* frp -
 *     Find restart_point.  This file does not have \r characters.
 *     Its reception was interrupted.  Now the local FP wants to
 *     issue REST.  What restart_point does it report?
 *
 *     The routine assumes that the file contains no \0 characters.
 *
 *     Returns 0 if the location was successfully calculated.
 *     Returns 1 otherwise.
 *     Also returns 1 if the file contains \r characters.
 */
int
frp (FILE * inf, u_long * restart_point)
{
  char *srch;
  u_long hisloc;
  int c;

  *restart_point = 0;
  hisloc = 0;
  while ((c = fread (acinput, 1, ACBUFSIZE, inf)) != 0)
    {
      acinput[c] = '\0';
      for (srch = acinput; *srch; srch++, hisloc++)
	{
	  if (*srch == '\r')
	    {
	      /* Well, well.  I will assume that lines are
	       * already terminated with \r\n.  Therefore
	       * the restart point is just the image file size.
	       */
	      fseek (inf, 0L, SEEK_END);
	      *restart_point = ftell (inf);
	      return 1;
	    }
	  if (*srch == '\n')
	    hisloc++;
	}			/* for */
    }				/* while */
  *restart_point = hisloc;
  return 0;
}				/* frp() */


/* frpn -
 *     Find the restart point given the filename.
 *
 *     Returns 0 if the location was successfully calculated.
 *     Returns 1 otherwise.
 *     Also returns 1 if the file contains \r characters.
 */
int
frpn (char *name, u_long * restart_point)
{
  FILE *f;
  int result;

  if (NULL == (f = Lfopen (name, "r")))
    return 1;
  result = frp (f, restart_point);
  Lfclose (f);
  return result;
}				/* frpn() */
