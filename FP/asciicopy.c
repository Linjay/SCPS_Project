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
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             asciicopy.c                                  */
/*                                                                  */
/* Description:                                                     */
/*    Efficient file transfer when type==ASCII.                     */
/*                                                                  */
/*
 * $Id: asciicopy.c,v 1.8 1999/11/22 15:52:41 scps Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/asciicopy.c,v 1.8 1999/11/22 15:52:41 scps Exp $
 * 
 *    Change History:
 * $Log: asciicopy.c,v $
 * Revision 1.8  1999/11/22 15:52:41  scps
 * Changed FP discaimers to read as follows:
 *
 * ---------------------------------------------
 * /*
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
 * */
 *
 * ---------------------------------------------
 *
 * 		--keith
 *
 * Revision 1.7  1999/03/23 20:24:33  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.6.2.2  1999/01/22 15:02:28  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:26  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:35  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.3  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.2  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 *
 * Revision 1.1  1997/05/06 14:11:59  steven
 * Initial revision
 *
 ********************************************************************/
static char rcsid[] = "$Id: asciicopy.c,v 1.8 1999/11/22 15:52:41 scps Exp $";

#include <stdio.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "asciicopy.h"
#include "tpif.h"

char acinput[ACBUFSIZE + 1];	/* Make sure there's always a null at the end */
char acoutput[ACBUFSIZE + 1];

/* asciicopytoU - quickly copy one file to another.  When there is a 
 *                <CR> delete it.
 */

void
asciicopytoU (int ins, FILE * outfile, int *rerr, int *werr, u_long * bytecount)
{
  int incnt;
  int outcnt;
  int i, o;


  *rerr = 0;
  *werr = 0;
  *bytecount = 0;
  o = 0;
  while ((incnt = scps_recv (ins, acinput, ACBUFSIZE, 0)) != 0)
    {
      for (i = 0; i < incnt; i++)
	{
	  /* SCHEDULER(); */
	  (*bytecount)++;
	  if (acinput[i] != '\r')
	    {
	      acoutput[o++] = acinput[i];
	      if (o == ACBUFSIZE)
		{
		  outcnt = fwrite (acoutput, 1, ACBUFSIZE, outfile);
		  if (outcnt != ACBUFSIZE)
		    {
		      *werr = ferror (outfile);
		      *rerr = errno;
		      return;
		    }
		  o = 0;
		}		/* output buffer full */
	    }			/* found <LF> */
	}
    }
  if (o)
    {
      outcnt = fwrite (acoutput, o, 1, outfile);
      if (outcnt != ACBUFSIZE)
	{
	  *werr = ferror (outfile);
	}
    }
  *rerr = errno;
}				/* end asciicopytoU() */



/* asciicopyfmU - quickly copy one file to another.  When there is a 
 *                newline character, insert a <CR>
 */

void
asciicopyfmU (FILE * infile, int outs, int *rerr, int *werr, u_long * bytecount)
{
  int incnt;
  int outcnt;
  int i, o;


  *rerr = 0;
  *werr = 0;
  *bytecount = 0;
  o = 0;
  while ((incnt = fread (acinput, 1, ACBUFSIZE, infile)) != 0)
    {
      for (i = 0; i < incnt; i++)
	{
	  /* SCHEDULER(); */
	  (*bytecount)++;
	  if (acinput[i] == '\n')
	    {
	      acoutput[o++] = '\r';
	      if (o == ACBUFSIZE)
		{
		  outcnt = scps_send (outs, acoutput, ACBUFSIZE, 0);
		  if (outcnt != ACBUFSIZE)
		    {
		      *werr = errno;
		      *rerr = ferror (infile);
		      return;
		    }
		  o = 0;
		}		/* output buffer full */
	    }			/* found <LF> */
	  acoutput[o++] = acinput[i];
	  if (o == ACBUFSIZE)
	    {
	      outcnt = scps_send (outs, acoutput, ACBUFSIZE, 0);
	      if (outcnt != ACBUFSIZE)
		{
		  *werr = errno;
		  *rerr = ferror (infile);
		  return;
		}
	      o = 0;
	    }			/* output buffer full */
	}
    }
  if (o)
    {
      outcnt = scps_send (outs, acoutput, o, 0);
      if (outcnt != o)
	*werr = errno;
    }
  *rerr = ferror (infile);
}				/* end asciicopyfmU() */
