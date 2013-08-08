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
/* Module:             crcnt.c                                      */
/*                                                                  */
/* Description:                                                     */
/*    Provides routines to calculate the CRC without using a table.
 *
 * $Id: crcnt.c,v 1.9 1999/11/22 16:14:33 scps Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/crcnt.c,v 1.9 1999/11/22 16:14:33 scps Exp $
 * 
 *    Change History:
 * $Log: crcnt.c,v $
 * Revision 1.9  1999/11/22 16:14:33  scps
 * Removed disclaimer comment blocks from revision logs.
 *
 * Revision 1.8  1999/11/22 15:52:42  scps
 * Changed FP discaimers
 *
 * Revision 1.7  1999/03/23 20:24:35  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.6.2.2  1999/01/22 15:02:31  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:30  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:36  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.4  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.3  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 * 
 * Revision 1.2  1997/08/15 19:50:22  steven
 * Adding Proxy
 * 
 * Revision 1.1  1997/06/16 14:09:30  steven
 * Initial revision
 *                                                                  */
/********************************************************************/

#include <sys/types.h>
#include <stdio.h>
#ifdef MSVC
#include <winsock.h>
#endif


static char rcsid[] = "$Id: crcnt.c,v 1.9 1999/11/22 16:14:33 scps Exp $";

#ifndef NOTTP
/* if using SCPS-TP */
extern void sched ();
#endif

#define CRC32_POLYNOMIAL 0xEDB88320


/* crcblock -
 *      Compute a SCPS standard CRC on a block of memory.
 *
 *      The caller can use iocrc to point to a CRC accumulator value
 *      to get the CRC of a file for example.
 *
 */
void
crcblock (char *buf, u_long len, u_long * iocrc)
{
  register u_long crc = *iocrc;
  register int j;
  register char *p;
  register u_long temp1, temp2;

  for (p = buf; len--; ++p)
    {
      temp1 = (crc >> 8) & 0x00FFFFFFL;
      temp2 = (crc ^ *p) & 0xff;
      for (j = 8; j > 0; j--)
	{
	  if (temp2 & 1)
	    temp2 = (temp2 >> 1) ^ CRC32_POLYNOMIAL;
	  else
	    temp2 >>= 1;
	}			/* for */
      crc = temp1 ^ temp2;
    }
  *iocrc = crc;
}				/* crcblock() */


/* crc -
 *      Compute a SCPS standard CRC.
 *
 *      It takes a FILE descriptor to read from and locations to store the 
 *      crc and the number of bytes read.  It returns 0 on success and 1 on 
 *      failure.  Errno is set on failure.
 *      
 *      This routine is the result of merging ideas of
 *         1) Mark R. Nelson "File Verification Using CRC", Dr. Dobb's
 *            Journal #188 MAY 1992 p 64 and following, and
 *         2) Code to generate a POSIX.2 checksum we got off the
 *            Internet which was derived from software contributed
 *            by James W. Williams of the University of Maryland.
 *            That algorithm is Copyright (c) 1991 The Regents of the
 *            University of California.  All rights reserved.
 *            This product includes software developed by the University of
 *            California, Berkeley and its contributors.
 *
 *         Does not look values up in a table.
 *         This is for applications (like space vehicles) where
 *         RAM is limited.
 */
int
crc (FILE * fd, u_long * cval, u_long * clen)
{
  register int nr;
  register u_long total;
  u_long crc;
  u_char buf[8192];

  crc = total = 0;		/* The initial value of the
				 * CRC does not affect its quality.
				 * But initialize it to zero for
				 * the sake of being normal. */
  while ((nr = fread (buf, 1, sizeof (buf), fd)) > 0)
    {
      total += nr;
      crcblock (buf, nr, &crc);
    }				/* while */
  if (nr < 0)
    return (1);

  *cval = crc ^ 0xffffffff;	/* Invert the CRC to get all
				   * the benefit. */
  *clen = total;
  return (0);
}				/* crc() */
