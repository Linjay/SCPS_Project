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
/* Module:             crcchk.c                                     */
/*                                                                  */
/* Description:                                                     */
/*    Calculates and reports the SCPS standard CRC for the
 *    specified file(s).
 * $Id: crcchk.c,v 1.10 2000/05/23 18:15:51 scps Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/crcchk.c,v 1.10 2000/05/23 18:15:51 scps Exp $
 * 
 *    Change History:
 * $Log: crcchk.c,v $
 * Revision 1.10  2000/05/23 18:15:51  scps
 * Changes the SCPS error code define statements to have a SCPS_ prefix.
 * This was required for Linux.
 *
 * 	Pat
 *
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
 * Revision 1.6.2.1  1998/12/29 14:27:29  scps
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
 * Revision 1.2  1997/06/16 14:09:30  steven
 * Added size LARGE.
 * 
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *                                                                  */
/********************************************************************/

static char rcsid[] = "$Id: crcchk.c,v 1.10 2000/05/23 18:15:51 scps Exp $";

/* Might be nice someday to change it so that if there is no filename,
 * it reads stdin for filenames, one per line, to allow
 * dir * /s /b | crcchk (DOS/Windows only)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/ftp.h>
#include <fcntl.h>
#ifdef MSVC
#include <winsock.h>
#endif

int crc (FILE * fd, u_long * cval, u_long * clen);
void crcblock (char *buf, u_long len, u_long * iocrc);

#define BINARY 0
#define ASCII  1

#define ACBUFSIZE 4096
char acinput[ACBUFSIZE + 1];	/* Make sure there's always a null at the end */
char acoutput[ACBUFSIZE + 1];

/* crca -
 *     Calculate the CRC in ASCII mode.
 */
int
crca (FILE * fd, u_long * cval, u_long * outlen, u_long * inlen)
{
  u_long crcval, total;
  int i, o, incnt;

  *inlen = *outlen = crcval = total = o = 0;
  while ((incnt = fread (acinput, 1, ACBUFSIZE, fd)) != 0)
    {
      for (i = 0; i < incnt; i++)
	{
	  (*inlen)++;
	  if (acinput[i] == '\n')
	    {
	      (*outlen)++;
	      acoutput[o++] = '\r';
	      if (o == ACBUFSIZE)
		{
		  crcblock (acoutput, ACBUFSIZE, &crcval);
		  o = 0;
		}		/* output buffer full */
	    }			/* found <LF> */
	  (*outlen)++;
	  acoutput[o++] = acinput[i];
	  if (o == ACBUFSIZE)
	    {
	      crcblock (acoutput, ACBUFSIZE, &crcval);
	      o = 0;
	    }			/* output buffer full */
	}			/* for */
    }				/* while */
  if (incnt < 0)
    return (1);
  if (o)
    crcblock (acoutput, o, &crcval);
  *cval = crcval ^ 0xffffffff;	/* Invert the CRC to get all
				   * the benefit. */
  return (0);
}				/* crca() */


int
main (argc, argv)
     int argc;
     char *argv[];
{
  FILE *chkfile;

  u_long cval, clen;
  u_long filesize;
  int crcres;
  char outline[80];
  int i;
  int type = BINARY;

#ifdef MSVC
  _fmode = _O_BINARY;
#endif
  for (i = 1; i < argc; i++)
    {
      if ((0 == strcmp (argv[i], "-a")) || (0 == strcmp (argv[i], "-A")))
	{
	  type = ASCII;
	  continue;
	}
      if ((0 == strcmp (argv[i], "-b")) || (0 == strcmp (argv[i], "-B")))
	{
	  type = BINARY;
	  continue;
	}
      chkfile = fopen (argv[i], "r");

      if (chkfile == NULL)
	{
	  sprintf (outline, "Couldn't open '%s' for reading", argv[i]);
	  perror (outline);
	}
      else
	{
#ifdef MSVC
	  /* With DOS there is no difference between
	   * ASCII and binary.   */
	  crcres = crc (chkfile, &cval, &clen);
#else
	  if (type == ASCII)
	    crcres = crca (chkfile, &cval, &clen, &filesize);
	  else
	    crcres = crc (chkfile, &cval, &clen);
#endif
	  if (crcres)
	    printf ("Error calculating the CRC in '%s'\n", argv[i]);
	  else if (type == ASCII)
	    printf ("%s CRC: 0x%lX (%lu) on %lu bytes (size: %lu)\n",
		    argv[i], cval, cval, clen, filesize);
	  else
	    printf ("%s CRC: 0x%lX (%lu) on %lu bytes\n", argv[i], cval,
		    cval, clen);
	  fclose (chkfile);
	}			/* if */
    }				/* for */
}				/* end main */
