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
/* Module:             logs.c                                       */
/*                                                                  */
/* Description:                                                     */
/*    Writes a log file for debugging the server.
 * $Id: logs.c,v 1.7 1999/11/22 15:52:43 scps Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/logs.c,v 1.7 1999/11/22 15:52:43 scps Exp $
 * 
 *    Change History:
 * $Log: logs.c,v $
 * Revision 1.7  1999/11/22 15:52:43  scps
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
 * Revision 1.6  1999/03/23 20:24:36  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.5.2.2  1999/01/22 15:02:34  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.5.2.1  1998/12/29 14:27:32  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:37  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.4  1997/11/20 17:36:33  steven
 * removed references to MSVC40
 *
 * Revision 1.3  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.2  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 * 
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *                                                                  */
/********************************************************************/

#include <stdio.h>
#ifdef MSVC
#include <winsock.h>
#else
#include <sys/time.h>
#endif
#include <time.h>
#include <stdarg.h>

static char rcsid[] = "$Id: logs.c,v 1.7 1999/11/22 15:52:43 scps Exp $";

char debuglogfn[] = "debugs.log";

FILE *logfile = NULL;
int closed = 0;


/* debugclose -
 *    Close the debug file, and set the closed flag.             
 */
void
debugclose (void)
{
  closed = 1;
  if (logfile)
    {
      Lfclose (logfile);
      logfile = NULL;
    }
}				/* debugclose() */


/* debuglog - I use this to write log messages to a file. 
 *            It's easier for me than syslog().
 */
void
debuglog (char *fmt,...)
{
  char vbuf[132];
  va_list ap;
  time_t t;
  struct timeval currtime;
  struct tm *tstruc;
  char chartime[20];
#ifdef MSVC
  time_t tod;
#endif

#ifdef DO_TIMING
  return;
#endif

  if (closed)
    return;
  if (logfile == NULL)
    {
      logfile = Lfopen (debuglogfn, "a+");	/* create if necessary, append */
      if (logfile == NULL)
	return;
      fprintf (logfile, "started\n");
    }				/* if not opened */
  va_start (ap, fmt);
  vsprintf (vbuf, fmt, ap);
  va_end (ap);

  /* write a time stamp */
#ifdef MSVC
  time (&tod);
  currtime.tv_sec = tod;
  currtime.tv_usec = 0;
#else
  gettimeofday (&currtime, NULL);
#endif
  t = (time_t) currtime.tv_sec;
  tstruc = localtime (&t);
  strftime (chartime, sizeof (chartime), "[%M:%S", tstruc);
  fwrite (chartime, 1, strlen (chartime), logfile);
  sprintf (chartime, "%2.2f]",
	   (double) ((double) currtime.tv_usec / 1000000.));
  fwrite (chartime + 1, 1, strlen (chartime + 1), logfile);

  /* write the stuff */
  fwrite (vbuf, 1, strlen (vbuf), logfile);
  fflush (logfile);
}				/* debuglog */
