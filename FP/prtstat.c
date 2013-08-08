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
/*                     Elaine Skrzypczak                            */
/*                                                                  */
/*  Modified by     :                                               */
/*                     Steve Sides                                  */
/********************************************************************/
/********************************************************************/
/* Module:             prtstat.c                                    */
/*                                                                  */
/* Description:                                                     */
/*    Measures detailed performance.
 * $Id: prtstat.c,v 1.11 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/prtstat.c,v 1.11 2007/04/19 15:09:36 feighery Exp $
 * 
 *    Change History:
 * $Log: prtstat.c,v $
 * Revision 1.11  2007/04/19 15:09:36  feighery
 * This version makes the gateway code (and only the gateway code) safe for
 * 64 bit architectures.  Before we were very sloppy and use a long and int
 * interchangeable.  As part of this change, it was required to make the
 * gateway code single threaded;  therefore gateway_single_thread=yes is the
 * default.  -- PDF
 *
 * Revision 1.10  2000/05/23 19:50:09  scps
 * There was a misplaced comment block in prtstat.c.  Fixed...  -PDF
 *
 * Revision 1.9  1999/11/22 15:52:44  scps
 * Changed FP discaimers to read as follows:
 *
 * ---------------------------------------------
 * 
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
 * 
 *
 * ---------------------------------------------
 *
 * 		--keith
 *
 * Revision 1.8  1999/03/23 20:24:37  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.7  1999/03/05 21:24:59  scps
 * Removed 'opening logfile' message.
 *
 * Revision 1.6  1999/03/02 19:49:45  scps
 * Ruhai testing fixes to run under linux.
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
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *                                                                  */
/********************************************************************/


#ifdef DO_TIMING
#include <stdio.h>
#include <sys/time.h>

FILE *doopen ();
#define Lfopen(a,b) fopen((a), (b))

int32_t gettime_usec = 0;
int32_t printstat_usec = 0;

/*-----------------------------------------------------------------*/
/* Subroutine: gettime                                             */
/*                                                                 */
/* Get the time in microseconds (usecs).                           */
/*-----------------------------------------------------------------*/
void
prtstat_gettime (sec, usec)
     int32_t *sec;
     int32_t *usec;
{
  struct timeval start;

  (void) gettimeofday (&start, (struct timezone *) 0);

  *sec = start.tv_sec;
  *usec = start.tv_usec;
}

/*-----------------------------------------------------------------*/
/* Subroutine: print_timestat.                                     */
/*                                                                 */
/* Log the start and stop time of the specified operation for the  */
/* purpose of collecting SCPS-FP benchmark data.                   */
/*-----------------------------------------------------------------*/
void
print_timestat (caller, type_op, operation,
		start_sec, start_usec,
		stop_sec, stop_usec,
		opt_delta,
		byte_count)
     char *caller;		/* subroutine (name) that called this */
     char *type_op;		/* type of operation-user cmd,socket.. */
     char *operation;		/* name of operation being timed.     */
     int32_t start_sec, start_usec;
     int32_t stop_sec, stop_usec;
     int32_t opt_delta;		/* optional delta to use instead of   */
			   /* the one computed here.             */
     int32_t byte_count;		/* the number bytes transfered.       */
			   /* Only applies to tp_write, tp_read  */

{
  extern FILE *tstatfp;		/* pointer to time status file */
  int32_t delta;
  int32_t tmp_stop_sec;
  int32_t tmp_stop_usec;
  char fname[15];

/*-------------------------------------------------------------*/
  /* If an optional delta is specified, use it in the print out. */
  /* We do this when gathering stats on the transport time for   */
  /* a send or recv of file that is split into multiple sends or */
  /* receives. We do this just to reduce the number of logs.     */
/*-------------------------------------------------------------*/
  if (opt_delta > 0)
    {
      delta = opt_delta;
    }
  else
    {
      tmp_stop_sec = stop_sec;
      tmp_stop_usec = stop_usec;
      if (stop_usec < start_usec)
	{
	  tmp_stop_sec -= 1;
	  tmp_stop_usec += 1000000;
	}

      delta = (tmp_stop_sec - start_sec) * 1000000 +
	(tmp_stop_usec - start_usec);
    }

  if (delta < 0)
    {
      delta = 0;
    }

  if (tstatfp == NULL)
    {
      if (doopen () == NULL)
	return;
    }

  /* tabs are there for Excel */
  fprintf (tstatfp,
	   "%-10s\t%-10s\t%-30s\t%ld:%ld\t%ld:%ld\t%10ld\t%ld\n",
	   caller, type_op, operation,
	   start_sec, start_usec, stop_sec, stop_usec,
	   delta, byte_count);
  fflush (tstatfp);
}

#include <unistd.h>
FILE *
doopen ()
{
   int32_t start_sec, start_usec;
   int32_t end_sec, end_usec;
   extern FILE *tstatfp;   /* pointer to time status file */
   extern int32_t gettime_usec;  /* processing time for            */
                               /* prtstat_gettime call.          */
   char fname[256];
   int accessible = 0;
   int32_t  tmp_stop_sec;
   int32_t  tmp_stop_usec;
   int logIndex = 1;
   char tempString[255];

   strcpy (fname, "fpstat.log");
   do {
      if ( (accessible=access(fname,F_OK))==0)
      {
         /* File already exists, append 'a' to fname */
	 sprintf(fname, "fpstat.log_%d", logIndex);
	 if ( strlen(fname)>250 ) {
	   fprintf(stderr, "There are too many log files.\n");
	   exit(-1);
	 }
	 logIndex++;
      }
   } while (accessible==0);

   if( (tstatfp = Lfopen(fname,"a+")) == NULL)
   {
      printf("Error opening %s file \n",fname);
      return NULL;
    }

   fprintf(tstatfp, "\n");
   fprintf(tstatfp,"%-10s\t%-10s\t%-30s\t%s\t%s\t%s\t%s\n",
                    "Subroutine","Optype", "Operation",
                    "Start (usecs)","End (usecs)", "Run (usecs)",
                    "Bytes");
   fprintf(tstatfp,"%-10s\t%-10s\t%-30s\t%s\t%s\t%s\t%s\t%s\n",
                    "----------","----------",
                    "------------------------------",
                    "-------------","-------------", "----------",
                    "-----", "-----");

   (void) prtstat_gettime(&start_sec, &start_usec);
   (void) prtstat_gettime(&end_sec, &end_usec);

   tmp_stop_sec = end_sec;
   tmp_stop_usec = end_usec;
   if (end_usec < start_usec)
   {
      tmp_stop_sec -= 1;
      tmp_stop_usec += 1000000;
    }

  gettime_usec = (tmp_stop_sec - start_sec) * 1000000 +
    (tmp_stop_usec - start_usec);

  fprintf (tstatfp, "%-10s\t%-10s\t%-30s\t%ld:%ld\t%ld:%ld\t%10ld\n",
	   "doopen", "admin", "Gettime",
	   start_sec, start_usec, end_sec, end_usec,
	   gettime_usec);
  fflush (tstatfp);

  return tstatfp;
}				/* doopen */

#endif
