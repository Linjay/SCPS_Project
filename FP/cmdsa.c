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
/*                     Wednesday, June 26, 1996 1:02 pm             */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             cmdsa.c                                      */
/*                                                                  */
/* Description:                                                     */
/*    Server commands, set A.  These are used in the base (small)   */
/*    implementation and, perhaps, in other configurations.         */
/*
$Id: cmdsa.c,v 1.12 2007/04/19 15:09:36 feighery Exp $
$Header: /home/cvsroot/SCPS_RI/FP/cmdsa.c,v 1.12 2007/04/19 15:09:36 feighery Exp $

   Change History:
$Log: cmdsa.c,v $
Revision 1.12  2007/04/19 15:09:36  feighery
This version makes the gateway code (and only the gateway code) safe for
64 bit architectures.  Before we were very sloppy and use a long and int
interchangeable.  As part of this change, it was required to make the
gateway code single threaded;  therefore gateway_single_thread=yes is the
default.  -- PDF

Revision 1.11  1999/11/22 16:14:33  scps
Removed disclaimer comment blocks from revision logs.

Revision 1.10  1999/11/22 15:52:41  scps
Changed FP discaimers

Revision 1.9  1999/05/27 18:17:21  scps
Added logic to the server to is would read and write 8192 byte as
opposed to 128 byte blocks.  -- PDF

Revision 1.8  1999/03/23 20:24:34  scps
Merged reference implementation with gateway-1-1-6-k branch.

Revision 1.7  1999/03/02 19:49:44  scps
Ruhai testing fixes to run under linux.
Revision 1.6.2.2  1999/01/22 15:02:30  scps
There was a problem with the FP in CVS I had to perform a update and a new
commit. -- PDF

Revision 1.6.2.1  1998/12/29 14:27:28  scps
Monolithic update to include gateway code.

Revision 1.6  1998/12/01 16:44:36  scps
Update to version 1.1.6 --ks

Revision 1.7  1997/11/25 01:35:05  steven
Editted comments.

Revision 1.6  1997/09/18 17:57:16  steven
Red-3 except files of CCSDS packets.

Revision 1.1  1997/02/28 21:25:57  steven
Initial revision

 *                                                                  */
/********************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>		/* for stat */
#ifdef MSVC
#include <time.h>
#include <winsock.h>
#undef ERROR
#include "ftp.h"
#else
#include <sys/time.h>		/* for gettimeofday() */
#include <arpa/ftp.h>		/* for symbolic constants only */
#include <netinet/in.h>		/* for sockaddr_in */
#include <netdb.h>
#include <unistd.h>		/* for close() */
#endif
#include "libs.h"
#include "tpif.h"
#if defined(MEDIUM) || defined(LARGE)
#include "rp.h"
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN  10
#endif
#define FP_BUFSIZ   40
#ifndef SEEK_SET
#define SEEK_SET 0
#endif
#ifdef SMALL
#else
#define ASCII_SUPPORT
#endif

int Latoaddr (char *, struct sockaddr_in *);
#ifdef MSVC
int dataconn (char *, _off_t);
#else
int dataconn (char *, uint32_t);
#endif
int crc (FILE *, u_long *, u_long *);
int send_data (FILE *, int);
int receive_data (int, FILE *, int *, u_long *);
char *crcrtxt (uint32_t);
u_long getcrc (char *);
int dologout (int);
int edit (char *, char *, char *);
void crcblock (char *buf, u_long len, u_long * iocrc);
int rcvdata_avail (int fd);
int Lstrout (char *str);

extern short autorestart;	/* 0 for autorest disabled  */
extern short restart_point;
extern short replywithtext;	/* do not include text in   */
				       /* replies.                 */
extern struct sockaddr_in data_addr;	/* data address             */
extern int flags;
extern int idletimeout;
extern short siteterm;		/* received the site
				 * terminate command        */
extern int sctrl;		/* control socket           */
extern int sdata;		/* data socket              */
extern short type;		/* transfer type is always  */
				       /* binary for now.          */
extern short runcrc;		/* if true, CRC gets calculated */

/* Change structure for record update */
struct change_cmd
  {
    char ch;
    int32_t foffset;
    short len;
  };

extern struct cmd *cmdtaba;
extern int reply ( /* int code, char *text, int suppoverride */ );

#ifdef LARGE
extern int sunique;
#endif

/* cmdintr -
 *     No operation in progress.
 */
int
cmdintr (argc, argv)
     int argc;
     char *argv[];
{
  return (reply (226, "OK", 0));
}				/* cmdintr() */


/* cmdarst -
 *     Enable auto-restart.
 *     Returns -1 on failure of ctrl conn.
 */
int
cmdarst (argc, argv)
     int argc;
     char *argv[];
{

#ifdef DO_TIMING
  int result;
  int32_t start_sec, start_usec, end_sec, end_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif
  autorestart = 1;

#ifdef DO_TIMING
  result = reply (200, "Autorestart enabled", 0);
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("cmdarst", "SFTP_cmd", "ARST",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
  return (result);
#else
  return reply (200, "Autorestart enabled", 0);
#endif
}				/* cmdarst() */


/* cmddele -
 *    delete a file.
 *
 *    Like all commands returns -1 on failure of control
 *    connection.  lookup_execute() tests the return value
 *    for less than zero, and returns -1 if so which indicates
 *    to the caller of lookup_execute() that the control
 *    connection is gone.
 */
int
cmddele (argc, argv)
     int argc;
     char *argv[];
{
  char replybuf[80];

  if (argc != 2)
    {
      return (reply (501, "Syntax error", 0));
    }
  if (remove (argv[1]))
    {
      nsprintfds (replybuf, sizeof (replybuf), "problem with: %s", 0, argv[1]);
      return (reply (550, replybuf, 0));
    }
  else
    {
      return (reply (250, "DELE OK", 0));
    }
}				/* cmddele() */


/* cmdidle -
 *    set idle seconds.
 *
 *    Like all commands returns -1 on failure of control
 *    connection.  lookup_execute() tests the return value
 *    for less than zero, and returns -1 if so which indicates
 *    to the caller of lookup_execute() that the control
 *    connection is gone.
 */
int
cmdidle (argc, argv)
     int argc;
     char *argv[];
{
  char cmdbuf[80];
#ifdef DO_TIMING
  int result;
  int32_t start_sec, start_usec, end_sec, end_usec;
  int32_t tmp_start_sec, tmp_start_usec, tmp_end_sec, tmp_end_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (argc != 2)
    {
      return (reply (501, "Syntax error", 0));
    }
  idletimeout = Latoi (argv[1]);
#ifdef DO_TIMING
  (void) prtstat_gettime (&tmp_start_sec, &tmp_start_usec);
#endif
  nsprintfds (cmdbuf, sizeof (cmdbuf),
	      "Idle timeout is %d sec", idletimeout, 0);

#ifdef DO_TIMING
  (void) prtstat_gettime (&tmp_end_sec, &tmp_end_usec);
  (void) print_timestat ("cmdidle", "NOTOPTIM", "nsprintfds",
			 tmp_start_sec, tmp_start_usec,
			 tmp_end_sec, tmp_end_usec, 0, 0);
#endif

#ifdef DO_TIMING
  result = reply (200, cmdbuf, 0);
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("cmdidle", "SFTP_cmd", "IDLE",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
  return (result);
#else
  return (reply (200, cmdbuf, 0));
#endif
}				/* cmdidle() */


/* cmdnars -
 *     Disable auto-restart.
 *     Returns -1 on failure of ctrl conn.
 */
int
cmdnars (argc, argv)
     int argc;
     char *argv[];
{
#ifdef DO_TIMING
  int result;
  int32_t start_sec, start_usec, end_sec, end_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  autorestart = 0;

#ifdef DO_TIMING
  result = reply (200, "Autorestart disabled", 0);
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("cmdnars", "SFTP_cmd", "NARS",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
  return (result);
#else
  return (reply (200, "Autorestart disabled", 0));
#endif
}				/* cmdnars() */


/* cmdnoop -
 *    no operation.
 *
 *    Like all commands returns -1 on failure of control
 *    connection.  lookup_execute() tests the return value
 *    for less than zero, and returns -1 if so which indicates
 *    to the caller of lookup_execute() that the control
 *    connection is gone.
 */
int
cmdnoop (argc, argv)
     int argc;
     char *argv[];
{
  return (reply (250, "NOOP OK", 0));
}				/* cmdnoop() */


/* cmdnsup -
 *     Enable reply text.
 */
int
cmdnsup (argc, argv)
     int argc;
     char *argv[];
{
#ifdef DO_TIMING
  int result;
  int32_t start_sec, start_usec, end_sec, end_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  replywithtext = 1;

#ifdef DO_TIMING
  result = reply (211, "Reply text enabled", 1);
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("cmdnsup", "SFTP_cmd", "NSUP",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
  return (result);
#else
  return reply (211, "Reply text enabled", 1);
#endif
}				/* cmdnsup() */


/* cmdport -
 *    Process the port command.
 *    Returns -1 on failure of control connection.
 *    Returns 0 otherwise.
 */
int
cmdport (argc, argv)
     int argc;
     char *argv[];
{
#ifdef DO_TIMING
  int result;
  int32_t start_sec, start_usec, end_sec, end_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (argc != 2)
    return (reply (501, "Syntax error", 0));

  if (Latoaddr (argv[1], &data_addr))
    return (reply (501, "Syntax error", 0));

#ifdef DO_TIMING
  result = reply (200, "Port OK", 0);
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("cmdport", "SFTP_cmd", "PORT",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
  return (result);
#else
  return (reply (200, "Port OK", 0));
#endif

}				/* cmdport() */


/* cmdquit -
 *    Quit
 *    Returns -1 on failure of control connection.
 *    Returns 0 otherwise.
 */
int
cmdquit (argc, argv)
     int argc;
     char *argv[];
{
  if (siteterm)
    exit (99);
  reply (221, "Cheers, Bye", 0);
#ifdef NOTTP
  shutdown (sctrl, 2);
#else
  scps_close (sctrl);
#endif
  sctrl = -1;
  return (0);
}				/* cmdquit() */


/* send_rrdata
 *    Send Record Read data.
 *    Use the control data of "instr" to read selected bytes and
 *    send them to "outstr".
 *    Returns -1 if needed to shutdown all;
 *    Returns 0 otherwise.
 */
int
send_rrdata (instr, outstr)
     FILE *instr;
     int outstr;
{
  register int cnt;
  char buf[8192];
  char tbuf[40];
  short *rc;
  int32_t record_count, low, high;
  FILE *tf = NULL;		/* target file */
  char *search;
  u_long fcrc;
  int response = 226;
  char *msg = "OK";
  int result;
  char optforced_read;
  int reqcnt;
  int32_t rdamt;
  char buffer[BSIZE];

#ifdef DO_TIMING
  int32_t start_sec, start_usec, end_sec, end_usec;
#endif

/* path-remote */
  if (NULL == Lfgets (buf, sizeof (buf), instr))
    goto file_err;
  buf[Lstrlen (buf) - 1] = '\0';
  if (NULL == (tf = Lfopen (buf, "r")))
    goto file_err;
/* forced read */
  if (NULL == Lfgets (buf, sizeof (buf), instr))
    goto file_err;
  optforced_read = buf[0] == 'Y';
/* record-count */
  if (NULL == Lfgets (buf, sizeof (buf), instr))
    goto file_err;
  rc = (short *) buf;
  record_count = (int32_t) (ntohs (*rc));
  fcrc = 0;
  for (; record_count; record_count--)
    {
/* record-id */
      if (NULL == Lfgets (buf, sizeof (buf), instr))
	{
	  Lfclose (tf);
	  return (reply (501, "Error on input file", 0));
	}
      buf[Lstrlen (buf) - 1] = '\0';
      for (search = buf; *search && *search != '-'; search++);
      *search++ = '\0';
      low = Latoul (buf);
      high = Latoul (search);
      if (0 != (result = fseek (tf, low, SEEK_SET)))
	{
	  if (optforced_read)
	    {
	      response = 258;
	      msg = "Completed with errors";
	    }
	  else
	    {
	      Lfclose (tf);
	      return (reply (556, "One or more bytes not found", 0));
	    }
	}
      reqcnt = (high - low) + 1;
      while (reqcnt)
	{
	  rdamt = (reqcnt < sizeof (buffer) ? reqcnt : sizeof (buffer));
	  cnt = fread (buffer, 1, rdamt, tf);
	  if (cnt == rdamt)
	    {
#ifdef DO_TIMING
	      (void) prtstat_gettime (&start_sec, &start_usec);
#endif
	      scps_send (outstr, buffer, (int) cnt, flags);
#ifdef DO_TIMING
	      (void) prtstat_gettime (&end_sec, &end_usec);
	      (void) print_timestat ("cmdread", "Socket", "write rcd data",
				     start_sec, start_usec, end_sec,
				     end_usec, 0, cnt);
#endif
	      /* Running the CRC kills performance.  Consider
	       * putting a flag here to skip it.  */
	      if (runcrc)
		crcblock (buffer, cnt, &fcrc);
	    }
	  else
	    {
	      if (high == 0xFFFFFFFFL)
		{
		  /* Error on the read--must have read to eof.  If read
		   * to eof was requested, return OK.  */
		  scps_send (outstr, buffer, (int) cnt, flags);
		  if (runcrc)
		    crcblock (buffer, cnt, &fcrc);
		  goto rrsenddone;
		}
	      else
		{
		  if (optforced_read)
		    {
		      response = 258;
		      msg = "Completed with errors";
		      scps_send ((int) outstr, buffer, (int) rdamt, flags);
		    }
		  else
		    {
		      scps_send ((int) outstr, buffer, (int) cnt, flags);
		      Lfclose (tf);
		      return (reply (556, "One or more segments not found", 0));
		    }		/* if forced read */
		}		/* if read to eof */
	    }			/* if read everything */
	  reqcnt -= rdamt;
	}			/* while more to read */

      if (rcvdata_avail (sctrl))
	{
	  char checkbuf[80];
	  int res;

	  res = scps_recv (sctrl, checkbuf, sizeof (checkbuf) - 1, flags);
	  if (res > 0)
	    {
	      checkbuf[4] = '\0';
	      Lstrtolower (checkbuf);
	      if (0 == Lstrcmp (checkbuf, "intr"))
		goto user_interrupt;

	      if (0 == Lstrcmp (checkbuf, "abor"))
		goto user_abort;
	    }
	  if (res < 0)
	    {
	      /* data_err is not really the proper place
	         * to go here, but its the most direct path
	         * to getline() which will die of loss of
	         * ctrl conn.  */
	      goto data_err;
	    }
	}			/* if */
    }				/* for */

rrsenddone:
  fcrc ^= 0xffffffff;
  if (tf)
    Lfclose (tf);
  return (reply (response, crcrtxt (fcrc), 0));

user_interrupt:
  Lstrout (">INTR\n");
  nsprintfds (tbuf, sizeof (tbuf), "Interrupted", 0, NULL);
  return (reply (256, tbuf, 0));

user_abort:
  Lstrout (">ABOR\n");
  nsprintfds (tbuf, sizeof (tbuf), "Aborted", 0, NULL);
  return (reply (226, tbuf, 0));

data_err:
  return (reply (426, "Data connection", 0));

file_err:
  if (tf)
    Lfclose (tf);
  return (reply (551, "Error on input file", 0));
}				/* send_rrdata() */


/* cmdrest -
 *    set restart point.
 *
 *    Like all commands returns -1 on failure of control
 *    connection.  lookup_execute() tests the return value
 *    for less than zero, and returns -1 if so which indicates
 *    to the caller of lookup_execute() that the control
 *    connection is gone.
 */
int
cmdrest (argc, argv)
     int argc;
     char *argv[];
{
  char cmdbuf[80];

  if (argc != 2)
    {
      return (reply (501, "Syntax error", 0));
    }

  restart_point = Latoi (argv[1]);
  nsprintfds (cmdbuf, sizeof (cmdbuf),
	      "Next RETR or STOR will start at location %d",
	      restart_point, 0);
  return (reply (350, cmdbuf, 0));
}				/* cmdrest() */


/* cmdretr -
 *    retr -- get or read -- record read.
 *    Returns -1 on failure of control connection.
 *    Returns 0 otherwise.
 */
int
cmdretr (argc, argv)
     int argc;
     char *argv[];
{
  FILE *fin;
  struct stat st;
  int result;

#ifdef DO_TIMING
  int32_t start_sec, start_usec, end_sec, end_usec;
  int32_t tmp_start_sec, tmp_start_usec, tmp_end_sec, tmp_end_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (argc != 2)
    /* Wrong number of arguments */
    return (reply (501, "Syntax error", 0));
  if (stat (argv[1], &st))
    {
      /* not there */
      return (reply (550, "File not found", 0));
    }
  else
    {
      fin = Lfopen (argv[1], "r");
      if (fin == NULL)
	{
	  return (reply (550, "Could not open for reading", 0));
	}
    }
  if (restart_point)
    {
      if (fseek (fin, restart_point, 0) < 0)
	{
	  Lfclose (fin);
	  return (reply (550, "Bad restart point", 0));
	}
    }
  sdata = dataconn (argv[1], st.st_size);
  if (sdata < 0)
    {
      /* I don't know if the control conn is good or bad
       * at this point.  I will assume it is good.
       * dataconn() issued the reply.  */
      Lfclose (fin);
      return (0);
    }

  if (0 == Lstrcmp (argv[0], "read"))
    result = send_rrdata (fin, sdata);
  else
    result = send_data (fin, sdata);

#ifdef DO_TIMING
  (void) prtstat_gettime (&tmp_start_sec, &tmp_start_usec);
#endif

  scps_close (sdata);
  sdata = -1;

#ifdef DO_TIMING
  (void) prtstat_gettime (&tmp_end_sec, &tmp_end_usec);
  (void) print_timestat ("cmdretr", "Socket", "close",
			 tmp_start_sec, tmp_start_usec,
			 tmp_end_sec, tmp_end_usec, 0, 0);
#endif

  Lfclose (fin);

  /* Berkeley puts code here to log outgoing transfers.
   * It logs file name, user = anonymous (y/n), authenticated (y/n),
   * time to send, time of day, remote host name, num bytes sent, etc.
   * I cut it out to save space. */

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("cmdretr", "SFTP_cmd", "RETR",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
#endif

  return (result);
}				/* cmdretr() */


/* cmdsite -
 *     Site specific commands given as an example.
 *
 *     TERMINATE: set the flag to terminate the server.
 *     TIME:      report the time.
 */
int
cmdsite (argc, argv)
     int argc;
     char *argv[];
{
  char atime[20];
  char replybuf[80];
  struct timeval tv;


  if (argc < 2)
    return (reply (501, "No command", 0));
  Lstrtolower (argv[1]);
  if (0 == Lstrcmp ("terminate", argv[1]))
    {
      /* Whatever terminate does goes here. */
      siteterm = 1;
      return (reply (251, "site terminate", 0));
    }
  if (0 == Lstrcmp ("time", argv[1]))
    {
#ifdef MSVC
      time_t tod;

      time (&tod);
      tv.tv_sec = tod;
      tv.tv_usec = 0;
#else
      gettimeofday (&tv, NULL);
#endif
      Litoa (tv.tv_sec, atime);
      nsprintfds (replybuf, sizeof (replybuf), "time %s", 0, atime);
      return (reply (216, replybuf, 1));
    }
  if (0 == Lstrcmp ("crcon", argv[1]))
    {
      runcrc = 1;
      return (reply (216, "crcon", 1));
    }
  if (0 == Lstrcmp ("crcoff", argv[1]))
    {
      runcrc = 0;
      return (reply (216, "crcoff", 1));
    }
  if (0 == Lstrcmp ("crc", argv[1]))
    {
      if (argc < 3)
	return (reply (501, "No filename", 0));
      return (reply (250, crcrtxt (getcrc (argv[2])), 0));
    }
  nsprintfds (replybuf, sizeof (replybuf), "%s?", 0, argv[1]);
  return (reply (501, replybuf, 1));
}				/* cmdsite() */


/* cmdsize -
 *    Respond to the size command
 *
 *    Returns -1 on failure of control connection.
 *    Returns 0 otherwise.
 */
int
cmdsize (argc, argv)
     int argc;
     char *argv[];
{
  char replybuf[80];

#ifdef DO_TIMING
  int32_t start_sec, start_usec, end_sec, end_usec;
  int32_t tmp_start_sec, tmp_start_usec, tmp_end_sec, tmp_end_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (argc < 2)
    {
      return (reply (501, "Syntax error", 0));
    }
  switch (type)
    {
    case TYPE_L:
    case TYPE_I:
      {
	struct stat stbuf;
	if (stat (argv[1], &stbuf) < 0)
	  {
	    nsprintfds (replybuf, sizeof (replybuf), "problem with: %s", 0,
			argv[1]);
	    reply (550, replybuf, 0);
	  }
	else
	  {
#ifdef DO_TIMING
	    (void) prtstat_gettime (&tmp_start_sec, &tmp_start_usec);
#endif
	    nsprintfds (replybuf, sizeof (replybuf), "%s SIZE %d bytes",
			stbuf.st_size, argv[1]);
#ifdef DO_TIMING
	    (void) prtstat_gettime (&tmp_end_sec, &tmp_end_usec);
	    (void) print_timestat ("cmdidle", "NOTOPTIM", "nsprintfds",
				   tmp_start_sec, tmp_start_usec,
				   tmp_end_sec, tmp_end_usec, 0, 0);
#endif
	    reply (213, replybuf, 1);
	  }
	break;
      }
#if defined(MEDIUM) || defined(LARGE)
    case TYPE_A:
      {
	char replybuf[1024];
	u_long size;
	FILE *file;


	if (((file = Lfopen (argv[1], "r")) == NULL) || frp (file, &size))
	  {
	    nsprintfds (replybuf, sizeof (replybuf), "problem with: %s", 0,
			argv[1]);
	    reply (550, replybuf, 0);
	  }
	else
	  {
	    sprintf (replybuf, "%s SIZE %lu bytes", argv[1], size);
	    reply (213, replybuf, 1);
	  }
	break;
      }
#endif
    default:
      reply (504, "Invalid file Type", 0);
    }				/* switch */

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("cmdsize", "SFTP_cmd", "SIZE",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
#endif
  return 0;
}				/* cmdsize() */


/* cmdstor -
 *    STOR -- put
 *    Returns -1 on failure of control connection.
 *    Returns 0 otherwise.
 */
int
cmdstor (argc, argv)
     int argc;
     char *argv[];
{
  extern char *gunique (char *);
  FILE *fout;
  char *mode;
  int statres;
  struct stat st;
  int mon;			/* monitor the control connection */
  int ret;			/* return value */
  char tmpname[SCPS_L_tmpnam];
  u_long crcval;


#ifdef DO_TIMING
  int32_t start_sec, start_usec, end_sec, end_usec;
  int32_t tmp_start_sec, tmp_start_usec, tmp_end_sec, tmp_end_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (argc != 2)
    /* Wrong number of arguments */
    return (reply (501, "Syntax error", 0));

#ifdef LARGE
  /* If the file does not exist, don't bother creating a unique name. */
  if (sunique && Lstat (argv[1], &st) == 0 && (argv[1] = gunique (argv[1]))
      == NULL)
    return (reply (452, "Unable to create unique file.", 0));
#endif

  if (restart_point)
    {
      mode = "r+w";
      /* Save the partial file in case there is an error. */
      if (NULL == Ltmpnam (tmpname))
	return (reply (451, "Could not create temp file", 0));
      fcopy (argv[1], tmpname);
    }
  else
    {
      mode = "w";
      statres = Lstat (argv[1], &st);
      if (0 == statres)
	{
	  /* The file exists.  Get a temporary
	   * name and rename it in case something
	   * dies. */
	  if (NULL == Ltmpnam (tmpname))
	    return (reply (451, "Could not create temp file", 0));
	  Lrename (argv[1], tmpname);
	}
    }

  fout = Lfopen (argv[1], mode);
  if (fout == NULL)
    {
      return (reply (553, "Could not open with write access", 0));
    }
  if (restart_point)
    {
      if (fseek (fout, restart_point, 0) < 0)
	{
	  ret = reply (550, "Seek error", 0);
	  goto done;
	}
    }
  /* dataconn() calls scps_connect() and replies 150 */
  sdata = dataconn (argv[1], (short) -1);
  if (sdata < 0)
    goto done;

  ret = receive_data (sdata, fout, &mon, &crcval);
  Lfclose (fout);
  fout = NULL;
  if (restart_point)
    {
      restart_point = 0;
      /* Rollback if necessary */
      if (3 == mon)
	{
	  /* Aborted */
	  remove (argv[1]);
	  Lrename (tmpname, argv[1]);
	}
      else
	{
	  /* The transfer was interrupted again, or
	   * file received OK.  Either way, I don't
	   * need the tmp file.  */
	  remove (tmpname);
	}
    }
  else
    {
      /* Rollback if necessary: no restart point */
      if (3 == mon)
	{
	  /* Aborted */
	  if (0 == statres)
	    {
	      /* argv[1] file existed.  Throw away
	         * the partial file, and put back 
	         * the original file.  */
	      remove (argv[1]);
	      Lrename (tmpname, argv[1]);
	    }
	  else
	    {
	      /* argv[1] file did not exist.  Throw
	         * away the partial file. */
	      remove (argv[1]);
	    }
	}
      else if (0 == statres)
	{
	  /* Either the transfer was interrupted
	   * or the file was received OK.  Either
	   * way, I don't need the temp file anymore */
	  remove (tmpname);
	}
    }				/* if autorestart */
  if (0 == ret)
    {
      ret = reply (226, crcrtxt (crcval), 0);
    }

#ifdef DO_TIMING
  (void) prtstat_gettime (&tmp_start_sec, &tmp_start_usec);
#endif

  scps_close (sdata);
  sdata = -1;

#ifdef DO_TIMING
  (void) prtstat_gettime (&tmp_end_sec, &tmp_end_usec);
  (void) print_timestat ("cmdstor", "Socket", "close",
			 tmp_start_sec, tmp_start_usec,
			 tmp_end_sec, tmp_end_usec, 0, 0);
#endif
done:
  if (fout)
    Lfclose (fout);

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("cmdstor", "SFTP_cmd", "STOR",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
#endif

  return (0);
}				/* cmdstor() */


/* cmdsupp -
 *     Disable reply text.
 */
int
cmdsupp (argc, argv)
     int argc;
     char *argv[];
{
#ifdef DO_TIMING
  int result;
  int32_t start_sec, start_usec, end_sec, end_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  replywithtext = 0;

#ifdef DO_TIMING
  result = reply (211, "Reply text disabled", 1);
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("cmdsupp", "SFTP_cmd", "SUPP",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
  return (result);
#else
  return reply (211, "Reply text disabled", 1);
#endif

}				/* cmdsupp() */


#ifdef SMALL
/* cmdtype -
 *     
 */
int
cmdtype (int argc, char *argv[])
{
  return (reply (200, "Type is binary", 0));
}				/* cmdtype() */
#else

extern int cmdtype (int, char **);
#endif

/* cmdupdt -
 *    Respond to the UPDT command.
 *
 *    - Read the control signals,
 *    - Check for errors,
 *    - Reply with an appropriate code.
 *
 *    Returns -1 on failure of control connection.
 *    Returns 0 otherwise.
 */
int
cmdupdt (argc, argv)
     int argc;
     char *argv[];
{
  FILE *crcfd = NULL;		/* crc file descriptor */
  FILE *ctrlf = NULL;		/* control file descriptor */
  FILE *delf = NULL;		/* delta file descriptor */
  char orgfn[MAXPATHLEN];	/* original */
  char newfn[MAXPATHLEN];	/* new      */
  char delfn[SCPS_L_tmpnam];	/* delta    */
  char line[80];
  int c;			/* counts characters read */
  u_long crcval;
  int32_t crclen;
  u_long ctlfcrc;		/* crc read from control file */
  int replyres;

  if (argc != 2)
    return (reply (501, "No control file name", 0));

  if (NULL == (ctrlf = Lfopen (argv[1], "r")))
    return (reply (501, "Couldn't open ctrl file.", 0));

  if (NULL == Lfgets (orgfn, sizeof (orgfn), ctrlf))
    goto updt_error;
  orgfn[Lstrlen (orgfn) - 1] = '\0';

  if (NULL == Lfgets (newfn, sizeof (newfn), ctrlf))
    goto updt_error;
  newfn[Lstrlen (newfn) - 1] = '\0';

  if (NULL == Lfgets (line, sizeof (line), ctrlf))
    goto updt_error;
  line[Lstrlen (line) - 1] = '\0';
  ctlfcrc = Latoul (line);
  if (NULL == (crcfd = Lfopen (orgfn, "r")))
    goto updt_error;
  if (crc (crcfd, &crcval, &crclen))
    goto updt_error;
  if (crcval != ctlfcrc)
    goto updt_error;
  Lfclose (crcfd);
  crcfd = NULL;

  if (NULL == Ltmpnam (delfn))
    goto updt_error;
  if (NULL == (delf = Lfopen (delfn, "w")))
    goto updt_error;

  while (0 != (c = Lfread (line, 1, sizeof (line), ctrlf)))
    fwrite (line, (short) 1, (short) c, delf);

  Lfclose (ctrlf);
  Lfclose (delf);

  if (edit (orgfn, newfn, delfn))
    replyres = reply (551, "UPDT edit error", 0);
  else
    replyres = reply (250, "UPDT OK", 0);

  return (replyres);

updt_error:
  if (ctrlf)
    Lfclose (ctrlf);
  if (crcfd)
    Lfclose (crcfd);
  if (delf)
    Lfclose (delf);
  return (reply (551, "UPDT Error.", 0));

}				/* cmdupdt() */


/* Command table for the base implementation. */
static struct cmd cmdtab[] =
{
  {"abor", cmdintr},
  {"arst", cmdarst},
  {"dele", cmddele},
  {"idle", cmdidle},
  {"intr", cmdintr},
  {"nars", cmdnars},
  {"noop", cmdnoop},
  {"nsup", cmdnsup},
  {"port", cmdport},
  {"quit", cmdquit},
  {"read", cmdretr},
  {"rest", cmdrest},
  {"retr", cmdretr},
  {"site", cmdsite},
  {"size", cmdsize},
  {"stor", cmdstor},
  {"supp", cmdsupp},
  {"type", cmdtype},
  {"updt", cmdupdt},
  {0}
};


/* cmdsa_initialize -
 *     Write the address of cmdtab to cmdtaba.
 */
void
cmdsa_initialize (void)
{
  cmdtaba = cmdtab;
}				/* cmdsa_initialize() */
