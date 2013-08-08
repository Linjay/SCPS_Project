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
/*                     Friday, October 06, 1995  10:01 PM           */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             server.c                                     */
/*                                                                  */
/* Description:                                                     */
/*    STRV FP server.  This module contains routines common to      */
/*    all build sizes.                                              */
/*                                                                  */
/*
 * $Id: server.c,v 1.19 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/server.c,v 1.19 2007/04/19 15:09:36 feighery Exp $
 * $Id: server.c,v 1.19 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/server.c,v 1.19 2007/04/19 15:09:36 feighery Exp $
 * 
 *    Change History:
 * $Log: server.c,v $
 * Revision 1.19  2007/04/19 15:09:36  feighery
 * This version makes the gateway code (and only the gateway code) safe for
 * 64 bit architectures.  Before we were very sloppy and use a long and int
 * interchangeable.  As part of this change, it was required to make the
 * gateway code single threaded;  therefore gateway_single_thread=yes is the
 * default.  -- PDF
 *
 * Revision 1.18  2002/09/23 19:52:15  scps
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
 * Revision 1.17  2001/01/09 20:43:54  scps
 * The goal of the rewritten VJ congestion control algorithm with the RI is to
 * perform no worse that Linux implementation under identical environments.
 *
 * The following description describes the implementation
 *
 * On a loss event (i.e., indicated by the reception of a snack or 3 dup acks), the
 * value of ssthresh is assigned to the flight size (seqsent - snd_una) divided by
 * two.  During this epoch on the second and third duplicate ack (if the loss event
 * was indicated by a snack), the value of ssthresh is assigned to flight size
 * (seqsent - snd_una) divided by two.  The value of ssthresh is always rounded up
 * to the nearest MSS.  ssthresh is modified on the second and third dup ack to
 * mimic the behavior of cutting ssthresh on the third dup ack (as per most TCP
 * implementations with or without SACK).  Since we cut ssthresh on the first dup
 * ack, the value of ssthresh was typically 1 MSS less than it should be.  Thus
 * after the epoch, the value of ssthresh should be the same in the RI as it would
 * be in other implementations of VJ.
 *
 * The total number of packets in flight during the epoch may not be greater than
 * the new value of ssthresh plus (3 * MSS) as per VJ.  In this context the phrase
 * "in flight" refers to (seqsent - snd_una) - the number of acks received during
 * the epoch.  At the start of the epoch, the variable "pkts_ack_in_epoch" is
 * assigned to seqsent - snd_una.  For each ack received, this variable is
 * decremented by an MSS, and incremented by an MSS when snd_cwnd is increased.
 *
 * Now during the congestion epoch, each time an ack that does not get us out of
 * the epoch is received, "pkts_ack_in_epoch" is decremented by an MSS.  If the
 * value of pkts_ack_in_epoch is less than [ssthresh + (3 * MSS)], then cwnd and
 * "pkts_ack_in_epoch" are incremented by an MSS, thus allowing another packet to
 * be emitted.  This process continues until we receive an ack which exits us from
 * the epoch.
 *
 * Once we exit an epoch, we must guarantee that the number of packet "in flight"
 * which is defined by seqsent - snd_una is less than the value of ssthresh.  This
 * is done by ignoring ack (i.e., do not increase cwnd) until [(seqsent - snd_una)
 * < ssthresh]
 *
 * Revision 1.16  2000/10/23 14:02:37  scps
 * Cleaned to the FP directory so it would compile cleanly  -- PDF
 *
 * Revision 1.15  2000/05/23 18:15:51  scps
 * Changes the SCPS error code define statements to have a SCPS_ prefix.
 * This was required for Linux.
 *
 * 	Pat
 *
 * Revision 1.14  1999/11/22 16:14:34  scps
 * Removed disclaimer comment blocks from revision logs.
 *
 * Revision 1.13  1999/11/22 15:52:44  scps
 * Changed FP discaimers
 *
 * Revision 1.12  1999/07/07 14:05:31  scps
 * Modified the FP files so the RATE and MTU command line parameters would
 * be set properly for both the control and the data connection. -- PDF
 *
 * Revision 1.11  1999/05/24 22:01:44  scps
 * Changed server.c to use #defined values for RBUFSIZE (read) and WBUFSIZE
 * (write).  Bothe are defined in server.c and set to 8192 bytes.  --keith
 *
 * Revision 1.10  1999/05/24 18:36:15  scps
 * Updated send_data buffsize from 68 bytes to 8192. --Keith
 *
 * Revision 1.9  1999/05/18 18:55:37  scps
 * Added command line options to the FP for users to be able to modify
 * the SCPS TP parameters.  --- PDF
 *
 * Revision 1.8  1999/03/23 20:24:37  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.7  1999/03/02 19:49:45  scps
 * Ruhai testing fixes to run under linux.
 * Revision 1.6.2.2  1999/01/22 15:02:36  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:34  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:38  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.8  1997/11/25 01:35:05  steven
 * Wrapped ifdef DEBUG around some debug lines.
 *
 * Revision 1.7  1997/11/20 17:36:33  steven
 * removed references to MSVC40
 *
 * Revision 1.6  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.5  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 * 
 * Revision 1.4  1997/08/15 19:50:22  steven
 * Adding Proxy
 * 
 * Revision 1.3  1997/06/16 14:09:30  steven
 * Added sizes MEDIUM and LARGE.
 * 
 * Revision 1.2  1997/04/23 20:00:45  steven
 * Start of SCPS-FP Full implementation.
 * 
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *
 ********************************************************************/

#include <stdio.h>		/* for file i/o */
#include <signal.h>		/* for signals */
#include <sys/types.h>		/* for stat */
#include <sys/stat.h>		/* for stat      */
#include <string.h>		/* for bzero */
#include <time.h>
#ifdef MSVC
#include <fcntl.h>
#include <direct.h>
#include <winsock.h>
#undef ERROR
#include "ftp.h"
#else
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>		/* for Berkeley socket prototypes */
#include <arpa/ftp.h>		/* for symbolic constants only */
#include <netinet/in.h>		/* for sockaddr_in */
#include <netdb.h>
#endif

#ifdef NOTTP
#include <errno.h>
#endif
/* #include "rx_avail.h" */
#include "libs.h"
#include "tpif.h"

#include "prtstat.h"

#define CMDLNSIZE   40
#define MAXARGS      3
#ifndef SEEK_SET
#define SEEK_SET 0
#endif

#define LFD_ZERO(p) Lbzero((char *)(p), sizeof(*(p)))

#ifdef SMALL
int cmdsa_initialize ();
#endif
#ifdef MEDIUM
void mibread ();
int cmdsa_initialize ();
int cmdsb_initialize ();
#endif
#ifdef LARGE
void mibread ();
int cmdsa_initialize ();
int cmdsb_initialize ();
int cmdsc_initialize ();
#endif

int idletimeout = 900;
extern int errno;

int rcvdata_avail (int fd);
int crc (FILE * fd, u_long * cval, u_long * clen);
int Lstrout (char *str);
void crcblock (char *buf, u_long len, u_long * iocrc);

/*  extern int socktimeout; */

#ifdef MSVC
extern int _fmode;
WORD wVersionRequested;
WSADATA wsaData;
#endif

/* #ifdef debug */
char dbgbuf[DBG_BUFSIZ];
/* #endif */

char cmdline[CMDLNSIZE];	/* control conn input.      */
int margc;			/* used to pass arguments to cmd handler */
int uargc;
char *margv[MAXARGS];		/* pointers to arguments    */

struct sockaddr_in data_addr;	/* data address             */
int sctrl = -1;			/* control socket           */
int sdata = -1;			/* data socket              */
int debug = 0;			/* puts debug messages on   */
				/* screen.                  */
#ifndef SMALL
int pdata = -1;			/* passive data socket      */
#endif
int stemp = -1;			/* temporary socket         */
#ifndef SMALL
short guest = 0;		/* true if logged in anonymously */
short form = 1;
short stru = 1;
short mode = 1;
#endif
short autorestart = 0;		/* 0 for autorest disabled  */
short restart_point = 0;
short type = TYPE_I;		/* transfer type is always  */
				/* binary for now.          */
short mode;
short struc;
short bets;
short betsfill;
int replywithtext = 0;		/* do not include text in   */
				/* replies.                 */
short siteterm = 0;		/* received the site
				 * terminate command        */
short runcrc;			/* if true, do CRC          */
#ifndef SMALL
short logged_in = 0;		/* true if received USER/
				 * PASS.                    */
int ogid;			/* original gid             */
int ouid;			/* original uid             */
#endif
int hash;			/* True if I want hash marks
				 * displayed.  Required so
				 * I can use the same transport
				 * module for the client.   */
int flags = 0;
int port;

struct sockaddr_in name;
struct sockaddr_in hisaddr;
int hisaddrlen;
#ifndef SMALL
struct sockaddr_in pasv_addr;
short usedefault;
#endif
#ifndef SMALL
char startdir[80];
#endif
#ifdef LARGE
int sunique;
#endif

extern char *builddate;
extern char *buildtime;
extern char *buildsize;
struct cmd *cmdtaba = NULL;
struct cmd *cmdtabb = NULL;
struct cmd *cmdtabc = NULL;
struct cmd *cmdtabd = NULL;


/* fp_conf_init -
 *     Initialize configurable parameters.  
 *     Executed once per connection.
 */
int
fp_conf_init (void)
{
  hash = 0;
  autorestart = 0;
  restart_point = 0;
  type = TYPE_I;
  replywithtext = 0;
  siteterm = 0;
  runcrc = 1;
  port = PORT;
#ifndef SMALL
  usedefault = 1;
  guest = 0;
  form = 1;
  stru = 1;
  mode = 1;
  chdir (startdir);
  setgid (ogid);
  setuid (ouid);
  logged_in = 0;
  mibread ();
#ifdef LARGE
  sunique = 0;
#endif
#endif
  return 0;
}				/* fp_conf_init() */


/* fp_initialize -
 *    Initialize all global variables, call init_socks().
 *    Executed once.
 */
int
fp_initialize ()
{
  cmdline[0] = '\0';
  sctrl = -1;
  sdata = -1;
#ifndef SMALL
  ogid = getgid ();
  ouid = getuid ();
  pdata = -1;
#endif
  idletimeout = 900;		/* 15 minutes */
#ifndef SMALL
  getcwd (startdir, sizeof (startdir));
#endif
  port = PORT;
  fp_conf_init ();
  /* socktimeout = 1;       tell the sockets layer to time sockets out */
  return (0);
}				/* fp_initialize() */


/* makemargv -
 *    Take the command line stored in cmdline[] and create
 *    margv, uargc, and margc.
 *
 *    Please excuse the use of globals (margv, margc, etc.)
 *    This code is already debugged, and I'm kind of pressed
 *    for time.
 *
 *    returns margc.
 */
int
makemargv (cmdline)
     char *cmdline;
{
  char *cl;
  int onblank;

  cl = cmdline;
  onblank = 1;
  margc = 0;
  /* make margc and margv */
  while (*cl)
    {
      if (onblank)
	{
	  if (*cl != ' ')
	    {
	      margv[margc++] = cl;
	      if (margc == MAXARGS)
		break;
	      onblank = 0;
	    }
	}
      else
	{
	  if (*cl == ' ')
	    {
	      *cl = '\0';
	      onblank = 1;
	    }
	}
      cl++;
    }				/* while */
  return margc;
}				/* makemargv() */


/* crcrtxt -
 *     Build the reply text that shows the CRC
 */
char *
crcrtxt (crc)
     u_long crc;
{
  static char buf[13];

  Lstrncpy (buf, "CRC:        ", 13);
  Litoa (crc, &(buf[4]));
  return buf;
}				/* crcrtxt() */


/* getcrc -
 *     Return the CRC or -1, given a filename;
 */
u_long
getcrc (filename)
     char *filename;
{
  int32_t res = -1;
  int32_t crcval;
  int32_t crclen;
  FILE *strm;
#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  strm = Lfopen (filename, "r");
  if (strm == NULL)
    return res;
  if (0 == crc (strm, &crcval, &crclen))
    res = crcval;
  Lfclose (strm);
#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("getcrc", "NOTOPTIM",
			 "CRCtime",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
#endif
  return res;
}				/* getcrc() */



/* reply -
 *    Reply to a command.  If suppoverride is true,
 *    reply text is sent regardless of the state
 *    of replywithtext.
 */
int
reply (code, text, suppoverride)
     int code;
     char *text;
     int suppoverride;
{
  int32_t wrres;
  char replybuf[82];
#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (debug)
    printf ("< %d %s\n", code, text);

  if (suppoverride || replywithtext)
    nsprintfds (replybuf, sizeof (replybuf), "%d %s\r\n", code, text);
  else
    nsprintfds (replybuf, sizeof (replybuf), "%d \r\n", code, NULL);

  wrres = scps_send (sctrl, replybuf, Lstrlen (replybuf), flags);
  /* tp-flush(sctrl); */

  if (wrres < 0)
    return -1;
  else
    {
#ifdef DO_TIMING
      (void) prtstat_gettime (&end_sec, &end_usec);
      (void) print_timestat ("sendreply", "Socket",
			     "send reply",
			     start_sec, start_usec,
			     end_sec, end_usec, 0, 0);
#endif
      return 0;
    }
}				/* reply() */


/* getdatasock -
 *    Get a data socket.
 *    Returns a value for sdata.
 *    In the Berkeley code this used to call bind().
 */
int
getdatasock ()
{
  int s;
#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif
  if (sdata >= 0)
    {
      scps_close (sdata);
      sdata = -1;
    }

  s = scps_socket (AF_INET, SOCK_STREAM, 0);

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("getdatasock", "Socket",
			 "socket",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
#endif
  if (s < 0)
    return (-1);

#ifndef NOTTP
  enable_options (s);
#endif /* NOTTP */

  return (s);
}				/* getdatasock() */


/* dataconn -
 *    Establish a data connection.
 *    Issue the 150 (or 425) reply.
 *    Works for both one-party and proxy.
 *
 *    Returns a value for sdata if there is a connection.
 *    Returns -1 if no dice.
 */
int
dataconn (name, size)
     char *name;
#ifdef MSVC
     _off_t size;
#else
     uint32_t size;
#endif
{
  char sizebuf[32];
  int result;
  int s;
  char replybuf[80];
#ifndef NOTTP
  int one = 1;
#endif

#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
#endif

  if (size != -1)
    nsprintfds (sizebuf, sizeof (sizebuf), " (%d bytes)", size, NULL);
  else
    sizebuf[0] = '\0';
  s = getdatasock ();
  if (s < 0)
    {
      reply (425, "Cannot create data socket", 0);
      return (-1);
    }


#ifdef DO_TIMING
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif
#ifndef NOTTP
  /* BETS is TP specific. */
  if (bets)
    scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_BETS, &one, sizeof (one));
#endif

#if defined(SYSV) || defined(__BSD__) || defined (MSVC) || defined(LINUX)
  result = scps_connect (s, (struct sockaddr *) &data_addr, sizeof (data_addr));
#else
  result = scps_connect (s, &data_addr, sizeof (data_addr));
#endif

  if (result < 0)
    {
      reply (425, "Cannot build data connection", 0);
      scps_close (s);
      return (-1);
    }

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("dataconn", "Socket",
			 "connect",
			 start_sec, start_usec,
			 end_sec, end_usec, 0, 0);
#endif
#if defined(MEDIUM) || defined(LARGE)
  switch (type)
    {
    case TYPE_A:
      nsprintfds (replybuf, sizeof (replybuf), "%s ASCII.", 0, name);
      break;

    case TYPE_I:
    case TYPE_L:
      nsprintfds (replybuf, sizeof (replybuf), "%s BINARY.", 0, name);
      break;

    }				/* switch */
#else
  nsprintfds (replybuf, sizeof (replybuf), "%s BINARY.", 0, name);
#endif
  reply (150, replybuf, 0);
  return (s);
}				/* dataconn() */


/* dologout -
 *    Close all sockets.
 *    Always returns -1.
 */
int
dologout (status)
     int status;
{
  if (sdata != -1)
    {
      scps_close (sdata);
      sdata = -1;
    }
  if (sctrl != -1)
    {
      scps_close (sctrl);
      sctrl = -1;
    }
  /* make sure everything is closed */
  /* tp-shutdownall(); */
  return (-1);
}				/* dologout() */


/* select_rd -
 *    Call select to read from the data or control connection.
 *    Berkeley uses out-of-band data which causes a signal to
 *    the application.  SCPS-TP may not support OOB, so I
 *    listen for "ABOR" and "INTR" this way.
 *
 *  Returns:
 *    0 - no error
 *    1 - data conn died, ctl conn died, or timed out.
 *    2 - received "INTR"
 *    3 - received "ABOR"
 */
#define RBUFSIZE 8192
int
select_rd (int instr, char *buf, int size, int *cnt)
{
  static char rbuf[RBUFSIZE];
#ifdef MSVC
  /* Windows ignores this. */
  int maxfds = 0;
#else
  int maxfds = sysconf (_SC_OPEN_MAX);
#endif
  struct timeval t;
#ifdef NOTTP
  fd_set rcvfds;
#else
  scps_fd_set rcvfds;
#endif
  int res;
  int ret;
  char *cmd;

#ifdef MSVC
  memset (&t, 0, sizeof (t));
#else
  bzero ((void *) &t, sizeof (t));
#endif
  t.tv_sec = 15;		/* set timeout to x seconds. */
#ifdef NOTTP
  FD_ZERO (&rcvfds);
  FD_SET (instr, &rcvfds);
  FD_SET (sctrl, &rcvfds);
  res = select (maxfds, &rcvfds, NULL, NULL, &t);
#else
  SCPS_FD_ZERO (&rcvfds);
  SCPS_FD_SET (instr, &rcvfds);
  SCPS_FD_SET (sctrl, &rcvfds);
  res = scps_select (maxfds, &rcvfds, NULL, NULL, &t);
#endif
  switch (res)
    {
    case -1:
      /* error */
      *cnt = 1;
      return (1);

    case 0:
      /* timeout */
      *cnt = 2;
      return (1);

    default:
      /* got an event */
#ifdef NOTTP
      if (FD_ISSET (instr, &rcvfds))
	{
#else
      if (SCPS_FD_ISSET (instr, &rcvfds))
	{
#endif
	  *cnt = scps_recv (instr, buf, size, flags);
	}
#ifdef NOTTP
      if (FD_ISSET (sctrl, &rcvfds))
	{
#else
      if (SCPS_FD_ISSET (sctrl, &rcvfds))
	{
#endif
	  ret = scps_recv (sctrl, rbuf, sizeof (rbuf), flags);
	  if (ret == 0)
	    {
	      *cnt = 3;
	      return (1);
	    }
	  Lstrtolower (rbuf);
	  cmd = Lstrstr (rbuf, "abor");
	  if (cmd != NULL)
	    return (3);
	  cmd = Lstrstr (rbuf, "intr");
	  if (cmd != NULL)
	    {
	      return (2);
	    }
	}
      return (0);
    }				/* switch */
}				/* select_rd() */


/* Tranfer the contents of "instr" to "outstr" peer using the appropriate
 * encapsulation of the data subject to Mode, Structure, and Type.
 * Issues the 226 reply.  Needs fn (filename) to put the CRC in the
 * reply text.
 *
 * Returns -1 if needed to shutdown all.
 * Returns 0 otherwise.
 *
 * NB: Form isn't handled. */
#define WBUFSIZE 8192
int
send_data (instr, outstr)
     FILE *instr;
     int outstr;
{
  register int cnt;
#if defined(MEDIUM) || defined(LARGE)
  int asciicopyfmfs (FILE * infile, int outs, u_long * bytecount, u_long * crcval);
  int copyresult;
#endif
  char buf[WBUFSIZE];
  int mon = 0;
  char tbuf[40];
  int32_t byte_count = 0;
  u_long fcrc;
#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
#endif

  fcrc = 0;

  restart_point = 0;		/* no longer needed */
  switch (type)
    {

    case TYPE_I:
    case TYPE_L:
#ifdef DO_TIMING
      (void) prtstat_gettime (&start_sec, &start_usec);
#endif
      for (;;)
	{
	  cnt = fread (buf, 1, sizeof (buf), instr);
	  if (cnt <= 0)
	    break;

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

	  /* Running the CRC kills performance.  Consider
	   * putting a flag here to skip it.  */
	  if (runcrc)
	    crcblock (buf, cnt, &fcrc);
	  if (scps_send (outstr, buf, cnt, flags) != cnt)
	    {
	      break;
	    }			/* if */
	  byte_count += cnt;
	}			/* for */

#ifdef DO_TIMING
      (void) prtstat_gettime (&end_sec, &end_usec);
      (void) print_timestat ("senddata", "Socket",
			     "send binary data",
			     start_sec, start_usec,
			     end_sec, end_usec, 0, byte_count);
#endif
      if (cnt != 0)
	{
	  if (cnt < 0)
	    goto file_err;
	  goto data_err;
	}
      if (mon)
	goto user_interrupt;
      fcrc ^= 0xffffffff;
      return (reply (226, crcrtxt (fcrc), 0));

#if defined(MEDIUM) || defined(LARGE)
    case TYPE_A:
      copyresult = asciicopyfmfs (instr, outstr, &byte_count, &fcrc);
      if (copyresult == 2)
	goto user_interrupt;
      if (copyresult == 3)
	goto user_abort;
      return (reply (226, crcrtxt (fcrc), 0));
#endif

    default:
      nsprintfds (tbuf, sizeof (tbuf),
		  "Unimplemented TYPE %d in send_data", type, NULL);
      return (reply (550, tbuf, 0));
    }

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
  return (reply (551, "Error on input file", 0));
}				/* send_data() */


/* Transfer data from peer to "outstr" using the appropriate encapulation of
 * the data subject to Mode, Structure, and Type.
 *
 * N.B.: Form isn't handled. */
int
receive_data (instr, outstr, mon, crcval)
     int instr, *mon;
     FILE *outstr;
     u_long *crcval;
{
#if defined(MEDIUM) || defined(LARGE)
  extern int asciicopytofs (int ins, FILE * outfile, u_long * bytecount,
			    u_long * crcval);
  int copyresult;
#endif
  int cnt = 0;
  u_long byte_count = 0;
  char buf[FP_BUFSIZ];

#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  int32_t delta_time = 0;
#endif

  *mon = *crcval = 0;
  switch (type)
    {

    case TYPE_I:
    case TYPE_L:

#ifdef DO_TIMING
      (void) prtstat_gettime (&start_sec, &start_usec);
#endif
      for (;;)
	{
	  *mon = select_rd (instr, buf, sizeof (buf), &cnt);

/* printf ("PDF XXX READ switch on *mon = %d\n",*mon); */
	  switch (*mon)
	    {
	    case 0:
/* printf ("PDF XXX READ case 0cnt = %d\n",cnt); */
	      if (cnt)
		{
		  /* This call to crcblock() kills performance.
		   * But it's nice to have a good CRC over the
		   * entire file.  Consider making it an option. */
		  crcblock (buf, cnt, crcval);
		  if (fwrite (buf, (size_t) 1, (size_t) cnt, outstr) !=
		      (size_t) cnt)
		    goto file_err;
		}
	      else
		{
		  goto read_done;
		}
	      byte_count += cnt;
	      break;

	    case 1:
	      /* error */
	      goto read_done;

	    case 2:
	      goto xfer_intr;

	    case 3:
	      goto xfer_abor;

	    default:
	      goto read_done;
	    }			/* switch */
	}			/* for */

    read_done:
/* printf ("PDF XXX READ read_done\n"); */
      *crcval ^= 0xffffffff;
#ifdef DO_TIMING
      (void) prtstat_gettime (&end_sec, &end_usec);
      (void) print_timestat ("recv_data", "Socket",
			     "recv binary data",
			     start_sec, start_usec,
			     end_sec, end_usec,
			     0, byte_count);

#endif
      if (cnt < 0)
	goto data_err;
      return (*mon);
#if defined(MEDIUM) || defined(LARGE)
    case TYPE_A:
      copyresult = asciicopytofs (instr, outstr, &byte_count, crcval);
      *mon = copyresult;
      switch (copyresult)
	{
	case 0:
	  return 0;
	case 1:
	  goto file_err;
	case 2:
	  goto xfer_intr;
	case 3:
	  goto xfer_abor;
	default:
	  reply (550, "Local error", 0);
	  return (-1);
	}			/* switch */
#endif
    default:
      nsprintfds (buf, sizeof (buf),
		  "Unimplemented TYPE %d in receive_data", type, NULL);
      reply (550, buf, 0);
      return (-1);
    }

xfer_intr:
  Lstrout (">INTR\n");
#if defined(MEDIUM) || defined(LARGE)
  sprintf (buf, "Transfer interrupted at %lu", byte_count);
#else
  nsprintfds (buf, sizeof (buf), "Transfer interrupted at %d", byte_count, NULL);
#endif
  reply (256, buf, 0);
  return (-1);

xfer_abor:
  Lstrout (">ABOR\n");
  reply (226, "Transfer aborted", 0);
  return (-1);

data_err:
  reply (426, "Data Connection", 0);
  return (-1);

file_err:
  reply (452, "Error writing file", 0);
  return (-1);
}				/* receive_data */


/* lookup_execute -
 *    Look up the command in the command table, and execute
 *    it.
 *    Returns 1 if found and did something.
 *    Returns 0 if not found.
 *    Returns -1 if found and an error occurred in execution.
 */
int
lookup_execute (argc, argv, cmdp)
     int argc;
     char *argv[];
     struct cmd *cmdp;
{
  int found = 0;

  Lstrtolower (argv[0]);
#ifndef SMALL
  if (0 == logged_in)
    if ((0 != Lstrncmp (argv[0], "user", 4)) &&
	(0 != Lstrncmp (argv[0], "pass", 4)) &&
	(0 != Lstrncmp (argv[0], "quit", 4)))
      {
	reply (530, "Not logged in", 0);
	return 1;
      }

#endif
  /* search for the command in the table */
  while (cmdp->c_name)
    {
      if (0 == Lstrcmp (cmdp->c_name, argv[0]))
	{
	  /* OK.  I found it. */
	  found = 1;
	  if ((*cmdp->c_func) (argc, argv) < 0)
	    found = -1;
	  break;
	}
      cmdp++;
    }
  return found;
}				/* lookup_execute() */


/* to_getch -
 *     Get a character.  Time out.
 *     Returns 0 or -1 on error,
 *             1 on success.
 */
int
to_getch (char *ch)
{
#ifdef MSVC
  /* Windows ignores this. */
  int maxfds = 0;
#else
  int maxfds = sysconf (_SC_OPEN_MAX);
#endif
  struct timeval t;
#ifdef NOTTP
  fd_set rcvfds;
#else
  scps_fd_set rcvfds;
#endif
  int res, result;

  if (sctrl < 0)
    return (-1);
  Lbzero ((char *) &t, sizeof (t));
  t.tv_sec = idletimeout;
#ifdef NOTTP
  LFD_ZERO (&rcvfds);
  FD_SET (sctrl, &rcvfds);
  res = select (maxfds, &rcvfds, NULL, NULL, &t);
#else
  SCPS_FD_ZERO (&rcvfds);
  SCPS_FD_SET (sctrl, &rcvfds);
  res = scps_select (maxfds, &rcvfds, NULL, NULL, &t);
#endif
  if (res == -1)
    {
      nsprintfds (dbgbuf, sizeof (dbgbuf), "select() error: %d\n", errno, NULL);
      Lstrout (dbgbuf);
      return (-1);
    }
  if (res == 1)
    {
      /* Got an event */
#ifdef NOTTP
      if (FD_ISSET (sctrl, &rcvfds))
	{
#else
      if (SCPS_FD_ISSET (sctrl, &rcvfds))
	{
#endif
	  result = scps_recv (sctrl, ch, 1, flags);
	  if (result != 1)
	    return (-1);
	  else
	    return 1;
	}
      else
	{
	  return (-1);
	}
    }
  return (-1);
}				/* to_getch() */


/* getline -
 *    Get a line from the control connection.
 *
 * Returns:
 *    0 - OK
 *   -1 - Burp
 */
int
getline (cmdline, cmdlen)
     char *cmdline;
     int cmdlen;
{
  int cmdlinep = 0;
  int result;
  char ch;

  cmdlen--;			/* don't read too much */
  while (1)
    {
      result = to_getch (&(cmdline[cmdlinep]));
      /* save the char read for comparison */
      ch = cmdline[cmdlinep];

      if (result <= 0)
	return (-1);
      if (cmdline[cmdlinep] == '\r')
	continue;
      cmdlinep++;
      cmdline[cmdlinep] = '\0';	/* make sure it's always terminated. */
      if (cmdlinep == cmdlen)
	cmdlinep--;		/* don't read past the end */
      if ((cmdlinep == 1) && (cmdline[0] == '\n'))
	{
	  /* empty line */
	  cmdlinep = 0;
	}
      else if ((cmdlinep != 0) && (ch == '\n'))
	{
	  cmdline[cmdlinep - 1] = '\0';
	  return (0);
	}
    }				/* while */
}				/* getline() */


/* versionstr -
 *     Converts an RCS Name string to a nice neat version string.
 *     Also writes the implementation size.  Caller ensures that
 *     the output buffer is large enough.
 */
char *
versionstr (char *namestr, char *outstr)
{
  char *s = outstr;

  if (namestr[5] == ':')
    {
      namestr += 7;
      for (; *namestr != '$'; namestr++)
	/* RCS does not allow dots in the symbolic name.
	 * So I convert '-' and '_' to a dot--I think it
	 * looks better.  */
	if (*namestr == '-' || *namestr == '_')
	  *outstr++ = '.';
	else
	  *outstr++ = *namestr;
    }
  *outstr++ = ':';
  *outstr++ = ' ';
  Lstrncpy (outstr, buildsize, (short) (Lstrlen (buildsize) + 1));
  return s;
}				/* versionstr() */


/* server_app -
 *    Listens on the control socket for a connection.  When
 *    a connection is established, it reads it for commands,
 *    parses them, looks them up, and executes them.
 */
void
server_app (void)
{
  static char firsttime = 1;
  int lresult;
  struct cmd *cmdpp[5];
  int l;
  char namestr[80];
  struct hostent *hp;

#ifdef NOTTP
  int on = -1;
  int tries = 1;
#endif

#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  nsprintfds (dbgbuf, sizeof (dbgbuf), "SCPS-FP Server [%s ", 0, builddate);
  Lstrout (dbgbuf);
  nsprintfds (dbgbuf, sizeof (dbgbuf), "%s]\r\n", 0, buildtime);
  Lstrout (dbgbuf);
  nsprintfds (dbgbuf, sizeof (dbgbuf), "Version: %s\r\n", 0, versionstr
	      ("$Name:  $", namestr));
  Lstrout (dbgbuf);

#ifdef NOTTP
  Lstrout ("running over UNIX sockets\r\n");
#else
  Lstrout ("running over SCPS-TP sockets\r\n");
#endif

  while (1)
    {
      if (sctrl >= 0)
	{
	  /* tp-abort(sctrl); */
	  scps_close (sctrl);
	  shutdown (sctrl, 2);
	}
      if (!firsttime)
	fp_conf_init ();
      else
	firsttime = 0;
      sctrl = scps_socket (AF_INET, SOCK_STREAM, 0);
      if (sctrl == -1)
	{
	  nsprintfds (dbgbuf, sizeof (dbgbuf), "-1 <- socket() errno:%d\n",
		      errno, 0);
	  Lstrout (dbgbuf);
	  continue;
	}

#ifndef NOTTP
      enable_options (sctrl);
#endif  /* NOTTP */

      Lbzero ((char *) &name, sizeof (name));
      name.sin_port = htons (port);

      name.sin_family = AF_INET;

      /* give name.sin_addr.s_addr this host's address. */
      if (gethostname (namestr, sizeof (namestr)))
	{
	  Lstrout ("gethostname failed\n");
	}
      hp = gethostbyname (namestr);
      if (NULL == hp)
	{
	  Lstrout ("gethostbyname failed\n");
	}
#ifdef MSVC
      memmove (&(name.sin_addr), hp->h_addr_list[0], hp->h_length);
#else
      bcopy (hp->h_addr_list[0], (caddr_t) & (name.sin_addr), hp->h_length);
#endif

#ifdef NOTTP			/* XXX PDF */

      if (setsockopt (sctrl, SOL_SOCKET, SO_REUSEADDR,
		      (char *) &on, sizeof (int)) < 0)
	{
	  nsprintfds (dbgbuf, sizeof (dbgbuf),
		      "-1 <- setsockopt() errno:%d\n", errno, 0);
	  Lstrout (dbgbuf);
	  exit (1);
	}

      for (tries = 1;; tries++)
	{
	  lresult = scps_bind (sctrl, (struct sockaddr *) &name, sizeof (struct sockaddr));
	  if (lresult >= 0)
	    {
	      break;
	    }
#ifdef MSVC
	  errno = WSAGetLastError ();
	  if (errno != WSAEADDRINUSE || tries > 10)
	    {
#else
	  if (errno != EADDRINUSE || tries > 10)
	    {
#endif
	      scps_close (sctrl);
	      sctrl = -1;
	      nsprintfds (dbgbuf, sizeof (dbgbuf), "errno: %d  ", errno, 0);
	      Lstrout (dbgbuf);
	      nsprintfds (dbgbuf, sizeof (dbgbuf), "tries: %d\n", tries, 0);
	      Lstrout (dbgbuf);
	      exit (1);
	    }
	  else
	    {
	      nsprintfds (dbgbuf, sizeof (dbgbuf), "try: %d\n", tries, 0);
	      Lstrout (dbgbuf);
	    }
#ifdef MSVC
	  Sleep (tries * 1000);
#else
	  sleep (tries);
#endif
	}
#else
      lresult = scps_bind (sctrl,
			   &name,
			   sizeof (struct sockaddr_in));
#ifdef DEBUG
      nsprintfds (dbgbuf, sizeof (dbgbuf), "%d <- scps_bind()\n", lresult, 0);
      Lstrout (dbgbuf);
#endif
#endif

      if (scps_listen (sctrl, 3) < 0)
	{
	  scps_close (sctrl);
	  sctrl = -1;
	  continue;
	}
      if (debug)
	Lstrout ("Listening.\n");
      hisaddrlen = sizeof (hisaddr);
#if defined(SYSV) || defined(__BSD__) || defined(MSVC) || defined(LINUX)
      if ((stemp = scps_accept (sctrl,
				(struct sockaddr *) &hisaddr,
				&hisaddrlen)) >= 0)
	{
#else
      if ((stemp = scps_accept (sctrl,
				&hisaddr,
				&hisaddrlen)) >= 0)
	{
#endif
	  scps_close (sctrl);
	  sctrl = stemp;
	  /* OK.  I have a connection */
	  if (debug)
	    {
	      hp = gethostbyaddr ((char *) &(hisaddr.sin_addr), sizeof
				  (hisaddr.sin_addr), AF_INET);
	      if (hp)
		{
		  printf ("Connected to '%s'\n", hp->h_name);
		}
	      else
		Lstrout ("Connected.\n");
	    }
	  versionstr ("$Name:  $", dbgbuf);
	  nsprintfds (namestr, sizeof (namestr),
		      "SCPS-FP server (V%s) ready.", 0, dbgbuf);
	  if (0 == reply (220, namestr, 1))
	    {
#ifdef DO_TIMING
	      (void) prtstat_gettime (&end_sec, &end_usec);
	      (void) print_timestat ("server_app", "SFTP_cmd",
				     "Server Startup",
				     start_sec, start_usec,
				     end_sec, end_usec, 0, 0);
#endif
	      cmdpp[0] = cmdtaba;
	      cmdpp[1] = cmdtabb;
	      cmdpp[2] = cmdtabc;
	      cmdpp[3] = cmdtabd;
	      while (1)
		{
		  if (getline (cmdline, sizeof (cmdline)) < 0)
		    break;
		  if (debug)
		    {
		      Lstrout ("> ");
		      Lstrout (cmdline);
		      Lstrout ("\n");
		    }
		  if (makemargv (cmdline))
		    {
		      for (lresult = l = 0; lresult == 0 && cmdpp[l]; l++)
			lresult = lookup_execute (margc, margv, cmdpp[l]);
		      if (0 > lresult)
			break;
		      if (0 == lresult)
			if (0 != reply (500, "Not recognized", 0))
			  break;
		    }		/* if makeargv */
		}		/* while */
	    }			/* if sent 220 */
	}
      else
	{
	  nsprintfds (dbgbuf, sizeof (dbgbuf), "errno: %d\n", errno, 0);
	  Lstrout (dbgbuf);
	}			/* if */
    }				/* once a server, always a server */
}				/* server_app() */


/* sigdie -
 *     
 */
void
sigdie (int sig)
{
  if (sig == SIGSEGV)
    abort ();
  else
    exit (1);
}				/* sigdie() */


/* main -
 *     
 */
int
main (argc, argv)
int argc;
char **argv;

{
#ifdef MSVC
  int err;

  _fmode = _O_BINARY;

  wVersionRequested = MAKEWORD (1, 1);

  err = WSAStartup (wVersionRequested, &wsaData);
  if (err != 0)
    {
      return;
    }
#endif
  signal (SIGSEGV, sigdie);
  signal (SIGINT, sigdie);
  fp_initialize ();

#ifndef NOTTP
  parse_options (argc, argv);
#endif /* NOTTP */
  
#ifdef SMALL
  cmdsa_initialize ();
#else
#ifdef MEDIUM
  cmdsa_initialize ();
  cmdsb_initialize ();
#else
#ifdef LARGE
  cmdsa_initialize ();
  cmdsb_initialize ();
  cmdsc_initialize ();
#endif
#endif
#endif

#ifdef NOTTP

  /* go be a server */
  server_app ();
#ifdef MSVC
  WSACleanup ();
#endif
#else

  /* Initialize SCPS thread structures */
  init_scheduler ();
  scheduler.run_queue[0] = create_thread (tp);
  scheduler.run_queue[1] = create_thread (server_app);
  (void) scps_Init ();
  start_threads ();
  exit (0);

#endif

}				/* main() */
