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
/*                     Thursday, April 17, 1997 6:03 pm             */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/*   This is unclassified Government software.
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
 * Module:             cmdcb.c                                      * 
 *                                                                  * 
 * Description:                                                     * 
 *    Client commands, set B.  These commands are used in the SCPS  * 
 *    full implementation.                                          * 
 *
 * $Id: cmdcb.c,v 1.12 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/cmdcb.c,v 1.12 2007/04/19 15:09:36 feighery Exp $
 *
 *    Change History:
 * $Log: cmdcb.c,v $
 * Revision 1.12  2007/04/19 15:09:36  feighery
 * This version makes the gateway code (and only the gateway code) safe for
 * 64 bit architectures.  Before we were very sloppy and use a long and int
 * interchangeable.  As part of this change, it was required to make the
 * gateway code single threaded;  therefore gateway_single_thread=yes is the
 * default.  -- PDF
 *
 * Revision 1.11  2002/09/23 19:52:14  scps
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
 * Revision 1.10  2000/10/23 14:02:36  scps
 * Cleaned to the FP directory so it would compile cleanly  -- PDF
 *
 * Revision 1.9  2000/10/23 13:06:25  scps
 * Inital try of removing the error associated with comments block and CVS --PDF
 *
 * Revision 1.8  1999/11/22 15:52:41  scps
 * Changed FP discaimers to read as follows:
 *
 *
 * 		--keith
 *
 * Revision 1.7  1999/03/23 20:24:34  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.6.2.2  1999/01/22 15:02:29  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:28  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:35  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.5  1997/11/25 01:35:05  steven
 * Change for fbsd get password.
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
 *
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *
 */

static char rcsid[] = "$Id: cmdcb.c,v 1.12 2007/04/19 15:09:36 feighery Exp $";

#include "libc.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>		/* for getpass() */
#include <arpa/ftp.h>		/* contains symbolic constants only */
#include "tpif.h"
#ifndef SMALL
#include "rp.h"			/* for ACBUFSIZE */
#endif

#ifndef NOTTP
#include "scpserrno.h"
#endif /* NOTTP */

extern int bets;		/* true if running in BETS mode.    */
extern int flags;
extern u_long restart_point;
extern short type;		/* i.e. TYPE_A or TYPE_I */
extern int debug;
extern int abortop;		/* Set true by the SIGINT routine. (^C)
				 * Lets the user abort transfer
				 * operations.                      */
extern int interruptop;		/* Set true by the SIGTSTP routine (^Z)
				 * (or maybe ^Y) Lets the user interrupt
				 * transfer operations.             */
extern int proxy;
extern int sctrl;
extern struct cmd *cmdtabb;
extern int recvrequest (char *, char *, char *, char *, int, int *);
extern int getreply (int expecteof, int *user_int);

extern int code;		/* reply code from server          */

extern char msgbuf[MBSIZE];	/* for sendcommand()               */
extern int hash;		/* true for displaying hash indicators */
extern int hash_size;		/* number of bytes represented by a hash mark */

int sendcommand (char *cmd);

char acinput[ACBUFSIZE + 1];	/* Make sure there's always a null at the end */
char acoutput[ACBUFSIZE + 1];


/* asciicopytofs - Efficient copy from instream to file system.
 *                 Converts to the appropriate line termination sequence.
 *    Returns
 *       0 - no error
 *       1 - file error
 *       2 - interrupted
 *       3 - aborted
 */
int
asciicopytofs (int ins, FILE * outfile, u_long * bytecount)
{
  int incnt;
  int outcnt;
  int i, o;
  u_long hashbytes = 0;


  *bytecount = 0;
  o = 0;
  while ((incnt = scps_recv (ins, acinput, ACBUFSIZE, 0)) != 0)
    {
      if (abortop)
	{
	  abortop = 0;
	  scps_send (sctrl, "ABOR\r\n", 6, flags);
	  /* ditch any remaining stuff. */
	  for (i = 0; i < 20 && scps_recv (ins, acinput, ACBUFSIZE, 0); i++);
	  if (debug)
	    {
	      printf ("---> ABOR\n");
	    }
	  return 3;
	}
      if (interruptop)
	{
	  interruptop = 0;
	  scps_send (sctrl, "INTR\r\n", 6, flags);
	  for (i = 0; i < 20 && scps_recv (ins, acinput, ACBUFSIZE, 0); i++);
	  if (debug)
	    {
	      printf ("---> INTR\n");
	    }
	  return 2;
	}
      for (i = 0; i < incnt; i++)
	{
	  (*bytecount)++;
	  if ((*bytecount) - hashbytes >= (uint32_t) (hash_size))
	    {
	      if (hash)
		{
		  printf ("#");
		  fflush (stdout);
		}
	      hashbytes = *bytecount;
	    }
#ifndef MSVC
	  if (acinput[i] != '\r')
	    {
#endif
	      acoutput[o++] = acinput[i];
	      if (o == ACBUFSIZE)
		{
		  outcnt = fwrite (acoutput, 1, ACBUFSIZE, outfile);
		  if (outcnt != ACBUFSIZE)
		    {
		      return 1;
		    }
		  o = 0;
		}		/* output buffer full */
#ifndef MSVC
	    }			/* found <CR> */
#endif
	}			/* for */
    }				/* while */
  if (o)
    {
      outcnt = fwrite (acoutput, 1, o, outfile);
      return (o != outcnt);
    }
  else
    return 0;
}				/* end asciicopytofs() */


/* asciicopyfmfs - Efficient copy from file system to out stream.
 *                 Converts (if necessary) to the network line
 *                 termination sequence <CR><LF>.
 */
int
asciicopyfmfs (FILE * infile, int outs, u_long * bytecount)
{
  int incnt;
  int outcnt;
  int i, o;
  u_long hashbytes = 0;


  *bytecount = 0;
  o = 0;
  while ((incnt = fread (acinput, 1, ACBUFSIZE, infile)) != 0)
    {
      if (interruptop)
	{
	  interruptop = 0;
	  return 2;
	}
      if (abortop)
	{
	  abortop = 0;
	  return 3;
	}
      for (i = 0; i < incnt; i++)
	{
	  /* SCHEDULER(); */
	  if (acinput[i] == '\n')
	    {
	      acoutput[o++] = '\r';
	      (*bytecount)++;
	      if (o == ACBUFSIZE)
		{
		  outcnt = scps_send (outs, acoutput, ACBUFSIZE, 0);
		  if (outcnt != ACBUFSIZE)
		    {
		      return 4;
		    }
		  o = 0;
		}		/* output buffer full */
	    }			/* found <LF> */
	  acoutput[o++] = acinput[i];
	  (*bytecount)++;
	  if ((*bytecount) - hashbytes >= (uint32_t) (hash_size))
	    {
	      if (hash)
		{
		  printf ("#");
		  fflush (stdout);
		}
	      hashbytes = *bytecount;
	    }
	  if (o == ACBUFSIZE)
	    {
	      outcnt = scps_send (outs, acoutput, ACBUFSIZE, 0);
	      if (outcnt != ACBUFSIZE)
		{
		  return 4;
		}
	      o = 0;
	    }			/* output buffer full */
	}
    }
  if (o)
    {
      outcnt = scps_send (outs, acoutput, o, 0);
      if (outcnt != o)
	{
	  return 4;
	}
    }
  return (0);
}				/* end asciicopyfmfs() */


/* dgmt -
 *     Calculates the number of seconds from local time to gmt.
 */
time_t
dgmt (void)
{
  struct tm lt, gmt;
  time_t t = time (NULL);

  memcpy (&lt, localtime (&t), sizeof (struct tm));
  memcpy (&gmt, gmtime (&t), sizeof (struct tm));
  return mktime (&lt) - mktime (&gmt);
}				/* dgmt() */

#ifdef EPLF
/* eplf_readable -
 *     Returns 0 if it didn't display anything (because it couldn't
 *               interpret the line).
 *     Returns 1 if it could interpret the line and display it.
 */
int
eplf_readable (char *line, time_t diffgmt)
{
  int flagcwd = 0;
  int flagsize = 0;
  time_t when;
  uint32_t size;

  if (*line++ != '+')
    return 0;
  while (*line)
    switch (*line)
      {
      case '\t':
	if (flagsize)
	  printf ("%10lu bytes   ", size);
	else
	  printf ("                   ");
	if (when)
	  printf ("%24.24s", ctime (&when));
	else
	  printf ("                        ");
	printf ("   %s%s", flagcwd ? "/" : "", line + 1);
	return 1;
      case 's':
	flagsize = 1;
	size = 0;
	while (*++line && (*line != ','))
	  size = size * 10 + (*line - '0');
	break;
      case 'm':
	when = 0;
	while (*++line && (*line != ','))
	  when = when * 10 + (*line - '0');
	when += diffgmt;
	break;
      case '/':
	flagcwd = 1;
      default:
	while (*line)
	  if (*line++ == ',')
	    break;
      }
  return 0;
}				/* eplf_readable() */
#endif

/* interp_list -
 *     Interpret LIST output (in EPLF).
 */
void
interp_list (char *filename)
{
  FILE *in;
#ifdef EPLF
  time_t diffgmt;		/* number of seconds from local time to gmt */
  int eplf = 0;
#else
  int c;
  char buf[512];
#endif

  if ((in = Lfopen (filename, "r")) == NULL)
    {
      printf ("Couldn't open %s for reading\n", filename);
      return;
    }
#ifdef EPLF
  diffgmt = dgmt ();
  while (fgets (acinput, sizeof (acinput) - 1, in))
    {
      if (0 == eplf_readable (acinput, diffgmt))
	printf ("%s\n", acinput);
      else
	eplf = 1;
    }
  if (eplf)
    printf ("Times are converted to local time.\n");
#else
  while ((c = fread (buf, 1, sizeof (buf), in)))
    fwrite (buf, 1, c, stdout);
#endif
  Lfclose (in);
}				/* interp_list() */


/* cmdlist -
 *     Issue the LIST command and process the result.
 *
 *     Returns 0 on success, -1 on error.
 */
int
cmdlist (int argc, char *argv[])
{
  int bucket;			/* recvrequest returns an int.  I don't care
				 * about it here.  Trash it. */
  char tmpname[SCPS_L_tmpnam];

  if (NULL == Ltmpnam (tmpname))
    {
      printf ("Couldn't create a temporary name\n");
      return 0;
    }
  if (argc == 2)
    recvrequest ("LIST", tmpname, argv[1], "w", 0, &bucket);
  else
    recvrequest ("LIST", tmpname, "*", "w", 0, &bucket);
  interp_list (tmpname);
  remove (tmpname);
  return 0;
}				/* cmdlist() */


/*
 * `Another' gets another argument, and stores the new argc and argv.
 *
 * Returns false if no new arguments have been added.
 * Returns -1 on error.
 */
int
another (int *pargc, char ***pargv, char *prompt)
{
  int len = strlen (cmdline), ret;

  if (len >= sizeof (cmdline) - 3)
    {
      printf ("sorry, arguments too long\n");
      return (-1);
    }
  printf ("(%s) ", prompt);
  cmdline[len++] = ' ';
  if (fgets (&cmdline[len], sizeof (cmdline) - len, stdin) == NULL)
    return (-1);
  len += strlen (&cmdline[len]);
  if (len > 0 && cmdline[len - 1] == '\n')
    cmdline[len - 1] = '\0';
  makemargv (cmdline);
  ret = margc > *pargc;
  *pargc = margc;
  *pargv = margv;
  return (ret);
}

#if defined(SUNOS)
/* gpass
 *    get password
 */
char *
gpass (char *str)
{
  static char passwd[80];
  char *w;

  printf (str);
  fflush (stdout);
  Ltoggleecho ();
  Ltoggledelay ();
  gets (passwd);
  Ltoggleecho ();
  Ltoggledelay ();
  return (passwd);
}				/* gpass() */
#endif

#if defined(__BSD__)
/* gpass
 *    get password
 */
char *
gpass (char *str)
{
  extern char *nb_gets (char *str);
  extern int connected;
  static char passwd[80];
  int oldconnected = connected;
  char *w;

  printf (str);
  fflush (stdout);
  Ltoggleecho ();
  connected = 0;		/* don't check the ctrl conn. */
  nb_gets (passwd);
  Ltoggleecho ();
  connected = oldconnected;
  return (passwd);
}				/* gpass() */
#endif

/* cmduser -
 *
 *    Returns 0 on success, -1 on error.
 */
int
cmduser (int argc, char *argv[])
{
  char acct[80];
  int n, aflag = 0;

  if (argc < 2)
    if (0 > another (&argc, &argv, "username"))
      return (-1);
  if (argc < 2 || argc > 4)
    {
      printf ("usage: %s username [password] [account]\n", argv[0]);
      code = -1;
      return (-1);
    }
  nsprintf (msgbuf, sizeof (msgbuf), "USER %s", argv[1]);
  n = sendcommand (msgbuf);
  if (n == CONTINUE)
    {
      if (argc < 3)
#if defined(SUNOS) || defined(__BSD__)
	argv[2] = gpass ("Password: "), argc++;
#else
	argv[2] = getpass ("Password: "), argc++;
#endif
      nsprintf (msgbuf, sizeof (msgbuf), "PASS %s", argv[2]);
      n = sendcommand (msgbuf);
      memset (argv[2], 0, strlen (argv[2]));
    }
  if (n == CONTINUE)
    {
      if (argc < 4)
	{
	  printf ("Account: ");
	  (void) fflush (stdout);
	  (void) fgets (acct, sizeof (acct) - 1, stdin);
	  acct[strlen (acct) - 1] = '\0';
	  argv[3] = acct;
	  argc++;
	}
      nsprintf (msgbuf, sizeof (msgbuf), "ACCT %s", argv[3]);
      n = sendcommand (msgbuf);
      aflag++;
    }
  if (n != COMPLETE)
    {
      fprintf (stdout, "Login failed.\n");
      return (-1);
    }
  if (!aflag && argc == 4)
    {
      nsprintf (msgbuf, sizeof (msgbuf), "ACCT %s", argv[3]);
      (void) sendcommand (msgbuf);
    }
  return 0;
}				/* cmduser() */


/* cmdlcd -
 *     Change local current working directory.
 *     Returns 0 on success, -1 on error.
 */
int
cmdlcd (int argc, char *argv[])
{
  char dirbuf[256];

  if (argc == 1)
    argv[1] = ".";
  if (argc > 2)
    {
      nsprintf (msgbuf, sizeof (msgbuf), "usage: %s directory-spec\n", argv[0]);
      Lstrout (msgbuf);
      code = -1;
      return (0);
    }
  if (0 > chdir (argv[1]))
    {
      nsprintf (msgbuf, sizeof (msgbuf), "Could not change to '%s'\n", argv[1]);
      Lstrout (msgbuf);
      code = -1;
      return (0);
    }
  else
    {
      getcwd (dirbuf, sizeof (dirbuf));
      nsprintf (msgbuf, sizeof (msgbuf), "Local directory is now '%s'\n", dirbuf);
      Lstrout (msgbuf);
      code = 0;
      return (0);
    }
}				/* cmdlcd() */


/* cmdcd -
 *     Change remote current working directory.
 *     Returns 0 on success, -1 on error.
 */
int
cmdcd (int argc, char *argv[])
{
  if (argc == 1)
    argv[1] = ".";
  if (argc > 2)
    {
      nsprintf (msgbuf, sizeof (msgbuf), "usage: %s directory-spec\n", argv[0]);
      Lstrout (msgbuf);
      code = -1;
      return (0);
    }
  nsprintf (msgbuf, sizeof (msgbuf), "CWD %s", argv[1]);
  return (COMPLETE == sendcommand (msgbuf) ? 0 : -1);
}				/* cmdcd() */


/* cmdta -
 *     Set type to ASCII.
 */
int
cmdta (int argc, char *argv[])
{
  type = TYPE_A;
  return (COMPLETE == sendcommand ("TYPE A") ? 0 : -1);
}				/* cmdta() */


/* cmdti -
 *     Set type to IMAGE.
 */
int
cmdti (int argc, char *argv[])
{
  type = TYPE_I;
  return (COMPLETE == sendcommand ("TYPE I") ? 0 : -1);
}				/* cmdti() */


/* cmdrename -
 *     Rename a remote file.
 */
int
cmdrename (int argc, char *argv[])
{
  char buf[80];

  if (argc < 2 && !another (&argc, &argv, "from-name"))
    goto usage;
  if (argc < 3 && !another (&argc, &argv, "to-name"))
    {
    usage:
      printf ("%s from-name to-name\n", argv[0]);
      code = -1;
      return 0;
    }
  nsprintf (buf, sizeof (buf), "RNFR %s", argv[1]);
  if (sendcommand (buf) == CONTINUE)
    {
      nsprintf (buf, sizeof (buf), "RNTO %s", argv[2]);
      return (COMPLETE == sendcommand (buf) ? 0 : -1);
    }
  else
    return -1;
}				/* cmdrename() */


/* cmdbets -
 *     Toggle bets mode.
 */
int
cmdbets (int argc, char *argv[])
{
  bets ^= 1;
  if (bets)
    {
      if (COMPLETE != sendcommand ("BETS"))
	return -1;
      printf ("Best Effort Transport Service enabled.\n");
    }
  else
    {
      if (COMPLETE != sendcommand ("NBES"))
	return -1;
      printf ("Best Effort Transport Service disabled.\n");
    }
  return 0;
}				/* cmdbets() */


/* cmdcdup -
 *     change to parent directory.
 */
int
cmdcdup (int argc, char *argv[])
{
  return (COMPLETE == sendcommand ("CDUP") ? 0 : -1);
}				/* cmdcdup() */


/* cmdcp -
 *     Execute a remote file copy.
 */
int
cmdcp (int argc, char *argv[])
{
  char buf[80];

  if (argc < 2 && !another (&argc, &argv, "from-name"))
    goto usage;
  if (argc < 3 && !another (&argc, &argv, "to-name"))
    {
    usage:
      printf ("%s from-name to-name\n", argv[0]);
      code = -1;
      return 0;
    }
  nsprintf (buf, sizeof (buf), "COPY %s %s", argv[1], argv[2]);
  return (COMPLETE == sendcommand (buf) ? 0 : -1);
}				/* cmdcp() */


/* cmdmkdir -
 *     Make a remote directory.
 */
int
cmdmkdir (int argc, char *argv[])
{
  char buf[256];

  if (argc < 2 && !another (&argc, &argv, "directory-name"))
    {
      printf ("usage: %s directory-name\n", argv[0]);
      code = -1;
      return 0;
    }
  nsprintf (buf, sizeof (buf), "MKD %s", argv[1]);
  return (COMPLETE == sendcommand (buf) ? 0 : -1);
}				/* cmdmkdir() */


/* cmdrmdir -
 *     Remove a directory
 */
int
cmdrmdir (int argc, char *argv[])
{
  char buf[256];

  if (argc < 2 && !another (&argc, &argv, "directory-name"))
    {
      printf ("usage: %s directory-name\n", argv[0]);
      code = -1;
      return 0;
    }
  nsprintf (buf, sizeof (buf), "RMD %s", argv[1]);
  return (COMPLETE == sendcommand (buf) ? 0 : -1);
}				/* cmdrmdir() */


/* cmdpwd -
 *     Print current working directory
 */
int
cmdpwd (int argc, char *argv[])
{
  return (COMPLETE == sendcommand ("PWD") ? 0 : -1);
}				/* cmdpwd() */


/* cmdrstat -
 *
 */
int
cmdrstat (int argc, char *argv[])
{
  return (COMPLETE == sendcommand ("STAT") ? 0 : -1);
}				/* cmdrstat() */


/* cmdsystem -
 *     Report remote system type.
 */
int
cmdsystem (int argc, char *argv[])
{
  return (COMPLETE == sendcommand ("SYST") ? 0 : -1);
}				/* cmdsystem() */


char lshelp[] = "list contents of remote directory 'ls [file(s)_spec]'";
char userhelp[] = "log in to server 'user username [password]'";
char lcdhelp[] = "change local current working dir 'lcd directory_spec'";
char cdhelp[] = "change remote current working dir 'cd directory_spec'";
char tahelp[] = "set transfer type to ascii";
char tihelp[] = "set transfer type to binary";
char renhelp[] = "rename a remote file 'ren from-name to-name'";
char betshelp[] = "toggle bets mode";
char cduphelp[] = "change to parent directory";
char cphelp[] = "duplicate a remote file";
char mkdirhelp[] = "make a directory";
char rmdirhelp[] = "remove a directory";
char pwdhelp[] = "print current working directory";
char rstathelp[] = "show remote status";
char systhelp[] = "show remote system type";

/*  c_name, c_help, c_conn, c_proxy, c_func */
static struct cmd bcmdtab[] =
{
  {"ls", lshelp, 1, 1, cmdlist},
  {"user", userhelp, 1, 1, cmduser},
  {"lcd", lcdhelp, 0, 0, cmdlcd},
  {"cd", cdhelp, 1, 1, cmdcd},
  {"ascii", tahelp, 1, 1, cmdta},
  {"binary", tihelp, 1, 1, cmdti},
  {"image", tihelp, 1, 1, cmdti},
  {"rename", renhelp, 1, 1, cmdrename},
  {"bets", betshelp, 1, 1, cmdbets},
  {"cdup", cduphelp, 1, 1, cmdcdup},
  {"cp", cphelp, 1, 1, cmdcp},
  {"mkdir", mkdirhelp, 1, 1, cmdmkdir},
  {"rmdir", rmdirhelp, 1, 1, cmdrmdir},
  {"pwd", pwdhelp, 1, 1, cmdpwd},
  {"rstatus", rstathelp, 1, 1, cmdrstat},
  {"system", systhelp, 1, 1, cmdsystem},
  {0}
};


/* cmdcb_initialize -
 */
void
cmdcb_initialize (void)
{
  cmdtabb = bcmdtab;
}				/* cmdcb_initialize() */
