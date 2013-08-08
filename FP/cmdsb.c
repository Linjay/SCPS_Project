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

/******************************************************************** 
 *  Created by      :                                               * 
 *                     Steven R. Sides                              * 
 *                     steven.r.sides@cpmx.saic.com                 * 
 *                     Friday, April 18, 1997 4:30 pm               * 
 *                                                                  * 
 *  Modified by     :                                               * 
 *                                                                  * 
 ******************************************************************** 
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
 * Module:             cmdsb.c                                      *
 *                                                                  * 
 * Description:                                                     * 
 *    Server commands, set B.  These commands are used in the SCPS  * 
 *    full implementation.                                          * 
 *
 * $Id: cmdsb.c,v 1.11 2002/09/23 19:52:14 scps Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/cmdsb.c,v 1.11 2002/09/23 19:52:14 scps Exp $
 * 
 *    Change History:
 * $Log: cmdsb.c,v $
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
 * Revision 1.10  2001/01/09 20:43:54  scps
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
 * Revision 1.9  2000/10/23 14:02:36  scps
 * Cleaned to the FP directory so it would compile cleanly  -- PDF
 *
 * Revision 1.8  1999/11/22 15:52:42  scps
 * Changed FP discaimers to read as follows:
 *
 * Revision 1.7  1999/03/23 20:24:34  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.6.2.2  1999/01/22 15:02:30  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:28  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:36  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.5  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.4  1997/09/05 13:35:13  steven
 * Grammatically correct copyright notice.
 * Proxy put, get, list.
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
static char rcsid[] = "$Id: cmdsb.c,v 1.11 2002/09/23 19:52:14 scps Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef MSVC
#include <winsock.h>
#include <wincrypt.h>
#undef ERROR
#include "ftp.h"
#else
#define NBBY 8			/* bits per byte--used in cmdsyst */
#include <unistd.h>
#include <pwd.h>
#include <sys/socket.h>
#define FTP_NAMES
#include <arpa/ftp.h>		/* contains symbolic constants only */
#include <time.h>
#include <string.h>
#ifndef SUNOS
#include <glob.h>
#endif
#include <netinet/in.h>		/* for sockaddr_in */
#include <netdb.h>
#endif
#include "libs.h"
#include "tpif.h"
#ifndef SMALL
#include "rp.h"
#endif

#ifdef SUNOS
#include <dirent.h>
char *typenames[] =
{"0", "ASCII", "EBCDIC", "Image", "Local"};
char *formnames[] =
{"0", "Nonprint", "Telnet", "Carriage-control"};
char *strunames[] =
{"0", "File", "Record", "Page"};
char *modenames[] =
{"0", "Stream", "Block", "Compressed"};
#endif

extern short bets;		/* true if running in BETS mode. */
extern struct cmd *cmdtabb;
extern short logged_in;
extern int sctrl;
extern int flags;
extern short type;		/* i.e. TYPE_A or TYPE_I  */

int recvrequest (char *, char *, char *, char *, int, int *);
int cmdretr (int argc, char *argv[]);
int reply (int, char *, int);
int select_rd (int instr, char *buf, int size, int *cnt);
int rcvdata_avail (int fd);
int Lstrout (char *str);
void crcblock (char *buf, u_long len, u_long * iocrc);

char username[16];
char password[80];
#ifndef MSVC
uid_t uid;
gid_t gid;
#endif
char userdir[80];

char acinput[ACBUFSIZE + 1];	/* Buffers for ASCII data type.  */
char acoutput[ACBUFSIZE + 1];
char fromname[MAXPATHLEN];
char *onoffnames[] =
{"Disabled", "Enabled"};

#ifdef MSVC
struct passwd
  {
    char *pw_name;		/* Username.  */
    char *pw_passwd;		/* Password.  */
    short pw_uid;		/* User ID.  */
    short pw_gid;		/* Group ID.  */
    char *pw_gecos;		/* Real name.  */
    char *pw_dir;		/* Home directory.  */
    char *pw_shell;		/* Shell program.  */
  };
#endif

/* asciicopytofs - Efficient copy from instream to file system.
 *                 Converts to the appropriate line termination sequence.
 *   Returns
 *      0 - all OK
 *      1 - file error
 *      2 - received INTR
 *      3 - received ABOR
 *
 *   Also writes the 
 */
int
asciicopytofs (int ins, FILE * outfile, u_long * bytecount, u_long * crcval)
{
  int incnt;
  int outcnt;
  int i, o;
  int mon;


  *bytecount = 0;
  if (crcval)
    *crcval = 0;
  o = 0;
  for (;;)
    {
      mon = select_rd (ins, acinput, ACBUFSIZE, &incnt);

      switch (mon)
	{
	case 0:		/* no error */
	  if (incnt)
	    {
	      for (i = 0; i < incnt; i++)
		{
		  (*bytecount)++;
		  /* In UNIX, remove all <CR> characters. */
		  if (acinput[i] != '\r')
		    {
		      acoutput[o++] = acinput[i];
		      if (o == ACBUFSIZE)
			{
			  if (crcval)
			    crcblock (acoutput, ACBUFSIZE, crcval);
			  outcnt = fwrite (acoutput, 1, ACBUFSIZE, outfile);
			  if (outcnt != ACBUFSIZE)
			    {
			      return 1;
			    }
			  o = 0;
			}	/* output buffer full */
		    }		/* found <CR> */
		}		/* for */
	    }
	  else
	    goto read_done;
	  break;

	case 1:		/* error */
	  goto read_done;

	case 2:		/* INTR */
	  goto xfer_intr;

	case 3:		/* ABOR */
	  goto xfer_abor;
	}			/* switch */
    }				/* for */

read_done:
  if (o)
    {
      if (crcval)
	crcblock (acoutput, o, crcval);
      outcnt = fwrite (acoutput, 1, o, outfile);
      return (o != outcnt);
    }
  else
    return 0;

xfer_intr:
  return 2;

xfer_abor:
  return 3;

}				/* end asciicopytofs() */


/* asciicopyfmfs - Efficient copy from file system to out stream.
 *                 Converts (if necessary) to the network line
 *                 termination sequence <CR><LF>.
 *    Returns
 *      0 - no error
 *      1 - file error
 *      2 - user interrupt
 *      3 - user abort
 *
 *   If crcval is non-NULL, this routine uses it to store the CRC of the
 *   bytes sent over the network.
 */
int
asciicopyfmfs (FILE * infile, int outs, u_long * bytecount, u_long * crcval)
{
  int incnt;
  int outcnt;
  int i, o;


  if (crcval)
    *crcval = 0;
  *bytecount = 0;
  o = 0;
  while ((incnt = fread (acinput, 1, ACBUFSIZE, infile)) != 0)
    {
      if (incnt < 0)
	goto data_error;
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
	      /* data_error is not really the proper place
	         * to go here, but its the most direct path
	         * to getline() which will die of loss of
	         * ctrl conn.  */
	      goto data_error;
	    }
	}			/* if */
      for (i = 0; i < incnt; i++)
	{
	  (*bytecount)++;
	  if (acinput[i] == '\n')
	    {
	      acoutput[o++] = '\r';
	      if (o == ACBUFSIZE)
		{
		  if (crcval)
		    crcblock (acoutput, ACBUFSIZE, crcval);
		  outcnt = scps_send (outs, acoutput, ACBUFSIZE, 0);
		  if (outcnt != ACBUFSIZE)
		    {
		      return 1;
		    }
		  o = 0;
		}		/* output buffer full */
	    }			/* found <LF> */
	  acoutput[o++] = acinput[i];
	  if (o == ACBUFSIZE)
	    {
	      if (crcval)
		crcblock (acoutput, ACBUFSIZE, crcval);
	      outcnt = scps_send (outs, acoutput, ACBUFSIZE, 0);
	      if (outcnt != ACBUFSIZE)
		{
		  return 1;
		}
	      o = 0;
	    }			/* output buffer full */
	}			/* for */
    }				/* while */
  if (o)
    {
      if (crcval)
	crcblock (acoutput, o, crcval);
      outcnt = scps_send (outs, acoutput, o, 0);
    }
  if (crcval)
    *crcval ^= 0xffffffff;
  return 0;

user_abort:
  return 3;
user_interrupt:
  return 2;
data_error:
  return 1;
}				/* end asciicopyfmfs() */


/* creply -
 *     Issue a reply after which 1 or more lines follow.
 */
int
creply (code, text)
     int code;
     char *text;
{
  char replybuf[82];
  int wrres;

  nsprintfds (replybuf, sizeof (replybuf), "%d-%s\r\n", code, text);
  wrres = scps_send (sctrl, replybuf, Lstrlen (replybuf), flags);
  if (wrres < 0)
    return -1;
  else
    return 0;
}				/* creply() */


/* genlist -
 *     Generate a directory listing.
 *
 *     Returns 0 on success,
 *             1 on failure.
 */
int
genlist (pattern, filename)
     char *pattern, *filename;
{
  extern int frpn (char *name, u_long * restart_point);
  FILE *fout;
#ifdef SUNOS
#define NAME  de->d_name
  DIR *dir;
  struct dirent *de;
  char cwd[MAXPATHLEN];
#else
#define NAME  g.gl_pathv[i]
  glob_t g;
#endif
  int i;
  struct tm *t;
  time_t fmt;			/* file modification time. */
  struct stat s;
  int ret;
#ifdef EPLF
  int next;
  char buffer[80];
#else
  char attribs[11];
  char timestr[13];
  int yr;
#endif

  fout = Lfopen (filename, "w");
  if (fout == NULL)
    return 1;
  ret = 0;
#ifdef SUNOS
  if (NULL == getcwd (cwd, sizeof (cwd)))
    {
      Lfclose (fout);
      return 1;
    }
  if (NULL == (dir = opendir (".")))
    {
      Lfclose (fout);
      return 1;
    }
  fprintf (fout, "CWD:%s:\n", cwd);
#endif
#ifndef EPLF
  fmt = time (NULL);
  t = localtime (&fmt);
  yr = t->tm_year;
#endif
#ifdef SUNOS
  while ((de = readdir (dir)))
    {
      if (0 == Lstat (NAME, &s))
	{
#else
  if (0 == glob (pattern, 0, NULL, &g))
    {
      for (i = 0; g.gl_pathc; g.gl_pathc--, i++)
	{
	  if (0 == Lstat (NAME, &s))
	    {
#endif
#ifdef EPLF
	      t = gmtime (&(s.st_mtime));
	      fmt = mktime (t);
	      next = nsprintfds (buffer, sizeof (buffer), "+", 0, NULL);
	      if (S_ISREG (s.st_mode))
		{
		  next += nsprintfds (buffer + next, sizeof (buffer) - next,
				      "r,", 0, NULL);
		  if (type == TYPE_A)
		    frpn (g.gl_pathv[i], &s.st_size);
		}
	      if (S_ISDIR (s.st_mode))
		next += nsprintfds (buffer + next, sizeof (buffer) - next,
				    "/,", 0, NULL);
	      next += nsprintfds (buffer + next, sizeof (buffer) - next,
				  "s%d,", s.st_size, NULL);
	      next += nsprintfds (buffer + next, sizeof (buffer) - next,
				  "m%d,", fmt, NULL);
	      if (type == TYPE_A)
		/* send_data() will add the \r */
		next += nsprintfds (buffer + next, sizeof (buffer) - next,
				    "\t%s\n", 0, g.gl_pathv[i]);
	      else
		next += nsprintfds (buffer + next, sizeof (buffer) - next,
				    "\t%s\r\n", 0, g.gl_pathv[i]);
	      fwrite (buffer, 1, Lstrlen (buffer), fout);
#else
	      strcpy (attribs, "----------");
	      if (S_ISDIR (s.st_mode))
		attribs[0] = 'd';
	      if (S_IRUSR & s.st_mode)
		attribs[1] = 'r';
	      if (S_IWUSR & s.st_mode)
		attribs[2] = 'w';
	      if (S_IXUSR & s.st_mode)
		attribs[3] = 'x';
	      if (S_IRGRP & s.st_mode)
		attribs[4] = 'r';
	      if (S_IWGRP & s.st_mode)
		attribs[5] = 'w';
	      if (S_IXGRP & s.st_mode)
		attribs[6] = 'x';
	      if (S_IROTH & s.st_mode)
		attribs[7] = 'r';
	      if (S_IWOTH & s.st_mode)
		attribs[8] = 'w';
	      if (S_IXOTH & s.st_mode)
		attribs[9] = 'x';
	      t = localtime (&(s.st_mtime));
	      if (t->tm_year == yr)
		strftime (timestr, sizeof (timestr), "%b %d %H:%M", t);
	      else
		strftime (timestr, sizeof (timestr), "%b %d  %Y", t);

	      if (type == TYPE_A)
		fprintf (fout, "%s  1 %5d %5d %8d %s %s\r\n", attribs, (int)
			 s.st_uid, (int) s.st_gid, (int) s.st_size, timestr, NAME);
	      else
		fprintf (fout, "%s  1 %5d %5d %8d %s %s\n", attribs, (int)
			 s.st_uid, (int) s.st_gid, (int) s.st_size, timestr, NAME);
#endif
#ifdef SUNOS
	    }			/* if */
	}			/* while */
      closedir (dir);
#else
	    }
	}
      globfree (&g);
    }
  else
    ret = 1;
#endif
  Lfclose (fout);
  return ret;
}				/* genlist() */


/* cmdlist -
 *    Respond to the LIST command.
 *
 *    Returns -1 on failure of control connection.
 *    Returns 0 otherwise.
 */
int
cmdlist (argc, argv)
     int argc;
     char *argv[];
{
  int result;
  int sargc;
  char *sargv[2];
  char tmpname[SCPS_L_tmpnam];

  if (NULL == Ltmpnam (tmpname))
    return (reply (451, "Couldn't create a temporary name.", 0));

  if (argc == 2)
    genlist (argv[1], tmpname);
  else
    genlist ("*", tmpname);
  sargv[0] = argv[0];
  sargv[1] = tmpname;
  sargc = 2;
  result = cmdretr (sargc, sargv);
  remove (tmpname);
  return result;
}				/* cmdlist() */

#ifdef MSVC
/*  getpwnam -
 *     Get password
 */
struct passwd *
getpwnam (char *name)
{
  static struct passwd p;
  return &p;
}				/* getpwnam() */


/*  sgetpwnam -
 * Save the result of a getpwnam.  Used for USER command, since
 * the data returned must not be clobbered by any other command
 * (e.g., globbing).
 * Returns 0 for error,
 *         1 for user OK.
 */
int
sgetpwnam (char *name)
{
  return 0;
}				/* sgetpwnam() */

#else

/*
 * Save the result of a getpwnam.  Used for USER command, since
 * the data returned must not be clobbered by any other command
 * (e.g., globbing).
 * Returns 0 for error,
 *         1 for user OK.
 */
int
sgetpwnam (name)
     char *name;
{
  struct passwd *p;
  int len;

  if ((p = getpwnam (name)) == NULL)
    return 0;

  if ((len = Lstrlen (p->pw_name)) < (sizeof (username) - 1))
    Lstrncpy (username, p->pw_name, len + 1);
  else
    return 0;
  if ((len = Lstrlen (p->pw_passwd)) < (sizeof (password) - 1))
    Lstrncpy (password, p->pw_passwd, len + 1);
  else
    return 0;
  if ((len = Lstrlen (p->pw_dir)) < (sizeof (userdir) - 1))
    Lstrncpy (userdir, p->pw_dir, len + 1);
  else
    return 0;
  uid = p->pw_uid;
  gid = p->pw_gid;
  return (1);
}				/* sgetpwnam() */

#endif

/* cmduser -
 *     
 */
int
cmduser (argc, argv)
     int argc;
     char *argv[];
{
  if (argc == 2)
    {
      logged_in = 0;
      if (0 == sgetpwnam (argv[1]))
	{
	  return (reply (530, "No such user.", 1));
	}
      return (reply (331, "Need password.", 1));
    }
  else
    return (reply (501, "Only one argument allowed.", 1));
}				/* cmduser() */

#ifdef MSVC
/*  crypt -
 *     Encrypt a string (such as a password).
 */
char *
crypt (const char *key, const char *salt)
{
  static char xret[10];
  static char xor[] = "BADBADBADBADBAD";
  char *c, *d;

  for (c = xor, d = xret; *key; key++, c++, d++)
    *d = *key ^ *c;
  *d = '\0';
  return xret;
}				/* crypt() */

#endif

#ifdef SUNOS
char *crypt (const char *key, const char *salt);
#endif

/* cmdpass -
 *     
 */
int
cmdpass (argc, argv)
     int argc;
     char *argv[];
{
  char homedir[MAXPATHLEN];
  char *xpasswd;
  int len;

  if (argc == 2)
    {
      if (logged_in != 0)
	return (reply (503, "Already logged in.", 0));
#ifndef __BSD__
      xpasswd = crypt (argv[1], password);
      len = Lstrlen (password);
      if (*password == '\0' || Lstrncmp (xpasswd, password, len))
	return (reply (530, "Login incorrect.", 1));
#endif
      if (chdir (userdir) < 0)
	return (reply (550, "Can't change to home directory.", 1));
      /*
       * Set home directory so that use of ~ (tilde) works correctly.
       */
#if !defined(SUNOS) && !defined(__BSD__)
      if (getcwd (homedir, MAXPATHLEN) != NULL)
	setenv ("HOME", homedir, 1);
#endif
      if (setegid (gid) < 0)
	return (reply (550, "Can't set gid.", 1));
      if (seteuid (uid) < 0)
	return (reply (550, "Can't set uid.", 1));
      logged_in = 1;
      return (reply (230, "Login OK.", 1));
    }
  else
    return (reply (501, "Only one argument allowed.", 1));
}				/* cmdpass() */


/* cmdcwd -
 *     Change current working directory.
 * Returns 0 for error,
 *         1 for OK.
 */
int
cmdcwd (argc, argv)
     int argc;
     char *argv[];
{
  char dirbuf[80];
  char replybuf[80];

  if (argc == 1 || argc > 2)
    return (reply (501, "Only one argument allowed.", 0));
  if (0 > chdir (argv[1]))
    return (reply (550, "Directory not found.", 0));
  getcwd (dirbuf, sizeof (dirbuf));
  nsprintfds (replybuf, sizeof (replybuf), "OK. CWD:%s", 0, dirbuf);
  return (reply (250, replybuf, 0));
}				/* cmdcwd() */


/* cmdtype -
 *     Set the data transfer type.
 * Returns 0 for failure of ctrl conn,
 *         1 for OK.
 */
int
cmdtype (argc, argv)
     int argc;
     char *argv[];
{
  char replybuf[80];

  if (argc == 1 || argc > 2)
    return (reply (501, "Only one argument allowed.", 0));
  if (0 == Lstrcmp ("A", argv[1]))
    {
      type = TYPE_A;
      return (reply (200, "ASCII", 0));
    }
  else if (0 == Lstrcmp ("I", argv[1]))
    {
      type = TYPE_I;
      return (reply (200, "BINARY", 0));
    }
  else
    {
      nsprintfds (replybuf, sizeof (replybuf), "%s in invalid", 0, argv[1]);
      return (reply (501, replybuf, 0));
    }
}				/* cmdtype() */


/* cmdrnfr -
 *     Rename from.
 */
int
cmdrnfr (argc, argv)
     int argc;
     char *argv[];
{
  struct stat st;

  if (Lstat (argv[1], &st) < 0)
    {
      return (reply (550, argv[1], 0));
    }
  /* An implementation might use an Access Control List file
   * that contains filenames that cannot be renamed.  Calls
   * to check that list would be inserted here.  */
  Lstrncpy (fromname, argv[1], MAXPATHLEN);
  return (reply (350, "Ready for destination name", 0));
}				/* cmdrnfr() */


/* cmdrnto -
 *     Rename to.
 */
int
cmdrnto (argc, argv)
     int argc;
     char *argv[];
{
  /* If an implementation uses an Access Control List file,
   * it would check the destination name here.  The SCPS
   * stack has a security layer so it might not want that
   * extra weight.  The people running the client/server
   * have probably thought carefully about which files they are
   * renaming and why they are doing it. */
  if (rename (fromname, argv[1]) < 0)
    return (reply (550, argv[1], 0));
  else
    return (reply (250, "RNTO OK", 0));
}				/* cmdrnto() */


/* cmdbets -
 *     Enable Best Effort Transport Service
 */
int
cmdbets (argc, argv)
     int argc;
     char *argv[];
{
  bets = 1;
  return (reply (250, "BETS OK", 0));
}				/* cmdbets() */


/* cmdnbes -
 *     Disable Best Effort Transport Service
 */
int
cmdnbes (argc, argv)
     int argc;
     char *argv[];
{
  bets = 0;
  return (reply (250, "NBES OK", 0));
}				/* cmdnbes() */


/* cmdcdup -
 *     Change to parent directory
 */
int
cmdcdup (argc, argv)
     int argc;
     char *argv[];
{
  char buf[80];
  char dirbuf[80];

  if (0 > chdir (".."))
    return (reply (550, "chdir(\"..\") failed.", 0));
  getcwd (dirbuf, sizeof (dirbuf));
  nsprintfds (buf, sizeof (buf), "OK. CWD:%s", 0, dirbuf);
  return (reply (200, buf, 0));
}				/* cmdcdup() */


/* cmdcopy -
 *     Copy a file.
 */
int
cmdcopy (argc, argv)
     int argc;
     char *argv[];
{
  if (argc < 3)
    return (reply (501, "Requires two arguments.", 0));
  if (fcopy (argv[1], argv[2]))
    return (reply (550, "COPY failed.", 0));
  else
    return (reply (250, "COPY OK.", 0));
}				/* cmdcopy() */


/* cmdmkd -
 *     Make a directory.
 */
int
cmdmkd (argc, argv)
     int argc;
     char *argv[];
{
  char buf[MAXPATHLEN];

  /*
   *    uid_t uid;
   *    gid_t gid;
   *    int   valid = 0;
   */

  /*
   * check the directory, can we mkdir here?
   *  if ( (dir_check(name, &uid, &gid, &valid)) <= 0 )
   *      return;
   */

  /*
   * check the filename, is it legal?
   *  if ( (fn_check(name)) <= 0 )
   *      return;
   */

  if (argc < 2)
    return (reply (501, "No directory.", 0));
  if (mkdir (argv[1], 0777) < 0)
    {
      nsprintfds (buf, sizeof (buf), "Unable to create:'%s'", 0, argv[1]);
      return (reply (550, buf, 0));
    }

  return (reply (257, "MKD OK.", 0));
}				/* cmdmkd() */


/* cmdpwd -
 *     Print working directory
 */
int
cmdpwd (argc, argv)
     int argc;
     char *argv[];
{
  char dir[MAXPATHLEN];
  char buf[MAXPATHLEN + 10];

  if (getcwd (dir, sizeof (dir)) != NULL)
    {
      nsprintfds (buf, sizeof (buf), "\"%s\"", 0, dir);
      return (reply (257, buf, 0));
    }
  else
    return (reply (550, "PWD: Error", 0));
}				/* cmdpwd() */


/* cmdrmd -
 *     Remove a directory
 */
int
cmdrmd (argc, argv)
     int argc;
     char *argv[];
{
  /*
   *  int c, d;
   *  int valid = 0;
   */

  /*
   * check the directory, can we rmdir here?
   *  if ( (dir_check(name, &c, &d, &valid)) <= 0 )
   *      return;
   */

  /*
   * delete permission?
   *  if ( (del_check(name)) == 0 )
   *      return;
   */

  if (argc < 2)
    return (reply (501, "No directory.", 0));
  if (rmdir (argv[1]) < 0)
    return (reply (550, "RMD: Error", 0));
  else
    return (reply (250, "RMD OK.", 0));
}				/* cmdrmd() */


/* cmdstat -
 *     Report the status.
 */
int
cmdstat (argc, argv)
     int argc;
     char *argv[];
{
  extern char *versionstr (char *namestr, char *outstr);
  extern struct sockaddr_in hisaddr;
  extern struct sockaddr_in data_addr;
  extern struct sockaddr_in pasv_addr;
  extern short guest;
  extern short form;
  extern short stru;
  extern short mode;
  extern short autorestart;
  extern short usedefault;
  extern char *builddate;
  extern char *buildtime;
  extern int sdata;
  extern int pdata;
  char buf[80];
  char namestr[80];
  struct sockaddr_in *sin;
  struct hostent *hp;
  u_char *a, *p, *d;

  d = namestr;
  if (0 == gethostname (namestr, sizeof (namestr)))
    {
      d += nsprintfds (d, 40, "%s ", 0, namestr);
    }
  nsprintfds (d, 40, "SCPS-FP server status:", 0, NULL);
  creply (211, namestr);
  versionstr ("$Name:  $", namestr);
  nsprintfds (buf, sizeof (buf), "Version %s", 0, namestr);
  creply (211, buf);
  d = buf;
  d += nsprintfds (d, 40, "Build date:%s  ", 0, builddate);
  nsprintfds (d, 40, "%s", 0, buildtime);
  creply (211, buf);
  hp = gethostbyaddr ((char *) &(hisaddr.sin_addr), sizeof
		      (hisaddr.sin_addr), AF_INET);
  if (hp)
    {
      Lstrncpy (namestr, hp->h_name, sizeof (namestr));
      nsprintfds (buf, sizeof (buf), "Connected to %s", 0, namestr);
      creply (211, buf);
    }
  if (guest)
    nsprintfds (buf, sizeof (buf), "Logged in anonymously", 0, NULL);
  else
    nsprintfds (buf, sizeof (buf), "Logged in as %s", 0, username);
  creply (211, buf);

  d = buf;
  d += nsprintfds (d, 25, "TYPE:%s  ", 0, typenames[type]);
  if (type == TYPE_A || type == TYPE_E)
    {
      nsprintfds (d, 25, "FORM:%s", 0, formnames[form]);
      creply (211, buf);
    }
  else
    creply (211, buf);
  d = buf;
  d += nsprintfds (d, 25, "STRUcture:%s  ", 0, strunames[stru]);
  nsprintfds (d, 25, "MODE:%s", 0, modenames[mode]);
  creply (211, buf);
  if (sdata != -1)
    creply (211, "Data connection open");
  else if (pdata != -1)
    {
      creply (211, "in Passive mode");
      sin = &pasv_addr;
      goto printaddr;
    }
  else if (usedefault == 0)
    {
      creply (211, "PORT:");
      sin = &data_addr;
    printaddr:
      a = (u_char *) & sin->sin_addr;
      p = (u_char *) & sin->sin_port;
#define UC(b) (((int) b) & 0xff)
      d = namestr;
      d += nsprintfds (d, 10, "(%d,", UC (a[0]), NULL);
      d += nsprintfds (d, 10, "%d,", UC (a[1]), NULL);
      d += nsprintfds (d, 10, "%d,", UC (a[2]), NULL);
      d += nsprintfds (d, 10, "%d,", UC (a[3]), NULL);
      d += nsprintfds (d, 10, "%d,", UC (p[0]), NULL);
      d += nsprintfds (d, 10, "%d)", UC (p[1]), NULL);
#undef UC
      creply (211, namestr);
    }
  else
    creply (211, "No data connection");
  d = buf;
  d += nsprintfds (d, 20, "BETS: %s  ", 0, onoffnames[bets]);
  d += nsprintfds (d, 20, "ARST: %s  ", 0, onoffnames[autorestart]);
  creply (211, buf);
  return (reply (211, "End of status", 1));
}				/* cmdstat() */


/* cmdsyst -
 *     Report the system type.
 */
int
cmdsyst (argc, argv)
     int argc;
     char *argv[];
{
  char buf[80];
  char *p = buf;


#ifdef MSVC
  p += nsprintfds (p, 30, "UNIX Type: L%d", NBBY, 0);
#else
#ifdef SYSV
  p += nsprintfds (p, 30, "Sys V", 0, 0);
#else
#ifdef __BSD__
  p += nsprintfds (p, 30, "UNIX Type: L%d", NBBY, 0);
#else
#ifdef LINUX
  p += nsprintfds (p, 30, "LINUX Type: L%d", NBBY, 0);
#else
  nsprintfds (buf, sizeof (buf), "UNKNOWN", 0, 0);
#endif
#endif
#endif
#endif

  return (reply (215, buf, 1));
}				/* cmdsyst() */


/* Command table for the base implementation. */
static struct cmd bcmdtab[] =
{
  {"list", cmdlist},
  {"user", cmduser},
  {"pass", cmdpass},
  {"cwd", cmdcwd},
  {"rnfr", cmdrnfr},
  {"rnto", cmdrnto},
  {"bets", cmdbets},
  {"nbes", cmdnbes},
  {"cdup", cmdcdup},
  {"copy", cmdcopy},
  {"mkd", cmdmkd},
  {"nlst", cmdlist},
  {"pwd", cmdpwd},
  {"rmd", cmdrmd},
  {"stat", cmdstat},
  {"syst", cmdsyst},
  {0}
};


/* cmdsb_initialize -
 */
void
cmdsb_initialize (void)
{
  cmdtabb = bcmdtab;
}				/* cmdsb_initialize() */
