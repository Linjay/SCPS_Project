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
 *                     Monday, June 9, 1997 5:17 pm                 * 
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
 * Module:             cmdsc.c                                      * 
 *                                                                  * 
 * Description:                                                     * 
 *    Server commands, set C.  These commands are used in the FTP   * 
 *    RFC 1123 compatibility implementation.                        * 
 *
 * $Id: cmdsc.c,v 1.10 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/cmdsc.c,v 1.10 2007/04/19 15:09:36 feighery Exp $
 * 
 * Change History:
 * $Log: cmdsc.c,v $
 * Revision 1.10  2007/04/19 15:09:36  feighery
 * This version makes the gateway code (and only the gateway code) safe for
 * 64 bit architectures.  Before we were very sloppy and use a long and int
 * interchangeable.  As part of this change, it was required to make the
 * gateway code single threaded;  therefore gateway_single_thread=yes is the
 * default.  -- PDF
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
 * Revision 1.3  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.2  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 *
 * Revision 1.1  1997/06/16 14:09:30  steven
 * Initial revision
 *
      #include <dirent.h>

     DIR *opendir(dirname)
     char *dirname;

     struct dirent *readdir(dirp)
     DIR *dirp;

     int32_t telldir(dirp)
     DIR *dirp;

     void seekdir(dirp, loc)
     DIR *dirp;
     int32_t loc;

     void rewinddir(dirp)
     DIR *dirp;

     int closedir(dirp)
     DIR *dirp;

 * 
 */

static char rcsid[] = "$Id: cmdsc.c,v 1.10 2007/04/19 15:09:36 feighery Exp $";

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
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
#include <arpa/ftp.h>		/* contains symbolic constants only */
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <netinet/in.h>		/* for sockaddr_in */
#include <netdb.h>
#endif
#include "libs.h"
#include "tpif.h"
#ifndef SMALL
#include "rp.h"
#endif

extern struct cmd *cmdtaba;
extern struct cmd *cmdtabb;
extern struct cmd *cmdtabc;
extern struct cmd *cmdtabd;
extern int sdata;
extern int pdata;		/* passive data socket      */
extern struct sockaddr_in hisaddr;
extern struct sockaddr_in pasv_addr;
extern uid_t uid;
extern int sunique;

int reply (int, char *, int);
int creply (int code, char *text);
int dataconn (char *, uint32_t);
int receive_data (int, FILE *, int *, u_long *);
char *crcrtxt (uint32_t);


/* Lqsort -
 *    Calls qsort().
 */
int
Lqsort (base, nmemb, size, compar)
     void *base;
     size_t nmemb;
     size_t size;
     int (*compar) (const void *, const void *);
{
  qsort (base, nmemb, size, compar);
  return (0);
}				/* Lqsort() */


/* cmdacct -
 *     
 */
int
cmdacct (argc, argv)
     int argc;
     char *argv[];
{
  return (reply (202, "Superfluous at this site", 1));
}				/* cmdacct() */


/* cmdappe -
 *    Append to a file.
 *
 *    If the file exists:
 *       If ABOR during transfer
 *          restore the original file
 *
 *       If INTR or timeout during transfer
 *          keep the partial.
 *
 *    If the file does not exist:
 *       If ABOR during transfer
 *          delete the partial
 *
 *       If INTR or timeout during transfer
 *          keep the partial.
 *
 *    Returns -1 on failure of control connection.
 *    Returns 0 otherwise.
 */
int
cmdappe (argc, argv)
     int argc;
     char *argv[];
{
  FILE *fout;
  char *mode;
  int statres;
  struct stat st;
  int mon;			/* monitor the control connection */
  int ret;			/* return value */
  char tmpname[MAXPATHLEN];
  u_long crcval;


#ifdef DO_TIMING
  int32_t start_sec, start_usec, end_sec, end_usec;
  int32_t tmp_start_sec, tmp_start_usec, tmp_end_sec, tmp_end_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (argc != 2)
    /* Wrong number of arguments */
    return (reply (501, "Syntax error", 0));

  mode = "a";
  statres = Lstat (argv[1], &st);
  if (0 == statres)
    {
      /* The file exists.  Get a temporary name and rename it in 
       * case something dies. */
      if (NULL == Ltmpnam (tmpname))
	return (reply (451, "Couldn't create a temporary name.", 0));
      Lrename (argv[1], tmpname);
    }
  else
    return (reply (550, "File not found", 0));

  fout = Lfopen (argv[1], mode);
  if (fout == NULL)
    {
      return (reply (553, "Could not open with write access", 0));
    }
  /* dataconn() calls scps_connect() and replies 150 */
  sdata = dataconn (argv[1], (short) -1);
  if (sdata < 0)
    goto done;

  ret = receive_data (sdata, fout, &mon, &crcval);
  Lfclose (fout);
  fout = NULL;
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
}				/* cmdappe() */


/* str_cmp -
 *     To get rid of a warning.
 */
int
str_cmp (const void *s1, const void *s2)
{
  return (strcmp (s1, s2));
}				/* str_cmp() */


/* cmdhelp -
 *     
 */
int
cmdhelp (argc, argv)
     int argc;
     char *argv[];
{
  struct cmd *cmdpp[5];
  char buf[82];
  int j, l;
  int columns, width, ncmds;
  struct cmd *c;
  char *b;
  char *m, *mp;

  creply (214, "The following commands are recognized and implemented");
  bzero (cmdpp, sizeof (cmdpp));
  cmdpp[0] = cmdtaba;
  cmdpp[1] = cmdtabb;
  cmdpp[2] = cmdtabc;
  cmdpp[3] = cmdtabd;
  for (l = 0, ncmds = 0, width = 0; cmdpp[l]; l++)
    /* count the commands. */
    for (c = cmdpp[l]; c->c_name; c++)
      ncmds++;
  width = 4;
  if ((m = malloc (5 * ncmds)))
    {
      int i, lines, tail = 0;

      mp = m;
      for (l = 0; cmdpp[l]; l++)
	{
	  for (c = cmdpp[l]; c->c_name; c++)
	    {
	      if (4 == Lstrlen (c->c_name))
		strcpy (mp, c->c_name);
	      else
		{
		  strcpy (mp, c->c_name);
		  strcpy (mp + 3, " ");
		}
	      mp += 5;
	    }
	}
      Lqsort (m, ncmds, 5, str_cmp);
      width = width + 4;
      columns = 72 / width;
      lines = (ncmds + columns - 1) / columns;
      b = buf;
      for (i = 0; i < lines; i++)
	{
	  for (j = 0;; j++)
	    {
	      int index;

	      index = j * lines + i;
	      mp = m + (index * 5);
	      b += nsprintfds (b, width + 1, "    %s", 0, mp);
	      tail = 1;

	      if (mp + lines * 5 >= m + ncmds * 5)
		{
		  creply (214, buf);
		  b = buf;
		  tail = 0;
		  break;
		}
	    }
	}
      if (tail)
	creply (214, buf);
      free (m);

    }
  else
    {
      int tail = 0;

      width = width + 4;
      columns = 72 / width;
      j = 0;
      b = buf;
      for (l = 0; cmdpp[l]; l++)
	{
	  for (c = cmdpp[l]; c->c_name; c++)
	    {
	      tail = 1;
	      if (strlen (c->c_name) == 4)
		b += nsprintfds (b, width + 1, "    %s", 0, c->c_name);
	      else
		/* length is either 3 or 4 */
		b += nsprintfds (b, width + 1, "    %s ", 0, c->c_name);
	      j += 1;
	      if (j == columns)
		{
		  creply (214, buf);
		  j = 0;
		  b = buf;
		  tail = 0;
		}
	    }
	}
      if (tail)
	creply (214, buf);
    }

  return (reply (214, "End list", 1));
}				/* cmdhelp() */


/* cmdmode -
 *     
 */
int
cmdmode (argc, argv)
     int argc;
     char *argv[];
{
  int mode;

  if (argc != 2)
    return (reply (501, "Syntax error", 0));
  mode = Latoi (argv[1]);
  if (mode == MODE_S)
    return (reply (200, "MODE S OK.", 0));
  else
    return (reply (502, "Unimplemented MODE type.", 0));
}				/* cmdmode() */


/* cmdpasv -
 *     Enter passive mode.
 */
int
cmdpasv (argc, argv)
     int argc;
     char *argv[];
{
  int len;
  char *p, *a, *b;
  char replybuf[80];

  pdata = socket (AF_INET, SOCK_STREAM, 0);
  if (pdata < 0)
    return (reply (425, "Can't open passive connection", 0));
  pasv_addr = hisaddr;
  pasv_addr.sin_port = 0;
  (void) seteuid ((uid_t) 0);
  if (bind (pdata, (struct sockaddr *) &pasv_addr, sizeof (pasv_addr)) < 0)
    {
      (void) seteuid (uid);
      goto pasv_error;
    }
  (void) seteuid (uid);
  len = sizeof (pasv_addr);
  if (getsockname (pdata, (struct sockaddr *) &pasv_addr, &len) < 0)
    goto pasv_error;
  if (listen (pdata, 1) < 0)
    goto pasv_error;
  a = (char *) &pasv_addr.sin_addr;
  p = (char *) &pasv_addr.sin_port;

#define UC(b) (((int) b) & 0xff)
  nsprintfds (replybuf, 40, "Entering Passive Mode (%d,", UC (a[0]), NULL);
  b = replybuf + Lstrlen (replybuf);
  b += nsprintfds (b, 8, "%d,", UC (a[1]), NULL);
  b += nsprintfds (b, 8, "%d,", UC (a[2]), NULL);
  b += nsprintfds (b, 8, "%d,", UC (a[3]), NULL);
  b += nsprintfds (b, 8, "%d,", UC (p[0]), NULL);
  b += nsprintfds (b, 8, "%d)", UC (p[1]), NULL);
  return (reply (227, replybuf, 0));

pasv_error:
  (void) close (pdata);
  pdata = -1;
  return (reply (425, "Can't open passive connection", 0));
}				/* cmdpasv() */


/* cmdstru -
 *     
 */
int
cmdstru (argc, argv)
     int argc;
     char *argv[];
{
  int struc;

  if (argc != 2)
    return (reply (501, "Syntax error", 0));
  struc = Latoi (argv[1]);
  if (struc == STRU_F)
    return (reply (200, "STRU F OK.", 0));
  else
    return (reply (502, "Unimplemented STRU type.", 0));
}				/* cmdstru() */


/*
 * Generate unique name for file with basename "local".
 * The file named "local" is already known to exist.
 */
char *
gunique (local)
     char *local;
{
  static char new[MAXPATHLEN];
  struct stat st;
  int count;
  int llen;
  char *cp;

  if ((llen = strlen (local)) + 6 > MAXPATHLEN)
    return (NULL);		/* not enough space to make unique name. */
  cp = strrchr (local, '/');
  if (cp)
    *cp = '\0';
  if (Lstat (cp ? local : ".", &st) < 0)
    return (NULL);		/* directory not found. */
  if (cp)
    *cp = '/';
  (void) Lstrcpy (new, local);
  cp = new +llen;
  *cp++ = '.';
  for (count = 1; count < 100; count++)
    {
      nsprintfds (cp, 8, "%d", count, NULL);
      if (Lstat (new, &st) < 0)
	return (new);
    }
  return (NULL);
}


/*  cmdstou -
 *     Store unique.
 *     Returns -1 on failure of ctrl conn.
 */
int
cmdstou (argc, argv)
     int argc;
     char *argv[];
{
  int cmdstor (int, char **);
  int res;

  sunique++;
  res = cmdstor (argc, argv);
  sunique = 0;
  return (res);
}				/* cmdstou() */


/* Command table for the base implementation. */
static struct cmd ccmdtab[] =
{
  {"acct", cmdacct},
  {"appe", cmdappe},
  {"help", cmdhelp},
  {"mode", cmdmode},
  {"pasv", cmdpasv},
  {"stru", cmdstru},
  {"stou", cmdstou},
  {0}
};


/* cmdsc_initialize -
 */
void
cmdsc_initialize (void)
{
  cmdtabc = ccmdtab;
}				/* cmdsc_initialize() */
