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
/*                     Wednesday, June 26, 1996 2:43 pm             */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             libc.c                                       */
/*                                                                  */
/* Description:                                                     */
/*    Library routines for the client.                              */
/*
 * $Id: libc.c,v 1.11 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/libc.c,v 1.11 2007/04/19 15:09:36 feighery Exp $
 * 
 *    Change History:
 * $Log: libc.c,v $
 * Revision 1.11  2007/04/19 15:09:36  feighery
 * This version makes the gateway code (and only the gateway code) safe for
 * 64 bit architectures.  Before we were very sloppy and use a long and int
 * interchangeable.  As part of this change, it was required to make the
 * gateway code single threaded;  therefore gateway_single_thread=yes is the
 * default.  -- PDF
 *
 * Revision 1.10  2002/09/23 19:52:15  scps
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
 * Revision 1.9  2001/03/30 18:15:55  scps
 * Fixed some problems with the RTO logic
 *   1)  When calculating an rto, the variance component needs to be
 *       clamped at 0.500 seconds.
 *   2)  After an RTO packet has been sucessfully retransmitted, do
 *       not adjuct rxt_shift until a new packet has been timed
 *   3)  If rxt_shift has reached 4, the srtt and rttbest are probably
 *       bogus and need to be reset
 *
 * Also in the FP logic if you use the -H option the data connection did
 * not used to use the correct address.   It used to use the hostname, not
 * it used the address associated with the -H options.  -- PDF
 * cvs: ----------------------------------------------------------------------
 *
 * Revision 1.8  1999/11/22 16:14:33  scps
 * Removed disclaimer comment blocks from revision logs.
 *
 * Revision 1.7  1999/11/22 15:52:43  scps
 * Changed FP discaimers
 *
 * Revision 1.6  1999/03/23 20:24:36  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.5.2.2  1999/01/22 15:02:33  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.5.2.1  1998/12/29 14:27:31  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:37  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.5  1997/11/25 01:35:05  steven
 * Now toggledelay is defined for fbsd too.
 *
 * Revision 1.4  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.3  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 * 
 * Revision 1.2  1997/06/16 14:09:30  steven
 * Added sizes MEDIUM and LARGE.
 * 
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *                                                                  */
/********************************************************************/

static char rcsid[] = "$Id: libc.c,v 1.11 2007/04/19 15:09:36 feighery Exp $";

#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/stat.h>
#ifdef MSVC
#include <winsock.h>
#include <time.h>
#undef ERROR
#include "ftp.h"
#else
#include <netinet/in.h>
#include <arpa/ftp.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <strings.h>
#endif
#include <ctype.h>
#include <string.h>
#include <stdlib.h>		/* for qsort() */
#if defined(SYSV) || defined(__BSD__) || defined(LINUX)
#include <termios.h>
#endif
#include "libc.h"

int termflags;
short nextport = 0;		/* next port number to use for a data
				 * connection.  (Before I use it, I
				 * add 5000).  This number wraps at
				 * 255 */
int digits[15] =
{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0};
char tmpnamres[SCPS_L_tmpnam];

extern char config_local_name[];

/* message -
 *     Display a message from socks.c
 */
void
message (char *s)
{
  /* #ifdef debug */
  printf ("%s\n", s);
  /* #endif */
}				/* message() */


/* Linet_addr -
 *
 */
int32_t
Linet_addr (char *cp)
{
  return inet_addr (cp);
}				/* Linet_addr() */


struct hostent *
Lgethostbyname (char *hostname)
{
  return gethostbyname (hostname);
}				/* Lgethostbyname */


struct hostent *
Lgethostbyaddr (char *addr, int len, int type)
{
  return gethostbyaddr (addr, len, type);
}				/* Lgethostbyaddr() */


int
Lgethostname (char *name, int namelen)
{
  return gethostname (name, namelen);
}				/* Lgethostname */


char *
Linet_ntoa (struct in_addr in)
{
  return inet_ntoa (in);
}				/* Linet_ntoa */


int
Lgetpeername (int s, struct sockaddr *name, int *namelen)
{
#ifdef MSVC
  memset (name, 0, *namelen);
#else
  bzero ((char *) name, *namelen);
#endif
  return *namelen;
}				/* Lgetpeername() */


/* Lgetaddrnport -
 *    Get the address of the current processor, and generate
 *    a new port number.
 */
void
Lgetaddrnport (addr)
     struct sockaddr_in *addr;
{
  char name[80];
  struct hostent *hp;

#ifdef MSVC
  memset (addr, 0, sizeof (struct sockaddr));
#else
  bzero ((char *) addr, sizeof (struct sockaddr));
#endif

  if (*config_local_name) {
    strcpy (name, config_local_name);
  } else {
    if (gethostname (name, sizeof (name)))
      return;
  }
  hp = gethostbyname (name);
  if (NULL == hp)
    return;

  nextport++;
  nextport &= 0xff;
#ifdef MSVC
  memmove (&(addr->sin_addr), hp->h_addr_list[0], hp->h_length);
#else
  bcopy (hp->h_addr_list[0], (caddr_t) & (addr->sin_addr), hp->h_length);
#endif
  addr->sin_port = htons ((u_short) (nextport + 5000));		/* arbitrary next port number */
  addr->sin_family = hp->h_addrtype;
}				/* Lgetaddrnport() */


/* Lperror -
 *    call perror()
 */
void
Lperror (char *str)
{
  perror (str);
}				/* Lperror() */


/* Lprerr -
 *    print error.
 */
void
Lprerr (char *file, int line)
{
  fprintf (stderr, "Error in %s at %d\n", file, line);
}				/* Lprerr() */


/* Lputchar -
 *    putchar
 */
int
Lputchar (char c)
{
  putchar (c);
  return (0);
}				/* Lputchar() */


/* Lfflush -
 *    call fflush
 */
int
Lfflush (FILE * stddev)
{
  fflush (stddev);
  return (0);
}				/* Lfflush() */


/* Lstrout -
 *    Write a string to stdout.
 */
int
Lstrout (char *msg)
{
  printf (msg);
  return (0);
}				/* Lstrout() */


/* Lstrncpy -
 *    
 */
void
Lstrncpy (char *s1, char *s2, int len)
{
  strncpy (s1, s2, len);
}				/* Lstrncpy() */


/* Lbzero -
 *    Sets the string to zero.
 */
void
Lbzero (char *s, int len)
{
#ifdef MSVC
  memset (s, 0, len);
#else
  bzero (s, len);
#endif
}				/* Lbzero() */


/* Lisdigit -
 *    Returns true if this is a digit.
 */
int
Lisdigit (int c)
{
  return isdigit (c);
}				/* Lisdigit() */

#if defined(SUNOS) || defined(__BSD__)
/* Ltoggledelay
 *    
 */
void
Ltoggledelay ()
{
  termflags ^= FNDELAY;
  (void) fcntl (fileno (stdin), F_SETFL, termflags);
}				/* Ltoggledelay() */
#endif


/* Ltoggleecho - toggle the ECHO flag to turn
 *               echo either on or off
 *               (used to get password) */
void
Ltoggleecho ()
{
#if defined(SYSV) || defined(MSVC)
#endif

#ifdef __BSD__
  struct termios tio;

  (void) ioctl (fileno (stdin), TIOCGETA, &tio);
  tio.c_lflag ^= ECHO;
  (void) ioctl (fileno (stdin), TIOCSETA, &tio);
#endif
#ifdef LINUX
  struct termios ttyb;

  (void) tcgetattr (0, &ttyb);
  ttyb.c_lflag ^= ECHO;
  (void) tcsetattr (0, TCSANOW, &ttyb);
#endif
#ifdef SUNOS
  struct sgttyb ttyb;

  (void) ioctl (fileno (stdin), TIOCGETP, &ttyb);
  ttyb.sg_flags ^= ECHO;
  (void) ioctl (fileno (stdin), TIOCSETP, &ttyb);
#endif
}				/* Ltoggleecho() */


/* Lechoon - turns console character echo on */
void
Lechoon ()
{
#if defined(SYSV) || defined(MSVC)
#elif defined(__BSD__)
  struct termios tio;

  (void) ioctl (fileno (stdin), TIOCGETA, &tio);
  tio.c_lflag |= ECHO;
  (void) ioctl (fileno (stdin), TIOCSETA, &tio);
#elif defined(LINUX)
  struct termios ttyb;

  (void) tcgetattr (0, &ttyb);
  ttyb.c_lflag |= ECHO;
  (void) tcsetattr (0, TCSANOW, &ttyb);

#else
  struct sgttyb ttyb;

  (void) ioctl (fileno (stdin), TIOCGETP, &ttyb);
  ttyb.sg_flags |= ECHO;
  (void) ioctl (fileno (stdin), TIOCSETP, &ttyb);
#endif
}				/* Lechoon() */


/* Linitialize - Setup console i/o for non-blocking. */
void
Linitialize ()
{
#if defined(SYSV) || defined(MSVC)
#else
  termflags = fcntl (fileno (stdin), F_GETFL, 0);
  termflags |= FNDELAY;
  (void) fcntl (fileno (stdin), F_SETFL, termflags);
  /* the default is to have it line buffered.  That is, I don't
   * get anything until they hit <return>, and then I get
   * the whole line all at once.  */
#endif
}				/* Linitialize() */


/* Lgetc - get one character from stdin.  If there
 *         was a character available, returns 1.  Otherwise
 *         return 0.  */
int
Lgetc (char *chp)
{
  int res;
  res = fread (chp, 1, 1, stdin);
  if ((res != 0) && (res != 1))
    return 0;
  else
    return res;
}				/* Lgetc() */


/* Lstrtolower */
void
Lstrtolower (char *str)
{
  while (*str)
    {
      *str = tolower (*str);
      str++;
    }				/* while */
}				/* Lstrtolower */


/* Lstrcmp -
 *    compare strings.
 */
int
Lstrcmp (char *s1, char *s2)
{
  return strcmp (s1, s2);
}				/* Lstrcmp() */

/* Lexit -
 *    Terminate the program.
 */
void
Lexit (int code)
{
  exit (code);
}				/* Lexit() */


/* Litoa -
 *    Converts an integer to an ASCII string.
 */
char *
Litoa (int i)
{
  static char integer[20];

  sprintf (integer, "%d", i);
  return integer;
}				/* Litoa() */


/* Labort -
 *    calls abort().
 */
void
Labort ()
{
  abort ();
  return;
}				/* Labort() */


/* Lsignal -
 *    calls signal
 */
#ifdef MSVC
int
Lsignal (int sig, int (*func) (int))
#else
void (*Lsignal (int sig, void (*func) ())) ()
#endif
{
  return (signal (sig, func));
}				/* Lsignal() */


/* Lstat -
 *    calls stat()
 */
int
Lstat (char *path, struct stat *buf)
{
  return stat (path, buf);
}				/* Lstat() */


/* Lstrstr -
 *    Find the occurrance of one string in another.
 */
char *
Lstrstr (char *s1, char *s2)
{
  return strstr (s1, s2);
}				/* Lstrstr() */


/* Laccess -
 *    Determine the accessability of a file.
 */
int
Laccess (char *path, int mode)
{
#ifdef MSVC
  return (int) (GetFileAttributes (path));
#else
  return (access (path, mode));
#endif
}				/* Laccess() */


/* Lfseek -
 *    Set the file pointer.
 */
int
Lfseek (FILE * stream, int32_t offset, int ptrname)
{
  return (fseek (stream, offset, ptrname));
}				/* Lfseek() */


/* Lstrlen -
 *    Gets the length of a string.
 */
int
Lstrlen (char *s)
{
  char *b;

  for (b = s; *s; s++);
  return ((int) (s - b));
}				/* Lstrlen() */


/* Lrindex -
 *    calls rindex()
 */
char *
Lrindex (char *s, char c)
{
#ifdef MSVC
  return (strrchr (s, c));
#else
  return (rindex (s, c));
#endif
}				/* Lrindex() */


/* Lfopen -
 *    Open a file.
 */
FILE *
Lfopen (char *filename, char *type)
{
  return (fopen (filename, type));
}				/* Lfopen() */


/* Lfclose -
 *    Close a file.
 */
int
Lfclose (FILE * stream)
{
  return (fclose (stream));
}				/* Lfclose() */


/* Lgettimeofday -
 *    calls gettimeofday().
 */
int
Lgettimeofday (struct timeval *tp, struct timezone *tzp)
{
#ifdef MSVC
  time_t tod;

  time (&tod);
  tp->tv_sec = tod;
  tp->tv_usec = 0;
  return (0);
#else
  return (gettimeofday (tp, tzp));
#endif
}				/* Lgettimeofday() */


/* Lfwrite -
 *    calls fwrite()
 */
int
Lfwrite (char *ptr, int size, int nitems, FILE * stream)
{
  return (fwrite (ptr, size, nitems, stream));
}				/* Lfwrite() */


/* Lfread -
 *    Calls fread().
 */
int
Lfread (char *ptr, int size, int nitems, FILE * stream)
{
  return (fread (ptr, size, nitems, stream));
}				/* Lfread() */


/* Latoi -
 *    Convert an ASCII string to integer.  Does not test for
 *    digits.  Just keeps doing the best it can until it
 *    hits the end of the string.
 */
int
Latoi (char *str)
{
  int ret = 0;

  while (*str)
    {
      ret = (ret * 10) + digits[(((*str) - '0') & 0xf)];
      str++;
    }
  return (ret);
}				/* Latoi() */


/* Latoul -
 *    Converts a decimal digit string to unsigned long.
 */
u_long
Latoul (char *str)
{
  u_long ret = 0;

  while (Lisdigit (*str))
    {
      ret = (ret * 10) + digits[(((*str) - '0') & 0xf)];
      str++;
    }
  return (ret);
}				/* Latoul() */


/* Lqsort -
 *    Calls qsort().
 */
int
Lqsort (void *base, size_t nmemb, size_t size,
	int (*compar) (const void *, const void *))
{
#if defined(SYSV) || defined(__BSD__) || defined(MSVC) || defined(LINUX)
  qsort (base, nmemb, size, compar);
  return (0);
#else
  return (qsort (base, nmemb, size, compar));
#endif
}				/* Lqsort() */


/* Lstrcat -
 *    Copies s2, including its terminating null character, to s1
 *    beginning at its terminating null character.  The caller
 *    must ensure that storage at s1 is available.
 *
 *    I wrote this based on other calls because I am tired of
 *    this external call list growing.  Eventually, we'll have
 *    write all this stuff from scratch.
 *
 *    Returns s1.
 */
char *
Lstrcat (char *s1, char *s2)
{
  char *ret = s1;

  for (; *s1; s1++);
  /* copy s2's terminating null too. */
  Lstrncpy (s1, s2, Lstrlen (s2) + 1);
  return (ret);
}				/* Lstrcat() */

/* putintd -
 *    Write the ASCII representation of the integer to the
 *    buffer at buf.
 */
static void
putintd (char *buf, unsigned int eger)
{
  unsigned int place = 1000000000;	/* position in the integer */
  unsigned int this;		/* current digit           */
  int started = 0;		/* don't put leading zeros */

  while (place)
    {
      if (eger >= place)
	{
	  this = eger / place;
	  *buf++ = this + '0';
	  eger -= this * place;
	  started = 1;
	}
      else
	{
	  if (started)
	    {
	      /* this is for embedded zeros like the one in 101 */
	      *buf++ = '0';
	    }			/* if started */
	}			/* if */
      place /= 10;
    }				/* while */
  if (0 == started)
    {
      /* all this just for 0 */
      *buf++ = '0';
    }				/* if */
  *buf = '\0';
}				/* putintd() */


/* putstr -
 *    Copy the string to the buffer called buf.
 */
static void
putstr (char *buf, char *str)
{
  for (; *str; str++, buf++)
    {
      *buf = *str;
    }				/* for */
  *buf = '\0';
}				/* putstr() */


/* nsprintf -
 *    Writes the formatted string to buf.  Does not write
 *    more than len bytes.  Only supports %d and %s.  Field
 *    width specifiers are not supported.
 *
 *    Returns the number of bytes written to buf.
 */
int
nsprintf (char *buf, int len, char *fmt,...)
{
  va_list args;
  char *start = buf;
  int inpercent = 0;		/* percent state */
  unsigned int arg;

  len--;			/* don't be off by one */
  va_start (args, fmt);
  while (*fmt && len)
    {
      switch (inpercent)
	{
	case 0:
	  if (*fmt == '%')
	    {
	      inpercent = 1;
	    }
	  else
	    {
	      *buf++ = *fmt;
	      len--;
	    }			/* if */
	  break;

	case 1:
	  switch (*fmt)
	    {
	    case 'd':
	      arg = va_arg (args, unsigned int);
	      if (len > 10000)
		len = (len - 11 > 0 ? len - 11 : 0);
	      else
		len = (len - 6 > 0 ? len - 6 : 0);
	      if (len)
		putintd (buf, arg);
	      break;

	    case 's':
	      {
		char *tstr;
		int temp;

		tstr = va_arg (args, char *);
		temp = Lstrlen (tstr) - 1;
		len = (len - temp > 0 ? len - temp : 0);
		if (len)
		  putstr (buf, tstr);
	      }
	      break;

	    }			/* switch */
	  for (; *buf; buf++);
	  inpercent = 0;
	  break;
	}			/* switch */
      fmt++;
    }				/* while */
  *buf = '\0';
  va_end (args);
  return (buf - start);
}				/* nsprintf() */


/* Lrename -
 *     calls rename()
 */
int
Lrename (char *oldpath, char *newpath)
{
  return rename (oldpath, newpath);
}				/* Lrename() */


/* fcopy -
 *    Copy filename1 to filename2.  If filename2 exists, fcopy()  
 *    remove()s it.
 *
 *    Returns 0 on success, 1 on failure.                        
 */
int
fcopy (char *filename1, char *filename2)
{
  FILE *infile;
  FILE *outfile;
  static char transferbuf[BUFSIZ];
  int cnt;

  if (NULL == filename1 || NULL == filename2)
    return 1;
  infile = Lfopen (filename1, "r");
  if (infile == NULL)
    return 1;
  outfile = Lfopen (filename2, "w");
  if (outfile == NULL)
    {
      Lfclose (infile);
      return 1;
    }
  while ((cnt = fread (transferbuf, 1, sizeof (transferbuf), infile)))
    {
      fwrite (transferbuf, 1, cnt, outfile);
    }
  Lfclose (infile);
  Lfclose (outfile);
  return 0;
}				/* fcopy() */


/*  Lstrcpy -
 *     Non-run-time-library string copy.
 */
void
Lstrcpy (char *dst, char *src)
{
  for (; *src; src++, dst++)
    *dst = *src;
  *dst = '\0';
}				/* Lstrcpy() */


/*  Ltmpnam -
 *     Generate a temporary name.  The caller
 *     must ensure that the sizeof(s) is >= SCPS_L_tmpnam.
 */
char *
Ltmpnam (char *s)
{
  char try[SCPS_L_tmpnam];
  int ord;
  time_t t;
  char *cp;
  struct stat stbuf;


  t = time (NULL);		/* Use this to generate the temporary name. */
  Lstrcpy (try, SCPS_P_tmpdir);
  if (stat (try, &stbuf) < 0)
    return (NULL);
#ifdef MSVC
  if (0 == (stbuf.st_mode & S_IFDIR))
#else
  if (0 == S_ISDIR (stbuf.st_mode))
#endif
    return (NULL);
  sprintf (try + Lstrlen (try), "/%d.", (int) (t & 0xFFFF));
  cp = try + Lstrlen (try);
  for (ord = 0; ord < 100; ord++)
    {
      sprintf (cp, "%d", ord);
      if (stat (try, &stbuf) < 0)
	goto done;
    }
  return (NULL);

done:
  Lstrcpy (tmpnamres, try);
  if (s)
    Lstrcpy (s, tmpnamres);
  return (tmpnamres);
}				/* Ltmpnam() */
