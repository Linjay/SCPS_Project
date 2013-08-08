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
/* Module:             libs.c                                       */
/*                                                                  */
/* Description:                                                     */
/*    Library routines for the server.                              */
/*
$Id: libs.c,v 1.11 2007/04/19 15:09:36 feighery Exp $
$Header: /home/cvsroot/SCPS_RI/FP/libs.c,v 1.11 2007/04/19 15:09:36 feighery Exp $

   Change History:
$Log: libs.c,v $
Revision 1.11  2007/04/19 15:09:36  feighery
This version makes the gateway code (and only the gateway code) safe for
64 bit architectures.  Before we were very sloppy and use a long and int
interchangeable.  As part of this change, it was required to make the
gateway code single threaded;  therefore gateway_single_thread=yes is the
default.  -- PDF

Revision 1.10  2002/09/23 19:52:15  scps
Added the following pieces of code for this rev

1)  Rewrote the readme tun based on user feedback

2)  Added ability to disable the rule generation for gateway operating

3)  Added support for OpenBSD based on user feedback.

        PDF

Revision 1.9  1999/11/22 16:14:33  scps
Removed disclaimer comment blocks from revision logs.

Revision 1.8  1999/11/22 15:52:43  scps
Changed FP discaimers

Revision 1.7  1999/07/07 14:05:31  scps
Modified the FP files so the RATE and MTU command line parameters would
be set properly for both the control and the data connection. -- PDF

Revision 1.6  1999/03/23 20:24:36  scps
Merged reference implementation with gateway-1-1-6-k branch.

Revision 1.5.2.2  1999/01/22 15:02:33  scps
There was a problem with the FP in CVS I had to perform a update and a new
commit. -- PDF

Revision 1.5.2.1  1998/12/29 14:27:31  scps
Monolithic update to include gateway code.

Revision 1.6  1998/12/01 16:44:37  scps
Update to version 1.1.6 --ks

Revision 1.5  1997/09/18 17:57:16  steven
Red-3 except files of CCSDS packets.

Revision 1.1  1997/02/28 21:25:57  steven
Initial revision

 *                                                                  */
/********************************************************************/

static char rcsid[] = "$Id: libs.c,v 1.11 2007/04/19 15:09:36 feighery Exp $";
#include <stdio.h>
#include <sys/types.h>		/* for stat      */
#include <sys/stat.h>		/* for stat      */
#include <time.h>

#ifdef MSVC
#include <winsock.h>
#else
#include <unistd.h>		/* for rename    */
#include <sys/socket.h>		/* for Berkeley socket prototypes */
#include <netinet/in.h>		/* for sockaddr_in */
#include <arpa/ftp.h>		/* for constants */
#endif
#include "libs.h"
#include "tpif.h"

int Lstrout (char *str);

extern char dbgbuf[DBG_BUFSIZ];
extern int flags;

char tmpnamres[SCPS_L_tmpnam];


/* putintd -
 *    Write the ASCII representation of the integer to the
 *    buffer at buf.
 */
int
putintd (buf, intd)
     char *buf;
     int32_t intd;
{
#ifdef STRV_SOUT
  int32_t place = 1000000000L;	/* position in the integer */
  int32_t this;			/* current digit           */
  int started = 0;		/* don't put leading zeros */

  while (place)
    {
      if (intd >= place)
	{
	  this = intd / place;
	  *buf++ = (char) (((char) (this)) + '0');
	  intd -= this * place;
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
#else
  sprintf (buf, "%ld", intd);
#endif
  return (0);
}				/* putintd() */


/* nsprintfds -
 *    Writes the formatted string to buf.  Does not write
 *    more than len bytes.  Only supports %d and %s.  Field
 *    width specifiers are not supported.  Does not support
 *    a varying number of arguments.
 *
 *    Returns the number of bytes written to buf.
 *    Whereever %d appears in the format string, the 'd'
 *    argument will be inserted.  Whereever %s appears
 *    in the format string, the 's' argument is inserted.
 */
int
nsprintfds (buf, len, fmt, d, s)
     char *buf, *fmt, *s;
     int len, d;
{
  char *start = buf;
  int inpercent = 0;		/* percent state */
  char *tstr;
  int temp;

  len--;			/* don't be off by one */
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
	      if (d > 10000)
		len = (len - 11 > 0 ? len - 11 : 0);
	      else
		len = (len - 6 > 0 ? len - 6 : 0);
	      if (len)
		putintd (buf, (int32_t) d);
	      break;

	    case 's':
	      {
		tstr = s;
		temp = Lstrlen (tstr) - 1;
		len = (len - temp > 0 ? len - temp : 0);
		if (len)
		  Lstrcpy (buf, tstr);
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
  return (buf - start);
}				/* nsprintfds() */


/* Lstrstr -
 *     Returns a pointer to the place in s1 where s2 starts (if any)
 */
char *
Lstrstr (s1, s2)
     char *s1, *s2;
{
  int len = Lstrlen (s2);

  for (; Lstrlen (s1) >= len; s1++)
    {
      if (0 == Lstrncmp (s1, s2, len))
	return s1;
    }
  return (char *) (0);
}				/* Lstrstr() */


/* Lstrncmp -
 *     Compare ASCII strings of length n.
 *     Returns    0 if s1 == s2
 *     Returns  < 0 if s1 < s2
 *     Returns  > 0 if s1 > s2
 */
int
Lstrncmp (s1, s2, n)
     const char*s1;
     const char *s2;
     int n;
{
  n--;
  for (; (*s1 && *s2) && n && (*s1 == *s2); s1++, s2++, n--);
  return *s1 - *s2;
}				/* Lstrncmp() */


/* message -
 *
 */
int
message (s)
     char *s;
{
  /* #ifdef debug */
  nsprintfds (dbgbuf, sizeof (dbgbuf), "%s\n", 0, s);
  Lstrout (dbgbuf);
  /* #endif */
  return (0);
}				/* message() */


/* Lstrlen -
 *
 */
int
Lstrlen (s1)
     char *s1;
{
  int i;

  for (i = 0; *s1; s1++, i++);
  return i;
}				/* Lstrlen() */


/* Lstrncpy -
 *
 */
char *
Lstrncpy (s1, s2, len)
     char *s1;
     const char *s2;
     short len;
{
  char *ret = s1;

  for (; len && *s2; len--, s1++, s2++)
    *s1 = *s2;
  if (len)
    *s1 = '\0';
  return ret;
}				/* Lstrncpy() */


/* Latoi -
 *    Convert an ASCII string to a short integer.
 */
short
Latoi (s)
     char *s;
{
  short ret = 0;

  for (; *s; s++)
    {
      ret = (short) ((ret * 10) + (*s & 0x0f));
    }
  return ret;
}				/* Latoi() */


/* Lstrcmp -
 *
 */
int
Lstrcmp (s1, s2)
 const char*s1, *s2;
{
  for (; (*s1 && *s2) && (*s1 == *s2); s1++, s2++)
    {
    }
  return *s1 - *s2;
}				/* Lstrcmp() */


/* Lstrtolower -
 *
 */
int
Lstrtolower (s)
     char *s;
{
  for (; *s; s++)
    {
      if ((*s & 0xE0) == 0x40)
	*s |= 0x20;
    }
  return (0);
}				/* Lstrtolower() */


char hexdigits[] = "0123456789ABCDEF";

/* Litoa -
 *     Convert an uint32_t integer to an ASCII string.
 */
int
Litoa (larg, str)
     int32_t larg;
     char *str;
{
  int i;


  str += 8;
  *str = '\0';
  for (i = 0; i < 8; i++)
    {
      str--;
      *str = hexdigits[larg & 0xf];
      larg >>= 4;
    }
  return (0);
}				/* Litoa() */


/* Lbcopy -
 *
 */
int
Lbcopy (src, dst, len)
     char *src, *dst;
     int len;
{
  for (; len; src++, dst++, len--)
    *dst = *src;
  return (0);
}				/* Lbcopy() */


/* Lbzero -
 *
 */
void
Lbzero (str, len)
     char *str;
     short len;
{
  for (; len; str++, len--)
    *str = 0;
  return;
}				/* Lbzero() */


/* Latoaddr -
 *     Converts an ASCII string to an address.
 *     Returns 0 on OK, 1 on failure.
 *
 *     Takes a string in the form n,n,n,n,m,m
 */
int
Latoaddr (str, addr)
     char *str;
     struct sockaddr_in *addr;
{
  unsigned short *w = (unsigned short *) &(addr->sin_addr);
  char *wc = (char *) &(addr->sin_addr);
  int num;
  char *s;
  char *vals[6];


  Lbzero ((char *) addr, sizeof (struct sockaddr_in));
  for (s = vals[0] = str, num = 1; *s; s++)
    {
      /* make each element of vals[] point to an
       * individual number in the PORT argument */
      if (*s == ',')
	{
	  *s = '\0';
	  if (num == 6)
	    /* too many numbers */
	    return (1);
	  vals[num++] = s + 1;
	}
    }
  if (num != 6)
    /* not enough numbers */
    return (1);
  *wc++ = (unsigned char) (Latoi (vals[0]));
  *wc++ = (unsigned char) (Latoi (vals[1]));
  *wc++ = (unsigned char) (Latoi (vals[2]));
  *wc++ = (unsigned char) (Latoi (vals[3]));
  w = (unsigned short *) &(addr->sin_port);
  *w = (unsigned short) ((Latoi (vals[4]) << 8) + Latoi (vals[5]));
#if defined(MSVC) || defined(__BSD__) || defined(LINUX)
  /* *wl = ntohl(*wl); */
  *w = ntohs (*w);
#endif
  addr->sin_family = AF_INET;
  return (0);
}				/* Latoaddr() */


/* Lstrout -
 *     Write the string to the standard output connection.
 */
int
Lstrout (str)
     char *str;
{
#ifdef STRV_SOUT
  int s;
  int result;
  char addrstr[80];

  if (sstdout == -1)
    {
      Lstrncpy (addrstr, WHERE_STDOUT_IS, 21);
      result = Latoaddr (addrstr, &sstdout_addr);
      s = scps_socket (sstdout_addr.sin_family, SOCK_STREAM, 0);
      if (s < 0)
	return -1;
      enable_options (s);
      result = scps_connect (s, &sstdout_addr, sizeof (sstdout_addr));
      if (result < 0)
	return -1;
      /* OK.  I have a stdout connection. */
      /* tp_setto(s, 32000); */
      sstdout = s;
    }
  scps_send (sstdout, str, Lstrlen (str), flags);
  return 0;
#else
  printf (str);
  fflush (stdout);
#endif
  return (0);
}				/* Lstrout() */


/* Latoul -
 *     Parse a string to an unsigned long. (Latoul() doesn't
 *     check anything.  Caller must ensure that buf contains
 *     a NULL terminated ASCII representation of a decimal
 *     integer in the range 0 to ULONG_MAX.)
 */
uint32_t
Latoul (char *buf)
{
  uint32_t accum = (uint32_t) (*buf & 0x0f);

  for (buf++; *buf; buf++)
    {
      accum *= 10;
      accum += (uint32_t) (*buf & 0x0f);
    }				/* for */
  return accum;
}				/* Latoul() */


/* Lstat -
 *    calls stat()
 */
int
Lstat (char *path, struct stat *buf)
{
  return stat (path, buf);
}				/* Lstat() */


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
