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

/* $Id: libc.h,v 1.9 2007/04/19 15:09:36 feighery Exp $ */
/* $Header: /home/cvsroot/SCPS_RI/FP/libc.h,v 1.9 2007/04/19 15:09:36 feighery Exp $ */

#include <stdio.h>
#ifdef MSVC
#include <winsock.h>
#else
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif

#include <sys/types.h>

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif


/* structure of a command table entry */
struct cmd
  {
    char *c_name;		/* name of command  */
    char *c_help;		/* help for command */
    char c_conn;		/* must be connected to use command */
    char c_proxy;		/* proxy server may execute */
    int (*c_func) (int argc, char *argv[]);	/* function to execute if this name matches */
  };

extern struct cmd cmdtab[];
#ifndef MAXPATHLEN
#define MAXPATHLEN    64
#endif
#define CMDLNSIZE    100
#define MAXARGS       14
#define MBSIZE        80	/* size of msgbuf            */
#define RSSIZE       256	/* size of reply_string      */
#define BSIZE        8192	/* size of data transfer buf */

extern char cmdline[CMDLNSIZE];
			 /* keyboard or ctl conn input            */

extern int margc;		/* used to pass arguments to cmd handler */
extern int uargc;		/*                                       */
extern char *margv[MAXARGS];
			 /* pointers to arguments                 */

extern int sctrl;		/* control socket                        */
extern int sdata;		/* data socket                           */

void fp_initialize ();		/* initialize all of the above, plus
				 * socket layer, plus TP                 */

int makemargv (char *s);	/* make margc and margv from cmdline     */

int lookup_execute (int, char **, struct cmd *);	/* look up a      */
			 /* command and execute it.               */

int nsprintf (char *buf, int len, char *fmt,...);	/* tiny string  */
			 /* formatter.  Does %d and %s.  Does not */
			 /* support field width specifiers.       */

char *Linet_ntoa (struct in_addr in);
char *Litoa (int i);
char *Lrindex (char *s, char c);
char *Lstrstr (char *s1, char *s2);
char *Lstrcat (char *s1, char *s2);
int Laccess (char *path, int mode);
int Latoi (char *str);
int Latoi (char *str);
FILE *Lfopen (char *filename, char *type);
int Lfclose (FILE * stream);
int Lfflush (FILE * stddev);
int Lfread (char *ptr, int size, int nitems, FILE * stream);
int Lfseek (FILE * stream, int32_t offset, int ptrname);
int Lfwrite (char *ptr, int size, int nitems, FILE * stream);
int Lgetc (char *chp);
int Lgethostname (char *name, int namelen);
int Lgetpeername (int s, struct sockaddr *name, int *namelen);
int Lgetsockname (int s, struct sockaddr *name, int *namelen);
int Lgettimeofday (struct timeval *tp, struct timezone *tzp);
int Lisdigit (int c);
int Lputchar (char c);
int Lqsort (void *base, size_t nmemb, size_t size, int (*compar) (const void
								  *, const
								  void *));
int Lsetsockopt ();
int Lstat (char *path, struct stat *buf);
int Lstrcmp (char *s1, char *s2);
int Lstrlen (char *str);
int Lstrout (char *msg);
int32_t Linet_addr (char *cp);
struct hostent *Lgethostbyaddr (char *addr, int len, int type);
struct hostent *Lgethostbyname (char *hostname);
void (*Lsignal (int sig, void (*func) ())) ();
void Labort ();
void Lbzero (char *s, int len);
void Lechoon ();
void Lexit (int code);
void Lgetaddrnport (struct sockaddr_in *addr);
void Linitialize ();
void Lperror (char *str);
void Lprerr (char *file, int line);
void Lstrncpy (char *s1, char *s2, int len);
void Lstrcpy (char *s1, char *s2);
void Lstrtolower (char *s);
void Ltoggleecho ();
u_long Latoul (char *str);
int Lrename (char *oldpath, char *newpath);
int fcopy (char *filename1, char *filename2);

#ifdef NOTTP

#define SCPS_P_tmpdir   P_tmpdir
#define SCPS_L_tmpnam   L_tmpnam
#define Ltmpnam(s)      tmpnam(s)

#else
/* If running over TP, then assume we're on a spacecraft
 * that might not have a runtime library.  So we need
 * to write our own tmpnam() */
#define SCPS_P_tmpdir    "/tmp"
#define SCPS_L_tmpnam    20	/* Length of temp name. Minimum 20 */
char *Ltmpnam (char *);		/* Library temnam() */

#endif
