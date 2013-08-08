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

/* $Id: libs.h,v 1.9 2007/04/19 15:09:36 feighery Exp $ */
/* $Header: /home/cvsroot/SCPS_RI/FP/libs.h,v 1.9 2007/04/19 15:09:36 feighery Exp $ */

#include <stdio.h>
#include <string.h>

#define BSIZE        8192       /* size of data transfer buf */

#define FP_BUFSIZ    40
/* #ifdef DEBUG */
#define DBG_BUFSIZ   80
/* #endif */
#ifndef MAXPATHLEN
#define MAXPATHLEN  512
#endif

#define NUMUSERS     50		/* number of name/pass pairs  */

/* structure of a command table entry */
struct cmd
  {
    char *c_name;		/* name of command */
    /* int (*c_func)(int argc, char*argv[]);    / function to execute if this name matches */
    int (*c_func) ();
  };

#define NAME_LEN 16

struct _user
  {
    char name[NAME_LEN];
    char pass[NAME_LEN];
  };

int putstr (char *buf, char *str);
int putintd (char *buf, int32_t intd);
int nsprintfds (char *buf, int len, char *fmt, int d, char *s);
char *Lstrstr (char *s1, char *s2);
int Lstrncmp (const char *s1, const char *s2, int n);
int message (char *s);
int Lstrlen (char *s1);
char *Lstrncpy (char *s1, const char *s2, short len);
short Latoi (char *s);
int Lstrcmp (const char *s1, const char *s2);
int Lstrtolower (char *s);
void Lbzero (char *s, short size);
int Litoa (int32_t larg, char *str);
uint32_t Latoul (char *str);
int Lstat (char *path, struct stat *buf);
int Lrename (char *oldpath, char *newpath);
int fcopy (char *filename1, char *filename2);
void Lstrcpy (char *dst, char *src);


#ifdef NOTTP

#define SCPS_P_tmpdir   P_tmpdir
#define SCPS_L_tmpnam   L_tmpnam
#define Ltmpnam(s)      tmpnam(s)
#define Lstrrchr(a,b)   strrchr(a,b)

#else
/* If running over TP, then assume we're on a spacecraft
 * that might not have a runtime library.  So we need
 * to write our own tmpnam() */
#define SCPS_P_tmpdir    "/tmp"
#define SCPS_L_tmpnam    20	/* Length of temp name. Minimum 20 */
char *Ltmpnam (char *);		/* Library temnam() */
char *Lstrrchr (char *, int);

#endif

#define Lfopen(a,b)     fopen(a,b)
#define Lfclose(a)      fclose(a)
#define Lfread(a,b,c,d) fread(a,b,c,d)
#define Lfgets(a,b,c)   fgets(a,b,c)
