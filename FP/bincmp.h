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

/* $Id: bincmp.h,v 1.9 2007/04/19 15:09:36 feighery Exp $ */
/* $Header: /home/cvsroot/SCPS_RI/FP/bincmp.h,v 1.9 2007/04/19 15:09:36 feighery Exp $ */

#ifndef MSC
#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif
#endif

#define RBUF_SIZE    8192	/* size of the buffer strsrch uses           */
#define INTERVAL_MAP 0.03	/* interval = INTERVAL_MAP * filesize        */
#define STRLEN_MAP   0.00722	/* search string len = STRLEN_MAP * filesize */
#define FOUNDAT_SIZE 3		/* can only find 2 occurrances per file.     */

struct _matches
  {
    struct _matches *next;
    struct _matches *prev;
    int32_t f1loc;			/* location of match in f1 */
    int32_t f2loc;			/* location of match in f2 */
    int32_t length;		/* size of match           */
  };

struct _matches *collectmatches (FILE * f1, FILE * f2, int32_t f1size);

int expandmatches (struct _matches **m, FILE * f1, FILE * f2, int32_t f1size, int32_t f2size);

void freemall (struct _matches *m);

int memfcmp (char *s1, char *s2, size_t n);
