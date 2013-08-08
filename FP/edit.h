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

/* $Id: edit.h,v 1.7 1999/11/22 15:52:43 scps Exp $ */
/* $Header: /home/cvsroot/SCPS_RI/FP/edit.h,v 1.7 1999/11/22 15:52:43 scps Exp $ */

 /* edit - Performs add, change and delete.  Delta file is the
  *        format of diff output with -f flag.
  *
  * Returns 0 if all went OK
  *         1 if invalid lines were specified in the delta file. 
  *         2 if unable to open original file.
  *         3 if unable to open delta file.
  *         4 if unable to open new file.
  */
int edit (char *ofile,		/* original file                       */
	  char *nfile,		/* new file                            */
	  char *dfile);		/* delta file                          */

struct change_cmd
  {
    char ch;
    u_long foffset;
    short len;
  };

/* read a change record.
 * Returns 1 if successful,
 * 0 otherwise.  */
int get_ch_rec (struct change_cmd *chcmdp, FILE * rf);
