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
/*                     Thursday, November 7, 1996 2:17 pm           */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             date.c                                       */
/*                                                                  */
/* Description:                                                     */
/*    Provides compile date, time, and build size.
 * $Id: date.c,v 1.10 1999/11/22 16:14:33 scps Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/date.c,v 1.10 1999/11/22 16:14:33 scps Exp $
 * $Id: date.c,v 1.10 1999/11/22 16:14:33 scps Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/date.c,v 1.10 1999/11/22 16:14:33 scps Exp $
 * 
 *    Change History:
 * $Log: date.c,v $
 * Revision 1.10  1999/11/22 16:14:33  scps
 * Removed disclaimer comment blocks from revision logs.
 *
 * Revision 1.9  1999/11/22 15:52:42  scps
 * Changed FP discaimers
 *
 * Revision 1.8  1999/03/23 20:24:35  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.7  1999/03/02 19:49:45  scps
 * Ruhai testing fixes to run under linux.
 * Revision 1.6.2.1  1998/12/29 14:27:30  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:37  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.4  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.3  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 * 
 * Revision 1.2  1997/06/16 14:09:30  steven
 * Added comments describing build sizes.
 * 
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *                                                                  */
/********************************************************************/

char *builddate = __DATE__;
char *buildtime = __TIME__;

#ifdef SMALL
/* SCPS Minimum Implementation */
char *buildsize = "A";
#else
#ifdef MEDIUM
/* A plus SCPS Full Implementation */
char *buildsize = "B";
#else
#ifdef LARGE
/* A plus B plus Internet FTP RFC 1123 Implementation */
char *buildsize = "C";
#else
char *buildsize = "-";
#endif
#endif
#endif


/*
Commands sorted by build size.
Command  SCPS  FTP    OPTIONAL   A   B   C
                      
ABOR     SCPS  FTP    OPTIONAL   x   x   x
ARST     SCPS                    x   x   x
DELE     SCPS  FTP               x   x   x
IDLE     SCPS (FTP)              x   x   x
INTR     SCPS                    x   x   x
NARS     SCPS                    x   x   x
NOOP     SCPS  FTP               x   x   x
NSUP     SCPS                    x   x   x
PORT     SCPS  FTP               x   x   x
QUIT     SCPS  FTP               x   x   x
READ     SCPS                    x   x   x
REST     SCPS (FTP)   OPTIONAL   x   x   x
RETR     SCPS  FTP               x   x   x
SITE     SCPS  FTP    OPTIONAL   x   x   x
SIZE     SCPS (FTP)              x   x   x
STOR     SCPS  FTP               x   x   x
SUPP     SCPS                    x   x   x
UPDT     SCPS                    x   x   x
BETS     SCPS                        x   x
CDUP           FTP                   x   x
COPY     SCPS                        x   x
CWD      SCPS  FTP                   x   x
LIST     SCPS  FTP                   x   x
MKD      SCPS  FTP                   x   x
NBES     SCPS                        x   x
NLST           FTP                   x   x
PASS     SCPS  FTP                   x   x
PWD      SCPS  FTP                   x   x
RMD      SCPS  FTP                   x   x
RNFR     SCPS  FTP                   x   x
RNTO     SCPS  FTP                   x   x
STAT     SCPS  FTP                   x   x
SYST           FTP                   x   x
TYPE     SCPS  FTP                   x   x
USER     SCPS  FTP                   x   x
ACCT           FTP                       x
APPE           FTP                       x
HELP     SCPS  FTP                       x
MODE     SCPS  FTP                       x
PASV     SCPS  FTP                       x
STRU     SCPS  FTP                       x
STOU                  OPTIONAL           x

------------------------------------------
Commands sorted by command:
Command  SCPS  FTP    OPTIONAL   A   B   C

ABOR     SCPS  FTP    OPTIONAL   x   x   x
ACCT           FTP                       x
APPE           FTP                       x
ARST     SCPS                    x   x   x
BETS     SCPS                        x   x
CDUP           FTP                   x   x
COPY     SCPS                        x   x
CWD      SCPS  FTP                   x   x
DELE     SCPS  FTP               x   x   x
HELP     SCPS  FTP                       x
IDLE     SCPS (FTP)              x   x   x
INTR     SCPS                    x   x   x
LIST     SCPS  FTP                   x   x
MKD      SCPS  FTP                   x   x
MODE     SCPS  FTP                       x
NARS     SCPS                    x   x   x
NBES     SCPS                        x   x
NLST           FTP                   x   x
NOOP     SCPS  FTP               x   x   x
NSUP     SCPS                    x   x   x
PASS     SCPS  FTP                   x   x
PASV     SCPS  FTP                       x
PORT     SCPS  FTP               x   x   x
PWD      SCPS  FTP                   x   x
QUIT     SCPS  FTP               x   x   x
READ     SCPS                    x   x   x
REST     SCPS (FTP)   OPTIONAL   x   x   x
RETR     SCPS  FTP               x   x   x
RMD      SCPS  FTP                   x   x
RNFR     SCPS  FTP                   x   x
RNTO     SCPS  FTP                   x   x
SITE     SCPS  FTP    OPTIONAL   x   x   x
SIZE     SCPS (FTP)              x   x   x
STAT     SCPS  FTP                   x   x
STOR     SCPS  FTP               x   x   x
STOU                  OPTIONAL           x
STRU     SCPS  FTP                       x
SUPP     SCPS                    x   x   x
SYST           FTP                   x   x
TYPE     SCPS  FTP                   x   x
UPDT     SCPS                    x   x   x
USER     SCPS  FTP                   x   x

*/
