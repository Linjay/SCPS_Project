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
 *                     Thursday, April 24, 1997 7:56 pm             * 
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
 * Module:             smibtab.c                                    * 
 *                                                                  * 
 * Description:                                                     * 
 *    Server specific MIB table and pointers.                       * 
 *                                                                  * 
 *
 * $Id: smibtab.c,v 1.9 2000/10/23 14:02:37 scps Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/smibtab.c,v 1.9 2000/10/23 14:02:37 scps Exp $
 * 
 *    Change History:
 * $Log: smibtab.c,v $
 * Revision 1.9  2000/10/23 14:02:37  scps
 * Cleaned to the FP directory so it would compile cleanly  -- PDF
 *
 * Revision 1.8  1999/11/22 15:52:45  scps
 * Changed FP discaimers to read as follows:
 *
 * ---------------------------------------------
 * /*
 * Revision 1.7  1999/03/23 20:24:38  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.6.2.2  1999/01/22 15:02:36  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:35  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:39  scps
 * Update to version 1.1.6 --ks
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
 */

static char rcsid[] = "$Id: smibtab.c,v 1.9 2000/10/23 14:02:37 scps Exp $";

#include <string.h>
#include "mibr.h"

extern int type;
extern int mode;
extern int struc;
extern int autorestart;
extern int numautor;
extern int idletimeout;
extern int sendport;
extern int bets;
extern int betsfill;
extern int replywithtext;
extern int debug;
extern int port;

int nothing;

/* Things are case sensitive here, and all 
 * the values must match (except those for pp)
 * those in cmibtab.c                            */
struct mibp mibptab[] =
{
  {"type", 0, "ai", 0, 0, &type},
  {"mode", 0, "sb", 0, 0, &mode},
  {"structure", 0, "fr", 0, 0, &struc},
  {"autorestart", 1, "", 0, 1, &autorestart},
  {"restartnum", 1, "", 0, 32767, &nothing},
  {"sendport", 1, "", 0, 1, &nothing},
  {"idle", 1, "", 1, 32767, &idletimeout},
  {"bets", 1, "", 0, 1, &bets},
  {"betsfill", 1, "", 0, 255, &betsfill},
  {"hash", 1, "", 0, 1, &nothing},
  {"hashsize", 1, "", 100, 32767, &nothing},
  {"srtxt", 1, "", 0, 1, &replywithtext},
  {"debug", 1, "", 0, 1, &debug},
  {"ctlport", 1, "", 1, 65535, &port},
  {0}
};
