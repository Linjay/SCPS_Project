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
/*                     Thursday, June 27, 1996 12:43 pm             */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             autopa.c                                     */
/*                                                                  */
/* Description:                                                     */
/*    Holds autouser, etc.  for expansion later.                    */
/*    Part of auto-restart.  Used to reestablish the control        */
/*    conn.  Small imp. doesn't need them because--no USER or PASS. */
/*
 * $Id: autopa.c,v 1.9 1999/11/22 16:14:32 scps Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/autopa.c,v 1.9 1999/11/22 16:14:32 scps Exp $
 * 
 *    Change History:
 * $Log: autopa.c,v $
 * Revision 1.9  1999/11/22 16:14:32  scps
 * Removed disclaimer comment blocks from revision logs.
 *
 * Revision 1.8  1999/11/22 15:52:41  scps
 * Changed FP discaimers
 *
 * Revision 1.7  1999/03/23 20:24:33  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.6.2.2  1999/01/22 15:02:28  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:27  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:35  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.4  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.3  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 * 
 * Revision 1.2  1997/06/16 14:09:30  steven
 * Added size LARGE.
 * 
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *                                                                  */
/********************************************************************/

static char rcsid[] = "$Id: autopa.c,v 1.9 1999/11/22 16:14:32 scps Exp $";

char autouser[1];		/* for expansion later             */
char autopass[1];
char autodir[1];
