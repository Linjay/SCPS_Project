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
/*                     Wednesday, July 10, 1996 5:52 pm             */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             rx_avail.c                                   */
/*                                                                  */
/* Description:                                                     */
/*    Checks a socket for received data using select.               */
/*
 * $Id: rx_avail.c,v 1.11 2005/10/18 15:37:51 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/rx_avail.c,v 1.11 2005/10/18 15:37:51 feighery Exp $
 * 
 *    Change History:
 * $Log: rx_avail.c,v $
 * Revision 1.11  2005/10/18 15:37:51  feighery
 * This is the initial cut of running the gateway under FreeBSD via the
 * TAP method.  Thanks should go to Marcin Jessa at yazzy@yazzy.com
 * for the majority of the effort.  The this required the latest and
 * greatest copy of FreeBSD or NetBSD to work.
 *
 * 	PDF
 *
 * Revision 1.10  2000/10/23 14:02:37  scps
 * Cleaned to the FP directory so it would compile cleanly  -- PDF
 *
 * Revision 1.9  1999/11/22 16:14:33  scps
 * Removed disclaimer comment blocks from revision logs.
 *
 * Revision 1.8  1999/11/22 15:52:44  scps
 * Changed FP discaimers
 *
 * Revision 1.7  1999/03/23 20:24:37  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.6.2.2  1999/01/22 15:02:35  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:33  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:38  scps
 * Update to version 1.1.6 --ks
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
 * 
 *    Rev 1.0   03 Jan 1997 20:45:56   steves
 * Initial revision.
 *                                                                  */
/********************************************************************/

static char rcsid[] = "$Id: rx_avail.c,v 1.11 2005/10/18 15:37:51 feighery Exp $";

#include <sys/types.h>
#include <string.h>
#ifdef MSVC
#include <winsock.h>
typedef struct sockaddr *caddr_t;
#else
#include <sys/time.h>
#if defined(LINUX) || defined(__FreeBSD__) || defined(__NetBSD__)
#include <unistd.h>
#else
#include <sys/unistd.h>
#endif
#endif


#ifndef NOTTP
#include "scps.h"
#endif /* NOTTP *

/* rcvdata_avail -
 *     Checks the socket for received data available.
 *     Returns 0 if not, non-zero if so.
 */
int
rcvdata_avail (int fd)
{
#ifdef MSVC
  /* Windows ignores this. */
  int maxfds = 0;
#else
  int maxfds = sysconf (_SC_OPEN_MAX);
#endif
  struct timeval t;
#ifdef NOTTP
  fd_set rcvfds;
#else
  scps_fd_set rcvfds;
#endif
  int res;

#ifdef MSVC
  memset (&t, 0, sizeof (t));
#else
  bzero (&t, sizeof (t));
#endif
#ifdef NOTTP
  FD_ZERO (&rcvfds);
  FD_SET (fd, &rcvfds);
  res = select (maxfds, &rcvfds, NULL, NULL, &t);
#else
  SCPS_FD_ZERO (&rcvfds);
  SCPS_FD_SET (fd, &rcvfds);
  res = scps_select (maxfds, &rcvfds, NULL, NULL, &t);
#endif
  if (res != -1)
    {
#ifdef NOTTP
      return (FD_ISSET (fd, &rcvfds));
#else
      return (SCPS_FD_ISSET (fd, &rcvfds));
#endif
    }
  else
    {
      /* Oh dear! */
      return 0;
    }
}				/* rcvdata_avail() */
