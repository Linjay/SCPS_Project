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
/*                     Thursday, April 24, 1997 7:42 pm             */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************
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
 * 
 */

/******************************************************************** 
 * Module:             mibr.c                                       * 
 *                                                                  * 
 * Description:                                                     * 
 *    MIB routines that are common to client and server.            * 
 *                                                                  * 
 *
 * $Id: mibr.c,v 1.8 2000/10/23 14:02:36 scps Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/mibr.c,v 1.8 2000/10/23 14:02:36 scps Exp $
 * 
 *    Change History:
 * $Log: mibr.c,v $
 * Revision 1.8  2000/10/23 14:02:36  scps
 * Cleaned to the FP directory so it would compile cleanly  -- PDF
 *
 * Revision 1.7  1999/11/22 15:52:44  scps
 * Changed FP discaimers to read as follows:
 *
 * ---------------------------------------------
 *
 * 		--keith
 *
 * Revision 1.6  1999/03/23 20:24:36  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.5.2.2  1999/01/22 15:02:34  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Revision 1.5.2.1  1998/12/29 14:27:32  scps
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
 * Revision 1.2  1997/08/15 19:50:22  steven
 * Adding Proxy
 *
 * Revision 1.1  1997/06/16 14:09:30  steven
 * Initial revision
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/ftp.h>
#include <string.h>
#include <ctype.h>		/* for tolower */
#include <unistd.h>
#include "mibr.h"
#include "fileio.h"

#define MIBFILE "mib.defaults"
extern short type;		/* transfer type      */
extern short mode;		/* transfer mode      */
extern short struc;		/* transfer structure */

/*
Sample mib.defaults file:

# Management Information Base defaults
#
#

# TYPE { (A)SCII | (I)MAGE }
TYPE=I

# MODE { (S)TREAM | (B)LOCK }
MODE=S

# STRUCTURE { (F)ILE | (R)ECORD }
STRUCTURE=F

# AUTORESTART { ENABLED(1) | DISABLED(0) }
AUTORESTART=0

# RESTARTNUM { 0 .. 32767 }
RESTARTNUM=99

# SENDPORT { ENABLED(1) | DISABLED(0) }
SENDPORT=1

# SEND REPLY TEXT  { YES(1) | NO(0) }
SRTXT=1

# IDLE (IDLE TIMEOUT IN SECONDS) { 1 .. 32767 }
IDLE=900

# BETS (BEST EFFORT TRANSPORT SERVICE) { ENABLED(1) | DISABLED(0) }
BETS=0

# BETSFILL { 0 .. 255 }
BETSFILL=0

# HASHSIZE (NUMBER OF BYTES PER HASH MARK) { 100 .. 32767 }
HASHSIZE=200

*/

/* This is defined in the [cs]mibtab.c file.  */
extern struct mibp mibptab[];


/* s2lwr -
 *     String to lower
 */
void
s2lwr (char *str)
{
  while (*str)
    {
      *str = tolower (*str);
      str++;
    }				/* while */
}				/* s2lwr() */


/* Strip trailing cr/lf from a line of text */
void
rip (char *buf)
{
  char *cp;

  if ((cp = strchr (buf, '\r')) != NULL)
    *cp = '\0';

  if ((cp = strchr (buf, '\n')) != NULL)
    *cp = '\0';
}				/* rip() */


/* setvalue -
 *     Returns 0 if I knew what to do and did it.
 *     Returns 1 if not.
 */
int
setvalue (char *p_name, char val)
{
  if (0 == strcmp (p_name, "type"))
    {
      switch (val)
	{
	case 'a':
	  type = TYPE_A;
	  return 0;
	case 'i':
	  type = TYPE_I;
	  return 0;
	}
    }
  if (0 == strcmp (p_name, "mode"))
    {
      switch (val)
	{
	case 's':
	  mode = MODE_S;
	  return 0;
	case 'b':
	  mode = MODE_B;
	  return 0;
	case 'c':
	  mode = MODE_C;
	  return 0;
	}
    }
  if (0 == strcmp (p_name, "structure"))
    {
      switch (val)
	{
	case 'f':
	  struc = STRU_F;
	  return 0;
	case 'r':
	  struc = STRU_R;
	  return 0;
	case 'p':
	  struc = STRU_P;
	  return 0;
	}
    }
  return 1;
}				/* setvalue() */


/* mibread -
 *    Reads the MIB file.  Performs syntax checking on each
 *    parameter.  When it finds a valid parameter name, it
 *    sets the value.  If it does not find a particular
 *    parameter, mibread() does not touch its value.
 *
 *    Returns 0 for no error.
 *    Returns 1 if there was a syntax error.
 *     
 */
int
mibread (void)
{
  FILE *mibfile;
  char buf[80];
  char copybuf[80];
  struct mibp *mibpp;
  char *p_name;
  char *p_val;
  int found;
  int n;

  if (NULL == (mibfile = Lfopen (MIBFILE, "r")))
    {
      fprintf (stderr, "Could not open '%s'\n", MIBFILE);
      return 1;
    }
  while (fgets (buf, sizeof (buf), mibfile))
    {
      rip (buf);
      strncpy (copybuf, buf, sizeof (buf));
      if (*copybuf == '#')
	continue;

      if (NULL == (p_name = strtok (copybuf, " =\t")))
	continue;		/* blank lines are OK. */

      if (0 == strlen (p_name))
	continue;		/* blank lines are OK. */

      s2lwr (p_name);
      for (mibpp = mibptab, found = 0; mibpp->p_name; mibpp++)
	{
	  if (0 == strcmp (p_name, mibpp->p_name))
	    {
	      found = 1;
	      break;
	    }
	}

      if (found == 0)
	{
	  fprintf (stderr, "No such parameter: '%s'\n", buf);
	  continue;
	}

      if (NULL == (p_val = strtok (NULL, " =\t")))
	{
	  fprintf (stderr, "No parameter value: '%s'\n", buf);
	  continue;
	}

      s2lwr (p_val);

      switch (mibpp->i)
	{
	case 0:
	  if (NULL == strchr (mibpp->valid, *p_val))
	    fprintf (stderr, "Invalid value: '%s'\n", buf);
	  else if (setvalue (mibpp->p_name, *p_val))
	    fprintf (stderr, "setvalue() error: '%s'\n", buf);
	  break;

	case 1:
	  n = atoi (p_val);
	  if (n >= mibpp->min && n <= mibpp->max)
	    *(mibpp->pp) = n;
	  else
	    fprintf (stderr, "Value out of range: '%s'\n", buf);
	  break;
	default:
	  fprintf (stderr, "Invalid mibpp->i\n");
	  return 1;
	}
    }
  Lfclose (mibfile);
  return 0;
}				/* mibread() */
