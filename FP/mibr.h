/*
  This is unclassified Government software.

  This source was developed under a prototype development contract by
  Science Applications International Corporation (SAIC) in McLean,
  Virginia for the Jet Propulsion Laboratories (JPL) of the National
  Aeronautics and Space Administration (NASA) for the Space
  Communications Protocol Standards (SCPS) project.
    
  SAIC assumes no legal responsibility for the source code and its
  subsequent use.  No warranty is expressed or implied.

*/

/* $Id: mibr.h,v 1.6 1999/03/23 20:24:36 scps Exp $ */
/* $Header: /home/cvsroot/SCPS_RI/FP/mibr.h,v 1.6 1999/03/23 20:24:36 scps Exp $ */

/* The MIB parameter structure. */
struct mibp
  {
    char *p_name;		/* name of parameter */
    int i;			/* indicator switch */
    char *valid;		/* valid values */
    int min;			/* valid range */
    int max;
    int *pp;			/* pointer to the parameter in RAM */
  };
