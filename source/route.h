/********************************************************
 *
 *                             NOTICE
 *
 * "This software was produced for the U.S. Government under
 * Contract No's. DAAB07-97-C-E601, F19628-94-C-0001,
 * NAS5-32607, and JPL contract 752939 and is subject
 * to the Rights in Noncommercial Computer Software and
 * Noncommercial Computer Software Documentation Clause
 * at (DFARS) 252.227-7014 (JUN 95), and the Rights in
 * Technical Data and Computer Software Clause at (DFARS)
 * 252.227-7013 (OCT 88) with Alternate II (APR 93),
 * FAR 52.227-14 Rights in Data General, and Article GP-51,
 * Rights in Data - General, respectively.
 *
 *        (c) 1999 The MITRE Corporation
 *
 * MITRE PROVIDES THIS SOFTWARE "AS IS" AND MAKES NO
 * WARRANTY, EXPRESS OR IMPLIED, AS TO THE ACCURACY,
 * CAPABILITY, EFFICIENCY, OR FUNCTIONING OF THE PRODUCT.
 * IN NO EVENT WILL MITRE BE LIABLE FOR ANY GENERAL,
 * CONSEQUENTIAL, INDIRECT, INCIDENTAL, EXEMPLARY, OR
 * SPECIAL DAMAGES, EVEN IF MITRE HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 * You accept this software on the condition that you
 * indemnify and hold harmless MITRE, its Board of
 * Trustees, officers, agents and employees, from any and
 * all liability or damages to third parties, including
 * attorneys' fees, court costs, and other related costs
 * and expenses, arising our of your use of the Product
 * irrespective of the cause of said liability, except
 * for liability arising from claims of US patent
 * infringements.
 *
 * The export from the United States or the subsequent
 * reexport of this software is subject to compliance
 * with United States export control and munitions
 * control restrictions.  You agree that in the event you
 * seek to export this software you assume full
 * responsibility for obtaining all necessary export
 * licenses and approvals and for assuring compliance
 * with applicable reexport restrictions.
 *
 ********************************************************/


#ifdef SCPS_ROUTE_H
#define SCPS_ROUTE_H  
#endif /* SCPS_ROUTE_H */

#include "scps.h"
#include "scps_ip.h"
#include "scpsudp.h"
#include "scpstp.h"
#include "net_types.h"
#include "../include/scps.h"
#include "../include/route.h"
 
void route_initialize (void);
void init_default_routes (void);
int route_create (int rate, int mtu, int smtu);
int route_delete (int this_route);
int route_rt_add (route *this_route);
int route_rt_delete (route *this_route);
void  route_rt_avail (route *this_route);
void  route_rt_unavail (route *this_route);


