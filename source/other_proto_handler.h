#ifndef OTHER_PROTO_HANDLER_H
#define OTHER_PROTO_HANDLER_H 
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

#include "scps.h"
#include "scpstp.h"
#include "scpserrno.h"
#include "tp_debug.h"
#include "gateway.h"
#include <stdio.h>
#include <math.h>


#ifdef SCPSSP
#include "scps_sp.h"
#endif /* SCPSSP */

#include "rt_alloc.h"

#include "scps_ip.h"
#include "scps_np.h"
#include "rs_config.h"

#define AIF	0
#define BIF	1

#define OTHER_PROTO_QLEN_DEFAULT	5

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: other_proto_handler.h,v $ -- $Revision: 1.4 $\n";
#endif

typedef
struct other_proto_pkt {
   unsigned char data[MAX_LL_DATA];
   int length;
   int offset;
   int fd;
   unsigned char src_mac_addr [6];
   unsigned char dst_mac_addr [6];
   unsigned short frame_type;
} other_proto_pkt_t;


typedef
struct other_pkt_q {
   queue *q;
   route *rt;
   route *def_rt;
} other_proto_q_t;

/*
 * Handler for incoming TP packets.
 */

void
other_proto_Handler (
struct _interface *interface,
struct _ll_queue_element **buffer,
int max_len,
int *offset,
scps_np_rqts *rqts,
unsigned char proto);

void other_proto_non_ip_Handler (
int interface_side,
struct _ll_queue_element **buffer,
scps_np_rqts *rqts,
int fd);

void other_proto_ipv6_Handler (
int interface_side,
struct _ll_queue_element **buffer,
scps_np_rqts *rqts,
int fd);

void other_proto_init ();
void other_proto_emit ();
void other_proto_non_ip_emit ();
void other_proto_ipv6_emit ();

#endif /* OTHER_PROTO_HANDLER_H */
