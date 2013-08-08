#ifdef TAP_INTERFACE
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
#include "scps_ip.h"
#include "scpsudp.h"
#include "tp_debug.h"  // Included for LOG_PACKET in case DEBUG_TCPTRACE is defined.

#ifdef LINUX
#include <linux/if_tun.h>
#endif

#if defined(__FreeBSD__) || defined(__NetBSD__)
#include <net/if_tap.h>
#endif

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tap.h,v $ -- $Revision: 1.5 $\n";
#endif

int tap_open (char dev []);

int ll_tap_qk_send (int tun_fd, unsigned char *data, int len);

int ll_tap_send  (struct _interface *interface, uint32_t remote_internet_addr,
                  int protocol, int data_len, struct msghdr *my_msg,
                  route *a_route, scps_np_rqts *rqts);

int tap_ind (struct _interface *interface, struct _ll_queue_element **buffer,
             int max_len, int *offset, scps_np_rqts *rqts);

void gateway_tap_cleanup(int a);

void gateway_tap_rules (void);

#endif /* TAP_INTERFACE */
