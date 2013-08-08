/*
 *   Space Communications Protocols Standards
 *                               Security Protocol
 */

/*
 * This software was developed by SPARTA, Inc and
 * was produced for the US Government under Contract
 * MDA904-95-C-50015 is subject to Department of Defense
 * Federal Acquisition Regulation Clause 252.227.7013,
 * Alt. 2, Clause 252.227.7013 and Federal Acquisition
 * Regulation Clause 52.227-14, Rights in Data - General
 *
 *
 * NOTICE
 *
 *
 * SPARTA PROVIDES THIS SOFTWARE "AS IS" AND MAKES NO
 * WARRANTY, EXPRESS OR IMPLIED, AS TO THE ACCURACY,
 * CAPABILITY, EFFICIENCY, OR FUNCTIONING OF THE PRODUCT.
 * IN NO EVENT WILL SPARTA BE LIABLE FOR ANY GENERAL,
 * CONSEQUENTIAL, INDIRECT, INCIDENTAL, EXEMPLARY, OR
 * SPECIAL DAMAGES, EVEN IF MITRE HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 * You accept this software on the condition that you
 * indemnify and hold harmless SPARTA, its Board of
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
 */

#ifndef scpssp
#define scpssp
#define MAX_TPDATA_LEN    2048	/* Maximum TP data packet length 
				   (excluding the tcp_PseudoHeader)        */

#ifdef USESCPSNP
#include "net_types.h"
#endif /* USESCPSNP */


/*  Quality-of-Service flags for scps_sp to be found in the 4 low-order
    bits of the clear header  */
#define CONFIDENTIALITY  0x01
#define AUTHENTICATION   0x02
#define SECURITY_LABEL   0x04
#define INTEGRITY        0x08


/* Bitflags indicating presence or absence of optional fields within the
   protected header.
*/
#define ICV_APPEND     0x01
#define PADDING        0x02
#define ENCAPS_NP_ADDR 0x04
#define SEC_LABEL      0x08

/* Note: The optional ICV is appended to the pdu.
*/

/* Error conditions:
*/
enum ERRORS
  {
    MEM_ALLOC_FAILED,
    DATA_OVERFLOW,
    INTEGRITY_CHECK_FAILED,
    AUTHENTICATION_FAILED,
    ERROR_ACCESSING_SA_FILE,
    SA_NOT_FOUND,
    CORRUPTED_SP_PDU,
    SECURITY_LABEL_BAD
  };

void log_sp_error (enum ERRORS error);

#define SECURE_GATEWAY_NO_SECURITY	0
#define SECURE_GATEWAY_ON_DEMAND	1
#define SECURE_GATEWAY_STRICT_SECURITY	2

#endif /* scpssp */
