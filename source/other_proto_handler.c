#ifdef GATEWAY
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
 * The expodef_rt from the United States or the subsequent 
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


#include "other_proto_handler.h"

#ifdef SCPSSP
#include "scps_sp.h"
#endif /* SCPSSP */

#ifdef GATEWAY_ROUTER
#include "rt_alloc.h"
#endif /* GATEWAY_ROUTER */

#ifdef TAP_INTERFACE
#include "tap.h"
#endif /* TAP_INTERFACE */

#include "scps_ip.h"
#include "scps_np.h"
#include "scps_defines.h"

int scps_np_get_template (scps_np_rqts * rqts,
			  scps_np_template * templ);
 
#ifdef GATEWAY
#include "rs_config.h"
extern GW_ifs gw_ifs;
int init_port_number_offset;
extern route *def_route;
extern route *other_route;
#endif /* GATEWAY */

#ifdef Sparc
#ifndef SOLARIS
extern int gettimeofday (struct timeval *tp, struct timezone *tzp);
#endif /* SOLARIS */
#endif /* Sparc */

extern struct _interface *sock_interface;
extern struct _interface *divert_interface;

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: other_proto_handler.c,v $ -- $Revision: 1.10 $\n";
#endif

extern tp_Socket *tp_allsocs;	/* Pointer to first TP socket */
extern uint32_t tp_now;
extern struct timeval end_time;
extern float elapsed_time;
extern int delayed_requested;
int delayed_sent;
extern short tp_id;
extern int cluster_check;

struct _ll_queue_element *in_data;      /* packet buffer */
extern GW_ifs gw_ifs;

int abs (int i);		/* test function prototype */

other_proto_q_t other_proto [PROTO_MAX] [2];
other_proto_q_t other_proto_non_ip [2];
other_proto_q_t other_proto_ipv6 [2];


/*
 * Handler for incoming TP packets.
 */

void
other_proto_init ()

{
	int i, j;

	for (i = 0; i < PROTO_MAX; i++) {
		for (j = 0; j < 2; j++) {
			other_proto [i] [j]. q = q_create ();
			other_proto [i] [j]. def_rt = NULL;
			other_proto [i] [j]. rt = NULL;
		}
	}

        for (j = 0; j < 2; j++) {
                other_proto_non_ip [j]. q = q_create ();
                other_proto_non_ip [j]. def_rt = NULL;
                other_proto_non_ip [j]. rt = NULL;
        }
        for (j = 0; j < 2; j++) {
                other_proto_ipv6 [j]. q = q_create ();
                other_proto_ipv6 [j]. def_rt = NULL;
                other_proto_ipv6 [j]. rt = NULL;
        }

}

void
other_proto_non_ip_Handler (interface_side, buffer, rqts, fd)
int interface_side;
struct _ll_queue_element **buffer;
scps_np_rqts *rqts;
int fd;

{
	other_proto_pkt_t *pkt;

	if (other_proto_non_ip [interface_side].q->q_len <= gw_ifs.c_other_proto_qlen) {
		if (interface_side == BIF) {
			other_proto_non_ip [interface_side].rt = other_route;
			other_proto_non_ip [interface_side].def_rt = other_route;
		} else {
			other_proto_non_ip [interface_side].rt = def_route;
			other_proto_non_ip [interface_side].def_rt = def_route;
		}

		pkt =  (other_proto_pkt_t *) malloc (sizeof (other_proto_pkt_t));
		pkt->fd = fd;
		memcpy (&(pkt->data [0]), (*buffer)->data, (*buffer)->size);
		pkt->length = (*buffer)->size;
		pkt->offset = (*buffer)->offset;
		q_addt (other_proto_non_ip [interface_side].q, (char *) pkt);
	}
        free_ll_queue_element (rqts->interface, *buffer);

}

void
other_proto_ipv6_Handler (interface_side, buffer, rqts, fd)
int interface_side;
struct _ll_queue_element **buffer;
scps_np_rqts *rqts;
int fd;

{
        other_proto_pkt_t *pkt;

        if (other_proto_ipv6 [interface_side].q->q_len <= gw_ifs.c_other_proto_qlen) {
                if (interface_side == BIF) {
                        other_proto_ipv6 [interface_side].rt = other_route;
                        other_proto_ipv6 [interface_side].def_rt = other_route;
                } else {
                        other_proto_ipv6 [interface_side].rt = def_route;
                        other_proto_ipv6 [interface_side].def_rt = def_route;
                }

                pkt =  (other_proto_pkt_t *) malloc (sizeof (other_proto_pkt_t));
                pkt->fd = fd;
                memcpy (&(pkt->data [0]), (*buffer)->data, (*buffer)->size);
                pkt->length = (*buffer)->size;
                pkt->offset = (*buffer)->offset;
                q_addt (other_proto_ipv6 [interface_side].q, (char *) pkt);
        }
        free_ll_queue_element (rqts->interface, *buffer);

}


void
other_proto_Handler (interface, buffer, max_len, offset, rqts, proto)
struct _interface *interface;
struct _ll_queue_element **buffer;
int max_len;
int *offset;
scps_np_rqts *rqts;
unsigned char proto;

{
  other_proto_pkt_t *pkt;
  int interface_side = -1;
  int fd;


  if (rqts->divert_port_number == gw_ifs.aif_divport) {
	interface_side = BIF;
	fd = interface->tap_b_fd;
        other_proto [proto] [interface_side].rt = other_route;
        other_proto [proto] [interface_side].def_rt = other_route;
  } else {
	interface_side = AIF;
	fd = interface->tap_a_fd;
        other_proto [proto] [interface_side].rt = def_route;
        other_proto [proto] [interface_side].def_rt = def_route;
  }

/*
  if (q_empty (other_proto [proto] [interface_side].q)) {
	other_proto [proto] [interface_side] .rt =
	       other_proto_get_route ();
  }
*/

  if (other_proto [proto] [interface_side].q->q_len <=
      gw_ifs.c_other_proto_qlen) {

      pkt =  (other_proto_pkt_t *) malloc (sizeof (other_proto_pkt_t));
      pkt->fd = fd;
      memcpy (&(pkt->src_mac_addr [0]), &(rqts->src_mac_addr [0]),6);
      memcpy (&(pkt->dst_mac_addr [0]), &(rqts->dst_mac_addr [0]),6);
      pkt->frame_type = rqts->frame_type;
      memcpy (&(pkt->data [0]), (*buffer)->data, MAX_LL_DATA);
      pkt->length = (*buffer)->size;
      pkt->offset = (*buffer)->offset;
      q_addt (other_proto [proto] [interface_side].q, (char *) pkt); 
  }

      free_ll_queue_element (rqts->interface, *buffer);
}


void
other_proto_emit ()

{
	int i, j;
  	other_proto_pkt_t *pkt;
        int rc;
	int len;

	for (i = 0; i < PROTO_MAX; i++) {
		for (j = 0; j < 2; j++) {
			if (q_empty (other_proto [i] [j].q)) {

			} else {
				if (( ((other_proto_pkt_t *)
				       other_proto [i] [j].q->q_head->qe_data)->length <
				       other_proto [i] [j].rt->current_credit) 
#ifdef FLOW_CONTROL_THRESH
				 && ((other_proto [i] [j].rt->cong_control != FLOW_CONTROL_CONGESTION_CONTROL) ||
				    ((other_proto [i] [j].rt->cong_control == FLOW_CONTROL_CONGESTION_CONTROL) &&
			             (((other_proto_pkt_t *)
                                     other_proto [i] [j].q->q_head->qe_data)->length <
                                       other_proto [i] [j].rt->flow_control)))
#endif /* FLOW_CONTROL_THRESH */
									) {	
					pkt = (other_proto_pkt_t *) q_deq (other_proto [i] [j].q);
				
					len = pkt->length;

       	                         	pkt->offset -=SIZE_OF_ETHER_PART;
       	   	                        pkt->length +=SIZE_OF_ETHER_PART;

					rc = ll_tap_qk_send (pkt->fd, 
                                                pkt->data + pkt->offset,
					        pkt->length);
					if (rc > 0) {
       						other_proto [i] [j].rt->current_credit -= len;
#ifdef FLOW_CONTROL_THRESH
				    		if (other_proto [i] [j].rt->cong_control ==
                                                     FLOW_CONTROL_CONGESTION_CONTROL) {
       							other_proto [i] [j].rt->flow_control -= len;
						}
#endif /* FLOW_CONTROL_THRESH */
					}
					free (pkt);
				} else if (gw_ifs.c_other_proto_xrate_drop == 1) {
					pkt = (other_proto_pkt_t *) q_deq (other_proto [i] [j].q);
					free (pkt);
				} else {

				}
			}
		}
	}
}



void
other_proto_non_ip_emit ()

{
	int j;
  	other_proto_pkt_t *pkt;
        int rc;

	for (j = 0; j < 2; j++) {
		if (q_empty (other_proto_non_ip [j].q)) {

		} else {
			if ( ( ((other_proto_pkt_t *)
			       other_proto_non_ip [j].q->q_head->qe_data)->length <
			       other_proto_non_ip [j].rt->current_credit) 
#ifdef FLOW_CONTROL_THRESH
	   		    && ((other_proto_non_ip  [j].rt->cong_control != FLOW_CONTROL_CONGESTION_CONTROL) ||
		    	       ((other_proto_non_ip [j].rt->cong_control == FLOW_CONTROL_CONGESTION_CONTROL) &&
			       (((other_proto_pkt_t *)
                               other_proto_non_ip [j].q->q_head->qe_data)->length <
                                other_proto_non_ip [j].rt->flow_control)))
#endif /* FLOW_CONTROL_THRESH */
									) {	
				pkt = (other_proto_pkt_t *) q_deq (other_proto_non_ip [j].q);
	
				rc = ll_tap_qk_send (pkt->fd, 
       	                                       pkt->data + pkt->offset,
				        pkt->length);

				if (rc > 0) {
       					other_proto_non_ip [j].rt->current_credit -= rc;
#ifdef FLOW_CONTROL_THRESH
				    	if (other_proto_non_ip [j].rt->cong_control ==
                                            FLOW_CONTROL_CONGESTION_CONTROL) {
       						other_proto_non_ip [j] .rt->flow_control -= rc;
					}
#endif /* FLOW_CONTROL_THRESH */
				}

				free (pkt);
			} else if (gw_ifs.c_other_proto_xrate_drop == 1) {
				pkt = (other_proto_pkt_t *) q_deq (other_proto_non_ip [j].q);
				free (pkt);
			} else {
	
			}
		}
	}
}

void
other_proto_ipv6_emit ()

{
        int j;
        other_proto_pkt_t *pkt;
        int rc;

        for (j = 0; j < 2; j++) {
                if (q_empty (other_proto_ipv6 [j].q)) {

                } else {
                        if ( ( ((other_proto_pkt_t *)
                               other_proto_ipv6 [j].q->q_head->qe_data)->length <
                               other_proto_ipv6 [j].rt->current_credit)
#ifdef FLOW_CONTROL_THRESH
	   		    && ((other_proto_non_ip  [j].rt->cong_control != FLOW_CONTROL_CONGESTION_CONTROL) ||
		    	       ((other_proto_non_ip [j].rt->cong_control == FLOW_CONTROL_CONGESTION_CONTROL) &&
			       (((other_proto_pkt_t *)
                               other_proto_non_ip [j].q->q_head->qe_data)->length <
                                other_proto_non_ip [j].rt->flow_control)))
#endif /* FLOW_CONTROL_THRESH */
				) {
                                pkt = (other_proto_pkt_t *) q_deq (other_proto_ipv6 [j].q);

                                rc = ll_tap_qk_send (pkt->fd,
                                               pkt->data + pkt->offset,
                                        pkt->length);

				if (rc > 0) {
                                	other_proto_ipv6 [j].rt->current_credit -= rc;
#ifdef FLOW_CONTROL_THRESH
				    	if (other_proto_non_ip [j].rt->cong_control ==
                                            FLOW_CONTROL_CONGESTION_CONTROL) {
       						other_proto_non_ip [j] .rt->flow_control -= rc;
					}
#endif /* FLOW_CONTROL_THRESH */
				}
                                free (pkt);
                        } else if (gw_ifs.c_other_proto_xrate_drop == 1) {
                                pkt = (other_proto_pkt_t *) q_deq (other_proto_ipv6 [j].q);
                                free (pkt);
                        } else {

                        }
                }
        }
}



#endif /* TAP_INTERFACE */
#endif /* GATEWAY */
