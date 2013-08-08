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
#include "scpstp.h"
#include "net_types.h"
#include "../include/scps.h"
#include "rt_alloc.h"
#include "route.h"

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: rt_alloc.c,v $ -- $Revision: 1.14 $\n";
#endif

int route_socket_list [ROUTE_SOCKET_LIST_MAX];

extern void free (void *ptr); 
extern void *malloc (size_t size);
extern void *memset (void *s, int c, size_t n);

route *route_list_head = NULL;
extern tp_Socket *tp_allsocs;          /* Pointer to first TP socket */
extern udp_Socket *udp_allsocs;        /* Pointer to first UDP socket */


void
route_initialize ()

{
	int i;

	for (i = 0; i < ROUTE_SOCKET_LIST_MAX; i++) {
		route_socket_list [i] = -1;
	}
}


int
route_create_default (rate, mtu, smtu)
int rate;
int mtu;
int smtu;

{
	int cong_control = 0;
	int new_route_sock = -1;
	int i;
 	route *new_rt;
	int route_sock = -1;
	int rc;
	void *s;

	for (i = 0; i < ROUTE_SOCKET_LIST_MAX; i++) {
		if (route_socket_list [i] == -1) {
			new_route_sock = i;
			break;
		}
	}
	
	if (new_route_sock == -1) {
		printf ("%s %d new route == -1\n", __FILE__, __LINE__);
		return (-1);
	}

	route_sock = scps_socket (AF_INET, SOCK_ROUTE, 0);

	if (route_sock == -1) {
		printf ("%s %d route_sock  == -1\n", __FILE__, __LINE__);
		return (-1);
	}

	route_socket_list [new_route_sock] = route_sock;
	new_rt = (route *) malloc (sizeof (route));
	memset (new_rt, 0, sizeof (route));

	s = scheduler.sockets[route_sock].ptr;
	((tp_Socket *) s)->rt_route = new_rt;

	route_rt_add (new_rt);

#ifdef ASSUME_CORRUPT
        new_rt -> flags = (RT_LINK_AVAIL | RT_COMPRESS | RT_ASSUME_CORRUPT);
#else /* ASSUME_CORRUPT */
        new_rt -> flags = (RT_LINK_AVAIL | RT_COMPRESS | RT_ASSUME_CONGEST);
#endif /* ASSUME_CORRUPT */
        new_rt -> rtt = 0;
        new_rt -> TCPONLY = 0;
        new_rt -> MSS_FF = 0;
        new_rt -> rtt_var = 3000000;
        new_rt -> initial_RTO = 6000000;
	new_rt -> interval = 100;     /* interval - MUST be an even multiple of tcp_TICK (0x111) */

	new_rt -> route_sock_id = route_sock;

#ifdef GATEWAY_ROUTER
	new_rt -> dst_ipaddr = 0x0; 
	new_rt -> dst_netmask = 0xffffffff;
	new_rt -> src_ipaddr = 0x0;
	new_rt -> src_netmask = 0xffffffff;
	new_rt -> dst_higport = 0x0;
	new_rt -> dst_lowport = 0x0;
	new_rt -> src_higport = 0x0;
	new_rt -> src_lowport = 0x0;
	new_rt -> protocol_id = 0x0;
	new_rt -> dscp = 0x0;
	new_rt -> lan_wan = 0x0;
	new_rt -> cong_control = 0x0;
#endif /* GATEWAY_ROUTER */

	if (!mtu) { 
		mtu = MAX_MTU;
	} 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_MTU, &mtu, sizeof (mtu));

	if (!smtu) { 
		smtu = MAX_MTU;
	} 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_SMTU, &smtu, sizeof (mtu));

	if (!rate) { 
		rate = DEFAULT_RATE;
	} 
	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_RATE, &rate, sizeof (rate));
	new_rt -> rate = rate;

	new_rt -> cong_control = cong_control;

	return (1);
}

#ifdef GATEWAY_ROUTER
int
route_add  (src_ipaddr, src_netmask, dst_ipaddr, dst_netmask,
            src_lowport, src_higport, dst_lowport, dst_higport,
	    rate, min_rate, flow_control, mtu, smtu, protocol_id, dscp, lan_wan, cong_control)
uint32_t src_ipaddr, src_netmask, dst_ipaddr, dst_netmask; 
unsigned short src_lowport, src_higport, dst_lowport, dst_higport;
int rate, min_rate, flow_control;
int mtu;
int smtu;
int protocol_id;
int dscp;
int lan_wan;
int cong_control;

{
	int new_route_sock = -1;
	int i;
 	route *new_rt;
	int route_sock = -1;
	int rc;
	void *s;

	for (i = 0; i < ROUTE_SOCKET_LIST_MAX; i++) {
		if (route_socket_list [i] == -1) {
			new_route_sock = i;
			break;
		}
	}
	
	if (new_route_sock == -1) {
		printf ("%s %d new route == -1\n", __FILE__, __LINE__);
		return (-1);
	}

	route_sock = scps_socket (AF_INET, SOCK_ROUTE, 0);

	if (route_sock == -1) {
		printf ("%s %d route_sock  == -1\n", __FILE__, __LINE__);
		return (-1);
	}

	route_socket_list [new_route_sock] = route_sock;
	new_rt = (route *) malloc (sizeof (route));
	memset (new_rt, 0, sizeof (route));

	s = scheduler.sockets[route_sock].ptr;
	((tp_Socket *) s)->rt_route = new_rt;

	route_rt_add (new_rt);

#ifdef ASSUME_CORRUPT
        new_rt -> flags = (RT_LINK_AVAIL | RT_COMPRESS | RT_ASSUME_CORRUPT);
#else /* ASSUME_CORRUPT */
        new_rt -> flags = (RT_LINK_AVAIL | RT_COMPRESS | RT_ASSUME_CONGEST);
#endif /* ASSUME_CORRUPT */
        new_rt -> rtt = 0;
        new_rt -> rtt_var = 3000000;
        new_rt -> initial_RTO = 6000000;
	new_rt -> interval = 100;     /* interval - MUST be an even multiple of tcp_TICK (0x111) */

	new_rt -> route_sock_id = route_sock;

#ifdef GATEWAY_ROUTER
	new_rt -> dst_ipaddr = dst_ipaddr; 
	new_rt -> dst_netmask = dst_netmask;
	new_rt -> src_ipaddr = src_ipaddr;
	new_rt -> src_netmask = src_netmask;
	new_rt -> dst_higport = dst_higport;
	new_rt -> dst_lowport = dst_lowport;
	new_rt -> src_higport = src_higport;
	new_rt -> src_lowport = src_lowport;
	new_rt -> protocol_id = protocol_id;
	new_rt -> dscp = dscp;
	new_rt -> lan_wan = lan_wan;
#endif /* GATEWAY_ROUTER */

	if ((new_rt -> cong_control < 0) || (new_rt -> cong_control > 3)) {
		cong_control = 1;
	}
	new_rt -> cong_control = cong_control;

	if (!mtu) { 
		mtu = MAX_MTU;
	} 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_MTU, &mtu, sizeof (mtu));

	if (!smtu) { 
		smtu = MAX_MTU;
	} 
        rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_SMTU, &smtu, sizeof (mtu));

	if (!rate) { 
		rate = DEFAULT_RATE;
	} 
	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_RATE, &rate, sizeof (rate));
	new_rt -> rate = rate;

	if (!min_rate) { 
		min_rate = DEFAULT_RATE;
	} 
	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_MIN_RATE, &rate, sizeof (min_rate));
	new_rt -> min_rate = min_rate;

#ifdef FLOW_CONTROL_THRESH
	if (!flow_control) { 
		flow_control = 0;
	} 
	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_FLOW_CONTROL, &rate, sizeof (flow_control));
	new_rt -> flow_control = flow_control;
#endif /* FLOW_CONTROL_THRESH */

	if (cong_control == NO_CONGESTION_CONTROL) {
		int zero = 0;
        	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPSTP_CONGEST, &zero, sizeof (zero));
	}

	if (cong_control == VJ_CONGESTION_CONTROL) {
		int one = 1;
        	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPSTP_VJ_CONGEST, &one, sizeof (one));
	}

	if (cong_control == VEGAS_CONGESTION_CONTROL) {
		int one = 1;
        	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPSTP_VEGAS_CONGEST, &one, sizeof (one));
	}

	if (cong_control == FLOW_CONTROL_CONGESTION_CONTROL) {
		int one = 1;
        	rc = scps_setsockopt (route_sock, SCPS_ROUTE, SCPSTP_FLOW_CONTROL_CONGEST, &one, sizeof (one));
	}
#ifndef XXXXX
{
	tp_Socket *tp_tmp = tp_allsocs;
	udp_Socket *udp_tmp = udp_allsocs;

	/* Since we have installed a new route
	 * let's see if that changes things.
 	 */

	while (tp_tmp) {
		if ((((tp_Socket *) tp_tmp)->Initialized != SCPSROUTE)) {
			tp_tmp->rt_route = NULL;
			tp_tmp->rt_route = route_rt_lookup_s (tp_tmp);
		}
		tp_tmp = tp_tmp ->next;
	}

	while (udp_tmp) {
		udp_tmp->rt_route = NULL;
		udp_tmp->rt_route = route_rt_lookup_s ((tp_Socket *) udp_tmp);
		udp_tmp = udp_tmp ->next;
	}
}
#endif /* XXXXX */
	return (new_route_sock);
}
#endif /* GATEWAY_ROUTER */

#ifdef GATEWAY_ROUTER
int
route_delete (route_id)
int route_id;

{
	tp_Socket *tp_tmp = tp_allsocs;
	udp_Socket *udp_tmp = udp_allsocs;
	int route_sock_id = -1;
	tp_Socket *tmp_s;

	if ((route_id < 0) || (route_id > ROUTE_SOCKET_LIST_MAX)) {
		return (-1);
	}

	route_sock_id = route_socket_list [route_id]; 

	if (route_sock_id != -1) {
		route_socket_list [route_id] = -1;
	} else {
		return (-1);
		printf ("OOPS not found\n");
	}
	/* Delete it off the list of routeing sockets */
	while (tp_tmp) {
		if (tp_tmp ->rt_route->route_sock_id == route_sock_id) {
			tp_tmp->rt_route = NULL;
			tp_tmp->rt_route = route_rt_lookup_s (tp_tmp);
		}
		tp_tmp = tp_tmp ->next;
	}

	while (udp_tmp) {
		if (udp_tmp ->rt_route->route_sock_id == route_sock_id) {
			udp_tmp->rt_route = NULL;
			udp_tmp->rt_route = route_rt_lookup_s ((tp_Socket *) udp_tmp);
		}
		udp_tmp = udp_tmp ->next;
	}

 	tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
        route_rt_delete (((tp_Socket *) tmp_s)->rt_route);
	scps_close (route_sock_id);
	return (1);
}
#endif /* GATEWAY_ROUTER */


#ifdef GATEWAY_ROUTER
int
route_avail (route_id)
int route_id;

{
	int route_sock_id = -1;
	tp_Socket *tmp_s;

	if ((route_id < 0) || (route_id > ROUTE_SOCKET_LIST_MAX)) {
		return (-1);
	}

	route_sock_id = route_socket_list [route_id]; 

	if (route_sock_id != -1) {
	} else {
		return (-1);
		printf ("OOPS not found\n");
	}

 	tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
	route_rt_avail (tmp_s->rt_route);
        (((tp_Socket *) tmp_s)->rt_route)->flags |= RT_LINK_AVAIL;

	return (1);
}
#endif /* GATEWAY_ROUTER */



#ifdef GATEWAY_ROUTER
void
route_rt_avail (this_route)
route *this_route;

{
	tp_Socket *tp_tmp = tp_allsocs;

	while (tp_tmp) {
		if (tp_tmp->Initialized != SCPSROUTE) {
			if (tp_tmp->rt_route == this_route) {
				if (tp_tmp->send_buff) {
					struct _hole_element *local_hole;
	
					local_hole = tp_tmp->send_buff->holes;
					while (local_hole) {
      	 			   		if (local_hole->rx_ctr > 0) {
							local_hole->Embargo_Time = 0;
						}
						local_hole = local_hole->next;
					}
				} else {
				}
			}
		}
		tp_tmp = tp_tmp ->next;
	}
}
#endif /* GATEWAY_ROUTER */



#ifdef GATEWAY_ROUTER
void
route_rt_unavail (this_route)
route *this_route;

{
	tp_Socket *tp_tmp = tp_allsocs;

	while (tp_tmp) {
		if (tp_tmp->Initialized != SCPSROUTE) {
			if (tp_tmp->rt_route == this_route) {
				struct timeval mytime;
			
				mytime.tv_sec  = 0;
				mytime.tv_usec = 20000;
			 	clear_timer (tp_tmp->otimers[Rexmit], 1);
				set_timer (&mytime, tp_tmp->otimers[Persist], 1);
			}
		}
		tp_tmp = tp_tmp ->next;
	}
}
#endif /* GATEWAY_ROUTER */



#ifdef GATEWAY_ROUTER
int
route_unavail (route_id)
int route_id;

{
	int route_sock_id = -1;
	tp_Socket *tmp_s;

	if ((route_id < 0) || (route_id > ROUTE_SOCKET_LIST_MAX)) {
		return (-1);
	}

	route_sock_id = route_socket_list [route_id]; 

 	tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
	route_rt_unavail (tmp_s->rt_route);
        (((tp_Socket *) tmp_s)->rt_route)->flags &= ~(RT_LINK_AVAIL);

	return (1);
}
#endif /* GATEWAY_ROUTER */


int
route_rt_add (this_route)
route *this_route;

{
	if (route_list_head) {
		this_route -> next = route_list_head;
		route_list_head = this_route;
	} else {
		this_route ->next = NULL;
		route_list_head = this_route;
	}

	return (1);
}


#ifdef GATEWAY_ROUTER
int
route_rt_delete (this_route)
route *this_route;

{
	route *tmp_this = NULL;
	route *tmp_prev = NULL;

	if (route_list_head == this_route) {
		route_list_head = route_list_head -> next;
		free (this_route);
		return (1);
	}

	tmp_prev = route_list_head;
	tmp_this = route_list_head -> next;

	while (tmp_this) {
		if (tmp_this == this_route) {
			tmp_prev->next = tmp_this -> next;
			free (this_route);
			return (1);
		}
		tmp_prev = tmp_this;
		tmp_this = tmp_this -> next;
	}

	printf ("%s %d ERROR was unable to delete route %p\n", __FILE__, __LINE__, this_route);
	return (0);
}
#endif /* GATEWAY_ROUTER */

#ifdef GATEWAY_ROUTER
route *
route_rt_lookup_s (s)
tp_Socket *s;

{
	route *rt;

	rt =  route_rt_lookup (s->my_ipv4_addr, s->his_ipv4_addr, s->myport, s->hisport, s->protocol_id ,s->DSCP, s->gateway_lan_or_wan);

	if (!rt) {
		rt = s->rt_route_def;
	}

	return (rt);
}
#endif /* GATEWAY_ROUTER */

#ifdef GATEWAY_ROUTER
route *
route_rt_lookup (src_ipaddr, dst_ipaddr, src_port, dst_port, proto_id, dscp, lan_or_wan)

uint32_t src_ipaddr;
uint32_t dst_ipaddr;
unsigned short src_port;
unsigned short dst_port;
unsigned char proto_id;
unsigned char dscp;
int lan_or_wan;

{
	route *rt;

	if ((rt = route_rt_lookup_ipport_both (src_ipaddr, dst_ipaddr, src_port, dst_port))) {
		/* We found a match */
	} else if ((rt = route_rt_lookup_ipport_dst (dst_ipaddr, dst_port))) {
		/* We found a match */
	} else if ((rt = route_rt_lookup_ip_both (src_ipaddr, dst_ipaddr))) {
		/* We found a match */
#ifdef GATEWAY_ROUTER_DSCP
	} else if ((rt = route_rt_lookup_lan_wan_dscp (lan_or_wan, dscp))) {
		/* We found a match */
#endif /* GATEWAY_ROUTER_DSCP */
	} else if ((rt = route_rt_lookup_ip_dst (dst_ipaddr))) {
		/* We found a match */

	} else {
		/* We must choose a default */
	}

	return (rt);
}
#endif /* GATEWAY_ROUTER */

#ifdef GATEWAY_ROUTER
route *
route_rt_lookup_ipport_both (src_ipaddr, dst_ipaddr, src_port, dst_port)
uint32_t src_ipaddr;
uint32_t dst_ipaddr;
unsigned short src_port;
unsigned short dst_port;

{
	uint32_t good_netmask = 0x0;
	route *good_rt = NULL;
	route *route_list = route_list_head;

	while (route_list) {
		if (((route_list -> dst_ipaddr & route_list -> dst_netmask) ==
		     (ntohl (dst_ipaddr) & route_list ->dst_netmask)) &&
		    ((route_list -> src_ipaddr & route_list -> src_netmask) ==
		     (ntohl (src_ipaddr) & route_list ->src_netmask)) &&
		    ((route_list -> src_lowport <= ntohs (src_port)) &&
		     (route_list -> src_higport >= ntohs (src_port))) &&
		    ((route_list -> dst_lowport <= ntohs (dst_port)) &&
		     (route_list -> dst_higport >= ntohs (dst_port)))) {
 
			if (route_list -> dst_netmask > good_netmask) {
				good_netmask = route_list -> dst_netmask;
				good_rt = route_list;
			}

		}

		route_list = route_list -> next;
	}

	return (good_rt);
}
#endif /* GATEWAY_ROUTER */


#ifdef GATEWAY_ROUTER
route *
route_rt_lookup_ipport_dst (dst_ipaddr, dst_port)
uint32_t dst_ipaddr;
unsigned short dst_port;

{
	uint32_t good_netmask = 0x0;
	route *good_rt = NULL;
	route *route_list = route_list_head;

	while (route_list) {
		if (((route_list -> dst_ipaddr & route_list -> dst_netmask) ==
		     (ntohl (dst_ipaddr) & route_list -> dst_netmask)) &&
		    ((route_list -> dst_lowport <= ntohs (dst_port)) &&
		     (route_list -> dst_higport >= ntohs (dst_port)))) {
			if (route_list -> dst_netmask > good_netmask) {
				good_netmask = route_list -> dst_netmask;
				good_rt = route_list;
			}

		}

		route_list = route_list -> next;
	}

	return (good_rt);
}
#endif /* GATEWAY_ROUTER */

#ifdef GATEWAY_ROUTER
route *
route_rt_lookup_ip_both (src_ipaddr, dst_ipaddr)
uint32_t src_ipaddr;
uint32_t dst_ipaddr;

{
	uint32_t good_netmask = 0x0;
	route *good_rt = NULL;
	route *route_list = route_list_head;

	while (route_list) {
		if (((route_list -> dst_ipaddr & route_list -> dst_netmask) ==
		     (ntohl (dst_ipaddr) & route_list ->dst_netmask)) &&
		    ((route_list -> src_ipaddr & route_list -> src_netmask) ==
		     (ntohl (src_ipaddr) & route_list ->src_netmask))) {

			if (route_list -> dst_netmask > good_netmask) {
				good_netmask = route_list -> dst_netmask;
				good_rt = route_list;
			}

		}

		route_list = route_list -> next;
	}

	return (good_rt);
}
#endif /* GATEWAY_ROUTER */

#ifdef GATEWAY_ROUTER
route *
route_rt_lookup_ip_dst (dst_ipaddr)
uint32_t dst_ipaddr;

{
	uint32_t good_netmask = 0x0;
	route *good_rt = NULL;
	route *route_list = route_list_head;

	while (route_list) {

		if ((route_list -> dst_ipaddr & route_list -> dst_netmask) ==
		     (ntohl (dst_ipaddr) & route_list ->dst_netmask)) {

			if (route_list -> dst_netmask > good_netmask) {
				good_netmask = route_list -> dst_netmask;
				good_rt = route_list;
			}
		}
		route_list = route_list -> next;
	}

	return (good_rt);
}
#endif /* GATEWAY_ROUTER */

#ifdef GATEWAY_ROUTER 
#ifdef GATEWAY_ROUTER_DSCP 
route *
route_rt_lookup_ip_dscp (dst_ipaddr, dscp)
uint32_t dst_ipaddr;
unsigned char dscp;

{
	uint32_t good_netmask = 0x0;
	route *good_rt = NULL;
	route *route_list = route_list_head;

	while (route_list) {
		if (route_list->dscp == dscp) {
			if ((route_list -> dst_ipaddr & route_list -> dst_netmask) ==
			     (ntohl (dst_ipaddr) & route_list ->dst_netmask)) {
	
				if (route_list -> dst_netmask > good_netmask) {
					good_netmask = route_list -> dst_netmask;
					good_rt = route_list;
				}
			}
		}
		route_list = route_list -> next;
	}

	return (good_rt);
}

#endif /* GATEWAY_ROUTER_DSCP */
#endif /* GATEWAY_ROUTER */

#ifdef GATEWAY_ROUTER 
#ifdef GATEWAY_ROUTER_DSCP 
route *
route_rt_lookup_lan_wan_dscp (lan_or_wan, dscp)
uint32_t lan_or_wan;
unsigned char dscp;

{
	route *good_rt = NULL;
	route *route_list = route_list_head;

	while (route_list) {
		if ( (route_list->dscp == dscp) && (route_list->lan_wan == lan_or_wan) ) {
			good_rt = route_list;
			break;
		}
		route_list = route_list -> next;
	}

	return (good_rt);
}

#endif /* GATEWAY_ROUTER_DSCP */
#endif /* GATEWAY_ROUTER */

int
route_modify (route_id, tag, value)
int route_id;
int tag;
int value;

{
	int rc = 1;
	int route_sock_id = -1;
	tp_Socket *tmp_s;

	if ((route_id < 0) || (route_id > ROUTE_SOCKET_LIST_MAX)) {
		return (-1);
	}

	route_sock_id = route_socket_list [route_id]; 

	if (route_sock_id == -1) {
		printf ("%s %d OOPS route_sock_id not found\n", __FILE__, __LINE__);
		return (-1);
	}

	switch (tag) {
		case GW_ROUTE_ATTRIB_RATE:
        		rc = scps_setsockopt (route_sock_id, SCPS_ROUTE, SCPS_RATE,
					     &value, sizeof (value));
                        {
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_RATE;
			tmp_s ->rt_route ->rate = value;
			}
		break;

		case GW_ROUTE_ATTRIB_MIN_RATE:
        		rc = scps_setsockopt (route_sock_id, SCPS_ROUTE, SCPS_MIN_RATE,
					     &value, sizeof (value));
                        {
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_MIN_RATE;
			tmp_s ->rt_route ->min_rate = value;
			}
		break;

		case GW_ROUTE_ATTRIB_FLOW_CONTROL:
        		rc = scps_setsockopt (route_sock_id, SCPS_ROUTE, SCPS_FLOW_CONTROL,
					     &value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_FLOW_CONTROL;
		break;

		case GW_ROUTE_ATTRIB_MTU:
        		rc = scps_setsockopt (route_sock_id, SCPS_ROUTE, SCPS_MTU,
					     &value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_MTU;
		break;

		case GW_ROUTE_ATTRIB_SMTU:
        		rc = scps_setsockopt (route_sock_id, SCPS_ROUTE, SCPS_SMTU,
					     &value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_SMTU;
		break;

		case GW_ROUTE_ATTRIB_CONG_CONTROL:
	                 if (value == 0) {
                 		int zero = 0;
                         	rc = scps_setsockopt (route_sock_id, SCPS_ROUTE, SCPSTP_CONGEST, &zero, sizeof (zero));
                 	}
                 
                 	if (value == 1) {
                 		int one = 1;
                         	rc = scps_setsockopt (route_sock_id, SCPS_ROUTE, SCPSTP_VJ_CONGEST, &one, sizeof (one));
                 	}

                 	if (value == 2) {
		                int one = 1;
                         	rc = scps_setsockopt (route_sock_id, SCPS_ROUTE, SCPSTP_VEGAS_CONGEST, &one, sizeof (one));
                 	}
                 	if (value == 3) {
		                int one = 1;
        			rc = scps_setsockopt (route_sock_id, SCPS_ROUTE, SCPSTP_FLOW_CONTROL_CONGEST, &one, sizeof (one));
                 	}
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_CONG_CONTROL;
		break;

		case GW_ROUTE_ATTRIB_SEND_BUFFER:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, SCPS_SOCKET, SCPS_SO_SNDBUF,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_SEND_BUFFER;
		} break;

		case GW_ROUTE_ATTRIB_RECEIVE_BUFFER:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, SCPS_SOCKET, SCPS_SO_RCVBUF,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_RECEIVE_BUFFER;
		} break;

		case GW_ROUTE_ATTRIB_MIN_RTO_VALUE:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_RTOMIN,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_MIN_RTO_VALUE;
		} break;

		case GW_ROUTE_ATTRIB_MAX_RTO_VALUE:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_RTOMAX,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_MAX_RTO_VALUE;
		} break;

		case GW_ROUTE_ATTRIB_MAX_RTO_CTR:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_TIMEOUT,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_MAX_RTO_CTR;
		} break;

		case GW_ROUTE_ATTRIB_MAX_PERSIST_CTR:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_MAXPERSIST_CTR,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_MAX_PERSIST_CTR;
		} break;

		case GW_ROUTE_ATTRIB_RTO_PERSIST_MAX:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_RTOPERSIST_MAX,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_RTO_PERSIST_MAX;
		} break;

		case GW_ROUTE_ATTRIB_RTO_PERSIST_CTR:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_RTO_TO_PERSIST_CTR,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_RTO_PERSIST_CTR;
		} break;

		case GW_ROUTE_ATTRIB_EMBARGO_FAST_RXMIT_CTR:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_EMBARGO_FAST_RXMIT_CTR,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_EMBARGO_FAST_RXMIT_CTR;
		} break;

		case GW_ROUTE_ATTRIB_TWO_MSL_TIMEOUT:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_2MSLTIMEOUT,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_TWO_MSL_TIMEOUT;
		} break;

		case GW_ROUTE_ATTRIB_ACK_BEHAVE:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_ACKBEHAVE,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_ACK_BEHAVE;
		} break;

		case GW_ROUTE_ATTRIB_ACK_DELAY:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_ACKDELAY,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_ACK_DELAY;
		} break;

		case GW_ROUTE_ATTRIB_ACK_FLOOR:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_ACKFLOOR,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_ACK_FLOOR;
		} break;

		case GW_ROUTE_ATTRIB_TIME_STAMPS:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_TIMESTAMP,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_TIME_STAMPS;
		} break;


		case GW_ROUTE_ATTRIB_SNACK:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_SNACK,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_SNACK;
		} break;

		case GW_ROUTE_ATTRIB_TCP_ONLY:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, SCPS_ROUTE, SCPS_TCPONLY,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_TCP_ONLY;
		} break;

		case GW_ROUTE_ATTRIB_SNACK_DELAY:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_SNACK_DELAY,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_SNACK_DELAY;
		} break;

		case GW_ROUTE_ATTRIB_NO_DELAY:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, SCPS_SOCKET, SCPS_SO_NDELAY,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_NO_DELAY;
		} break;

		case GW_ROUTE_ATTRIB_COMPRESS:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_COMPRESS,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_COMPRESS;
		} break;

		case GW_ROUTE_ATTRIB_VEGAS_ALPHA:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_VEGAS_ALPHA,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_VEGAS_ALPHA;
		} break;

		case GW_ROUTE_ATTRIB_VEGAS_BETA:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_VEGAS_BETA,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_VEGAS_BETA;
		} break;

		case GW_ROUTE_ATTRIB_VEGAS_GAMMA:
		{
			tp_Socket *tmp_s;
			rc = scps_setsockopt (route_sock_id, PROTO_SCPSTP, SCPSTP_VEGAS_GAMMA,
				&value, sizeof (value));
			tmp_s = (tp_Socket *) scheduler.sockets[route_sock_id].ptr;
			tmp_s->rt_route->new_params_flag |=GW_ROUTE_ATTRIB_VEGAS_GAMMA;
		} break;

		break;

	}

	return (rc);
}

