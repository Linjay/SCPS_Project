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
#include "route.h"

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: route.c,v $ -- $Revision: 1.4 $\n";
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
route_create (rate, mtu, smtu)
int rate;
int mtu;
int smtu;

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

	return (1);
}


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
			tmp_prev = tmp_this -> next;
			free (this_route);
			return (1);
		}
		tmp_prev = tmp_this;
		tmp_this = tmp_this -> next;
	}

	printf ("%s %d ERROR was unable to delete route %p\n", __FILE__, __LINE__, this_route);
	return (0);
}
