/* The following software implements the tm driver test module for the
 * STRV-1d flight test
 */


#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>           /* struct timeval */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gw_route_cmdr.h"

extern char Usage [];

extern unsigned char command;
extern char *gateway_host;
extern char *src_ip_host;
extern unsigned int src_netmask_host;
extern char *dst_ip_host;
extern unsigned int dst_netmask_host;

extern int route_id;

extern struct sockaddr_in gw_route_server;

extern int s_gw_route_cmdr;

extern uint32_t rate;
extern uint32_t min_rate;
extern uint32_t flow_control;
extern uint32_t mtu;
extern uint32_t smtu;
extern int	protocol_id;
extern int	cong_control;
extern int	send_buffer;
extern int	receive_buffer;
extern int	min_rto_value;
extern int	max_rto_value;
extern int	max_rto_ctr;
extern int	max_persist_ctr;
extern int 	rto_persist_max;
extern int	rto_persist_ctr;
extern int	embargo_fast_rxmit_ctr;
extern int 	two_msl_timeout;
extern int	ack_behave;
extern int	ack_delay;
extern int	ack_floor;
extern int	time_stamps;
extern int	snack;
extern int	no_delay;
extern int	snack_delay;
extern int	tcp_only;
extern int	compress;
extern int	vegas_alpha;
extern int	vegas_beta;
extern int	vegas_gamma;

gateway_command_t route_mod;

void
build_route_modify_cmd ()

{
	route_mod.command = GW_COMMAND_ROUTE_MODIFY;
	route_mod.seq_num = 0x1;
	
	if (route_id >= 0) {
		route_mod.data.route_mod.route_id = route_id;
	}
	
	if (rate) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_RATE;
		route_mod.data.route_mod.rate = rate;
	} 
	if (min_rate) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_MIN_RATE;
		route_mod.data.route_mod.min_rate = min_rate;
	} 
	if (flow_control) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_FLOW_CONTROL;
		route_mod.data.route_mod.flow_control = flow_control;
	} 
	if (mtu) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_MTU;
		route_mod.data.route_mod.mtu = mtu;
	} 
	if (smtu) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_SMTU;
		route_mod.data.route_mod.smtu = smtu;
	} 

	if (cong_control != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_CONG_CONTROL;
		route_mod.data.route_mod.cong_control = cong_control;
	} 

	if (send_buffer != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_SEND_BUFFER;
		route_mod.data.route_mod.send_buffer = send_buffer;
	} 

	if (receive_buffer != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_RECEIVE_BUFFER;
		route_mod.data.route_mod.receive_buffer = receive_buffer;
	} 
 
	if (vegas_alpha != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_VEGAS_ALPHA;
		route_mod.data.route_mod.vegas_alpha = vegas_alpha;
	} 

	if (vegas_beta != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_VEGAS_BETA;
		route_mod.data.route_mod.vegas_beta = vegas_beta;
	} 

	if (vegas_gamma != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_VEGAS_GAMMA;
		route_mod.data.route_mod.vegas_gamma = vegas_gamma;
	} 

	if (max_rto_value != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_MAX_RTO_VALUE;
		route_mod.data.route_mod.max_rto_value = max_rto_value;
	} 

	if (max_rto_ctr != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_MAX_RTO_CTR;
		route_mod.data.route_mod.max_rto_ctr = max_rto_ctr;
	} 

	if (max_persist_ctr != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_MAX_PERSIST_CTR;
		route_mod.data.route_mod.max_persist_ctr = max_persist_ctr;
	} 

	if (rto_persist_max != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_RTO_PERSIST_MAX;
		route_mod.data.route_mod.rto_persist_max = rto_persist_max;
	} 

	if (rto_persist_ctr != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_RTO_PERSIST_CTR;
		route_mod.data.route_mod.rto_persist_ctr = rto_persist_ctr;
	} 

	if (embargo_fast_rxmit_ctr != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_EMBARGO_FAST_RXMIT_CTR;
		route_mod.data.route_mod.embargo_fast_rxmit_ctr = embargo_fast_rxmit_ctr;
	} 

	if (two_msl_timeout != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_TWO_MSL_TIMEOUT;
		route_mod.data.route_mod.two_msl_timeout = two_msl_timeout;
	} 

	if (ack_behave != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_ACK_BEHAVE;
		route_mod.data.route_mod.ack_behave = ack_behave;
	} 

	if (ack_delay != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_ACK_DELAY;
		route_mod.data.route_mod.ack_delay = ack_delay;
	} 

	if (ack_floor != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_ACK_FLOOR;
		route_mod.data.route_mod.ack_floor = ack_floor;
	} 

	if (time_stamps != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_TIME_STAMPS;
		route_mod.data.route_mod.time_stamps = time_stamps;
	} 

	if (snack != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_SNACK;
		route_mod.data.route_mod.snack = snack;
	} 

	if (no_delay != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_NO_DELAY;
		route_mod.data.route_mod.no_delay = no_delay;
	} 

	if (snack_delay != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_SNACK_DELAY;
		route_mod.data.route_mod.snack_delay = snack_delay;
	} 

	if (tcp_only != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_TCP_ONLY;
		route_mod.data.route_mod.tcp_only = tcp_only;
	} 

	if (compress != -1) {
		route_mod.data.route_mod.attrib_list |= GW_ROUTE_ATTRIB_COMPRESS;
		route_mod.data.route_mod.compress = compress;
	} 

}
	
void
verify_route_modify ()

{
	int error = 0;

	if (!gateway_host) {
		printf ("Address of the gateway is required\n");
		error = 1;
	}

	if (route_id < 0) {
		printf ("Route_id is required\n");
		error = 1;
	}

	if (error) {
		printf ("Fatal errors....\n");
		printf ("Terminating the gateway route commander \n");
		fprintf (stderr, Usage);
		exit(0);
	}

}


void
send_route_modify_cmd ()

{
	int  rc;

	rc = send (s_gw_route_cmdr, &route_mod, sizeof (route_mod) , 0);
	if (rc <= 0) {
		perror ("Error in sending route to gateway");
	} else {  
	}
	
}

void    
recv_route_modify_resp ()
                
{
	fd_set read_set;
	int rc;
	struct timeval timeout;

	FD_ZERO (&read_set);
	FD_SET (s_gw_route_cmdr, &read_set);

	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	rc = select (10, &read_set, NULL, NULL, &timeout);

	if (rc == -1) {
		perror ("Error in select");
	}

	if (FD_ISSET (s_gw_route_cmdr, &read_set)) { 
		read_route_modify_resp ();
	} else {
		printf ("No response from gateway\n");
	}


}

void
read_route_modify_resp ()

{
	int rc;
	unsigned char buffer [MAX_PKT_SIZE];
	unsigned char *pbuffer = buffer;
	gateway_command_t *resp;

	rc = recv (s_gw_route_cmdr, pbuffer, MAX_PKT_SIZE, 0x0);

	if (rc <= 0) {
		perror ("Error in reading data from the gateway");
	} else {
		resp = (gateway_command_t *) buffer;
		printf ("Return code %d\n", resp->data.route_mod_resp.rc);
	}
}



void
route_modify ()

{
	verify_route_modify ();
	build_route_modify_cmd ();
	send_route_modify_cmd ();
	recv_route_modify_resp ();
}

