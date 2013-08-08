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

extern uint32_t src_ip_long;
extern uint32_t dst_ip_long;

extern unsigned short src_lowport;
extern unsigned short src_higport;
extern unsigned short dst_lowport;
extern unsigned short dst_higport;
extern unsigned char dscp;
extern unsigned char lan_wan;

extern struct sockaddr_in gw_route_server;

extern int s_gw_route_cmdr;

extern uint32_t rate;
extern uint32_t min_rate;
extern uint32_t flow_control;
extern uint32_t mtu;
extern uint32_t smtu;
extern int	protocol_id;
extern int	cong_control;

gateway_command_t route_add_cmd;


void
build_route_add_cmd ()

{
	route_add_cmd.command = GW_COMMAND_ROUTE_ADD;
	route_add_cmd.seq_num = 0x1;
	
	if (src_ip_long) {
		route_add_cmd.data.route_add.src_ipaddr = src_ip_long;
	} else {
		route_add_cmd.data.route_add.src_ipaddr = 0x0;
	}
	
	if (src_netmask_host) {
		route_add_cmd.data.route_add.src_netmask = src_netmask_host;
	} else {
		route_add_cmd.data.route_add.src_netmask = 0xffffffff;
	}
	
	if (dst_ip_long) {
		route_add_cmd.data.route_add.dst_ipaddr = dst_ip_long;
	} else {
		route_add_cmd.data.route_add.dst_ipaddr = 0x00;
	}
	
	if (dscp) {
		route_add_cmd.data.route_add.dscp = dscp;
	} else {
		route_add_cmd.data.route_add.dscp = 0x00;
	}
	
	if (lan_wan) {
		route_add_cmd.data.route_add.lan_wan = lan_wan;
	} else {
		route_add_cmd.data.route_add.lan_wan = 0x00;
	}
	
	if (dst_netmask_host) {
		route_add_cmd.data.route_add.dst_netmask = dst_netmask_host;
	} else {
		route_add_cmd.data.route_add.dst_netmask = 0xffffffff;
	}
	
	if (src_lowport) {
		route_add_cmd.data.route_add.src_lowport = src_lowport;
	} else {
		route_add_cmd.data.route_add.src_lowport = 0x00;
	}
	
	if (src_higport) {
		route_add_cmd.data.route_add.src_higport = src_higport;
	} else {
		route_add_cmd.data.route_add.src_higport = 0x00;
	}
	
	if (dst_lowport) {
		route_add_cmd.data.route_add.dst_lowport = dst_lowport;
	} else {
		route_add_cmd.data.route_add.dst_lowport = 0x00;
	}
	
	if (dst_higport) {
		route_add_cmd.data.route_add.dst_higport = dst_higport;
	} else {
		route_add_cmd.data.route_add.dst_higport = 0x00;
	}
	
	if (rate) {
		route_add_cmd.data.route_add.rate = rate;
	} 
	if (min_rate) {
		route_add_cmd.data.route_add.min_rate = min_rate;
	} 
	if (flow_control) {
		route_add_cmd.data.route_add.flow_control = flow_control;
	} 
	if (mtu) {
		route_add_cmd.data.route_add.mtu = mtu;
	} 
	if (smtu) {
		route_add_cmd.data.route_add.smtu = smtu;
	} 
	if (protocol_id) {
		route_add_cmd.data.route_add.protocol_id = protocol_id;
	} 

        if ((cong_control < 0) || (cong_control > 2)) cong_control = 1;
	route_add_cmd.data.route_add.cong_control = cong_control;
}
	
void
verify_route_add ()

{
	int error = 0;

	if (!gateway_host) {
		printf ("Address of the gateway is required\n");
		error = 1;
	}

	if ( (!dst_ip_host) && (lan_wan == 0)) {
		printf ("Destination Address or lan_wan interface is required\n");
		error = 1;
	}

	if (((src_lowport) && (!src_higport)) || ((!src_lowport) && (src_higport))) {
		printf ("If the source port is used, a range is required\n");
		error = 1;
	}

	if (((dst_lowport) && (!dst_higport)) || ((!dst_lowport) && (dst_higport))) {
		printf ("If the destination port is used, a range is required\n");
		error = 1;
	}

	if (error) {
		printf ("Fatal errors....\n");
		printf ("Terminating the TC encoder Server\n");
		fprintf (stderr, Usage);
		exit(0);
	}

}


void
send_route_add_cmd ()

{
	int  rc;

	rc = send (s_gw_route_cmdr, &route_add_cmd, sizeof (route_add_cmd) , 0);
	if (rc <= 0) {
		perror ("Error in sending route add to gateway");
	} else {  
	}
	
}

void    
recv_route_add_resp ()
                
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
		read_route_add_resp ();
	} else {
		printf ("No response from gateway\n");
	}


}

void
read_route_add_resp ()

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
		printf ("Route id %d\n", resp->data.route_add_resp.route_id);
	}
}



void
route_add ()

{
	verify_route_add ();
	build_route_add_cmd ();
	send_route_add_cmd ();
	recv_route_add_resp ();
}

