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

extern struct sockaddr_in gw_route_server;

extern int s_gw_route_cmdr;

extern uint32_t rate;
extern uint32_t min_rate;
extern uint32_t flow_control;
extern uint32_t mtu;
extern uint32_t smtu;
extern int	protocol_id;
extern int lan_wan;
extern int	cong_control;
extern unsigned char	dscp;

gateway_command_t route_get_cmd;


void
build_route_get_cmd ()

{
	route_get_cmd.command = GW_COMMAND_ROUTE_GET;
	route_get_cmd.seq_num = 0x1;
	
	if (src_ip_long) {
		route_get_cmd.data.route_get.src_ipaddr = src_ip_long;
	} else {
		route_get_cmd.data.route_get.src_ipaddr = 0x0;
	}
	
	if (src_netmask_host) {
		route_get_cmd.data.route_get.src_netmask = src_netmask_host;
	} else {
		route_get_cmd.data.route_get.src_netmask = 0xffffffff;
	}
	
	if (dst_ip_long) {
		route_get_cmd.data.route_get.dst_ipaddr = dst_ip_long;
	} else {
		route_get_cmd.data.route_get.dst_ipaddr = 0x00;
	}
	
	if (dst_netmask_host) {
		route_get_cmd.data.route_get.dst_netmask = dst_netmask_host;
	} else {
		route_get_cmd.data.route_get.dst_netmask = 0xffffffff;
	}
	
	if (src_lowport) {
		route_get_cmd.data.route_get.src_port = src_lowport;
	} else {
		route_get_cmd.data.route_get.src_port = 0x00;
	}
	
	
	if (dst_lowport) {
		route_get_cmd.data.route_get.dst_port = dst_lowport;
	} else {
		route_get_cmd.data.route_get.dst_port = 0x00;
	}
	
	if (protocol_id) {
		route_get_cmd.data.route_get.protocol_id = protocol_id;
	} else {
		route_get_cmd.data.route_get.protocol_id = 0;
	}

	if (lan_wan) {
		route_get_cmd.data.route_get.lan_wan = lan_wan;
	} else {
		route_get_cmd.data.route_get.lan_wan = 0;
	}

}
	
void
verify_route_get ()

{
	int error = 0;

	if (!gateway_host) {
		printf ("Address of the gateway is required\n");
		error = 1;
	}

	if (!dst_ip_host) {
		printf ("Destination Address is required\n");
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
send_route_get_cmd ()

{
	int  rc;

	rc = send (s_gw_route_cmdr, &route_get_cmd, sizeof (route_get_cmd) , 0);
	if (rc <= 0) {
		perror ("Error in sending route get to gateway");
	} else {  
	}
	
}

void    
recv_route_get_resp ()
                
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
		read_route_get_resp ();
	} else {
		printf ("No response from gateway\n");
	}


}

void
read_route_get_resp ()

{
	int rc;
	unsigned char buffer [MAX_PKT_SIZE];
	unsigned char *pbuffer = buffer;
	gateway_command_t *resp;
	char src_host [500];
	struct in_addr src_inaddr;
	char dst_host [500];
	struct in_addr dst_inaddr;

	rc = recv (s_gw_route_cmdr, pbuffer, MAX_PKT_SIZE, 0x0);

	if (rc <= 0) {
		perror ("Error in reading data from the gateway");
	} else {
		resp = (gateway_command_t *) buffer;
		printf ("Route id %d\n", resp->data.route_get_resp.route_id);
		if (resp->data.route_get_resp.route_id > 0) {

			memset (src_host, 0x00, 500); 
			memset (dst_host, 0x00, 500);

			if (resp->data.route_get_resp.src_ipaddr) {
				src_inaddr.s_addr = ntohl (resp->data.route_get_resp.src_ipaddr);
				strcpy (src_host, inet_ntoa (src_inaddr));
			} else {
				sprintf (src_host,"0.0.0.0");
			}
			
			if (resp->data.route_get_resp.dst_ipaddr) {
				dst_inaddr.s_addr = ntohl (resp->data.route_get_resp.dst_ipaddr);
				strcpy (dst_host, inet_ntoa (dst_inaddr));
			} else {
				sprintf (dst_host,"0.0.0.0");
			}

			printf ("%d\t%s\t%lx\t%s\t%lx\t%d\t%d\t%d\t%d\t%ld\t%ld\t%ld\t%ld\t%ld\t%d\t%x\t%d\n",
				resp->data.route_get_resp.route_id,
				src_host,
				resp->data.route_get_resp.src_netmask,
				dst_host,
				resp->data.route_get_resp.dst_netmask,
				resp->data.route_get_resp.src_lowport,
				resp->data.route_get_resp.src_higport,
				resp->data.route_get_resp.dst_lowport,
				resp->data.route_get_resp.dst_higport,
				resp->data.route_get_resp.rate,
				resp->data.route_get_resp.min_rate,
				resp->data.route_get_resp.flow_control,
				resp->data.route_get_resp.mtu,
				resp->data.route_get_resp.smtu,
				resp->data.route_get_resp.protocol_id,
				resp->data.route_get_resp.dscp,
				resp->data.route_get_resp.cong_control);
		}

	}
}
 


void
route_get ()

{
	verify_route_get ();
	build_route_get_cmd ();
	send_route_get_cmd ();
	recv_route_get_resp ();
}

