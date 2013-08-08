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
extern struct sockaddr_in gw_route_server;

extern int s_gw_route_cmdr;

extern int route_id;
gateway_command_t route_list_cmd;


void
build_route_list_cmd ()

{
	memset (&route_list_cmd, 0x00, sizeof (route_list_cmd));
	route_list_cmd.command = GW_COMMAND_ROUTE_LIST;
	route_list_cmd.seq_num = 0x1;
	
	if (route_id >= 0) {
		route_list_cmd.data.route_lst.route_id = route_id;
	}
	
}
	
void
verify_route_list ()

{
	int error = 0;

	if (!gateway_host) {
		printf ("Address of the gateway is required\n");
		error = 1;
	}

	if (error) {
		printf ("Fatal errors....\n");
		printf ("Terminating the gateway route commander\n");
		fprintf (stderr, Usage);
		exit(0);
	}

}


void
send_route_list_cmd ()

{
	int  rc;

	rc = send (s_gw_route_cmdr, &route_list_cmd, sizeof (route_list_cmd) , 0);

	if (rc <= 0) {
		perror ("Error in sending route list to gateway");
	} else {  
	}
	
}


void    
recv_route_list_resp ()
                
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
		read_route_list_resp ();
	} else {
		printf ("No response from gateway\n");
	}


}

void
display_route_list (resp)
gateway_command_t *resp;

{
	int i;
	struct in_addr src_inaddr;
	struct in_addr dst_inaddr;
	char src_host [20];
	char dst_host [20];

	for (i = 0; i< resp->data.route_lst_resp.num_in_list; i++) {
		
		memset (src_host, 0x00, 20);
		memset (dst_host, 0x00, 20);

		if (resp->data.route_lst_resp.route_list[i].src_ipaddr) {
			src_inaddr.s_addr = ntohl (resp->data.route_lst_resp.route_list[i].src_ipaddr); 
			strcpy (src_host, inet_ntoa (src_inaddr));
		} else {
			sprintf (src_host,"0.0.0.0");
		}

		if (resp->data.route_lst_resp.route_list[i].dst_ipaddr) {
			dst_inaddr.s_addr = ntohl (resp->data.route_lst_resp.route_list[i].dst_ipaddr); 
			strcpy (dst_host, inet_ntoa (dst_inaddr));
		} else {
			sprintf (dst_host,"0.0.0.0");
		}

		printf ("%d\t%s\t%lx\t%s\t%lx\t%d\t%d\t%d\t%d\t%ld\t%ld\t%ld\t%ld\t%ld\t%d\t%x\t%d\t%d\n",
			resp->data.route_lst_resp.route_list[i].route_id,
			src_host,
			resp->data.route_lst_resp.route_list[i].src_netmask,
			dst_host,
			resp->data.route_lst_resp.route_list[i].dst_netmask,
			resp->data.route_lst_resp.route_list[i].src_lowport,
			resp->data.route_lst_resp.route_list[i].src_higport,
			resp->data.route_lst_resp.route_list[i].dst_lowport,
			resp->data.route_lst_resp.route_list[i].dst_higport, 
			resp->data.route_lst_resp.route_list[i].rate,
			resp->data.route_lst_resp.route_list[i].min_rate,
			resp->data.route_lst_resp.route_list[i].flow_control,
			resp->data.route_lst_resp.route_list[i].mtu,
			resp->data.route_lst_resp.route_list[i].smtu,
			resp->data.route_lst_resp.route_list[i].protocol_id,
			resp->data.route_lst_resp.route_list[i].dscp,
			resp->data.route_lst_resp.route_list[i].lan_wan,
			resp->data.route_lst_resp.route_list[i].cong_control);
	}

}

void
read_route_list_resp ()

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
		display_route_list (resp);
	}
}




void
route_list ()

{
	verify_route_list ();
	build_route_list_cmd ();
	send_route_list_cmd ();
	recv_route_list_resp ();
}

