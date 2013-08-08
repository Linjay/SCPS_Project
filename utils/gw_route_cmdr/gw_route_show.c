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
gateway_command_t route_show_cmd;


void
build_route_show_cmd ()

{
	memset (&route_show_cmd, 0x00, sizeof (route_show_cmd));
	route_show_cmd.command = GW_COMMAND_ROUTE_SHOW;
	route_show_cmd.seq_num = 0x1;
	
	route_show_cmd.data.route_show.route_id = route_id;
}
	
void
verify_route_show ()

{
	int error = 0;

	if (!gateway_host) {
		printf ("Address of the gateway is required\n");
		error = 1;
	}

	if (route_id < 0) {
		printf ("Route ID is required\n");
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
send_route_show_cmd ()

{
	int  rc;

	rc = send (s_gw_route_cmdr, &route_show_cmd, sizeof (route_show_cmd) , 0);

	if (rc <= 0) {
		perror ("Error in sending route show to gateway");
	} else {  
	}
	
}


void    
recv_route_show_resp ()
                
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
		read_route_show_resp ();
	} else {
		printf ("No response from gateway\n");
	}


}

void
display_route_show (resp)
gateway_command_t *resp;

{
	struct in_addr src_inaddr;
	struct in_addr dst_inaddr;
	char src_host [20];
	char dst_host [20];

	memset (src_host, 0x00, 20);
	memset (dst_host, 0x00, 20);

	if (resp->data.route_show_resp.src_ipaddr) {
		src_inaddr.s_addr = ntohl (resp->data.route_show_resp.src_ipaddr); 
		strcpy (src_host, inet_ntoa (src_inaddr));
	} else {
		sprintf (src_host,"0.0.0.0");
	}

	if (resp->data.route_show_resp.dst_ipaddr) {
		dst_inaddr.s_addr = ntohl (resp->data.route_show_resp.dst_ipaddr); 
		strcpy (dst_host, inet_ntoa (dst_inaddr));
	} else {
		sprintf (dst_host,"0.0.0.0");
	}

	printf ("route_id: %d\n", resp->data.route_show_resp.route_id);

	printf ("src_host: %lx\tNetmask: %lx\tport_range: %d-%d \n", src_host, resp->data.route_show_resp.src_netmask,resp->data.route_show_resp.src_lowport, resp->data.route_show_resp.src_higport);

	printf ("dst_host: %lx\tNetmask: %lx\tport_range: %d-%d \n", dst_host, resp->data.route_show_resp.dst_netmask,resp->data.route_show_resp.dst_lowport, resp->data.route_show_resp.dst_higport);

	printf ("protocol_id: %d\t\tdscp: %d\t\t\tlan_or_wan: %d\n", resp->data.route_show_resp.protocol_id, resp->data.route_show_resp.dscp, resp->data.route_show_resp.lan_wan);

	printf ("Rate: %ld\t\tMin_rate: %ld\tCC: %d\n", resp->data.route_show_resp.rate, resp->data.route_show_resp.min_rate, resp->data.route_show_resp.cong_control);


	printf ("flow_control: %d\t\tTCP_only: %d\t\tSnd_buf: %d\n", resp->data.route_show_resp.flow_control, resp->data. route_show_resp.tcp_only, resp->data.route_show_resp.send_buffer);

	printf ("Rcv_buf: %d\t\ttmtu:%d\t\tsend_mtu: %d\n", resp->data.route_show_resp.receive_buffer, resp->data.route_show_resp.mtu, resp->data.route_show_resp.smtu);

	printf ("Min_rto_value: %d\tMax_rto_value: %d\tMax_rto_ctr: %d\tEmbargo_rxmit_ctr %d\n", resp->data.route_show_resp.min_rto_value, resp->data.route_show_resp.max_rto_value, resp->data.route_show_resp.max_rto_ctr, resp->data.route_show_resp.embargo_fast_rxmit_ctr);

	printf ("Max_persist_rto: %d\tMax_persist_ctr: %d\tPersist_RTO_ctr: %d\n", resp->data.route_show_resp.rto_persist_max, resp->data.route_show_resp.max_persist_ctr, resp->data.route_show_resp.rto_persist_ctr);
	printf ("TCP_ACK_Behave: %d\tTCP_ACK_delay: %d\tTCP_ACK_floor: %d\n", resp->data.route_show_resp.ack_behave, resp->data.route_show_resp.ack_delay, resp->data.route_show_resp.ack_floor);

	printf ("Vegas_ALPHA: %d\t\tVegas_BETA: %d\t\tVegas_GAMMA: %d\n", resp->data.route_show_resp.vegas_alpha, resp->data.route_show_resp.vegas_beta, resp->data.route_show_resp.vegas_gamma);

	printf ("Two_MSL_timeout: %d\tTCP_timestamps: %d\tTCP_SNACK: %d\n", resp->data.route_show_resp.two_msl_timeout, resp->data.route_show_resp.time_stamps, resp->data.route_show_resp.snack);

	printf ("TCP_SNACK_Delay: %d\tTCP_no_delay: %d\t\tTCP_compress: %d\n",resp->data.route_show_resp.snack_delay, resp->data.route_show_resp.no_delay, resp->data.route_show_resp.compress);
}

void
read_route_show_resp ()

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
		display_route_show (resp);
	}
}




void
route_show ()

{
	verify_route_show ();
	build_route_show_cmd ();
	send_route_show_cmd ();
	recv_route_show_resp ();
}

