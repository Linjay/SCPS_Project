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
gateway_command_t route_avail_cmd;


void
build_route_avail_cmd ()

{
	memset (&route_avail_cmd, 0x00, sizeof (route_avail_cmd));
	route_avail_cmd.command = GW_COMMAND_ROUTE_AVAIL;
	route_avail_cmd.seq_num = 0x1;
	
	if (route_id >= 0) {
		route_avail_cmd.data.route_del.route_id = route_id;
	}
	
}
	
void
verify_route_available ()

{
	int error = 0;

	if (!gateway_host) {
		printf ("Address of the gateway is required\n");
		error = 1;
	}

	if (route_id < 0) {
		printf ("Route id is required \n");
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
send_route_avail_cmd ()

{
	int  rc;

	rc = send (s_gw_route_cmdr, &route_avail_cmd, sizeof (route_avail_cmd) , 0);

	if (rc <= 0) {
		perror ("Error in sending route available to gateway");
	} else {  
	}
	
}


void    
recv_route_avail_resp ()
                
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
		read_route_avail_resp ();
	} else {
		printf ("No response from gateway\n");
	}


}

void
read_route_avail_resp ()

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
		printf ("Route id %d\n", resp->data.route_del_resp.rc);
	}
}



void
route_available ()

{
	verify_route_available ();
	build_route_avail_cmd ();
	send_route_avail_cmd ();
	recv_route_avail_resp ();
}

