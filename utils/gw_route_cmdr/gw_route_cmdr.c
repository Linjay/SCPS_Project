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

char Usage [] = "\
Usage: gw_route_cmdr \n\
	-A ##   Command: (A)dd (D)elete (G)et (M)odify (L)ist a(V)ailable (U)navailable\n\
	-G ## 	Set the IP address of the gateway\n\
	-S ## 	Set the source IP address\n\
	-s ## 	Set the source netmask\n\
	-D ## 	Set the destination IP address\n\
	-d ## 	Set the destination netmask\n\
	-X ## 	Set the source transport low port number\n\
	-x ## 	Set the source transport high port number\n\
	-C ## 	Set the destination transport low port number\n\
	-c ## 	Set the destination transport high port number\n\
	-R ##	Set the rate \n\
	-Z ##	Set the min rate \n\
	-F ##	Set the flow control \n\
	-M ##	Set the receiving MTU \n\
	-m ##	Set the sending MTU \n\
	-r ##	Set the route id\n\
	-p ##	Set the protocol id\n\
	-T ##   Set the congestion control algorithm\n\
	-t ##   Set the DSCP bits \n\
	-L      Set the direction to LAN side \n\
	-W      Set the direction to WAN side \n\
";


unsigned char command = 0x00;
char *gateway_host = NULL;
char *src_ip_host = NULL;
unsigned int src_netmask_host = 0xffffffff;
char *dst_ip_host = NULL;
unsigned int dst_netmask_host = 0xffffffff;

uint32_t src_ip_long = 0x0;
uint32_t dst_ip_long = 0x0;

unsigned short src_lowport = 0x0;
unsigned short src_higport = 0x0;
unsigned short dst_lowport = 0x0;
unsigned short dst_higport = 0x0;
unsigned char dscp = 0x00;
int lan_wan = 0x00;

uint32_t rate;
uint32_t min_rate;
uint32_t flow_control;
uint32_t mtu;
uint32_t smtu;
int	protocol_id = 0;
int	cong_control = -1;
int	send_buffer = -1;
int	receive_buffer = -1;
int	min_rto_value = -1;
int	max_rto_value = -1;
int	max_rto_ctr =	-1;
int	max_persist_ctr = -1;
int 	rto_persist_max = -1;
int	rto_persist_ctr = -1;
int	embargo_fast_rxmit_ctr = -1;
int 	two_msl_timeout = -1;
int	ack_behave	= -1;
int	ack_delay	= -1;
int	ack_floor	= -1;
int	time_stamps	= -1;
int	snack 		= -1;
int	no_delay 	= -1;
int	snack_delay 	= -1;
int	tcp_only 	= -1;
int	compress	= -1;
int	vegas_alpha	= -1;
int	vegas_beta	= -1;
int	vegas_gamma	= -1;
 
struct sockaddr_in gw_route_server;

int s_gw_route_cmdr = 0;
int route_id = -1;

int
main (argc, argv)
int argc;
char **argv;

{
	get_args (argc, argv);
	display_args ();
	verify_initial_args ();
	convert_ips_to_long ();

	initialize ();
	create_gw_route_socket ();

	parse_cmd ();
	return (0);
}


void
initialize ()

{
	init_sighup_mask ();
}


void
main_loop ()

{
	fd_set read_set;
	int rc;

	while (1) {

		FD_ZERO (&read_set);

		rc = select (10, &read_set, NULL, NULL, NULL);

		if (rc == -1) {
			perror ("Error in select");
			continue;
		}

	}
}


void
send_data_to_gw_route_server (buffer, length)
char *buffer;
int length;

{
	int  rc;

	rc = send (s_gw_route_cmdr, buffer, length, 0);
	if (rc <= 0) {
		perror ("Error in sending data to the TC Client");
	} else {
#ifdef DEBUG
		printf ("Sending %d bytes of data to the TC Client.\n",length);
#endif /* DEBUG */
	}	
}



void
create_gw_route_socket ()

{
	uint32_t tmp_addr; 
	struct hostent *addr;

	memset ((char *) &gw_route_server, 0, sizeof (gw_route_server));

	gw_route_server.sin_family = AF_INET;
	gw_route_server.sin_port = htons (GW_ROUTE_SERVER_PORT);
#ifndef LINUX
	gw_route_server.sin_len = sizeof (gw_route_server);
#endif /*  LINUX */
	
	if (atoi (gateway_host) > 0) {
		gw_route_server.sin_addr.s_addr = inet_addr (gateway_host);
	} else {
		if ((addr = gethostbyname (gateway_host)) == NULL) {
			perror ("Optaining address for TC server");
		} else {
			memcpy ((char *) &tmp_addr, addr->h_addr, addr->h_length);
			gw_route_server.sin_addr.s_addr = tmp_addr;
		}
	}

	if ((s_gw_route_cmdr = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
	  perror ("Creating the TC client socket");
	  exit (0);
	}

	if (connect (s_gw_route_cmdr, (struct sockaddr *) &gw_route_server,
		sizeof (gw_route_server)) < 0) {
                perror ("Connect the gateway route server ");
                exit (0);
	}
}


void
convert_ips_to_long ()

{
	struct hostent *addr;
	uint32_t tmp_addr; 

	if (src_ip_host) {
		if (atoi (src_ip_host) > 0) {
			src_ip_long = inet_addr (src_ip_host);
		} else {
			if ((addr = gethostbyname (src_ip_host)) == NULL) {
				perror ("Obtaining address for source");
			} else {
				memcpy ((char *) &tmp_addr, addr->h_addr, addr->h_length);
				src_ip_long = tmp_addr;
			}
		}
	}

	if (dst_ip_host) {
		if (atoi (dst_ip_host) > 0) {
			dst_ip_long = inet_addr (dst_ip_host);
		} else {
			if ((addr = gethostbyname (dst_ip_host)) == NULL) {
				perror ("Obtaining address for destination");
			} else {
				memcpy ((char *) &tmp_addr, addr->h_addr, addr->h_length);
				dst_ip_long = tmp_addr;
			}
		}
	}

}


void
display_args ()

{

#ifdef DEBUG
	printf ("\n");

	if (gateway_host) {
		printf ("The address of the gateway is %s\n", gateway_host);
	}

	if (command) {
		printf ("The command is %c\n", command);
	}

	if (src_ip_host) {
		printf ("The source address and netmask are %s/%0x\n", src_ip_host, src_netmask_host);
	}

	if (src_lowport) {
		printf ("The source port range is from %d to %d\n", src_lowport, src_higport);
	}

	if (dst_ip_host) {
		printf ("The destination address and netmask are %s/%0x\n", dst_ip_host, dst_netmask_host);
	}

	if (dst_lowport) {
		printf ("The destination port range is from %d to %d\n", dst_lowport, dst_higport);
	}

	printf ("\n");
#endif /* DEBUG */
}

void
verify_initial_args ()

{
	int error = 0;

	if (!gateway_host) {
		printf ("Address of the gateway is required\n");
		error = 1;
	}

	if (!command) {
		printf ("Route Command is required\n");
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
get_args (argc, argv)
int argc;
char **argv;

{
	int c;

	while ((c = getopt (argc, argv, "A:G:S:s:D:d:X:x:C:c:R:M:m:r:p:T:t:Z:F:LWB:b:a:e:g:h:i:f:k:l:n:o:q:w:u:v:I:y:E:J:K:H:j:")) != -1) {
	  switch (c)  {
		case 'G':  /* Set the address of the Gateway */
		  gateway_host = optarg;
		  break;

		case 'A':  /* Command */
		  command = optarg [0];
		  break;

		case 'S':  /* Set the source IP address*/
		  src_ip_host = optarg;
		  break;

		case 's':  /* Set the source netmask*/
		  src_netmask_host = strtoul (optarg, (char **)NULL, 16);
		  break;

		case 'D':  /* Set the destination IP address*/
		  dst_ip_host = optarg;
		  break;

		case 'd':  /* Set the destination netmask*/
		  dst_netmask_host = strtoul (optarg, (char **)NULL, 16);
		  break;

		case 'X':  /* Set the source transport layer low port number */
		  src_lowport = atoi (optarg);
		  break;

		case 'x':  /* Set the source transport layer high port number */
		  src_higport = atoi (optarg);
		  break;

		case 'C':  /* Set the destination transport layer low port number */
		  dst_lowport = atoi (optarg);
		  break;

		case 'c':  /* Set the destination transport layer high port number */
		  dst_higport = atoi (optarg);
		  break;

		case 'R':  /* Set the rate control */
		  rate = atoi (optarg);
		  break;

		case 'Z':  /* Set the minimum rate control */
		  min_rate = atoi (optarg);
		  break;

		case 'F':  /* Set the flow control */
		  flow_control = atoi (optarg);
		  break;

		case 'M':  /* Set the receiving MTU */
		  mtu = atoi (optarg);
		  break;

		case 'm':  /* Set the sending MTU */
		  smtu = atoi (optarg);
		  break;

		case 'r':  /* Set the route id */
		  route_id = atoi (optarg);
		  break;

		case 'p':  /* Set the protcol id */
		  protocol_id = atoi (optarg);
		  break;

		case 'T':  /* Set the Congestion Control */
		  cong_control = atoi (optarg);
		  break;

		case 't':  /* Set the DSCP bits */

		  dscp = atoi (optarg);
		  if (!dscp)
			sscanf (optarg,"%x", &dscp);
		  break;

		case 'L':  /* Set the LAN WAN side */
		  lan_wan = 1;
		  break;

		case 'W':  /* Set the LAN WAN side */
		  lan_wan = 2;
		  break;

		case 'B':  /* Set the Send Buffer */
		  send_buffer = atoi (optarg);
	          break;

		case 'b':  /* Set the Receive  Buffer */
		  receive_buffer = atoi (optarg);
	          break;

		case 'a':  /* Set the Vegas Alpha parameter */
		  vegas_alpha = atoi (optarg);
	          break;

		case 'e':  /* Set the Vegas Beta parameter */
		  vegas_beta = atoi (optarg);
	          break;

		case 'g':  /* Set the Vegas Gamma parameter*/
		  vegas_gamma = atoi (optarg);
	          break;

		case 'h':  /* Set the minimum RTO value */
		  min_rto_value = atoi (optarg);
	          break;

		case 'i':  /* Set the maximum RTO value */
		  max_rto_value = atoi (optarg);
	          break;

		case 'j':  /* Set the Maximum RTO counter */
		  max_rto_ctr  = atoi (optarg);
	          break;

		case 'k':  /* Set the number of times the persist counter will fire before reset */
		  max_persist_ctr = atoi (optarg);
	          break;

		case 'l':  /* Set the maximum value of the persist timer */
		  rto_persist_max  = atoi (optarg);
	          break;

		case 'n':  /* Set the number of times the rto timer will expier before persist is entered */
		  rto_persist_ctr = atoi (optarg);
	          break;

		case 'o':  /* Set the number of times the embargo timer will fire before persist in entered */
		  embargo_fast_rxmit_ctr  = atoi (optarg);
	          break;

		case 'q':  /* Set the 2 * maximum segment liftime timeout value */
		  two_msl_timeout = atoi (optarg);
	          break;

		case 'w':  /* Set the TP ack behavior parameter*/
		  ack_behave  = atoi (optarg);
	          break;

		case 'u':  /* Set the TP ack delay value */
		  ack_delay = atoi (optarg);
	          break;

		case 'v':  /* Set the TP ack floor value */
		  ack_floor  = atoi (optarg);
	          break;

		case 'I':  /* Set the TP timestamps parameter */
		  time_stamps = atoi (optarg);
	          break;

		case 'y':  /* Set the TP snack parameter */
		  snack  = atoi (optarg);
	          break;

		case 'E':  /* Set the TP no delay flag */
		  no_delay = atoi (optarg);
	          break;

		case 'J':  /* Set the snack delay value */
		  snack_delay = atoi (optarg);
	          break;

		case 'K':  /* Set the tcp only flag */
		  tcp_only  = atoi (optarg);
	          break;

		case 'H':  /* Set the TP compression */
		  compress  = atoi (optarg);
	          break;

		default:
		  goto usage;
 	  }
	}

	return;

usage:
	fprintf (stderr, Usage);
	exit(0);
}


void                    
int_hndlr ()    
                
{                       
	exit (0);
}


void
init_sighup_mask ()

{
	signal (SIGINT, (void *) int_hndlr);
	signal (SIGTERM, (void *) int_hndlr);
}


void
parse_cmd ()

{
	switch (command) {
	  case 'A':
	  case 'a' :
	    route_add ();
	    break;

	  case 'D':
	  case 'd' :
	    route_delete ();
	    break;

	  case 'L':
	  case 'l' :
	    route_list ();
	    break;

	  case 'G':
	  case 'g' :
	    route_get ();
	    break;

	  case 'S':
	  case 's' :
	    route_show ();
	    break;

	  case 'M':
	  case 'm' :
	    route_modify ();
	    break;

	  case 'V':
	  case 'v' :
	    route_available ();
	    break;

	  case 'U':
	  case 'u' :
	    route_unavailable ();
	    break;

	}
}

