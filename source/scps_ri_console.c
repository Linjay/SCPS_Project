#ifdef SCPS_RI_CONSOLE

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <fcntl.h>
#include "scps.h"
#include "route.h"
#include "rt_alloc.h"
#include "net_types.h"
#include "scps_ri_console.h"


struct sockaddr_in sin_command;
extern int s_command;

#if !defined(errno)
extern int errno;
#endif /* !defined(errno) */

extern int route_socket_list [ROUTE_SOCKET_LIST_MAX];

extern void *memset (void *s, int c, size_t n);

void    
read_scps_ri_console ()
	  
{       
	char buffer [1500];
	char *pbuffer = buffer;
	struct sockaddr_in sin_from;
	int flags = 0x00;
	int sin_from_len;
	int rc;
    
	sin_from_len = sizeof (sin_from);
	rc = recvfrom (s_command, pbuffer, 1500, flags,
		       (struct sockaddr *)&sin_from, &sin_from_len);
    
#ifdef DEBUG
	if (rc <= 0) {
		perror ("Error in reading data SCPS RI console ");
	} else {
		printf ("Received %d bytes of data from SCPS RI console\n",rc);
	}
#endif /* DEBUG */
	parse_console_command (pbuffer, &sin_from, sin_from_len);
}

void
parse_console_command (data, sin_from, sin_from_len)
struct sockaddr_in *sin_from;
int		   sin_from_len;

unsigned char *data;

{
	gateway_command_t *cmd = (gateway_command_t *) data;

#ifdef DEBUG_CONSOLE
syslog (LOG_ERR, "Reading command %x \n", cmd->command);
#endif /* DEBUG_CONSOLE */

	switch (cmd->command) {

		case GW_COMMAND_ROUTE_ADD:
			console_route_add (cmd, sin_from, sin_from_len);
			break;

		case GW_COMMAND_ROUTE_DELETE:
			console_route_delete (cmd, sin_from, sin_from_len);
			break;

		case GW_COMMAND_ROUTE_LIST:
			console_route_list (cmd, sin_from, sin_from_len);
			break;

		case GW_COMMAND_ROUTE_GET:
			console_route_get (cmd, sin_from, sin_from_len);
			break;

		case GW_COMMAND_ROUTE_SHOW:
			console_route_show (cmd, sin_from, sin_from_len);
			break;

		case GW_COMMAND_ROUTE_MODIFY:
			console_route_modify (cmd, sin_from, sin_from_len);
			break;

		case GW_COMMAND_ROUTE_AVAIL:
			console_route_avail (cmd, sin_from, sin_from_len);
			break;

		case GW_COMMAND_ROUTE_UNAVAIL:
			console_route_unavail (cmd, sin_from, sin_from_len);
			break;

		default:
			printf ("SCPS RI Console warning invalid command %c\n",cmd->command);

	}

}


void
console_route_add (cmd, sin_to, sin_to_len)
gateway_command_t *cmd;
struct sockaddr_in *sin_to;
int		   sin_to_len;

{
	int rc;
	gateway_command_t resp;

	rc = ROUTE_ADD_IPPORT_BOTH (htonl (cmd->data.route_add.src_ipaddr),
			       cmd->data.route_add.src_netmask,
			       htonl (cmd->data.route_add.dst_ipaddr),
			       cmd->data.route_add.dst_netmask,
			       cmd->data.route_add.src_lowport,
			       cmd->data.route_add.src_higport,
			       cmd->data.route_add.dst_lowport,
			       cmd->data.route_add.dst_higport,
			       cmd->data.route_add.rate,
			       cmd->data.route_add.min_rate,
			       cmd->data.route_add.flow_control,
			       cmd->data.route_add.mtu,
			       cmd->data.route_add.smtu,
			       cmd->data.route_add.protocol_id,
			       cmd->data.route_add.dscp,
			       cmd->data.route_add.lan_wan,
			       cmd->data.route_add.cong_control);

	resp.command = GW_COMMAND_ROUTE_ADD_RESP;
	resp.seq_num = cmd->seq_num;
	resp.data.route_add_resp.route_id = rc;
	rc = sendto (s_command, &resp, sizeof (resp), 0, (struct sockaddr *) sin_to, sin_to_len);
}



void
console_route_delete (cmd, sin_to, sin_to_len)
gateway_command_t *cmd;
struct sockaddr_in *sin_to;
int		   sin_to_len;

{
	int rc;
	gateway_command_t resp;


	rc = route_delete (cmd->data.route_del.route_id);
	resp.command = GW_COMMAND_ROUTE_DELETE_RESP;
	resp.seq_num = cmd->seq_num;
	resp.data.route_del_resp.rc = rc;
	rc = sendto (s_command, &resp, sizeof (resp), 0, (struct sockaddr *) sin_to, sin_to_len);
}



void
console_route_avail (cmd, sin_to, sin_to_len)
gateway_command_t *cmd;
struct sockaddr_in *sin_to;
int		   sin_to_len;

{
	int rc;
	gateway_command_t resp;


	rc = route_avail (cmd->data.route_avail.route_id);
	resp.command = GW_COMMAND_ROUTE_AVAIL_RESP;
	resp.seq_num = cmd->seq_num;
	resp.data.route_avail_resp.rc = rc;
	rc = sendto (s_command, &resp, sizeof (resp), 0, (struct sockaddr *) sin_to, sin_to_len);
}



void
console_route_unavail (cmd, sin_to, sin_to_len)
gateway_command_t *cmd;
struct sockaddr_in *sin_to;
int		   sin_to_len;

{
	int rc;
	gateway_command_t resp;


	rc = route_unavail (cmd->data.route_unavail.route_id);
	resp.command = GW_COMMAND_ROUTE_UNAVAIL_RESP;
	resp.seq_num = cmd->seq_num;
	resp.data.route_unavail_resp.rc = rc;
	rc = sendto (s_command, &resp, sizeof (resp), 0, (struct sockaddr *) sin_to, sin_to_len);
}



void
console_route_list (cmd, sin_to, sin_to_len)
gateway_command_t *cmd;
struct sockaddr_in *sin_to;
int		   sin_to_len;

{
	int rc;
	int counter = 0;
	gateway_command_t resp;
	void *s;
	route *rt;
	int i;

	resp.command = GW_COMMAND_ROUTE_LIST_RESP;
	resp.seq_num = cmd->seq_num;

	for (i = 0; i < ROUTE_SOCKET_LIST_MAX; i++) {
		if (route_socket_list [i] != -1) {
			s = (void *) scheduler.sockets[route_socket_list [i]].ptr;
			rt = (route *) ((tp_Socket *) s)->rt_route;

			resp.data.route_lst_resp.route_list[counter].route_id = i;
			resp.data.route_lst_resp.route_list[counter].src_ipaddr =
			     rt ->src_ipaddr;
			resp.data.route_lst_resp.route_list[counter].src_netmask =
			     rt ->src_netmask;
			resp.data.route_lst_resp.route_list[counter].dst_ipaddr =
			     rt ->dst_ipaddr;
			resp.data.route_lst_resp.route_list[counter].dst_netmask =
			     rt ->dst_netmask;
			resp.data.route_lst_resp.route_list[counter].src_lowport =
			     rt ->src_lowport;
			resp.data.route_lst_resp.route_list[counter].src_higport =
			     rt ->src_higport;
			resp.data.route_lst_resp.route_list[counter].dst_lowport =
			     rt ->dst_lowport;
			resp.data.route_lst_resp.route_list[counter].dst_higport =
			     rt ->dst_higport;
			resp.data.route_lst_resp.route_list[counter].rate =
			     rt ->rate;
			resp.data.route_lst_resp.route_list[counter].min_rate =
			     rt ->min_rate;
			resp.data.route_lst_resp.route_list[counter].flow_control =
			     rt ->flow_control;
			resp.data.route_lst_resp.route_list[counter].mtu =
			     rt ->MTU;
			resp.data.route_lst_resp.route_list[counter].smtu =
			     rt ->SMTU;
			resp.data.route_lst_resp.route_list[counter].protocol_id =
			     rt ->protocol_id;
			resp.data.route_lst_resp.route_list[counter].dscp =
			     rt ->dscp;
			resp.data.route_lst_resp.route_list[counter].lan_wan =
			     rt ->lan_wan;
			resp.data.route_lst_resp.route_list[counter].cong_control =
			     rt ->cong_control;
			counter ++;
		}
	}	
	resp.data.route_lst_resp.num_in_list = counter;

	rc = sendto (s_command, &resp, sizeof (resp), 0, (struct sockaddr *) sin_to, sin_to_len);
}

void
console_route_show (cmd, sin_to, sin_to_len)
gateway_command_t *cmd;
struct sockaddr_in *sin_to;
int		   sin_to_len;

{
	int rc;
	gateway_command_t resp;
	tp_Socket *s;
	route *rt;
	int route_id;
	int socket_id;
	int value;
	int len;

	memset (&resp, 0x00, sizeof (resp));
	resp.command = GW_COMMAND_ROUTE_SHOW_RESP;
	resp.seq_num = cmd->seq_num;

	route_id = cmd->data.route_avail.route_id;
	socket_id = route_socket_list [route_id];
	s = (void *) scheduler.sockets[socket_id].ptr;
	rt = (route *) ((tp_Socket *) s)->rt_route;

	resp.data.route_show_resp.route_id = route_id;
	resp.data.route_show_resp.src_ipaddr = rt ->src_ipaddr;
	resp.data.route_show_resp.src_netmask = rt ->src_netmask;
	resp.data.route_show_resp.dst_ipaddr = rt ->dst_ipaddr;
	resp.data.route_show_resp.dst_netmask = rt ->dst_netmask;
	resp.data.route_show_resp.src_lowport = rt ->src_lowport;
	resp.data.route_show_resp.src_higport = rt ->src_higport;
	resp.data.route_show_resp.dst_lowport = rt ->dst_lowport;
	resp.data.route_show_resp.dst_higport = rt ->dst_higport;
	resp.data.route_show_resp.rate = rt ->rate;
	resp.data.route_show_resp.min_rate = rt ->min_rate;
	resp.data.route_show_resp.flow_control = rt ->flow_control;
	resp.data.route_show_resp.mtu = rt ->MTU;
	resp.data.route_show_resp.smtu = rt ->SMTU;
	resp.data.route_show_resp.protocol_id = rt ->protocol_id;
	resp.data.route_show_resp.dscp = rt ->dscp;
	resp.data.route_show_resp.lan_wan = rt ->lan_wan;
	resp.data.route_show_resp.cong_control = rt ->cong_control;

	
	if (!(scps_getsockopt (socket_id, SCPS_SOCKET, SCPS_SO_SNDBUF, &value, &len))) {
		resp.data.route_show_resp.send_buffer = value;
        } else {
		resp.data.route_show_resp.send_buffer = -1;
	}

	if (!(scps_getsockopt (socket_id, SCPS_SOCKET, SCPS_SO_RCVBUF, &value, &len))) {
		resp.data.route_show_resp.receive_buffer = value;
        } else {
		resp.data.route_show_resp.receive_buffer = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_MAXPERSIST_CTR, &value, &len))) {
		resp.data.route_show_resp.max_persist_ctr = value;
        } else {
		resp.data.route_show_resp.max_persist_ctr = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_RTO_TO_PERSIST_CTR, &value, &len))) {
		resp.data.route_show_resp.rto_persist_ctr = value;
        } else {
		resp.data.route_show_resp.rto_persist_ctr = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_EMBARGO_FAST_RXMIT_CTR, &value, &len))) {
		resp.data.route_show_resp.embargo_fast_rxmit_ctr = value;
        } else {
		resp.data.route_show_resp.embargo_fast_rxmit_ctr = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_ACKBEHAVE, &value, &len))) {
		resp.data.route_show_resp.ack_behave = value;
        } else {
		resp.data.route_show_resp.ack_behave = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_ACKDELAY, &value, &len))) {
		resp.data.route_show_resp.ack_delay = value;
        } else {
		resp.data.route_show_resp.ack_delay = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_ACKFLOOR, &value, &len))) {
		resp.data.route_show_resp.ack_floor = value;
        } else {
		resp.data.route_show_resp.ack_floor = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_SNACK, &value, &len))) {
		resp.data.route_show_resp.snack = value;
        } else {
		resp.data.route_show_resp.snack = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_TIMESTAMP, &value, &len))) {
		resp.data.route_show_resp.time_stamps = value;
        } else {
		resp.data.route_show_resp.time_stamps = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_SNACK_DELAY, &value, &len))) {
		resp.data.route_show_resp.snack_delay = value;
        } else {
		resp.data.route_show_resp.snack_delay = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_COMPRESS, &value, &len))) {
		resp.data.route_show_resp.compress = value;
        } else {
		resp.data.route_show_resp.compress = -1;
	}

	if (!(scps_getsockopt (socket_id, SCPS_ROUTE, SCPS_TCPONLY, &value, &len))) {
		resp.data.route_show_resp.tcp_only = value;
        } else {
		resp.data.route_show_resp.tcp_only = -1;
	}

	if (!(scps_getsockopt (socket_id, SCPS_SOCKET, SCPS_SO_NDELAY, &value, &len))) {
		resp.data.route_show_resp.no_delay = value;
        } else {
		resp.data.route_show_resp.no_delay = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_VEGAS_ALPHA, &value, &len))) {
		resp.data.route_show_resp.vegas_alpha = value;
        } else {
		resp.data.route_show_resp.vegas_alpha = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_VEGAS_BETA, &value, &len))) {
		resp.data.route_show_resp.vegas_beta = value;
        } else {
		resp.data.route_show_resp.vegas_beta = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_VEGAS_GAMMA, &value, &len))) {
		resp.data.route_show_resp.vegas_gamma = value;
        } else {
		resp.data.route_show_resp.vegas_gamma = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_2MSLTIMEOUT, &value, &len))) {
		resp.data.route_show_resp.two_msl_timeout = value;
        } else {
		resp.data.route_show_resp.two_msl_timeout = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_RTOPERSIST_MAX, &value, &len))) {
		resp.data.route_show_resp.rto_persist_max = value;
        } else {
		resp.data.route_show_resp.rto_persist_max = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_TIMEOUT, &value, &len))) {
		resp.data.route_show_resp.max_rto_ctr = value;
        } else {
		resp.data.route_show_resp.max_rto_ctr = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_RTOMAX, &value, &len))) {
		resp.data.route_show_resp.max_rto_value = value;
        } else {
		resp.data.route_show_resp.max_rto_value = -1;
	}

	if (!(scps_getsockopt (socket_id, PROTO_SCPSTP, SCPSTP_RTOMIN, &value, &len))) {
		resp.data.route_show_resp.min_rto_value = value;
        } else {
		resp.data.route_show_resp.min_rto_value = -1;
	}

	rc = sendto (s_command, &resp, sizeof (resp), 0, (struct sockaddr *) sin_to, sin_to_len);
}


void
console_route_get (cmd, sin_to, sin_to_len)
gateway_command_t *cmd;
struct sockaddr_in *sin_to;
int		   sin_to_len;

{
	int rc;
	gateway_command_t resp;
	route *rt;
	int i;

	rt = route_rt_lookup (cmd->data.route_get.src_ipaddr, cmd->data.route_get.dst_ipaddr,
			      cmd->data.route_get.src_port, cmd->data.route_get.dst_port, 0, 0, 0);

	memset (&resp, 0x00, sizeof (gateway_command_t));

	resp.command = GW_COMMAND_ROUTE_GET_RESP;
	resp.seq_num = cmd->seq_num;

	if (!rt) {
		resp.data.route_get_resp.route_id = -1;
	} else {

		for (i = 0; i < ROUTE_SOCKET_LIST_MAX; i++) {
			if (route_socket_list [i] == rt->route_sock_id) {
				break;
			}
			
		}

		resp.data.route_get_resp.route_id = i;
		resp.data.route_get_resp.src_ipaddr = htonl (rt ->src_ipaddr);
		resp.data.route_get_resp.src_netmask = rt ->src_netmask;
		resp.data.route_get_resp.dst_ipaddr = htonl (rt ->dst_ipaddr);
		resp.data.route_get_resp.dst_netmask = rt ->dst_netmask;
		resp.data.route_get_resp.src_lowport = rt ->src_lowport;
		resp.data.route_get_resp.src_higport = rt ->src_higport;
		resp.data.route_get_resp.dst_lowport = rt ->dst_lowport;
		resp.data.route_get_resp.dst_higport = rt ->dst_higport;
		resp.data.route_get_resp.rate = rt ->rate;
		resp.data.route_get_resp.min_rate = rt ->min_rate;
		resp.data.route_get_resp.mtu = rt ->MTU;
		resp.data.route_get_resp.smtu = rt ->SMTU;
		resp.data.route_get_resp.protocol_id = rt ->protocol_id;
		resp.data.route_get_resp.dscp = rt ->dscp;
		resp.data.route_get_resp.lan_wan = rt ->lan_wan;
		resp.data.route_get_resp.cong_control = rt ->cong_control;
	
	}	

	rc = sendto (s_command, &resp, sizeof (resp), 0, (struct sockaddr *) sin_to, sin_to_len);
}

void
console_route_modify (cmd, sin_to, sin_to_len)
gateway_command_t *cmd;
struct sockaddr_in *sin_to;
int		   sin_to_len;

{
	int rc = -1;
	int rc1 = -1;
	gateway_command_t resp;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_RATE) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_RATE,
			        cmd->data.route_mod.rate);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_MIN_RATE) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_MIN_RATE,
			        cmd->data.route_mod.min_rate);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_FLOW_CONTROL) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_FLOW_CONTROL,
			        cmd->data.route_mod.flow_control);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_MTU) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_MTU,
			        cmd->data.route_mod.mtu);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_SMTU) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_SMTU,
			        cmd->data.route_mod.smtu);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_CONG_CONTROL) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_CONG_CONTROL,
			        cmd->data.route_mod.cong_control);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_SEND_BUFFER) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_SEND_BUFFER,
			        cmd->data.route_mod.send_buffer);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_RECEIVE_BUFFER) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_RECEIVE_BUFFER,
			        cmd->data.route_mod.receive_buffer);
	}
	if (rc != -1) rc1 = rc;


        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_MAX_RTO_VALUE) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_MAX_RTO_VALUE,
			        cmd->data.route_mod.max_rto_value);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_MIN_RTO_VALUE) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_MIN_RTO_VALUE,
			        cmd->data.route_mod.min_rto_value);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_MAX_RTO_CTR) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_MAX_RTO_CTR,
			        cmd->data.route_mod.max_rto_ctr);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_MAX_PERSIST_CTR) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_MAX_PERSIST_CTR,
			        cmd->data.route_mod.max_persist_ctr);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_RTO_PERSIST_MAX) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_RTO_PERSIST_MAX,
			        cmd->data.route_mod.rto_persist_max);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_RTO_PERSIST_CTR) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_RTO_PERSIST_CTR,
			        cmd->data.route_mod.rto_persist_ctr);
	}

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_EMBARGO_FAST_RXMIT_CTR) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_EMBARGO_FAST_RXMIT_CTR,
			        cmd->data.route_mod.embargo_fast_rxmit_ctr);
	}

	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_TWO_MSL_TIMEOUT) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_TWO_MSL_TIMEOUT,
			        cmd->data.route_mod.two_msl_timeout);
	}

	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_ACK_BEHAVE) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_ACK_BEHAVE,
			        cmd->data.route_mod.ack_behave);
	}

	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_ACK_DELAY) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_ACK_DELAY,
			        cmd->data.route_mod.ack_delay);
	}

	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_ACK_FLOOR) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_ACK_FLOOR,
			        cmd->data.route_mod.ack_floor);
	}

	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_SNACK) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_SNACK,
			        cmd->data.route_mod.snack);
	}

	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_NO_DELAY) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_NO_DELAY,
			        cmd->data.route_mod.no_delay);
	}

	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_SNACK_DELAY) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_SNACK_DELAY,
			        cmd->data.route_mod.snack_delay);
	}

	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_TCP_ONLY) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_TCP_ONLY,
			        cmd->data.route_mod.tcp_only);
	}

	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_COMPRESS) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_COMPRESS,
			        cmd->data.route_mod.compress);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_VEGAS_ALPHA) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_VEGAS_ALPHA,
			        cmd->data.route_mod.vegas_alpha);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_VEGAS_BETA) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_VEGAS_BETA,
			        cmd->data.route_mod.vegas_beta);
	}
	if (rc != -1) rc1 = rc;

        if (cmd->data.route_mod.attrib_list & GW_ROUTE_ATTRIB_VEGAS_GAMMA) {
		rc = route_modify (cmd->data.route_mod.route_id,
 			       GW_ROUTE_ATTRIB_VEGAS_GAMMA,
			        cmd->data.route_mod.vegas_gamma);
	}
	if (rc != -1) rc1 = rc;


	resp.command = GW_COMMAND_ROUTE_MODIFY_RESP;
	resp.seq_num = cmd->seq_num;
	resp.data.route_add_resp.route_id = rc1;
	rc = sendto (s_command, &resp, sizeof (resp), 0, (struct sockaddr *) sin_to, sin_to_len);
}

#endif /* SCPS_RI_CONSOLE */
