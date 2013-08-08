#ifndef ROUTE_H
#define ROUTE_H

#include "scps.h"

#define GW_ROUTE_SERVER_PORT 8000

#define GW_COMMAND_ROUTE_ADD		0x0001
#define GW_COMMAND_ROUTE_DELETE		0x0002
#define GW_COMMAND_ROUTE_MODIFY		0x0003
#define GW_COMMAND_ROUTE_LIST		0x0004
#define GW_COMMAND_ROUTE_GET		0x0005
#define GW_COMMAND_ROUTE_AVAIL		0x0006
#define GW_COMMAND_ROUTE_UNAVAIL	0x0007
#define GW_COMMAND_ROUTE_SHOW		0x0008

#define GW_COMMAND_ROUTE_ADD_RESP	0x0011
#define GW_COMMAND_ROUTE_DELETE_RESP	0x0012
#define GW_COMMAND_ROUTE_MODIFY_RESP	0x0013
#define GW_COMMAND_ROUTE_LIST_RESP	0x0014
#define GW_COMMAND_ROUTE_GET_RESP	0x0015
#define GW_COMMAND_ROUTE_AVAIL_RESP	0x0016
#define GW_COMMAND_ROUTE_UNAVAIL_RESP	0x0017
#define GW_COMMAND_ROUTE_SHOW_RESP	0x0018

#define ROUTE_SOCKET_LIST_MAX		20

#define GW_ROUTE_ATTRIB_RATE			0x0000001
#define GW_ROUTE_ATTRIB_MTU			0x0000002
#define GW_ROUTE_ATTRIB_SMTU			0x0000004
#define GW_ROUTE_ATTRIB_CONG_CONTROL		0x0000008
#define GW_ROUTE_ATTRIB_MIN_RATE		0x0000010
#define GW_ROUTE_ATTRIB_FLOW_CONTROL		0x0000020
#define GW_ROUTE_ATTRIB_SEND_BUFFER		0x0000040
#define GW_ROUTE_ATTRIB_RECEIVE_BUFFER		0x0000080
#define GW_ROUTE_ATTRIB_MIN_RTO_VALUE		0x0000100
#define GW_ROUTE_ATTRIB_MAX_RTO_VALUE		0x0000200
#define GW_ROUTE_ATTRIB_MAX_RTO_CTR		0x0000400
#define GW_ROUTE_ATTRIB_MAX_PERSIST_CTR		0x0000800
#define GW_ROUTE_ATTRIB_RTO_PERSIST_MAX		0x0001000
#define GW_ROUTE_ATTRIB_RTO_PERSIST_CTR		0x0002000
#define GW_ROUTE_ATTRIB_EMBARGO_FAST_RXMIT_CTR	0x0004000
#define GW_ROUTE_ATTRIB_TWO_MSL_TIMEOUT		0x0008000
#define GW_ROUTE_ATTRIB_ACK_BEHAVE		0x0010000
#define GW_ROUTE_ATTRIB_ACK_DELAY		0x0020000
#define GW_ROUTE_ATTRIB_ACK_FLOOR		0x0040000
#define GW_ROUTE_ATTRIB_TIME_STAMPS		0x0080000
#define GW_ROUTE_ATTRIB_SNACK			0x0100000
#define GW_ROUTE_ATTRIB_NO_DELAY		0x0200000
#define GW_ROUTE_ATTRIB_SNACK_DELAY		0x0400000
#define GW_ROUTE_ATTRIB_TCP_ONLY		0x0800000
#define GW_ROUTE_ATTRIB_COMPRESS		0x1000000
#define GW_ROUTE_ATTRIB_VEGAS_ALPHA		0x2000000
#define GW_ROUTE_ATTRIB_VEGAS_BETA		0x4000000
#define GW_ROUTE_ATTRIB_VEGAS_GAMMA		0x8000000

typedef struct a_route_add {
	uint32_t src_ipaddr;
	uint32_t src_netmask;
	uint32_t dst_ipaddr;
	uint32_t dst_netmask;
	unsigned short src_lowport;
	unsigned short src_higport;
	unsigned short dst_lowport;
	unsigned short dst_higport;
	uint32_t rate;
	uint32_t min_rate;
	uint32_t flow_control;
	int protocol_id;
	int dscp;
	int lan_wan;
	uint32_t mtu;
	uint32_t smtu;
	int cong_control;
} route_add_t;


typedef struct a_route_add_resp {
	int route_id;
} route_add_resp_t;

typedef struct a_route_del {
	int route_id;
} route_del_t;

typedef struct a_route_del_resp {
	int rc;
} route_del_resp_t;

typedef struct a_route_lst {
	int route_id;
} route_lst_t;

typedef struct a_route_show {
	int route_id;
} route_show_t;

typedef struct a_route_element {
	int	 route_id;
	uint32_t src_ipaddr;
	uint32_t src_netmask;
	uint32_t dst_ipaddr;
	uint32_t dst_netmask;
	unsigned short src_lowport;
	unsigned short src_higport;
	unsigned short dst_lowport;
	unsigned short dst_higport;
	uint32_t rate;
	uint32_t min_rate;
	uint32_t flow_control;
	uint32_t mtu;
	uint32_t smtu;
	int protocol_id;
	int dscp;
	int lan_wan;
	int cong_control;
} route_element_t;

typedef struct a_route_lst_resp {
	int num_in_list;
	route_element_t route_list [ROUTE_SOCKET_LIST_MAX];
} route_lst_resp_t;

typedef struct a_route_show_resp {
	int	 route_id;
	uint32_t src_ipaddr;
	uint32_t src_netmask;
	uint32_t dst_ipaddr;
	uint32_t dst_netmask;
	unsigned short src_lowport;
	unsigned short src_higport;
	unsigned short dst_lowport;
	unsigned short dst_higport;
	uint32_t rate;
	uint32_t min_rate;
	uint32_t flow_control;
	uint32_t mtu;
	uint32_t smtu;
	int protocol_id;
	int dscp;
	int cong_control;
	int lan_wan;
	int send_buffer;
	int receive_buffer;
	int min_rto_value;
	int max_rto_value;
	int max_rto_ctr;
	int max_persist_ctr;
	int rto_persist_max;
	int rto_persist_ctr;
	int embargo_fast_rxmit_ctr;
	int two_msl_timeout;
	int ack_behave;
	int ack_delay;
	int ack_floor;
	int time_stamps;
	int snack;
	int no_delay;
	int snack_delay;
	int tcp_only;
	int compress;
	int vegas_alpha;
	int vegas_beta;
	int vegas_gamma;
} route_show_resp_t;


typedef struct a_route_get {
	uint32_t src_ipaddr;
	uint32_t src_netmask;
	uint32_t dst_ipaddr;
	uint32_t dst_netmask;
	unsigned short src_port;
	unsigned short dst_port;
	int protocol_id;
	int dscp;
	int lan_wan;
} route_get_t;


typedef struct a_route_get_resp {
	int	 route_id;
	uint32_t src_ipaddr;
	uint32_t src_netmask;
	uint32_t dst_ipaddr;
	uint32_t dst_netmask;
	unsigned short src_lowport;
	unsigned short src_higport;
	unsigned short dst_lowport;
	unsigned short dst_higport;
	uint32_t rate;
	uint32_t min_rate;
	uint32_t flow_control;
	uint32_t mtu;
	uint32_t smtu;
	int protocol_id;
	int dscp;
	int lan_wan;
	int cong_control;
} route_get_resp_t;


typedef struct a_route_mod {
	int	 route_id;
	uint32_t  attrib_list;
	uint32_t rate;
	uint32_t min_rate;
	uint32_t flow_control;
	uint32_t mtu;
	uint32_t smtu;
	int protocol_id;
	int dscp;
	int cong_control;
	int lan_wan;
	int send_buffer;
	int receive_buffer;
	int min_rto_value;
	int max_rto_value;
	int max_rto_ctr;
	int max_persist_ctr;
	int rto_persist_max;
	int rto_persist_ctr;
	int embargo_fast_rxmit_ctr;
	int two_msl_timeout;
	int ack_behave;
	int ack_delay;
	int ack_floor;
	int time_stamps;
	int snack;
	int no_delay;
	int snack_delay;
	int tcp_only;
	int compress;
	int vegas_alpha;
	int vegas_beta;
	int vegas_gamma;
} route_mod_t;


typedef struct a_route_mod_resp {
	int rc;
} route_mod_resp_t;

typedef struct a_route_avail {
	int route_id;
} route_avail_t;

typedef struct a_route_avail_resp {
	int rc;
} route_avail_resp_t;

typedef struct a_route_unavail {
	int route_id;
} route_unavail_t;

typedef struct a_route_unavail_resp {
	int rc;
} route_unavail_resp_t;

typedef struct a_gateway_command {
	char command;
	int seq_num;
	union {
		route_add_t		route_add;
		route_add_resp_t	route_add_resp;
		route_del_t		route_del;
		route_del_resp_t	route_del_resp;
		route_lst_t		route_lst;
		route_lst_resp_t	route_lst_resp;
		route_get_t		route_get;
		route_get_resp_t	route_get_resp;
		route_mod_t		route_mod;
		route_mod_resp_t	route_mod_resp;
		route_show_t		route_show;
		route_show_resp_t	route_show_resp;
		route_avail_t		route_avail;
		route_avail_resp_t	route_avail_resp;
		route_unavail_t		route_unavail;
		route_unavail_resp_t	route_unavail_resp;
	} data;
} gateway_command_t;

#endif /* ROUTE_H */
