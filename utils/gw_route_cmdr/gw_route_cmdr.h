#ifndef GW_ROUTER_CMDR_H
#define GW_ROUTER_CMDR_H

#include "../../include/route.h"

#define MAX_PKT_SIZE 1400

void main_loop (void);
void initialize (void);
void send_data_to_tcc (char *buffer, int length);
void create_gw_route_socket (void);
void display_args (void);
void verify_initial_args (void);
void verify_args (void);
void get_args (int argc, char **argv);
void int_hndlr (void);
void init_sighup_mask (void);
void convert_ips_to_long (void);
void route_add (void);
void route_delete (void);
void route_list (void);
void route_get (void);
void route_modify (void);
void route_available (void);
void route_unavailable (void);
void parse_cmd (void);
void read_route_add_resp (void);
void recv_route_add_resp (void);
void read_route_delete_resp (void);
void recv_route_delete_resp (void);
void read_route_list_resp (void);
void recv_route_list_resp (void);
void read_route_get_resp (void);
void recv_route_get_resp (void);
void read_route_modify_resp (void);
void recv_route_modify_resp (void);
void read_route_avail_resp (void);
void recv_route_avail_resp (void);
void read_route_unavail_resp (void);
void recv_route_unavail_resp (void);
void display_route_list (gateway_command_t *resp);

#endif /* GW_ROUTER_CMDR_H */
