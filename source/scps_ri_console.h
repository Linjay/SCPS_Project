#ifdef SCPS_RI_CONSOLE
#ifndef SCPS_RI_CONSOLE_H
#define SCPS_RI_CONSOLE_H

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

void parse_console_command (unsigned char *data, struct sockaddr_in *sin, int len);
void console_route_add (gateway_command_t *cmd, struct sockaddr_in *sin, int len);
void console_route_delete (gateway_command_t *cmd, struct sockaddr_in *sin, int len);
void console_route_list (gateway_command_t *cmd, struct sockaddr_in *sin, int len);
void console_route_get (gateway_command_t *cmd, struct sockaddr_in *sin, int len);
void console_route_modify (gateway_command_t *cmd, struct sockaddr_in *sin, int len);
void console_route_avail (gateway_command_t *cmd, struct sockaddr_in *sin, int len);
void console_route_unavail (gateway_command_t *cmd, struct sockaddr_in *sin, int len);
void read_scps_ri_console (void);


#endif /* SCPS_RI_CONSOLE_H */
#endif /* SCPS_RI_CONSOLE */
