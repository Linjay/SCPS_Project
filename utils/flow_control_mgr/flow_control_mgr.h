#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

#define FLOW_CONTROL_PORT 59998

#define MAX_PKT_SIZE 1500
#define MSG_LEN 1500

struct flow_control_struct {
	uint8_t version;
	uint8_t command;
        uint8_t seq_num;
	uint8_t flow_id;
	uint32_t signal_addr;
	uint32_t pep_addr;
	uint16_t amount;
	uint8_t  len_auth_string;
	unsigned char    auth_string [200];
};



void udp_init_socket (void);
int udp_open (void);
void udp_init_socket_specific (void);
void udp_init_socket2 (void);
int udp_socket_read (char *buf);

