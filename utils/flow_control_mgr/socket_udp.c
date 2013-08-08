#include "net/if.h"
#include <stdio.h>
#include <syslog.h>
#include "flow_control_mgr.h"

extern int port;
extern int server;

int sd_udp;

char cmd[256];

void
udp_init_socket ()

{
 	sd_udp = udp_open ();
	if (sd_udp < 0) {
		 printf ("Can't get socket \n");
		exit (1);
	}
}


int
udp_open ()

{
    int fd;
    struct sockaddr_in local_sock_addr;

    if ((fd = socket (AF_INET, SOCK_DGRAM, 0x0)) < 0) {
	printf ("UDP open failed\n");
        return fd;
    }

    memset ((char *) &local_sock_addr, 0, sizeof (struct sockaddr_in));
    local_sock_addr.sin_family = AF_INET;
    local_sock_addr.sin_addr.s_addr = htonl (INADDR_ANY);
    local_sock_addr.sin_port = htons (FLOW_CONTROL_PORT);

    if (bind (fd, (struct sockaddr *) &local_sock_addr, sizeof (local_sock_addr)) < 0)  {
	printf ("BIND FAILED\n");

    }
printf ("BIND OK\n");
    return fd;
}


void
udp_init_socket_specific ()

{
}

void
udp_init_socket2 ()

{

} 


int
udp_socket_read (buf)
char *buf;

{
        int length;

	length = read (sd_udp,  buf, MAX_PKT_SIZE);

#ifdef PRINT_PKT
#endif /* PRINT_PKT */
{
      int i;
printf ("PDF reading a packet from the udp device\n");
      for (i = 0; i < length ; i++)
        {
        printf ("%2x ", (unsigned char) (0x0ff & (buf[i])));
        if ((i +1) % 16 == 0)
          printf ("\n");
        }
          printf ("\n");
}

	return (length);
}


void
udp_socket_write (buf, length)
char *buf;
int length;

{

}


void
udp_socket_close ()

{
	int rc;

	rc = close (sd_udp);
}


void
udp_cleanup ()

{

}


