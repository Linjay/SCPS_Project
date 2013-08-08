#ifdef TAP_INTERFACE
/********************************************************
 *
 *                             NOTICE
 *
 * "This software was produced for the U.S. Government under
 * Contract No's. DAAB07-97-C-E601, F19628-94-C-0001,
 * NAS5-32607, and JPL contract 752939 and is subject
 * to the Rights in Noncommercial Computer Software and
 * Noncommercial Computer Software Documentation Clause
 * at (DFARS) 252.227-7014 (JUN 95), and the Rights in
 * Technical Data and Computer Software Clause at (DFARS)
 * 252.227-7013 (OCT 88) with Alternate II (APR 93),
 * FAR 52.227-14 Rights in Data General, and Article GP-51,
 * Rights in Data - General, respectively.
 *
 *        (c) 1999 The MITRE Corporation
 *
 * MITRE PROVIDES THIS SOFTWARE "AS IS" AND MAKES NO
 * WARRANTY, EXPRESS OR IMPLIED, AS TO THE ACCURACY,
 * CAPABILITY, EFFICIENCY, OR FUNCTIONING OF THE PRODUCT.
 * IN NO EVENT WILL MITRE BE LIABLE FOR ANY GENERAL,
 * CONSEQUENTIAL, INDIRECT, INCIDENTAL, EXEMPLARY, OR
 * SPECIAL DAMAGES, EVEN IF MITRE HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 * You accept this software on the condition that you
 * indemnify and hold harmless MITRE, its Board of
 * Trustees, officers, agents and employees, from any and
 * all liability or damages to third parties, including
 * attorneys' fees, court costs, and other related costs
 * and expenses, arising our of your use of the Product
 * irrespective of the cause of said liability, except
 * for liability arising from claims of US patent
 * infringements.
 *
 * The export from the United States or the subsequent
 * reexport of this software is subject to compliance
 * with United States export control and munitions
 * control restrictions.  You agree that in the event you
 * seek to export this software you assume full
 * responsibility for obtaining all necessary export
 * licenses and approvals and for assuring compliance
 * with applicable reexport restrictions.
 *
 ********************************************************/


#include "scps.h"
#include "scps_ip.h"
#include "scpsudp.h"
#include "tp_debug.h"  // Included for LOG_PACKET in case DEBUG_TCPTRACE is defined.
#include "tap.h"
#include "other_proto_handler.h"
#include <syslog.h>
#ifdef __FreeBSD__
#define __ISBSDISH__
#endif /* __FreeBSD__ */
#ifdef __NetBSD__
#define __ISBSDISH__
#endif /* __NetBSD__ */
#ifdef __OpenBSD__
#define __ISBSDISH__
#endif /* __OpenBSD__ */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tap.c,v $ -- $Revision: 1.13 $\n";
#endif

extern struct msghdr out_msg;
extern struct _ll_queue_element *in_data;

extern int scps_udp_port;
extern int errno;

udp_Header *up;

#ifdef GATEWAY
#include "rs_config.h"
extern GW_ifs gw_ifs;
extern struct _interface *sock_interface;
extern struct _interface *divert_interface;

#ifdef GATEWAY_DUAL_INTERFACE
extern int special_port_number;
extern uint32_t special_ip_addr;
#endif /* GATEWAY_DUAL_INTERFACE */
#endif /* GATEWAY */


extern void err_dump ();

#ifdef LINUX 
int
tap_open (dev)
char *dev;

{
    struct ifreq ifr;
    int fd, err;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0){
        return fd;
    }
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        return err;
    }

  if (fcntl (fd, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

  if (fcntl (fd, F_SETOWN, getpid ()) > 0)
    err_dump ("fcntl problem with F_SETOWN");

    if(dev){
        strncpy(dev, ifr.ifr_name,IFNAMSIZ);
    }
    return fd;
}
#endif /* LINUX */

#if defined(__FreeBSD__) || defined(__NetBSD__)
/*
 * Allocate Ether TAP device, returns opened fd.
 * Stores dev name in the first arg(must be large enough).
 */

int tap_open(char *dev)
{
    char tapname[14];
    int i, fd;

	sprintf(tapname, "/dev/%s", dev);

/* Open device */
	if( (fd=open(tapname, O_RDWR)) > 0 ) {

		if (fcntl (fd, F_SETFL, O_NDELAY) > 0)
			err_dump ("fcntl problem");

		if (fcntl (fd, F_SETFL, FIONBIO) > 0)
			err_dump ("fcntl problem");

		if (fcntl (fd, F_SETOWN, getpid ()) > 0)
			err_dump ("fcntl problem with F_SETOWN");

		return fd;
	} else {
		return -1;
	}
}

int tap_close(int fd, char *dev)
{
    return close(fd);
}

/* Write frames to TAP device */
int tap_write(int fd, char *buf, int len)
{
    return write(fd, buf, len);
}

/* Read frames from TAP device */
int tap_read(int fd, char *buf, int len)
{
    return read(fd, buf, len);
}

#endif /* __FreeBSD__ || __NetBSD__ */

int
ll_tap_qk_send  (tun_fd, data, len)
int tun_fd;
unsigned char *data;
int len;

{
	int rc;

#ifdef DISPLAY_PKT
{
      int i;
      printf ("%s %d ll_tap_quick_send\n", __FILE__, __LINE__);
      for (i = 0; i < len; i++)
        {
        printf ("%2x ", (unsigned char) (0x0ff & (data[i])));
        if ((i +1) % 16 == 0)
          printf ("\n");
        }
          printf ("\n");
}
#endif /* DISPLAY_PKT */

	rc = write (tun_fd, data, len);
	if (rc < 0) {rc = 0;syslog (LOG_ERR, "Gateway: tun write failed\n"); }
	return (rc);

}


int
ll_tap_send  (struct _interface *interface, uint32_t remote_internet_addr,
            int protocol, int data_len, struct msghdr *my_msg,
            route *a_route, scps_np_rqts *rqts)
{
    int sock = 0;
    struct sockaddr_in remote_addr;
    unsigned char linear_buffer[MAX_MTU];
    int length;
    int size = 0;
    int rval;
    int i;
    memset((char *) &remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(scps_udp_port);
    remote_addr.sin_addr.s_addr=remote_internet_addr;
    my_msg->msg_iov[0].iov_len = 0;

    sock = rqts->recv_tap_if; 
#ifdef GATEWAY_DUAL_INTERFACE
    if (interface == sock_interface) {
        sock = interface ->udp_socket;

        if (!special_port_number) {
            special_port_number = scps_udp_port;
        }

       remote_addr.sin_port = htons (special_port_number);
 
        if (special_ip_addr) {
           memcpy ((void *) &remote_addr.sin_addr,
              (void *) &special_ip_addr,
              sizeof (special_ip_addr));
        }
        my_msg->msg_name = (caddr_t) &remote_addr;
        my_msg->msg_namelen = sizeof(remote_addr);
        rc = sendmsg (sock, my_msg, 0);
        return (rc);
  }
#endif /* GATEWAY_DUAL_INTERFACE */


    my_msg->msg_name = (caddr_t) &remote_addr;
    my_msg->msg_namelen = sizeof(remote_addr);

    // XXX Toss this and replace write with a writev().

  memcpy (&(linear_buffer [0]), &(rqts->dst_mac_addr [0]), MAC_ADDR_SIZE);
  memcpy (&(linear_buffer [MAC_ADDR_SIZE]), &(rqts->src_mac_addr [0]), MAC_ADDR_SIZE);
  linear_buffer [START_OF_FRAME_TYPE] = (rqts->frame_type & (0xff00)) >> 8; 
  linear_buffer [START_OF_FRAME_TYPE +1] = (rqts->frame_type & (0x00ff));

   for (i = 0,length=0,size=SIZE_OF_ETHER_PART; i < my_msg->msg_iovlen; i++) {
        length = my_msg->msg_iov[i].iov_len;
        memcpy(&linear_buffer[size], my_msg->msg_iov[i].iov_base,
               length);
        size += length;
    }

#ifdef DISPLAY_PKT
      printf ("%s %d ll_tap_send\n", __FILE__, __LINE__);
      for (i = 0; i < size; i++)
        {
        printf ("%2x ", (unsigned char) (0x0ff & (linear_buffer[i])));
        if ((i +1) % 16 == 0)
          printf ("\n");
        }
          printf ("\n\n");
#endif /* DISPLAY_PKT */

    rval=write(sock,linear_buffer,size);
    return rval;

}

int
tap_ind (interface, buffer, max_len, offset, rqts)
struct _interface *interface;
struct _ll_queue_element **buffer;
int max_len;
int *offset;
scps_np_rqts *rqts;

{
  int interface_side = -1;
  int fd = -1;

  memcpy (&(rqts->dst_mac_addr [0]),
          ((*buffer)->data + (*buffer)->offset + 0),
          MAC_ADDR_SIZE);

  memcpy (&(rqts->src_mac_addr [0]),
          ((*buffer)->data + (*buffer)->offset + MAC_ADDR_SIZE),
          MAC_ADDR_SIZE);

  rqts->frame_type = (
          (((int)*((*buffer)->data + (*buffer)->offset + START_OF_FRAME_TYPE)) * 256) +
          (((int)*((*buffer)->data + (*buffer)->offset + START_OF_FRAME_TYPE + 1))));

  if ((*buffer)->divert_port_number == interface->div_a_port) {
	rqts->recv_tap_if = interface->tap_a_fd;
	rqts->peer_tap_if = interface->tap_b_fd;
	rqts->divert_port_number = gw_ifs.aif_divport;
	interface_side = AIF;
	fd = interface->tap_b_fd;
  } else if ((*buffer)->divert_port_number == interface->div_b_port) {
	rqts->recv_tap_if = interface->tap_b_fd;
	rqts->peer_tap_if = interface->tap_a_fd;
	rqts->divert_port_number = gw_ifs.bif_divport;
	interface_side = BIF;
	fd = interface->tap_a_fd;
  }

  switch (in_data->frame_type) {

	case 0x0806:
	{
		int fd;
		int rc;
		
		if ((*buffer)->divert_port_number == interface->div_a_port) {
			fd = interface->tap_b_fd;
		} else if ((*buffer)->divert_port_number == interface->div_b_port) {
			fd = interface->tap_a_fd;
		} else {
			printf ("%s %d ERROR in TAP_ind bad divert_port_number\n",__FILE__, __LINE__);
		        free_ll_queue_element (rqts->interface, *buffer);
			return (0);
		}

		rc = ll_tap_qk_send (fd, ((*buffer)->data +(*buffer)->offset), (*buffer)->size); 
      		free_ll_queue_element (rqts->interface, *buffer);
		return (0);

	}
	break;

        case 0x86dd:

/* Need to check for the IPv6 equivalent of ARP for IPv6
 * (Router Solicitation and Router Advertisement */
                (*buffer)->offset +=SIZE_OF_ETHER_PART;
                (*buffer)->size -=SIZE_OF_ETHER_PART;
                *offset +=SIZE_OF_ETHER_PART;

                if ((int)*((*buffer)->data + (*buffer)->offset + 6) == 0x3a) { /* ICMP */
                        if ( ((unsigned char )*((*buffer)->data + (*buffer)->offset + 40) == 135) ||  /* 135 */
                             ((unsigned char )*((*buffer)->data + (*buffer)->offset + 40) == 136) ) 	{ /* 136 */
                		int fd;
                		int rc;

                		if ((*buffer)->divert_port_number == interface->div_a_port) {
                      	  		fd = interface->tap_b_fd;
                		} else if ((*buffer)->divert_port_number == interface->div_b_port) {
                     	 		fd = interface->tap_a_fd;
                		} else {
                      	  		printf ("%s %d ERROR in TAP_ind bad divert_port_number\n", __FILE__, __LINE__);
                      	 		return (0);
                		}

                		(*buffer)->offset -=SIZE_OF_ETHER_PART;
                		(*buffer)->size +=SIZE_OF_ETHER_PART;
                		*offset -=SIZE_OF_ETHER_PART;

                		rc = ll_tap_qk_send (fd, ((*buffer)->data +(*buffer)->offset), (*buffer)->size);
               	 		free_ll_queue_element (rqts->interface, *buffer);
                		return (0);

                	}
                }

                return ((*buffer)->size);
        break;

	case 0x0800:
		(*buffer)->offset +=SIZE_OF_ETHER_PART;
		(*buffer)->size -=SIZE_OF_ETHER_PART;
		*offset +=SIZE_OF_ETHER_PART;
		return ((*buffer)->size);
	break;

	default:
		if (gw_ifs.c_other_proto_non_ip == 1) {
			other_proto_non_ip_Handler (interface_side, buffer, rqts, fd);
			return (0);
		}
      		free_ll_queue_element (rqts->interface, *buffer);
		return (0);
	break;
  }

  return (0);
}

#endif /* TAP_INTERFACE */
