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

/* for clock_ValueRough */
#include <sys/time.h>

#include "scps.h"
#include "scps_defines.h"
#include "scpstp.h"

/* for setup_lower */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/uio.h>
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ll.h"
#ifdef SCPS_RI_CONSOLE
#include "scps_ri_console.h"
#endif /* SCPS_RI_CONSOLE */

#ifdef LOGGER
#include "pcap.h"
#define DLT_CCSDS_PATH     20
#define DEFAULT_PATH_SNAP 256
#define TIMEZ_OFFSET        0	/* not sure about this - works for U.S. */
#endif /* LOGGER */

#define DIVERT_PORT 52000

#ifdef GATEWAY
#include "rs_config.h"
extern GW_ifs gw_ifs;
extern int divert_insert_rule;
#endif /* GATEWAY */

#ifdef ENCAP_DIVERT
int divert_socket;
#endif /* ENCAP_DIVERT */

#ifdef SCPS_RI_CONSOLE 
struct sockaddr_in sin_command;
int s_command;
#endif /* SCPS_RI_CONSOLE */

#ifdef TAP_INTERFACE
#include "tap.h"
#endif /* TAP_INTERFACE */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: ll_support.c,v $ -- $Revision: 1.53 $\n";
#endif

extern void *malloc (size_t size);
#ifndef LINUX
extern void *memset (void *s, int c, size_t n);
#endif /* LINUX */
#include <stdarg.h>
extern void err_dump ();

#include <unistd.h>
extern pid_t getpid (void);

struct _interface *sock_interface;
struct _interface *divert_interface;

#if !defined(errno)
extern int errno;
#endif /* !defined(errno) */

extern int ll_read_avail;

struct timeval mytime;

spanner_ip_addr spanner_address;

struct sockaddr_in local_sock_addr;
 struct sockaddr_in remote_addr;
struct sockaddr_in useless_addr;
int real_socket;

#ifdef ENCAP_RAW
uint32_t header[5];
#endif /* ENCAP_RAW */

struct iovec iov[2];		/* scatter/gather array for sndmsg */
struct msghdr msg;		/* the message for sndmsg */

#ifdef __FreeBSD__
#define __ISBSDISH__
#endif /* __FreeBSD__ */
#ifdef __NetBSD__
#define __ISBSDISH__
#endif /* __NetBSD__ */

#ifdef __OpenBSD__
#define __ISBSDISH__
#endif /* __OpenBSD__ */

#ifdef SOLARIS
#define __ISBSDISH__
#endif /* SOLARIS */

#ifdef DIVERT_N_RAWIP
#define __ISBSDISH__
#endif /* DIVERT_N_RAWIP */
#undef DEBUG
#undef RCV_DEBUG

int trans_loopback = 0;
int scps_udp_port = SCPS_UDP_PORT;
int scps_udp_port1 = Other_SCPS_UDP_PORT;

#ifdef GATEWAY_DUAL_INTERFACE
int special_port_number = SCPS_UDP_PORT;
uint32_t  special_ip_addr = 0;
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef SCPS_RI_CONSOLE 
#include "route.h" 
#endif /* SCPS_RI_CONSOLE */

#ifdef GATEWAY
#ifdef LOW_CPU_IDLE
extern int gw_no_delay;
#endif /* LOW_CPU_IDLE */
#endif /* GATEWAY */

uint32_t timebefore = 0;

#ifdef LOGGER
static char *logfile = "logfile";	/* packet log filename */
static FILE *lf;		/* packet log file handle */

extern struct timeval lltimeout;

extern sigset_t alarmset;

int
init_logger (void)
{
  lf = fopen (logfile, "w");
  /* lf = fopen(logfile, "a"); */
  if (lf == NULL)
    {
      fprintf (stderr, "error opening packet log file: %s\n", logfile);
      return -1;
    }
  if ((sf_write_header (lf, 1, TIMEZ_OFFSET, DEFAULT_PATH_SNAP)) < 0)
    {
      fprintf (stderr, "error initializing log file\n");
      return -1;
    }
  fflush (lf);
  return 1;
}
#endif /* LOGGER */

uint32_t local_inet;

/*  
 * set up a lower-layer socket and return a socket descriptor for it 
 *  usage:  sd = setup_lower(remote_internet_addr);  
 */

struct _interface *
create_interface (spanner_ip_addr local_addr, spanner_ip_addr span_addr)
{
  struct _interface *interface, *index;

#ifdef LL_BUFFER
     int optlen, rcvbuff, sndbuff;
#endif /* LL_BUFFER */

#ifdef __ISBSDISH__
  int hincl = 0;
#endif /* __ISBSDISH__ */

  spanner_address = span_addr;
  if (!(local_addr))
    get_local_internet_addr ((char *) &local_addr);

  interface = (struct _interface *) malloc (sizeof (struct _interface));
  memset (interface, 0, sizeof (struct _interface));
  initialize_interface (interface, local_addr);
  index = interface;
  sock_interface = interface;

  sock_interface->local_ipaddr = local_addr;
  sock_interface->remote_ipaddr = span_addr;

#ifdef LL_RAWIP
  if (((interface->tp_socket = socket (AF_INET, SOCK_RAW, SCPSTP)) < 0) ||
      ((interface->ctp_socket = socket (AF_INET, SOCK_RAW, SCPSCTP)) < 0) ||
      ((interface->udp_socket = socket (AF_INET, SOCK_RAW, SCPSUDP)) < 0) ||
      ((interface->sp_socket = socket (AF_INET, SOCK_RAW, SP)) < 0) ||
#ifdef DIVERT_N_RAWIP
      ((interface->raw_socket = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) ||
#endif /*  DIVERT_N_RAWIP */
      ((interface->np_socket = socket (AF_INET, SOCK_RAW, SCPSNP)) < 0))
#elif ENCAP_RAW
    if ((interface->raw_socket = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
#else /* must be ENCAP_UDP */
  if ((interface->udp_socket = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
#endif /* LL_RAWIP */
    {
#ifdef LL_RAWIP
      syslog (LOG_ERR, 
	"setup_lower:  can't create RAW_IP socket\n Are you sure that you have permissions to run over RAW_IP sockets?\n");
#elif ENCAP_RAW
      syslog (LOG_ERR.
	"setup_lower:  can't create RAW_IP socket\n Are you sure that you have permissions to run over RAW_IP sockets?\n");
#elif ENCAP_UDP
      syslog (LOG_ERR, "setup_lower:  can't create SOCK_DGRAM socket");
#endif /* LL_RAWIP */
      return (0x0);
    }

#ifdef SCPS_RI_CONSOLE 
        if ((s_command = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
          perror ("Creating SCPS RI console socket");
          exit (0); 
        }
#endif /* SCPS_RI_CONSOLE */

#ifdef __ISBSDISH__
#ifdef LL_RAWIP
  setsockopt (interface->tp_socket, IPPROTO_IP, IP_HDRINCL,
	      (const void *) &hincl, sizeof (hincl));
  setsockopt (interface->ctp_socket, IPPROTO_IP, IP_HDRINCL,
	      (const void *) &hincl, sizeof (hincl));
#ifdef DIVERT_N_RAWIP
  setsockopt (interface->raw_socket, IPPROTO_IP, IP_HDRINCL,
	      (const void *) &hincl, sizeof (hincl));
#endif /*  DIVERT_N_RAWIP */
  setsockopt (interface->udp_socket, IPPROTO_IP, IP_HDRINCL,
	      (const void *) &hincl, sizeof (hincl));
  setsockopt (interface->sp_socket, IPPROTO_IP, IP_HDRINCL,
	      (const void *) &hincl, sizeof (hincl));
  setsockopt (interface->np_socket, IPPROTO_IP, IP_HDRINCL,
	      (const void *) &hincl, sizeof (hincl));
#endif /* LL_RAWIP */

#ifdef ENCAP_RAW
  setsockopt (interface->raw_socket, IPPROTO_IP, IP_HDRINCL,
	      (const void *) &hincl, sizeof (hincl));
#endif /* ENCAP_RAW */

#endif /* __ISBSDISH__ */

#ifdef ENCAP_RAW
#ifdef IRIX
  header[0] = 0x45000000;	/* version 4, hdr len 5, TOS 0 */
  header[0] = htonl (header[0]);
  /* Must OR in length (then clear) */
  header[1] = 0;		/* ID = 0, last frag, offset = 0 */
  header[2] = 0x20ff0000;	/* TTL = 32, proto = raw ip, cksum = 0 */
  header[2] = htonl (header[2]);
  /* checksum must be filled in later */
  header[3] = local_addr;	/* source IP address */
  /* header[3] = htonl(header[3]); */
  header[4] = 0;		/* dest IP address - must be filled in later */

  iov[0].iov_base = (char *) header;
  iov[0].iov_len = sizeof (header);
#endif /* IRIX */

#ifdef SUNOS
  header[0] = 0x45000000;	/* version 4, hdr len 5, TOS 0 */
  header[0] = htonl (header[0]);
  /* Must OR in length (then clear) */
  header[1] = 0;		/* ID = 0, last frag, offset = 0 */
  header[2] = 0x20ff0000;	/* TTL = 32, proto = raw ip, cksum = 0 */
  header[2] = htonl (header[2]);
  /* checksum must be filled in later */
  header[3] = local_addr;	/* source IP address */
  /* header[3] = htonl(header[3]); */
  header[4] = 0;		/* dest IP address - must be filled in later */

  iov[0].iov_base = (char *) header;
  iov[0].iov_len = sizeof (header);
#endif /* SUNOS */
#endif /* ENCAP_RAW */

  /* set up for bind */
  memset ((char *) &local_sock_addr, 0, sizeof (local_sock_addr));
  local_sock_addr.sin_family = AF_INET;
#ifdef LL_RAWIP
  local_sock_addr.sin_port = (short) 0;
#elif ENCAP_RAW
  local_sock_addr.sin_port = (short) 0;
#else /* We must be using UDP */
  local_sock_addr.sin_port = htons (scps_udp_port);
#endif /* LL_RAWIP */

#ifndef LL_RAWIP
  if (spanner_address)
    memcpy ((char *) &remote_addr.sin_addr, (char *) &spanner_address,
	    sizeof (spanner_address));
#endif /* LL_RAWIP */

  memcpy (&local_sock_addr.sin_addr, (char *) &local_addr, sizeof (local_addr));
#if defined (__FreeBSD__) || defined (__OpenBSD__) || defined (__NetBSD__)
  local_sock_addr.sin_len = sizeof (local_sock_addr);
#endif /* __FreeBSD__ || __OpenBSD__ || __NetBSD__ */

#ifdef LL_RAWIP
  if ((bind (interface->tp_socket, (struct sockaddr *) &local_sock_addr,
	     sizeof (local_sock_addr)) < 0) ||
      (bind (interface->ctp_socket, (struct sockaddr *) &local_sock_addr,
	     sizeof (local_sock_addr)) < 0) ||
#ifdef DIVERT_N_RAWIP
      (bind (interface->raw_socket, (struct sockaddr *) &local_sock_addr,
	     sizeof (local_sock_addr)) < 0) ||
#endif /*  DIVERT_N_RAWIP */
      (bind (interface->udp_socket, (struct sockaddr *) &local_sock_addr,
	     sizeof (local_sock_addr)) < 0) ||
      (bind (interface->sp_socket, (struct sockaddr *) &local_sock_addr,
	     sizeof (local_sock_addr)) < 0) ||
      (bind (interface->np_socket, (struct sockaddr *) &local_sock_addr,
	     sizeof (local_sock_addr)) < 0))
    err_dump ("setup_lower:  couldn't bind to local address");
#elif ENCAP_RAW
  if (bind (interface->raw_socket, (struct sockaddr *) &local_sock_addr,
	    sizeof (local_sock_addr)) < 0)
    err_dump ("setup_lower:  couldn't bind to local address");
#elif ENCAP_UDP
  if (bind (interface->udp_socket, (struct sockaddr *) &local_sock_addr,
	    sizeof (local_sock_addr)) < 0)
    {
#ifdef LL_LOOPBACK
      /* The main UDP Port is in use, bind to the Other_SCPS_UDP_PORT */
      local_sock_addr.sin_port = htons (scps_udp_port1);
      if (bind (interface->udp_socket, (struct sockaddr *) &local_sock_addr,
		sizeof (local_sock_addr)) < 0)
	err_dump ("setup_lower:  couldn't bind to local address");
      else
	trans_loopback = 1;
#else /* LL_LOOPBACK */
      err_dump ("setup_lower:  couldn't bind to local address");
#endif /* LL_LOOPBACK */
    }
#endif /* LL_RAWIP */

#ifdef SCPS_RI_CONSOLE 
        memset ((char *) &sin_command, 0, sizeof (sin_command));
        sin_command.sin_family = AF_INET;
        sin_command.sin_port = htons (GW_ROUTE_SERVER_PORT);
#ifndef LINUX
        sin_command.sin_len = sizeof (sin_command);
#endif /* LINUX */
        sin_command.sin_addr.s_addr = htonl (INADDR_ANY);

        if (bind (s_command, (struct sockaddr *) &sin_command,
                  sizeof (sin_command)) < 0) {
          perror ("Binding SCPS RI console socket");
          exit (0);
        }
printf ("CREATED SCPS RI CONSOLE SOCKET XX\n");
#endif /* SCPS_RI_CONSOLE */ 

#ifdef LL_RAWIP
  if ((fcntl (interface->tp_socket, F_SETFL, O_NDELAY) > 0) ||
      (fcntl (interface->ctp_socket, F_SETFL, O_NDELAY) > 0) ||
#ifdef DIVERT_N_RAWIP
      (fcntl (interface->raw_socket, F_SETFL, O_NDELAY) > 0) ||
#endif /*  DIVERT_N_RAWIP */
      (fcntl (interface->udp_socket, F_SETFL, O_NDELAY) > 0) ||
      (fcntl (interface->sp_socket, F_SETFL, O_NDELAY) > 0) ||
      (fcntl (interface->np_socket, F_SETFL, O_NDELAY) > 0))
    err_dump ("fcntl problem");

  if ((fcntl (interface->tp_socket, F_SETOWN, getpid ()) > 0) ||
#ifdef DIVERT_N_RAWIP
      (fcntl (interface->raw_socket, F_SETOWN, getpid ()) > 0) ||
#endif /*  DIVERT_N_RAWIP */
      (fcntl (interface->udp_socket, F_SETOWN, getpid ()) > 0) ||
      (fcntl (interface->sp_socket, F_SETOWN, getpid ()) > 0) ||
      (fcntl (interface->np_socket, F_SETOWN, getpid ()) > 0))
    err_dump ("fcntl problem with F_SETOWN");

  FD_SET (interface->tp_socket, &llfd_set);
  if (interface->tp_socket > ll_max_socket)
    ll_max_socket = interface->tp_socket;

  FD_SET (interface->ctp_socket, &llfd_set);
  if (interface->ctp_socket > ll_max_socket)
    ll_max_socket = interface->ctp_socket;

#ifdef DIVERT_N_RAWIP
  FD_SET (interface->raw_socket, &llfd_set);
  if (interface->raw_socket > ll_max_socket)
    ll_max_socket = interface->raw_socket;
#endif /*  DIVERT_N_RAWIP */
  FD_SET (interface->udp_socket, &llfd_set);
  if (interface->udp_socket > ll_max_socket)
    ll_max_socket = interface->udp_socket;

  FD_SET (interface->sp_socket, &llfd_set);
  if (interface->sp_socket > ll_max_socket)
    ll_max_socket = interface->sp_socket;

  FD_SET (interface->np_socket, &llfd_set);
  if (interface->np_socket > ll_max_socket)
    ll_max_socket = interface->np_socket;

  /* mark socket as non-blocking */

  if ((fcntl (interface->tp_socket, F_SETFL, O_NDELAY) > 0) ||
      (fcntl (interface->ctp_socket, F_SETFL, O_NDELAY) > 0) ||
#ifdef DIVERT_N_RAWIP
      (fcntl (interface->raw_socket, F_SETFL, O_NDELAY) > 0) ||
#endif /*  DIVERT_N_RAWIP */
      (fcntl (interface->udp_socket, F_SETFL, O_NDELAY) > 0) ||
      (fcntl (interface->sp_socket, F_SETFL, O_NDELAY) > 0) ||
      (fcntl (interface->np_socket, F_SETFL, O_NDELAY) > 0))
    err_dump ("fcntl problem");

#elif ENCAP_RAW

  if (fcntl (interface->raw_socket, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

  if (fcntl (interface->raw_socket, F_SETOWN, getpid ()) > 0)
    err_dump ("fcntl problem with F_SETOWN");

  FD_SET (interface->raw_socket, &llfd_set);

  if (interface->raw_socket > ll_max_socket)
    ll_max_socket = interface->raw_socket;

  if (fcntl (interface->raw_socket, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

#elif ENCAP_UDP

  if (fcntl (interface->udp_socket, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

  if (fcntl (interface->udp_socket, F_SETOWN, getpid ()) > 0)
    err_dump ("fcntl problem with F_SETOWN");

  FD_SET (interface->udp_socket, &llfd_set);

  if (interface->udp_socket > ll_max_socket)
    ll_max_socket = interface->udp_socket;

  if (fcntl (interface->udp_socket, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

#endif /* LL_RAWIP */

#ifdef SCPS_RI_CONSOLE 
  if (fcntl (s_command, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");
        
  if (fcntl (s_command, F_SETOWN, getpid ()) > 0)  
    err_dump ("fcntl problem with F_SETOWN");

  FD_SET (s_command, &llfd_set);
                  
  if (s_command > ll_max_socket)
    ll_max_socket = s_command;
        
  if (fcntl (s_command, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

#endif /* SCPS_RI_CONSOLE */

  /* set up for connect */
  memset ((char *) &useless_addr, 0, sizeof (useless_addr));
  useless_addr.sin_family = AF_INET;
  useless_addr.sin_port = (short) 0;
  useless_addr.sin_addr.s_addr = INADDR_ANY;

#ifdef LL_RAWIP
  /* 
   * set up Raw IP Header template - fill in an IP header
   *  with everything that can be known in advance 
   */

  iov[0].iov_len = 0;
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;		/* only 2 elements in our scatter/gather */
#endif /* LL_RAWIP */

#ifdef ENCAP_RAW
  /*
   * set up Raw IP Header template - fill in an IP header
   *  with everything that can be known in advance
   */

  iov[0].iov_len = 0;
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;		/* only 2 elements in our scatter/gather */
#endif /* ENCAP_RAW */

  /* Establish receive buffer size */
#ifdef LL_BUFFER
#ifdef LL_RAWIP
  rcvbuff = LL_BUFFER;
  optlen = sizeof (rcvbuff);
  if ((setsockopt (interface->tp_socket, SOL_SOCKET, SO_RCVBUF,
		   (char *) &rcvbuff, sizeof (rcvbuff)) < 0) ||
      (setsockopt (interface->ctp_socket, SOL_SOCKET, SO_RCVBUF,
		   (char *) &rcvbuff, sizeof (rcvbuff)) < 0) ||
#ifdef DIVERT_N_RAWIP
      (setsockopt (interface->raw_socket, SOL_SOCKET, SO_RCVBUF,
		   (char *) &rcvbuff, sizeof (rcvbuff)) < 0) ||
#endif /*  DIVERT_N_RAWIP */
      (setsockopt (interface->udp_socket, SOL_SOCKET, SO_RCVBUF,
		   (char *) &rcvbuff, sizeof (rcvbuff)) < 0) ||
      (setsockopt (interface->sp_socket, SOL_SOCKET, SO_RCVBUF,
		   (char *) &rcvbuff, sizeof (rcvbuff)) < 0) ||
      (setsockopt (interface->np_socket, SOL_SOCKET, SO_RCVBUF,
		   (char *) &rcvbuff, sizeof (rcvbuff)) < 0))
    {
#ifdef DEBUG
      fprintf (stderr, "Error setting receive buffer size to %d  :%d\n",
	       rcvbuff, errno);
#endif /* DEBUG */
    }
  sndbuff = LL_BUFFER;
  optlen = sizeof (sndbuff);
  if ((setsockopt (interface->tp_socket, SOL_SOCKET, SO_SNDBUF,
		   (char *) &sndbuff, sizeof (sndbuff)) < 0) ||
      (setsockopt (interface->ctp_socket, SOL_SOCKET, SO_SNDBUF,
		   (char *) &sndbuff, sizeof (sndbuff)) < 0) ||
#ifdef DIVERT_N_RAWIP
      (setsockopt (interface->raw_socket, SOL_SOCKET, SO_SNDBUF,
		   (char *) &sndbuff, sizeof (sndbuff)) < 0) ||
#endif /*  DIVERT_N_RAWIP */
      (setsockopt (interface->udp_socket, SOL_SOCKET, SO_SNDBUF,
		   (char *) &sndbuff, sizeof (sndbuff)) < 0) ||
      (setsockopt (interface->sp_socket, SOL_SOCKET, SO_SNDBUF,
		   (char *) &sndbuff, sizeof (sndbuff)) < 0) ||
      (setsockopt (interface->np_socket, SOL_SOCKET, SO_SNDBUF,
		   (char *) &sndbuff, sizeof (sndbuff)) < 0))
    fprintf (stderr, "Error setting send buffer size to %d\n", sndbuff);
#elif ENCAP_RAW
  rcvbuff = LL_BUFFER;
  optlen = sizeof (rcvbuff);
  if (setsockopt (interface->raw_socket, SOL_SOCKET, SO_RCVBUF,
		  (char *) &rcvbuff, sizeof (rcvbuff)) < 0)
    {
#ifdef DEBUG
      fprintf (stderr, "Error setting receive buffer size to %d  :%d\n",
	       rcvbuff, errno);
#endif /* DEBUG */
    }
  sndbuff = LL_BUFFER;
  optlen = sizeof (sndbuff);
  if (setsockopt (interface->raw_socket, SOL_SOCKET, SO_SNDBUF,
		  (char *) &sndbuff, sizeof (sndbuff)) < 0)
    fprintf (stderr, "Error setting send buffer size to %d  :%d\n",
	     sndbuff, errno);
#elif ENCAP_UDP
  rcvbuff = LL_BUFFER;
  optlen = sizeof (rcvbuff);
  if (setsockopt (interface->udp_socket, SOL_SOCKET, SO_RCVBUF,
		  (char *) &rcvbuff, sizeof (rcvbuff)) < 0)
    {
#ifdef DEBUG
      fprintf (stderr, "Error setting receive buffer size to %d  :%d\n",
	       rcvbuff, errno);
#endif /* DEBUG */
    }
  sndbuff = LL_BUFFER;
  optlen = sizeof (sndbuff);
  if (setsockopt (interface->udp_socket, SOL_SOCKET, SO_SNDBUF,
		  (char *) &sndbuff, sizeof (sndbuff)) < 0)
    fprintf (stderr, "Error setting send buffer size to %d  :%d\n",
	     sndbuff, errno);
#endif /* LL_RAWIP */
#endif /* LL_BUFFER */

  if (!(scheduler.interface))
    scheduler.interface = (void *) interface;
  else
    {
      index =  (struct _interface *) (scheduler.interface);
      while (index->next)
	index = index->next;

      index->next = interface;
      interface ->next = (struct _interface *) (scheduler.interface);
    }

/*  
 * We can only do this once we've got a global list of interfaces and
 * this interface has been attached to it!
 *
 * if (!(scheduler.service_interface_now))
 *   toggle_iostatus(1);
 */

  return (interface);
}

#ifdef TUN_INTERFACE

#ifdef LINUX
#include <linux/if_tun.h>
int tun_open(char *dev)

{
    struct ifreq ifr;
    int fd, err;
    printf ("Trying to Open up tun\n ");
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0){
        return fd;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
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
#include <net/if_tun.h>
int tun_open(char *dev)
{
    char tunname[14];
    int i, fd = -1;

    if( *dev ){
       sprintf(tunname, "/dev/%s", dev);
       fd = open(tunname, O_RDWR);
    } else {
       for(i=0; i < 255; i++){
          sprintf(tunname, "/dev/tun%d", i);
          /* Open device */
          if( (fd=open(tunname, O_RDWR)) > 0 ){
             sprintf(dev, "tun%d", i);
             break;
          }
       }
    }
    if( fd > -1 ){
       i=1;
       /* Enable extended modes */
       ioctl(fd, TUNSLMODE, &i);
/*       ioctl(fd, TUNSIFHEAD, &i); */
    }
    return fd;
}
#endif /* __FreeBSD__ || __NetBSD__ */

int tun_close(int fd, char *dev)
{
    return close(fd);
}

/* Read/write frames from/to TUN device */
int tun_write(int fd, char *buf, int len)
{
    return write(fd, buf, len);
}

int tun_read(int fd, char *buf, int len)
{
    return read(fd, buf, len);
}



int
ll_tun_send  (struct _interface *interface, uint32_t remote_internet_addr,
            int protocol, int data_len, struct msghdr *my_msg,
            route *a_route)
{
    int sock = 0;
    struct sockaddr_in remote_addr;
    unsigned char linear_buffer[MAX_MTU];
    int length;
    int size = 0;
    int rval;
    int i;
    int rc;
    sock = interface->tun_c_fd;
    memset((char *) &remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(scps_udp_port);
    remote_addr.sin_addr.s_addr=remote_internet_addr;
    my_msg->msg_iov[0].iov_len = 0;

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
    for (i = 0,length=0,size=0; i < my_msg->msg_iovlen; i++) {
        length = my_msg->msg_iov[i].iov_len;
        memcpy(&linear_buffer[size], my_msg->msg_iov[i].iov_base,
               length);
        size += length;
    }
#ifdef PKT
      for (i = 0; i < size; i++)
        {
        printf ("%2x ", (unsigned char) (0x0ff & (linear_buffer[i])));
        if ((i +1) % 16 == 0)
          printf ("\n");
        }
          printf ("\n");
#endif /* PKT */
    rval=write(sock,linear_buffer,size);
    return rval;

}

#endif /* TUN_INTERFACE */

#ifdef ENCAP_DIVERT

void
create_divert_interface (local_addr, port_number1)
     spanner_ip_addr local_addr;
     int32_t port_number1;

{
  int optlen, rcvbuff, sndbuff;
  struct _interface *interface, *index;
#ifdef __ISBSDISH__
  int hincl = 0;
#endif /* __ISBSHISH__ */
  int32_t port_number2;
  int32_t port_number3;

#ifdef SCPS_RI_CONSOLE
   int one = 1;
#endif /* SCPS_RI_CONSOLE */

  local_addr = 0;

  port_number1 = gw_ifs.c_divport;
  port_number2 = gw_ifs.aif_divport;
  port_number3 = gw_ifs.bif_divport;

  if (!(local_addr))
    get_local_internet_addr ((char *) &local_addr);

  if (!(port_number1))
    port_number1 = DEF_C_PORT;

  if (!(port_number2))
    port_number2 = DEF_A_PORT;

  if (!(port_number3))
    port_number3 = DEF_B_PORT;

  interface = (struct _interface *) malloc (sizeof (struct _interface));
  memset (interface, 0, sizeof (struct _interface));
  initialize_interface (interface, local_addr);
  index = interface;
  divert_interface = interface;

#ifdef TUN_INTERFACE

  if ((interface->tun_a_fd = tun_open (&(gw_ifs.aif_tun_name))) < 0) {

  }
  FD_SET (interface->tun_a_fd, &llfd_set);
  if (interface->tun_a_fd > ll_max_socket){
      ll_max_socket = interface->tun_a_fd;
  }
  interface->div_a_port = port_number2;

  if ((interface->tun_b_fd = tun_open (&(gw_ifs.bif_tun_name))) < 0) {

  }
  FD_SET (interface->tun_b_fd, &llfd_set);
  if (interface->tun_b_fd > ll_max_socket){
      ll_max_socket = interface->tun_b_fd;
  }
  interface->div_b_port = port_number3;

  if ((interface->tun_c_fd = tun_open (&(gw_ifs.c_tun_name))) < 0) {

  }
  FD_SET (interface->tun_c_fd, &llfd_set);
  if (interface->tun_c_fd > ll_max_socket){
      ll_max_socket = interface->tun_c_fd;
  }
  interface->div_port = port_number1;

#ifdef SCPS_RI_CONSOLE
        if ((s_command = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror ("Creating SCPS RI console socket");
                exit (0);
        }

        if (setsockopt (s_command, SOL_SOCKET, SO_REUSEADDR,
		      (char *) &one, sizeof (int)) < 0) {
    		err_dump ("Trying to set reuseaddr ");
	}

        memset ((char *) &sin_command, 0, sizeof (sin_command));
        sin_command.sin_family = AF_INET;
        sin_command.sin_port = htons (GW_ROUTE_SERVER_PORT);
#ifndef LINUX
        sin_command.sin_len = sizeof (sin_command);
#endif /* LINUX */
        sin_command.sin_addr.s_addr = htonl (INADDR_ANY);
        if (bind (s_command, (struct sockaddr *) &sin_command,
                sizeof (sin_command)) < 0) {
                perror ("Binding SCPS RI console socket");
                exit (0);
        }

  if (fcntl (s_command, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

  if (fcntl (s_command, F_SETOWN, getpid ()) > 0)
    err_dump ("fcntl problem with F_SETOWN");

  FD_SET (s_command, &llfd_set);

  if (s_command > ll_max_socket)
    ll_max_socket = s_command;

  if (fcntl (s_command, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

#endif /* SCPS_RI_CONSOLE */

#else /* TUN_INTERFACE */

#ifdef TAP_INTERFACE

  if ((interface->tap_a_fd = tap_open (((char *)&(gw_ifs.aif_tap_name)))) < 0) {

  }
  FD_SET (interface->tap_a_fd, &llfd_set);
  if (interface->tap_a_fd > ll_max_socket){
      ll_max_socket = interface->tap_a_fd;
  }
  interface->div_a_port = port_number2;

  if ((interface->tap_b_fd = tap_open (((char *)&(gw_ifs.bif_tap_name)))) < 0) {

  }
  FD_SET (interface->tap_b_fd, &llfd_set);
  if (interface->tap_b_fd > ll_max_socket){
      ll_max_socket = interface->tap_b_fd;
  }
  interface->div_b_port = port_number3;

#ifdef SCPS_RI_CONSOLE
        if ((s_command = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror ("Creating SCPS RI console socket");
                exit (0);
        }

        memset ((char *) &sin_command, 0, sizeof (sin_command));
        sin_command.sin_family = AF_INET;
        sin_command.sin_port = htons (GW_ROUTE_SERVER_PORT);
#ifndef LINUX
        sin_command.sin_len = sizeof (sin_command);
#endif /* LINUX */
        sin_command.sin_addr.s_addr = htonl (INADDR_ANY);
        if (bind (s_command, (struct sockaddr *) &sin_command,
                sizeof (sin_command)) < 0) {
                perror ("Binding SCPS RI console socket");
                exit (0);
        }

  if (fcntl (s_command, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

  if (fcntl (s_command, F_SETOWN, getpid ()) > 0)
    err_dump ("fcntl problem with F_SETOWN");

  FD_SET (s_command, &llfd_set);

  if (s_command > ll_max_socket)
    ll_max_socket = s_command;

  if (fcntl (s_command, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

#endif /* SCPS_RI_CONSOLE */
#else /* TAP_INTERFACE */

  /* Create all three Divert Sockets */

  if ((interface->div_socket = socket (AF_INET, SOCK_RAW, IPPROTO_DIVERT)) <
      0)
    {
      syslog (LOG_ERR,
	"setup_lower:  can't create Divert socket 1\n Are you sure that you have permissions to run over RAW_IP sockets?\n");
      return;
    }
  interface->div_port = port_number1;

  if ((interface->div_a_socket = socket (AF_INET, SOCK_RAW, IPPROTO_DIVERT))
      < 0)
    {
      syslog (LOG_ERR,
	"setup_lower:  can't create Divert socket a\n Are you sure that you have permissions to run over RAW_IP sockets?\n");
      return;
    }
  interface->div_a_port = port_number2;

  if ((interface->div_b_socket = socket (AF_INET, SOCK_RAW, IPPROTO_DIVERT))
      < 0)
    {
      syslog (LOG_ERR,
	"setup_lower:  can't create Divert socket b\n Are you sure that you have permissions to run over RAW_IP sockets?\n");
      return;
    }
  interface->div_b_port = port_number3;

#ifdef SCPS_RI_CONSOLE
        if ((s_command = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror ("Creating SCPS RI console socket");
                exit (0);
        }         
#endif /* SCPS_RI_CONSOLE */

#ifdef __ISBSDISH__
  setsockopt (interface->div_socket, IPPROTO_IP, IP_HDRINCL,
	      (const void *) &hincl, sizeof (hincl));

  setsockopt (interface->div_a_socket, IPPROTO_IP, IP_HDRINCL,
	      (const void *) &hincl, sizeof (hincl));

  setsockopt (interface->div_b_socket, IPPROTO_IP, IP_HDRINCL,
	      (const void *) &hincl, sizeof (hincl));
#endif /* __ISBSDISH__ */

/* Bind to all three sockets */
  memset ((char *) &local_sock_addr, 0, sizeof (local_sock_addr));
#ifndef LINUX
  local_sock_addr.sin_len = sizeof (local_sock_addr);
#endif /* LINUX */
  local_sock_addr.sin_family = AF_INET;
  local_sock_addr.sin_port = htons (port_number1);
  local_sock_addr.sin_addr.s_addr = htonl (INADDR_ANY);

  if (bind (interface->div_socket, (struct sockaddr *) &local_sock_addr,
	    sizeof (local_sock_addr)) < 0)
    {
      err_dump ("setup_lower:  couldn't bind to local address");
    }
  interface->div_port = port_number1;

  memset ((char *) &local_sock_addr, 0, sizeof (local_sock_addr));
#ifndef LINUX
  local_sock_addr.sin_len = sizeof (local_sock_addr);
#endif /* LINUX */
  local_sock_addr.sin_family = AF_INET;
  local_sock_addr.sin_port = htons (port_number2);
  local_sock_addr.sin_addr.s_addr = htonl (INADDR_ANY);

  if (bind (interface->div_a_socket, (struct sockaddr *) &local_sock_addr,
	    sizeof (local_sock_addr)) < 0)
    {
      err_dump ("setup_lower:  couldn't bind to local address");
    }

  memset ((char *) &local_sock_addr, 0, sizeof (local_sock_addr));
#ifndef LINUX
  local_sock_addr.sin_len = sizeof (local_sock_addr);
#endif /* LINUX */
  local_sock_addr.sin_family = AF_INET;
  local_sock_addr.sin_port = htons (port_number3);
  local_sock_addr.sin_addr.s_addr = htonl (INADDR_ANY);

  if (bind (interface->div_b_socket, (struct sockaddr *) &local_sock_addr,
	    sizeof (local_sock_addr)) < 0)
    {
      err_dump ("setup_lower:  couldn't bind to local address");
    }
  interface->div_b_port = port_number3;

#ifdef SCPS_RI_CONSOLE
        memset ((char *) &sin_command, 0, sizeof (sin_command));
        sin_command.sin_family = AF_INET; 
        sin_command.sin_port = htons (GW_ROUTE_SERVER_PORT);
#ifndef LINUX
        sin_command.sin_len = sizeof (sin_command);
#endif /* LINUX */
        sin_command.sin_addr.s_addr = htonl (INADDR_ANY);
        if (bind (s_command, (struct sockaddr *) &sin_command,
                sizeof (sin_command)) < 0) {
                perror ("Binding SCPS RI console socket");  
                exit (0); 
        }
#endif /* SCPS_RI_CONSOLE */

/* Do some File controls */
  if (fcntl (interface->div_socket, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

  if (fcntl (interface->div_socket, F_SETOWN, getpid ()) > 0)
    err_dump ("fcntl problem with F_SETOWN");

  FD_SET (interface->div_socket, &llfd_set);
  if (interface->div_socket > ll_max_socket)
    ll_max_socket = interface->div_socket;

  if (fcntl (interface->div_a_socket, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

  if (fcntl (interface->div_a_socket, F_SETOWN, getpid ()) > 0)
    err_dump ("fcntl problem with F_SETOWN");

  FD_SET (interface->div_a_socket, &llfd_set);
  if (interface->div_a_socket > ll_max_socket)
    ll_max_socket = interface->div_a_socket;

  if (fcntl (interface->div_b_socket, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");

  if (fcntl (interface->div_b_socket, F_SETOWN, getpid ()) > 0)
    err_dump ("fcntl problem with F_SETOWN");

  FD_SET (interface->div_b_socket, &llfd_set);
  if (interface->div_b_socket > ll_max_socket)
    ll_max_socket = interface->div_b_socket;

#ifdef SCPS_RI_CONSOLE
  if (fcntl (s_command, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");
        
  if (fcntl (s_command, F_SETOWN, getpid ()) > 0)  
    err_dump ("fcntl problem with F_SETOWN");
        
  FD_SET (s_command, &llfd_set);
                
  if (s_command > ll_max_socket)
    ll_max_socket = s_command;

  if (fcntl (s_command, F_SETFL, O_NDELAY) > 0)
    err_dump ("fcntl problem");
  
#endif /* SCPS_RI_CONSOLE */ 

/* Do some set sock options */

  rcvbuff = LL_BUFFER;
  optlen = sizeof (rcvbuff);
  if (setsockopt (interface->div_socket, SOL_SOCKET, SO_RCVBUF,
		  (char *) &rcvbuff, sizeof (rcvbuff)) < 0)
    fprintf (stderr, "Error a setting receive buffer size to %d  :%d\n",
	     rcvbuff, errno);

  sndbuff = LL_BUFFER;
  optlen = sizeof (sndbuff);
  if (setsockopt (interface->div_socket, SOL_SOCKET, SO_SNDBUF,
		  (char *) &sndbuff, sizeof (sndbuff)) < 0)
    fprintf (stderr, "Error a setting send buffer size to %d\n", sndbuff);

  rcvbuff = LL_BUFFER;
  optlen = sizeof (rcvbuff);
  if (setsockopt (interface->div_a_socket, SOL_SOCKET, SO_RCVBUF,
		  (char *) &rcvbuff, sizeof (rcvbuff)) < 0)
    fprintf (stderr, "Error b setting receive buffer size to %d  :%d\n",
	     rcvbuff, errno);

  sndbuff = LL_BUFFER;
  optlen = sizeof (sndbuff);
  if (setsockopt (interface->div_a_socket, SOL_SOCKET, SO_SNDBUF,
		  (char *) &sndbuff, sizeof (sndbuff)) < 0)
    fprintf (stderr, "Error b setting send buffer size to %d\n", sndbuff);

  rcvbuff = LL_BUFFER;
  optlen = sizeof (rcvbuff);
  if (setsockopt (interface->div_b_socket, SOL_SOCKET, SO_RCVBUF,
		  (char *) &rcvbuff, sizeof (rcvbuff)) < 0)
    fprintf (stderr, "Error c setting receive buffer size to %d  :%d\n",
	     rcvbuff, errno);

  sndbuff = LL_BUFFER;
  optlen = sizeof (sndbuff);
  if (setsockopt (interface->div_b_socket, SOL_SOCKET, SO_SNDBUF,
		  (char *) &sndbuff, sizeof (sndbuff)) < 0)
    fprintf (stderr, "Error c setting send buffer size to %d\n", sndbuff);

#endif /* TAP_INTERFACE */

#endif /* TUN_INTERFACE */

  if (!(scheduler.interface))
    scheduler.interface = (void *) interface;
  else
    {
      index =  (struct _interface *) (scheduler.interface);
      while (index->next)
	index = index->next;

      index->next = interface;
      interface ->next = (struct _interface *) (scheduler.interface);
    }

  divert_socket = interface->div_socket;
  return;
}
#endif /* ENCAP_DIVERT */

int
ll_iovsend (struct _interface *interface, struct addrs addr,
	    int protocol, int data_len, struct msghdr *my_msg,
	    route *a_route, scps_np_rqts *rqts)
{
  int cc = 0;
  int sock = 0;
#ifdef ENCAP_DIVERT
  int sin_len = 0;
#endif /* ENCAP_DIVERT */
  uint32_t remote_internet_addr;

#ifdef IPV6
  struct ipv6_addr  remote_internet_addr_v6;
#endif /* IPV6 */

  if (addr.nl_protocol == NL_PROTOCOL_IPV4) {
        remote_internet_addr = addr.nl_head.ipv4_addr;
  }

#ifdef IPV6
  if (addr.nl_protocol == NL_PROTOCOL_IPV6) {
        memcpy (remote_internet_addr_v6.addr, addr.nl_head.ipv6_addr.addr, sizeof (struct ipv6_addr));

  }
#endif /* IPV6 */

#ifdef LOGGER
  struct pcap_pkthdr pcaph;	/* per-packet pcap header */
#endif /* LOGGER */

#ifdef TUN_INTERFACE

 cc = ll_tun_send  (interface, remote_internet_addr,
            protocol, data_len, my_msg, a_route);
 return (cc);

#endif /* TUN_INTERFACE */

#ifdef TAP_INTERFACE

 cc = ll_tap_send  (interface, remote_internet_addr,
            protocol, data_len, my_msg, a_route, rqts);
 return (cc);

#endif /* TAP_INTERFACE */


#ifdef ENCAP_DIVERT
  sock = interface->div_socket;
#else /* ENCAP_DIVERT */
#ifdef LL_RAWIP
  switch (protocol)
    {
    case SCPSCTP:
      sock = interface->ctp_socket;
      break;
    case SCPSTP:
      sock = interface->tp_socket;
      break;
    case SCPSUDP:
      sock = interface->udp_socket;
      break;
    case SP:
      sock = interface->sp_socket;
      break;
    case SCPSNP:
      sock = interface->np_socket;
    }
#elif ENCAP_RAW
  sock = interface->raw_socket;
#elif ENCAP_UDP
  sock = interface->udp_socket;
#endif /* LL_RAWIP */

#endif /* ENCAP_DIVERT */

  /* set up for connect */

  memset ((char *) &remote_addr, 0, sizeof (remote_addr));
  remote_addr.sin_family = AF_INET;
#ifdef LL_RAWIP
  remote_addr.sin_port = (short) 0;
#elif ENCAP_RAW
  remote_addr.sin_port = (short) 0;
#elif LL_LOOPBACK
  if (trans_loopback)
    remote_addr.sin_port = htons (scps_udp_port);
  else
    remote_addr.sin_port = htons (scps_udp_port1);
#elif ENCAP_UDP
  remote_addr.sin_port = htons (scps_udp_port);
#endif /* LL_RAWIP */

  if (spanner_address)
    {
      memcpy ((char *) &remote_addr.sin_addr, (char *) &spanner_address,
	      sizeof (spanner_address));
    }
  else
    {
      memcpy ((void *) &remote_addr.sin_addr,
	      (void *) &remote_internet_addr,
	      sizeof (remote_internet_addr));
    }

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
  }
#endif /* GATEWAY_DUAL_INTERFACE */

#ifdef DIVERT_N_RAWIP
	sock = sock_interface ->tp_socket;
#endif /* DIVERT_N_RAWIP */

#ifndef LL_RAWIP
  my_msg->msg_iov[0].iov_len = 0;
#endif /* LL_RAWIP */

  my_msg->msg_name = (caddr_t) & remote_addr;
  my_msg->msg_namelen = sizeof (remote_addr);


  /* Copy the other msg's header for now ... */
#ifdef ENCAP_RAW
#ifdef IRIX
  header[4] = htonl ((spanner_address ? spanner_address : remote_internet_addr)
    );
  iov[0].iov_len = 20;
  header[0] &= ntohl (0xffff0000);	/* out with the bad length */
  header[0] |= htonl ((uint32_t) (0xffff & (data_len + 20)));	/* in with the good */
  my_msg->msg_iov[0].iov_base = iov[0].iov_base;
  my_msg->msg_iov[0].iov_len = iov[0].iov_len;
#endif /* IRIX */
#ifdef SUNOS
  header[4] = htonl ((spanner_address ? spanner_address : remote_internet_addr)
    );
  iov[0].iov_len = 20;
  header[0] &= ntohl (0xffff0000);	/* out with the bad length */
  header[0] |= htonl ((uint32_t) (0xffff & (data_len + 20)));	/* in with the good */
  my_msg->msg_iov[0].iov_base = iov[0].iov_base;
  my_msg->msg_iov[0].iov_len = iov[0].iov_len;
#endif /* SUNOS */
#endif /* ENCAP_RAW */

#ifdef MPF      
  if (a_route -> mpf == 1) {

    unsigned char linear_buffer[MAX_LL_DATA];
    uint32_t mpf_header[5];
    struct sockaddr_in divert_sin;
    int length;
    int size = 0;
    int i;
    int j;

    for (j = 0; j < a_route ->mpf_src_cnt; j++) {

       size = 0;

       mpf_header[0] = 0x45000000;	/* version 4, hdr len 5, TOS 0 */
       mpf_header[0] &= (0xffff0000);      /* out with the bad length */
       mpf_header[0] |= ((uint32_t) (0xffff & (data_len + 20)));     /* in with the good */
       mpf_header[0] = htonl (mpf_header [0]);
       mpf_header[1] = 0;		/* ID = 0, last frag, offset = 0 */
       mpf_header[1] = htonl (mpf_header [1]);
       mpf_header[2] = 0x20040000;	/* TTL = 32, proto = ipip, cksum = 0 */
       mpf_header[2] = htonl (mpf_header [2]);
       mpf_header[3] = a_route->mpf_src [j];	/* source IP address */
       mpf_header[3] = htonl (mpf_header [3]);
       mpf_header[4] = a_route->mpf_dst [j];	/* dest IP address */
       mpf_header[4] = htonl (mpf_header [4]);

       if (interface == divert_interface) {
          memset ((void *) &divert_sin, 0, sizeof (divert_sin));
#ifndef LINUX
          divert_sin.sin_len = sizeof (struct sockaddr_in);
#endif /* LINUX */
          divert_sin.sin_family = AF_INET;
          divert_sin.sin_addr.s_addr = htonl (INADDR_ANY);
          divert_sin.sin_port = htons (divert_insert_rule);
	
          memcpy (&linear_buffer, &mpf_header, 20);

          for (i = 0; i < my_msg->msg_iovlen; i++) {
     	     length = my_msg->msg_iov[i].iov_len;
     	     memcpy (&linear_buffer[size+20], my_msg->msg_iov[i].iov_base,
                     length);
     	     size += length;
          }
	  size +=20;
  
#ifdef ENCAP_DIVERT_DEBUG
          for (i = 0; i < size; i++) {
     	     printf ("%2x ", (unsigned char) (0x0ff & (linear_buffer[i])));
     	     if ((i +1) % 16 == 0)
     	         printf ("\n");
          }
  	  printf ("\n");
#endif /* ENCAP_DIVERT_DEBUG */

          sin_len = sizeof (struct sockaddr_in);
          memset ((void *) &divert_sin, 0, sin_len);
          divert_sin.sin_addr.s_addr = 0;

#ifdef DIVERT_N_RAWIP
          errno = 0;
          divert_sin.sin_addr.s_addr = htonl (remote_internet_addr); 
          divert_sin.sin_port = htons (0);
          cc = sendto (sock, &linear_buffer, size, MSG_DONTROUTE,
                       (struct sockaddr *) &divert_sin, sin_len);
#else /* DIVERT_N_RAWIP */
      if (a_route ->DIV_ADDR) {
        strcpy (divert_sin.sin_zero, a_route->IFNAME);
      }
 
          divert_sin.sin_port = htons (divert_insert_rule);

          cc = sendto (sock, &linear_buffer, size, 0, (struct sockaddr *)
     		    &divert_sin, sin_len);
#endif /* DIVERT_N_RAWIP */
       } else {
          cc = sendmsg (sock, my_msg, 0);
       }
   
     }
  } else {

#ifdef ENCAP_DIVERT
  {
    unsigned char linear_buffer[MAX_LL_DATA];
    struct sockaddr_in divert_sin;
    int length;
    int size = 0;
    int i;

    if (interface == divert_interface) {
      memset ((void *) &divert_sin, 0, sizeof (divert_sin));
#ifndef LINUX
      divert_sin.sin_len = sizeof (struct sockaddr_in);
#endif /* LINUX */
      divert_sin.sin_family = AF_INET;
      divert_sin.sin_addr.s_addr = htonl (INADDR_ANY);
      divert_sin.sin_port = htons (divert_insert_rule);
  
      for (i = 0; i < my_msg->msg_iovlen; i++)
        {
  	length = my_msg->msg_iov[i].iov_len;
  	memcpy (&linear_buffer[size], my_msg->msg_iov[i].iov_base, length);
  	size += length;
        }
  
#ifdef ENCAP_DIVERT_DEBUG
      for (i = 0; i < size; i++)
        {
  	printf ("%2x ", (unsigned char) (0x0ff & (linear_buffer[i])));
  	if ((i +1) % 16 == 0)
  	  printf ("\n");
        }
  	  printf ("\n");
#endif /* ENCAP_DIVERT_DEBUG */

      sin_len = sizeof (struct sockaddr_in);
      memset ((void *) &divert_sin, 0, sin_len);
      divert_sin.sin_addr.s_addr = 0;

#ifdef DIVERT_N_RAWIP
      errno = 0;
      divert_sin.sin_addr.s_addr = htonl (remote_internet_addr); 
      divert_sin.sin_port = htons (0);
      cc = sendto (sock, &linear_buffer, size, MSG_DONTROUTE, (struct sockaddr *)
  		 &divert_sin, sin_len);
#else /* DIVERT_N_RAWIP */
      if (a_route ->DIV_ADDR) {
        strcpy (divert_sin.sin_zero, a_route->IFNAME);
      }
 
      divert_sin.sin_port = htons (divert_insert_rule);

      cc = sendto (sock, &linear_buffer, size, 0, (struct sockaddr *)
  		 &divert_sin, sin_len);
#endif /* DIVERT_N_RAWIP */
    } else {
    unsigned char linear_buffer[MAX_LL_DATA];
    int length;
    int size = 0;
    int i;
      for (i = 0; i < my_msg->msg_iovlen; i++)
        {
        length = my_msg->msg_iov[i].iov_len;
        memcpy (&linear_buffer[size], my_msg->msg_iov[i].iov_base, length);
        size += length;
        }
#ifdef PKT_DEBUG
      for (i = 0; i < size; i++)
        {
        printf ("%2x ", (unsigned char) (0x0ff & (linear_buffer[i])));
        if ((i +1) % 16 == 0)
          printf ("\n");
        }
          printf ("\n");
#endif /* PKT_DEBUG */
       cc = sendmsg (sock, my_msg, 0);

    }

  }
  
#else /* ENCAP_DIVERT */
  cc = sendmsg (sock, my_msg, 0);
#endif /* ENCAP_DIVERT */
  }
#else /* MPF */

#ifdef ENCAP_DIVERT
  {
    unsigned char linear_buffer[MAX_LL_DATA];
    struct sockaddr_in divert_sin;
    int length;
    int size = 0;
    int i;

    if (interface == divert_interface) {
      memset ((void *) &divert_sin, 0, sizeof (divert_sin));
#ifndef LINUX
      divert_sin.sin_len = sizeof (struct sockaddr_in);
#endif /* LINUX */
      divert_sin.sin_family = AF_INET;
      divert_sin.sin_addr.s_addr = htonl (INADDR_ANY);
      divert_sin.sin_port = htons (divert_insert_rule);
  
      for (i = 0; i < my_msg->msg_iovlen; i++)
        {
  	length = my_msg->msg_iov[i].iov_len;
  	memcpy (&linear_buffer[size], my_msg->msg_iov[i].iov_base, length);
  	size += length;
        }
  
#ifdef ENCAP_DIVERT_DEBUG
      for (i = 0; i < size; i++)
        {
  	printf ("%2x ", (unsigned char) (0x0ff & (linear_buffer[i])));
  	if ((i +1) % 16 == 0)
  	  printf ("\n");
        }
  	  printf ("\n");
#endif /* ENCAP_DIVERT_DEBUG */

      sin_len = sizeof (struct sockaddr_in);
      memset ((void *) &divert_sin, 0, sin_len);
      divert_sin.sin_addr.s_addr = 0;

#ifdef DIVERT_N_RAWIP
      errno = 0;
      divert_sin.sin_addr.s_addr = htonl (remote_internet_addr); 
      divert_sin.sin_port = htons (0);
      cc = sendto (sock, &linear_buffer, size, MSG_DONTROUTE, (struct sockaddr *)
  		 &divert_sin, sin_len);
#else /* DIVERT_N_RAWIP */
      if (a_route ->DIV_ADDR) {
       strcpy (divert_sin.sin_zero, a_route->IFNAME);
      }
      divert_sin.sin_port = divert_insert_rule;

      cc = sendto (sock, &linear_buffer, size, 0, (struct sockaddr *)
  		 &divert_sin, sin_len);

#endif /* DIVERT_N_RAWIP */
    } else {
       cc = sendmsg (sock, my_msg, 0);

    }

#ifdef GATEWAY
{
	struct stat sb;
	if (gw_ifs.c_pkt_io_filename[0] != '\0') {
		if ((stat (gw_ifs.c_pkt_io_filename, &sb)) < 0) {
		} else {
			syslog (LOG_ERR,"Gateway: Writing data to OS %d\n",cc);
		}		
	}
}
#endif /* GATEWAY */

  }
  
#else /* ENCAP_DIVERT */
    { unsigned char linear_buffer[MAX_LL_DATA];
    int length;
    int size = 0;
    int i;
      for (i = 0; i < my_msg->msg_iovlen; i++)
        {
        length = my_msg->msg_iov[i].iov_len;
        memcpy (&linear_buffer[size], my_msg->msg_iov[i].iov_base, length);
        size += length;
        }
#ifdef PKT_DEBUG
      for (i = 0; i < size; i++)
        {
        printf ("%2x ", (unsigned char) (0x0ff & (linear_buffer[i])));
        if ((i +1) % 16 == 0)
          printf ("\n");
        }
          printf ("\n");
#endif /* PKT_DEBUG */
  }
  cc = sendmsg (sock, my_msg, 0);
#endif /* ENCAP_DIVERT */
#endif /* MPF */

#ifdef LOGGER
  gettimeofday (&(pcaph.ts), NULL);
  pcaph.len = cc;
  pcaph.caplen = cc;
  pcap_dump ((u_char *) lf, &pcaph, (u_char *) data);	/* log it */
  fflush (lf);
#endif /* LOGGER */

  return (cc);
}

/*
 *  ll_nbreceive performs a non-blocking receive 
 */

int
ll_nbreceive (struct _interface *interface,
	      struct _ll_queue_element **buffer, int max_len, int *offset)
{
  volatile int cc;

#ifdef LOGGER
  struct pcap_pkthdr pcaph;	/* per-packet pcap header */
#endif /* LOGGER */

  interface->is_free = 0;
  /* sigprocmask(SIG_BLOCK, &alarmset, 0x0); */

  if (interface->incoming.head)
    {

      cc = interface->incoming.head->size;

      *buffer = interface->incoming.head;

      /* memcpy(buffer, &(interface.incoming.head->data), cc); */

      *offset = interface->incoming.head->offset;

      if (interface->incoming.head == interface->incoming.tail)
	interface->incoming.head = interface->incoming.tail = NULL;
      else
	interface->incoming.head = interface->incoming.head->next;

      interface->incoming.size--;
      scheduler.interface_data--;
    }
  else
    cc = 0;

  interface->is_free = 1;
  /* sigprocmask(SIG_UNBLOCK, &alarmset, 0x0); */
  return (cc);
}

struct _ll_queue_element *
alloc_llbuff (struct _interface *interface)
{
  struct _ll_queue_element *buffer = NULL;

  interface->is_free = 0;
  /* sigprocmask(SIG_BLOCK, &alarmset, 0x0); */

  if (interface->available.head)
    {
      buffer = interface->available.head;
      interface->available.head = interface->available.head->next;
      interface->available.size--;
      buffer->next = NULL;
    }

  interface->is_free = 1;
  /* sigprocmask(SIG_UNBLOCK, &alarmset, 0x0); */
  return (buffer);
}

void
free_ll_queue_element (struct _interface *interface,
		       struct _ll_queue_element *buffer)
{
  buffer->next = NULL;

  interface->is_free = 0;
  /* sigprocmask(SIG_BLOCK, &alarmset, 0x0); */

  if (interface->available.tail)
    {
      interface->available.tail->next = buffer;
      interface->available.tail = interface->available.tail->next;
    }
  else
    interface->available.head =
      interface->available.tail =
      buffer;

  interface->available.tail->next = NULL;
  interface->available.size++;

  interface->is_free = 1;
  /* sigprocmask(SIG_UNBLOCK, &alarmset, 0x0); */
}

void
initialize_interface (struct _interface *interface, uint32_t local_addr)
{
  int num_elements;
  struct _ll_queue_element *new_element;

  memset (&lltimeout, 0, sizeof (struct timeval));

  interface->incoming.head = interface->incoming.tail = NULL;
  interface->outgoing.head = interface->outgoing.tail = NULL;
  interface->available.head = interface->available.tail = NULL;
  interface->tp_socket = interface->ctp_socket = interface->udp_socket = 0;
  interface->raw_socket = interface->sp_socket = interface->div_socket = 0;
  interface->div_a_socket = interface->div_b_socket = 0;
  interface->incoming.size =
    interface->outgoing.size =
    interface->available.size = 0;
  interface->next = NULL;
  interface->is_free = 1;
  interface->service_now = 0;
  interface->address = local_addr;
  interface->MTU = MAX_MTU;	/* A magic number (sorry), that assumes Ethernet */

  for (num_elements = 0;
       num_elements < MAX_LL_QUEUE_ELEMENTS; num_elements++)
    {
      if ((new_element =
	   (struct _ll_queue_element *) malloc (sizeof (struct _ll_queue_element))))
	{
	  memset (new_element, 0, sizeof (struct _ll_queue_element));
	  new_element->next = interface->available.head;
	  interface->available.head = new_element;
	  interface->available.size++;
	  if (!(interface->available.tail))
	    interface->available.tail = new_element;
	}
      else
	break;
    }
}

void
move_ll_queue_element (struct _ll_queue from, struct _ll_queue to)
{
  if (from.head)
    {
      if (to.tail)
	{
	  to.tail->next = from.head;
	  to.tail = to.tail->next;
	}
      else
	to.head = to.tail = from.head;

      from.head = from.head->next;
      to.tail->next = NULL;
    }
}

void
service_interface (struct _interface *interface)
{
  int to_read = 0, ready = 0, handled = 0;
  fd_set local_fd_set;

#ifndef MAX_TO_HANDLE
#define MAX_TO_HANDLE 100
#endif /* MAX_TO_HANDLE */

  if ((!(interface->is_free)) || (!(interface->available.head)))
    return;

  handled = MAX_TO_HANDLE;
  memcpy (&local_fd_set, &llfd_set, sizeof (fd_set));

  lltimeout.tv_sec = 0;
  lltimeout.tv_usec = 0;
#ifdef LOW_CPU_IDLE
  lltimeout.tv_sec = 0;
  lltimeout.tv_usec = 100;
#ifdef GATEWAY
  if (gw_no_delay) {
  	lltimeout.tv_sec = 0;
  	lltimeout.tv_usec = 0;
  }
#endif /* GATEWAY */
#ifdef LOW_CPU_UTILIZATION
  lltimeout.tv_sec = 0;
  lltimeout.tv_usec = 100;
#endif /* LOW_CPU_UTILIZATION */
#endif /* LOW_CPU_IDLE */

  if ((select ((ll_max_socket + 1), &local_fd_set, 0x0, 0x0, &lltimeout)) < 1)
    return;

  interface->is_free = 0;

#ifdef TUN_INTERFACE

  if (FD_ISSET (interface->tun_a_fd, &local_fd_set)) {
      ready = interface->tun_a_fd;
#ifdef DEBUG
      printf ("Socket tun a is set\n");
#endif /* DEBUG */
    }

  if (FD_ISSET (interface->tun_b_fd, &local_fd_set)) {
      ready = interface->tun_b_fd;
#ifdef DEBUG
      printf ("Socket tun b is set\n");
#endif /* DEBUG */
    }

  if (FD_ISSET (interface->tun_c_fd, &local_fd_set)) {
      ready = interface->tun_c_fd;
#ifdef DEBUG
      printf ("Socket tun c is set\n");
#endif /* DEBUG */
    }

  if (FD_ISSET (interface->udp_socket, &local_fd_set)) {
    ready = interface->udp_socket;
  }

#else /* TUN_INTERFACE */
#ifdef TAP_INTERFACE

  if (FD_ISSET (interface->tap_a_fd, &local_fd_set)) {
      ready = interface->tap_a_fd;
#ifdef DEBUG
      printf ("Socket tap a is set\n");
#endif /* DEBUG */
    }

  if (FD_ISSET (interface->tap_b_fd, &local_fd_set)) {
      ready = interface->tap_b_fd;
#ifdef DEBUG
      printf ("Socket tap b is set\n");
#endif /* DEBUG */
    }

  if (FD_ISSET (interface->udp_socket, &local_fd_set)) {
    ready = interface->udp_socket;
  }
#else /* TAP_INTERFACE */


#ifdef ENCAP_DIVERT
  if (FD_ISSET (interface->div_socket, &local_fd_set))
    {
      ready = interface->div_socket;
#ifdef DEBUG
      printf ("Socket div is set\n");
#endif /* DEBUG */
    }

  if (FD_ISSET (interface->div_a_socket, &local_fd_set))
    {
      ready = ((ready << 8) | (interface->div_a_socket));
#ifdef DEBUG
      printf ("Socket div a is set\n");
#endif /* DEBUG */
    }

  if (FD_ISSET (interface->div_b_socket, &local_fd_set))
    {
      ready = ((ready << 8) | (interface->div_b_socket));
#ifdef DEBUG
      printf ("Socket div b is set\n");
#endif /* DEBUG */
    }

#else /* ENCAP_DIVERT */
#ifdef ENCAP_RAW
  if (FD_ISSET (interface->raw_socket, &local_fd_set))
    ready = interface->raw_socket;
#else /* ENCAP_RAW */

#ifdef LL_RAWIP
  if (FD_ISSET (interface->ctp_socket, &local_fd_set))
    ready = interface->ctp_socket;

  if (FD_ISSET (interface->tp_socket, &local_fd_set))
    ready = ((ready << 8) | (interface->tp_socket));

  if (FD_ISSET (interface->sp_socket, &local_fd_set))
    ready = ((ready << 8) | (interface->sp_socket));

  if (FD_ISSET (interface->np_socket, &local_fd_set))
    ready = ((ready << 8) | (interface->np_socket));

#endif /* LL_RAWIP */

  if (FD_ISSET (interface->udp_socket, &local_fd_set))
    ready = ((ready << 8) | (interface->udp_socket));

#endif /* ENCAP_RAW */

#endif /* ENCAP_DIVERT */

#endif /* TAP_INTERFACE */
#endif /* TUN_INTERFACE */

  to_read = (ready & 0xFF);
  ready = (ready >> 8);

#ifdef SCPS_RI_CONSOLE
  if (FD_ISSET (s_command, &local_fd_set)) { 
        read_scps_ri_console ();
  }     
#endif /* SCPS_RI_CONSOLE */

/*  while ((handled--) && ((ready) || (to_read))) */
  while ((ready) || (to_read))
    {
      if (interface->available.head)
	interface->available.head->size =
	  read (to_read,
		(void *) &(interface->available.head->data), MAX_LL_DATA);
      if ((!(interface->available.head)) ||
	  (interface->available.head->size <= 0))
	{
	  to_read = (ready & 0xFF);
	  ready = (ready >> 8);
	  continue;
	} else {

	}

      if (interface->available.head->size > 0)
	{
#ifdef ENCAP_DIVERT
#ifdef TUN_INTERFACE
	  if (to_read == interface->tun_a_fd) {
	      interface->available.head->divert_port_number = interface->div_a_port;
	  } else if (to_read == interface->tun_b_fd) {
	      interface->available.head->divert_port_number = interface->div_b_port;
	  } else if (to_read == interface->tun_c_fd) {
	      interface->available.head->divert_port_number = interface->div_port;
          } else if (to_read == interface->udp_socket) {
              interface->available.head->divert_port_number = interface->div_port;
	  }
#else /* TUN_INTERFACE */
#ifdef TAP_INTERFACE
	  if (to_read == interface->tap_a_fd) {
	      interface->available.head->divert_port_number = interface->div_a_port;
	  } else if (to_read == interface->tap_b_fd) {
	      interface->available.head->divert_port_number = interface->div_b_port;
          } else if (to_read == interface->udp_socket) {
              interface->available.head->divert_port_number = interface->div_port;
	  }
#else /* TAP_INTERFACE */
	  if (to_read == interface->div_socket) {
	      interface->available.head->divert_port_number = interface->div_port;
	  } else if (to_read == interface->div_a_socket) {
	      interface->available.head->divert_port_number = interface->div_a_port;
	  } else if (to_read == interface->div_b_socket) {
	      interface->available.head->divert_port_number = interface->div_b_port;
	  }
#endif /* TAP_INTERFACE */
#endif /* TUN_INTERFACE */
#endif /* ENCAP_DIVERT */

	  interface->available.head->offset = 0;

#ifdef TAP_INTERFACE 
	  memcpy (&(interface->available.head->dst_mac_addr [0]),
	          &(interface->available.head->data [0]),
		  MAC_ADDR_SIZE);

	  memcpy (&(interface->available.head->src_mac_addr [MAC_ADDR_SIZE]),
	          &(interface->available.head->data [MAC_ADDR_SIZE]),
		  MAC_ADDR_SIZE);

	  interface->available.head->frame_type = (
		 ((int) (((int) interface->available.head->data [START_OF_FRAME_TYPE]) * 256)) +
		 ((int) ((int) interface->available.head->data [START_OF_FRAME_TYPE+1])));

	  interface->available.head->frame_size = interface->available.head->size;
#ifdef DEBUG_TAP_INTERFACE
	printf ("DST %02x %02x %02x %02x %02x %02x\n",
		interface->available.head->dst_mac_addr [0],
		interface->available.head->dst_mac_addr [1],
		interface->available.head->dst_mac_addr [2],
		interface->available.head->dst_mac_addr [3],
		interface->available.head->dst_mac_addr [4],
		interface->available.head->dst_mac_addr [5]);

	printf ("SRC %02x %02x %02x %02x %02x %02x\n",
		interface->available.head->src_mac_addr [0],
		interface->available.head->src_mac_addr [1],
		interface->available.head->src_mac_addr [2],
		interface->available.head->src_mac_addr [3],
		interface->available.head->src_mac_addr [4],
		interface->available.head->src_mac_addr [5]);

	printf ("Frame type = %x\n", interface->available.head->frame_type);
#endif /* DEBUG_TAP_INTERFACE */

#endif /* TAP_INTERFACE */

	  if (interface->incoming.tail)
	    {
	      interface->incoming.tail->next = interface->available.head;
	      interface->incoming.tail = interface->incoming.tail->next;
	    }
	  else
	    interface->incoming.head =
	      interface->incoming.tail =
	      interface->available.head;

	  if (interface->available.head == interface->available.tail)
	    interface->available.head = interface->available.tail = NULL;
	  else
	    interface->available.head = interface->available.head->next;

	  interface->incoming.tail->next = NULL;
	  interface->available.size--;
	  interface->incoming.size++;
	  scheduler.interface_data++;
	}
    }

#ifndef SOLARIS
#ifdef ASYNC_IO
  if (scheduler.service_interface_now)
    toggle_iostatus (1);
#endif /* ASYNC_IO */
#endif /* SOLARIS */

  interface->is_free = 1;
}

#ifndef SOLARIS
#ifdef ASYNC_IO
void
toggle_iostatus (int status)
{
  char setting;
  int flags = O_NDELAY;

  if (status)
    {
      scheduler.service_interface_now = 0;
    }
  else
    {
      scheduler.service_interface_now = 1;
    }


  /* For each interface */

/* This needs to walk all the interfaces */

#ifdef ENCAP_DIVERT
  if (fcntl (((struct _interface *) (scheduler.interface))->div_socket,
	     F_SETFL, flags) < 0)
    printf ("fnctl failed!\n");

  if (fcntl (((struct _interface *) (scheduler.interface))->div_a_socket,
	     F_SETFL, flags) < 0)
    printf ("fnctl failed!\n");

  if (fcntl (((struct _interface *) (scheduler.interface))->div_b_socket,
	     F_SETFL, flags) < 0)
    printf ("fnctl failed!\n");

  if ((fcntl (((struct _interface *) (scheduler.interface))->udp_socket,
              F_SETFL, flags) < 0)
    printf ("fnctl failed!\n");
#else /* ENCAP_DIVERT */
#ifdef ENCAP_RAW

  if (fcntl (((struct _interface *) (scheduler.interface))->raw_socket,
	     F_SETFL, flags) < 0)
    printf ("fnctl failed!\n");
#elif ENCAP_UDP
  if ((fcntl (((struct _interface *) (scheduler.interface))->udp_socket,
	      F_SETFL, flags) < 0)

#ifdef LL_RAWIP
      || (fcntl (((struct _interface *) (scheduler.interface))->tp_socket,
		 F_SETFL, flags) < 0) ||
      (fcntl (((struct _interface *) (scheduler.interface))->ctp_socket,
	      F_SETFL, flags) < 0) ||
      (fcntl (((struct _interface *) (scheduler.interface))->sp_socket,
	      F_SETFL, flags) < 0) ||
      (fcntl (((struct _interface *) (scheduler.interface))->np_socket,
	      F_SETFL, flags) < 0)
#endif /* LL_RAWIP */
    )
    printf ("fnctl failed!\n");
#endif /* ENCAP_RAW */

#endif /* ENCAP_DIVERT */

}
#endif /* ASYNC_IO */
#endif /* SOLARIS */

#ifdef SOLARIS
#undef __ISBSDISH__
#endif /* SOLARIS */
