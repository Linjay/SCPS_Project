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


/*  SCPSTP initiator
 *  
 *  Opens a SCPSTP socket and blasts away.
 *
 */

#include "../include/scps.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "scps.h"
#include <stdlib.h>

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: scps_initiator.c,v $ -- $Revision: 1.10 $\n";
#endif

void scps_init (void);
void initiator_application (void);
extern void *memset (void *s, int c, size_t n);
#include "net_types.h"
int udp_WriteTo (int sockid, byte * dp, int len, scps_np_addr ina, word port);
int32_t atoi (const char *str);
int atoi (const char *str);
int32_t get_remote_internet_addr (char *host);


#define UDP_EOT 0xfe

int global_argc;
char **global_argv;

extern int optind;
extern char *optarg;

extern char config_init_name[];
extern char config_resp_name[];
extern char config_span_name[];
extern int config_tp_pkt_count;
extern int config_tp_pkt_size;
extern int config_udp_pkt_count;
extern int config_udp_pkt_size;
extern word config_tp_init_port;
extern word config_tp_resp_port;
extern word config_udp_init_port;
extern word config_udp_resp_port;
unsigned int mtu_val;

struct sockaddr_in hisaddress;

int tp_sock, udp_sock;

#define BUF_SIZE 65536

byte outbuf[BUF_SIZE];
byte inbuf[BUF_SIZE];
int sockbufsize = 0;
int route_mtu = 0;
int32_t rate_control = 0;
int32_t ackdelay = 0;
int32_t ackfloor = 0;
char *peer_host;

int one = 1;
int zero = 0;
struct timeval select_time;

static int seq_num = 0;
static tp_total_bytes, udp_total_bytes;
int my_counter;

int options = 0;

#define BETS          0x01
#define COMPRESS      0x02
#define NOCONGEST     0x04
#define SNACK         0x08
#define TIMESTAMP     0x10
#define NODELAY       0x20
#define NOBLOCK       0x40

int BETS_Holes = 0;
int s_size = 0;
struct _Hole HOLES[50];
uint32_t host;
scps_fd_set readset, writeset;
int select_val = 0;
struct _timer *my_timers[5];

char Usage[] = "\n\
Usage scps_init [-options] host \n\
\n\
Common options:\n\
     -b ##  set socket buffer size (in bytes) \n\
     -B     enable BETS operation if supported by peer \n\
     -C     enable COMPRESSED operation if supported by peer \n\
     -D     don't buffer TP writes (sets SCPSTP_NODELAY socket option) \n\
     -G     disable congestion control \n\
     -L     Set socket to non-blocking operation. \n\
     -M ##  Set the route_socket's MTU (in bytes) \n\
     -R ##  Set the route_socket's rate control value (in bps) \n\
     -S     disable SNACK operation if supported by peer \n\
     -T     disable TIMESTAMPS if supported by peer \n\
";

void
little_timer_handler (void)
{
  struct timeval othertime;

  gettimeofday (&othertime, NULL);
  }

  void
  initiator_application ()
  {
  int cc, bytes_to_send, tp_prev_bytes;
  static int tp_write_cnt = 0;
  static int udp_write_cnt = 0;

  scps_init ();

  if (rate_control)
  scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_RATE,
		   &rate_control, sizeof (rate_control));

  if (route_mtu)
  scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_MTU,
		   &route_mtu, sizeof (route_mtu));

  if (tp_total_bytes > 0)
  {

  if ((tp_sock = scps_socket (AF_INET, SOCK_STREAM, 0)) < 0)
  {
  printf ("Error!! Failed to create a tp_socket\n");
  exit (-1);
  }

    /* Bind to a local port */
  hisaddress.sin_port = htons (config_tp_init_port);
  memset (&(hisaddress.sin_addr), 0, sizeof (uint32_t));

  scps_bind (tp_sock, (struct sockaddr *) &hisaddress, sizeof (hisaddress));

  if (sockbufsize)
  {
  scps_setsockopt (tp_sock, SCPS_SOCKET, SCPS_SO_RCVBUF, &sockbufsize, sizeof (sockbufsize));
  scps_setsockopt (tp_sock, SCPS_SOCKET, SCPS_SO_SNDBUF, &sockbufsize, sizeof (sockbufsize));
  }

  if (options & TIMESTAMP)
  scps_setsockopt (tp_sock, PROTO_SCPSTP, SCPSTP_TIMESTAMP,
		   &zero, sizeof (zero));

  if (options & COMPRESS)
  scps_setsockopt (tp_sock, PROTO_SCPSTP, SCPSTP_COMPRESS,
		   &one, sizeof (one));

  if (options & SNACK)
  scps_setsockopt (tp_sock, PROTO_SCPSTP, SCPSTP_SNACK,
		   &zero, sizeof (zero));

  if (options & BETS)
  scps_setsockopt (tp_sock, PROTO_SCPSTP, SCPSTP_BETS,
		   &one, sizeof (one));

  if (options & NOCONGEST)
  scps_setsockopt (tp_sock, PROTO_SCPSTP, SCPSTP_CONGEST,
		   &zero, sizeof (zero));

  if (options & NODELAY)
  scps_setsockopt (tp_sock, PROTO_SCPSTP, SCPSTP_NODELAY,
		   &one, sizeof (one));

  if (options & NOBLOCK)
  scps_setsockopt (tp_sock, SCPS_SOCKET, SCPS_SO_NBLOCK,
		   &one, sizeof (one));

  if (ackdelay)
  {
  scps_setsockopt (tp_sock, PROTO_SCPSTP, SCPSTP_ACKDELAY,
		   &ackdelay, sizeof (ackdelay));
  if (!(ackfloor))
  scps_setsockopt (tp_sock, PROTO_SCPSTP, SCPSTP_ACKFLOOR,
		   &ackdelay, sizeof (ackdelay));
  }
  if (ackfloor)
  scps_setsockopt (tp_sock, PROTO_SCPSTP, SCPSTP_ACKFLOOR,
		   &ackfloor, sizeof (ackfloor));

    /* Open a connection with a distant host/port */
  hisaddress.sin_port = htons (config_tp_resp_port);
  memcpy (&(hisaddress.sin_addr), &host, sizeof (uint32_t));

  scps_connect (tp_sock, (struct sockaddr *) &hisaddress, sizeof (hisaddress));
  }

  if (udp_total_bytes > 0)
  {

  if ((udp_sock = scps_socket (AF_INET, SOCK_DGRAM, 0)) < 0)
  {
  printf ("Error!! Failed to create a udp_socket\n");
  exit (-1);
  }

    /* Bind to a local port */
  hisaddress.sin_port = htons (config_udp_init_port);
  memset (&(hisaddress.sin_addr), 0, sizeof (uint32_t));
  scps_bind (udp_sock, (struct sockaddr *) &hisaddress, sizeof (hisaddress));

    /* Connect to a peer */
  hisaddress.sin_port = htons (config_udp_resp_port);
  memcpy (&host, &(hisaddress.sin_addr), sizeof (uint32_t));
  scps_connect (udp_sock, (struct sockaddr *) &hisaddress, sizeof (hisaddress));
  }

  SCPS_FD_ZERO (&writeset);
  SCPS_FD_SET (tp_sock, &writeset);

  memset ((void *) &select_time, 0, sizeof (select_time));

  /* Wait for the tp_connection to complete */
  select_val = scps_select (tp_sock, NULL, &writeset, NULL, &select_time);

  if (!(select_val && SCPS_FD_ISSET (tp_sock, &writeset)))
  printf ("Select Error! \n");

  tp_prev_bytes = tp_total_bytes;

  while ((tp_total_bytes > 0) || (udp_total_bytes > 0))
  {				/* data to send? */
  if (tp_total_bytes)
  {
      /*  Meter TP data out one packet at a time */
  bytes_to_send = ((tp_total_bytes > config_tp_pkt_size) ?
		   config_tp_pkt_size : tp_total_bytes);

  if (options & NOBLOCK)
  {
	/* 
	 * Wait forever for the tp data - we don't need to do this with 
	 * blocking sockets, but this is a demo program.
	 */
  SCPS_FD_ZERO (&writeset);
  SCPS_FD_SET (tp_sock, &writeset);
  select_val = scps_select (1, NULL, &writeset, NULL, &select_time);
  if (SCPS_FD_ISSET (tp_sock, &writeset))
  cc = scps_write (tp_sock, outbuf, bytes_to_send);
  else
  {
  printf ("Select Error!\n");
  cc = -1;
  }
  }
  else
  cc = scps_write (tp_sock, outbuf, bytes_to_send);

  if (cc > 0)
  {
  tp_write_cnt++;

  tp_total_bytes -= cc;
  seq_num += cc;
  }
  }
  if (udp_total_bytes)
  {
      /*  Meter UDP data out one packet at a time */
  bytes_to_send = ((udp_total_bytes > config_udp_pkt_size) ?
		   config_udp_pkt_size : udp_total_bytes);

  outbuf[0] = (byte) udp_write_cnt;	/* UDP seq num, sort of */

      /* send an EOT flag in second byte of last UDP segment */
  if (udp_total_bytes <= config_udp_pkt_size)
  outbuf[1] = (byte) UDP_EOT;

      /* cc = scps_write(udp_sock, outbuf, bytes_to_send); */
  cc = udp_WriteTo (udp_sock, outbuf, bytes_to_send, host,
		    config_udp_resp_port);
  if (cc > 0)
  {
  udp_write_cnt++;
  udp_total_bytes -= cc;
  }
  }
  for (my_counter = 0; my_counter < 20; my_counter++)
  sched ();
  }

  /* No more data to send - wrap things up */
  if (config_tp_pkt_count)
  {

  scps_getsockopt (tp_sock, SCPS_SOCKET, SCPS_SO_BETS_NUM_SEND_HOLES,
		   (char *) &BETS_Holes, (int *) &s_size);
  printf ("\nInitiator experienced %d BETS holes\n", BETS_Holes);
  s_size = sizeof (HOLES);
  scps_getsockopt (tp_sock, SCPS_SOCKET, SCPS_SO_BETS_SEND_HOLES,
		   (char *) &HOLES, (int *) &s_size);
  for (s_size = 0; s_size < BETS_Holes; s_size++)
  {
  printf ("BETS Hole %d: Octets %lu - %lu\n",
	  s_size, HOLES[s_size].Start, HOLES[s_size].Finish);
  }

  scps_close (tp_sock);
  }

  if (config_udp_pkt_count)
  {
  scps_close (udp_sock);
  }
  threadExit ();
  }

  void
  scps_init ()
  {
  int i;

  tp_total_bytes = config_tp_pkt_count * config_tp_pkt_size;
  udp_total_bytes = config_udp_pkt_count * config_udp_pkt_size;

  host = (uint32_t) get_remote_internet_addr (peer_host);

  tp_total_bytes = config_tp_pkt_count * config_tp_pkt_size;

  if (udp_total_bytes > 0)
  {
    /* Initialize outbuf array to stuff */
  for (i = 0; i < BUF_SIZE; i++)
  outbuf[i] = (byte) i;
  }
  }

  int
  main (argc, argv)
  int argc;
  char **argv;
  {
  int c;

  if (argc < 2) goto usage;

  while ((c = getopt (argc, argv, "A:BCDGLM:R:STa:b:")) != -1)
  {
  switch (c)
  {

case 'a':
  ackfloor = atoi (optarg);
  break;

case 'A':
  ackdelay = atoi (optarg);

case 'b':
  sockbufsize = atoi (optarg);
  break;

case 'B':
  options |= BETS;
  break;

case 'C':
  options |= COMPRESS;
  break;

case 'D':
  options |= NODELAY;
  break;

case 'G':
  options |= NOCONGEST;
  break;

case 'L':
  options |= NOBLOCK;
  break;

case 'M':
  route_mtu = atoi (optarg);
  break;

case 'R':
  rate_control = atoi (optarg);
  break;

case 'S':
  options |= SNACK;
  break;

case 'T':
  options |= TIMESTAMP;
  break;

  }
  }

  peer_host = argv[optind];

  /* Boilerplate code */
  init_scheduler ();
  scheduler.run_queue[0] = create_thread (tp);

  /* Here is the only customization needed/allowed - addition of user thread(s) */
  scheduler.run_queue[1] = create_thread (initiator_application);

  (void) scps_Init ();
  start_threads ();
  exit (0);

usage:
  fprintf (stderr, Usage);
  exit (1);
  }
