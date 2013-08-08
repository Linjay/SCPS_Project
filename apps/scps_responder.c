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


/*  SCPSTP responder
 *  
 *  Listens on a socket then consumes whatever data shows up.
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "scps.h"

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: scps_responder.c,v $ -- $Revision: 1.10 $\n";
#endif

extern void *memset (void *s, int c, size_t n);
int32_t atoi (const char *str);
int atoi (const char *str);


#ifdef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: scps_responder.c,v $ -- $Revision: 1.10 $\n";
#endif

int global_argc;
char **global_argv;

extern int errno;
extern int optind;
extern char *optarg;

#define UDP_EOT 0xfe

int tp_listen_sock, tp_sock;
int udp_sock;

byte inbuf[65536];

/* This goosh is from scps_config.c */
extern char config_span_name[];
extern int config_tp_pkt_count;
extern int config_tp_pkt_size;
extern int config_tp_read_size;
extern word config_tp_init_port;
extern word config_tp_resp_port;
extern int config_udp_pkt_count;
extern int config_udp_pkt_size;
extern int config_udp_read_size;
extern word config_udp_init_port;
extern word config_udp_resp_port;

int sockbufsize = 0;
int route_mtu = 0;
int32_t rate_control = 0;
int32_t ackdelay = 0;
int32_t ackfloor = 0;
char *peer_host;
int options = 0;		/* Flags containing SCPS options chosen at command line */

/* Needed for command-line initialization of SCPS options */
#define BETS          0x01
#define COMPRESS      0x02
#define NOCONGEST     0x04
#define SNACK         0x08
#define TIMESTAMP     0x10
#define NODELAY       0x20
#define NOBLOCK       0x40

char Usage[] = "\
Usage scps_resp [-options] \n\
\n\
Common options:\n \
     -a ## set the default ACKFLOOR (in milliseconds) \n\
     -A ## set the default ACKDELAY (in milliseconds) \n\
     -b ##  set socket buffer size (in bytes) \n\
     -B     enable BETS operation if supported by peer \n\
     -C     enable COMPRESSED operation if supported by peer \n\
     -D     don't buffer TP writes (sets SCPSTP_NODELAY socket option) \n\
     -G     disable congestion control \n\
     -L     Set socket to non-blocking operation.\n\
     -M ##  Set the route_socket's MTU (in bytes) \n\
     -R ##  Set the route_socket's rate control value (in bps) \n\
     -S     disable SNACK operation if supported by peer \n\
     -T     disable TIMESTAMPS if supported by peer \n\
";

void responder_application (void);

void
responder_application (void)
{
  /* TP testing stuff */
  int tp_pkt_cnt = 0;
  volatile int tp_total_data = 0;	/* must be volatile if compiled with -O2 */
  volatile int tp_done = 0;	/* must be volatile if compiled with -O2 */
  int streamlen = 0;
  struct timeval select_time;
  int next_seq_num;
  int32_t BETS_Hole, BETS_Start;
  int32_t Total_BETS = 0;
  int BETS_Hits = 0;
  int s_size = 0;

  /* UDP testing stuff */
  volatile int udp_read_cnt = 0;	/* must be volatile if compiled with -O2 */
  volatile int udp_pkt_cnt = 0;	/* must be volatile if compiled with -O2 */
  int udp_total_data = 0;
  volatile byte udp_seq_num = 0;	/* must be volatile if compiled with -O2 */
  volatile int udp_done = 0;	/* must be volatile if compiled with -O2 */
  struct timeval udp_now, udp_last_rcpt;

  int ret_len, error;

  volatile int r_to_w = 1;	/* UDP read size to write size ratio (volatile ) */
  float elapsed;
  double d_r_to_w;
  int one = 1;
  int zero = 0;
  int select_val;
  unsigned int readset;
  struct sockaddr_in cli_addr;
  int clilen;

  select_time.tv_sec = 15;
  select_time.tv_usec = 0;

  if (config_udp_pkt_size)
    {
      d_r_to_w = ceil ((double) config_udp_pkt_size / (double) config_udp_read_size);
      r_to_w = (int) rint (d_r_to_w);
      if (r_to_w == 0)
	r_to_w = 1;
    }

  /* If we are expecting  TP packets, do this */

  if (config_tp_pkt_count > 0)
    {
      tp_listen_sock = scps_socket (AF_INET, SOCK_STREAM, 0);

      /* Bind to a local port */
      cli_addr.sin_port = htons (config_tp_resp_port);
      memset (&(cli_addr.sin_addr), 0, sizeof (uint32_t));
      scps_bind (tp_listen_sock, (struct sockaddr *) &cli_addr, sizeof (cli_addr));

      if (sockbufsize)
	{
	  scps_setsockopt (tp_listen_sock, SCPS_SOCKET, SCPS_SO_RCVBUF,
			   &sockbufsize, sizeof (sockbufsize));
	  scps_setsockopt (tp_listen_sock, SCPS_SOCKET, SCPS_SO_SNDBUF,
			   &sockbufsize, sizeof (sockbufsize));
	}

      /* Set some SCPS options on the socket... */

      if (options & TIMESTAMP)
	scps_setsockopt (tp_listen_sock, PROTO_SCPSTP, SCPSTP_TIMESTAMP,
			 &zero, sizeof (zero));

      if (options & COMPRESS)
	scps_setsockopt (tp_listen_sock, PROTO_SCPSTP, SCPSTP_COMPRESS,
			 &one, sizeof (one));

      if (options & SNACK)
	scps_setsockopt (tp_listen_sock, PROTO_SCPSTP, SCPSTP_SNACK,
			 &zero, sizeof (zero));

      if (options & BETS)
	scps_setsockopt (tp_listen_sock, PROTO_SCPSTP, SCPSTP_BETS,
			 &one, sizeof (one));

      if (options & NODELAY)
	scps_setsockopt (tp_listen_sock, PROTO_SCPSTP, SCPSTP_NODELAY,
			 &one, sizeof (one));

      if (options & NOCONGEST)
	scps_setsockopt (tp_listen_sock, PROTO_SCPSTP, SCPSTP_CONGEST,
			 &zero, sizeof (zero));

      if (options & NOBLOCK)
	{
	  scps_setsockopt (tp_listen_sock, SCPS_SOCKET, SCPS_SO_NBLOCK,
			   &one, sizeof (one));
	}

      /* Change socket's ACKDELAY and ACKFLOOR parameters from default */
      if (ackdelay)
	{
	  scps_setsockopt (tp_listen_sock, PROTO_SCPSTP, SCPSTP_ACKDELAY,
			   &ackdelay, sizeof (ackdelay));
	  if (!(ackfloor))
	    scps_setsockopt (tp_listen_sock, PROTO_SCPSTP, SCPSTP_ACKFLOOR,
			     &ackdelay, sizeof (ackdelay));
	}
      if (ackfloor)
	scps_setsockopt (tp_listen_sock, PROTO_SCPSTP, SCPSTP_ACKFLOOR,
			 &ackfloor, sizeof (ackfloor));

      /* Now, let the socket listen */
      scps_listen (tp_listen_sock, 0);
    }


  /* If we are expecting UDP packets, initialize here */

  if (config_udp_pkt_count > 0)
    {
      udp_sock = scps_socket (AF_INET, SOCK_DGRAM, 0);

      /* Bind to a local port */
      cli_addr.sin_port = htons (config_udp_resp_port);
      memset (&(cli_addr.sin_addr), 0, sizeof (uint32_t));

      scps_bind (udp_sock, (struct sockaddr *) &cli_addr, sizeof (cli_addr));
    }

  next_seq_num = 0;
  tp_pkt_cnt = 0;
  udp_read_cnt = 0;

  if (config_tp_pkt_count == 0)
    tp_done = 1;

  if (config_udp_pkt_count == 0)
    udp_done = 1;
  else
    gettimeofday (&udp_last_rcpt, NULL);	/* initialize last UDP receipt time */

  if (config_tp_pkt_count)
    {

      /* We don't need to do a select here, but this makes sure it works :o) */
      SCPS_FD_ZERO (&readset);
      SCPS_FD_SET (tp_listen_sock, &readset);
      /* readset = (1 << tp_listen_sock); */
      select_val = scps_select (tp_listen_sock, &readset, NULL, NULL, &select_time);
      if (!(select_val))
	printf ("Select timeout!\n");
      else if (SCPS_FD_ISSET (tp_listen_sock, &readset))
	printf ("Listening socket is available!\n");

      tp_sock = scps_accept (tp_listen_sock, (struct sockaddr *) &cli_addr, &clilen);

      printf ("scps_resp: accept from %s\n", inet_ntoa (cli_addr.sin_addr));

      scps_close (tp_listen_sock);
    }

  /* The big loop */

  while (1)
    {
      if (!tp_done)
	{			/* expecting any TP? */

	  if (options & NOBLOCK)
	    {
	      /* 
	       * Wait forever for the tp data - we don't need to do this with 
	       * blocking sockets, but this is a demo program.
	       */
	      memset (&select_time, 0, sizeof (select_time));
	      SCPS_FD_ZERO (&readset);
	      SCPS_FD_SET (tp_sock, &readset);

	      select_val = scps_select (1, &readset, NULL, NULL, &select_time);

	      if (SCPS_FD_ISSET (tp_sock, &readset))
		ret_len = scps_read (tp_sock, (caddr_t) & inbuf, config_tp_read_size);
	      else
		{
		  printf ("Select Error!\n");
		  ret_len = scps_read (tp_sock, (caddr_t) & inbuf, config_tp_read_size);
		}
	    }

	  else
	    ret_len = scps_read (tp_sock, (caddr_t) & inbuf, config_tp_read_size);

	  if (ret_len < 0)
	    {
	      error = GET_ERR ();
	      if (error == SCPS_EBETS)
		{
		  BETS_Hits++;
		  BETS_Hole = 0;
		  scps_getsockopt (tp_sock, SCPS_SOCKET, SCPS_SO_BETS_RHOLE_SIZE,
				   (char *) &BETS_Hole, (int *) &s_size);
		  scps_getsockopt (tp_sock, SCPS_SOCKET, SCPS_SO_BETS_RHOLE_START,
				   (char *) &BETS_Start, (int *) &s_size);
		  printf ("BETS Hole reported of length %ld at byte: %ld\n",
			  BETS_Hole, BETS_Start);
		  streamlen += BETS_Hole;
		  Total_BETS += BETS_Hole;
		}

	      else if ((error != SCPS_EWOULDBLOCK) && (error != SCPS_ENOTCONN))
		{
		  switch (error)
		    {
		    case SCPS_ECONNRESET:
		      printf ("TP connection reset by peer, exiting\n");
		      break;
		    case SCPS_ECONNABORTED:
		      printf ("TP abnormal close, exiting\n");
		      break;
		    case SCPS_ETIMEDOUT:
		      printf ("TP connection timed out, exiting\n");
		      break;
		    default:
		      printf ("Unknown TP error: %d, pkt %d, exiting\n",
			      error, tp_pkt_cnt);
		    }
		  tp_done = 1;
		}
	    }			/* if ret_len < 0 */

	  else if (ret_len == 0)
	    {
	      printf ("TP total data received = %d bytes\n", tp_total_data);
	      printf ("%d BETS Holes reported\n", BETS_Hits);
	      printf ("%ld total bytes missing\n", Total_BETS);

	      if (!scps_close (tp_sock))
		printf ("*********** Normal close ***********\n");
	      tp_done = 1;

	    }
	  else
	    {
	      tp_total_data += ret_len;
	      streamlen += ret_len;
	    }
	}

      if (!udp_done)
	{			/* expecting any UDP? */

	  memset (&cli_addr, 0, sizeof (cli_addr));
	  ret_len = scps_recvfrom (udp_sock, (caddr_t) & inbuf,
				   config_udp_read_size, &cli_addr, &clilen);

	  if (ret_len > 0)
	    {
	      gettimeofday (&udp_last_rcpt, NULL);	/* record time of receipt */
	      udp_total_data += ret_len;
	      udp_read_cnt++;
	      if (!((udp_read_cnt - 1) % r_to_w))
		{		/* we hit a segment boundary */
		  if (udp_seq_num++ == inbuf[0])
		    udp_pkt_cnt++;
		  else
		    {		/* we missed a segment */
		      udp_seq_num = (int) inbuf[0] + 1;
		    }
		}
	      if (inbuf[1] == UDP_EOT)	/* got EOT flag - we're done */
		{
		  printf ("UDP received EOT . . . ");
		  do
		    {		/* read off rest of last pkt if necessary */
		      ret_len = scps_read (udp_sock,
					   (caddr_t) & inbuf, config_udp_read_size);
		      if (ret_len > 0)
			{
			  udp_total_data += ret_len;
			  udp_read_cnt++;
			}
		    }
		  while (ret_len > 0);
		  scps_close (udp_sock);
		  printf
		    ("Total UDP data received = %d bytes in %d reads (max read size = %d)\n",
		     udp_total_data, udp_read_cnt, config_udp_read_size);
		  printf ("Total UDP segments received = %d\n", udp_pkt_cnt);

		  udp_done = 1;
		}
	    }

	  if (ret_len < 0)
	    {
	      error = GET_ERR ();
	      if (error != SCPS_EWOULDBLOCK)
		{
		  switch (error)
		    {
		    case SCPS_EBADF:
		      printf ("Bad UDP socket descriptor\n");
		      break;
		    default:
		      printf ("Unknown UDP error: %d, pkt %d, exiting\n",
			      error, udp_read_cnt);
		    }
		  udp_done = 1;
		}
	    }
	  if (ret_len <= 0)
	    {
	      gettimeofday (&udp_now, NULL);	/* how int32_t since last seg? */
	      elapsed = (float) ((udp_now.tv_sec - udp_last_rcpt.tv_sec) +
				 ((float) (udp_now.tv_usec - udp_last_rcpt.tv_usec)
				  / 1000000.0));
	      if (elapsed > 10.0)
		{
		  printf ("UDP Timer expired . . . ");
		  scps_close (udp_sock);
		  printf ("WARNING: Elapsed time is off by at least %f.\n", elapsed);
		  printf
		    ("Total UDP data received = %d bytes in %d reads (max read size = %d)\n",
		     udp_total_data, udp_read_cnt, config_udp_read_size);
		  printf ("Total UDP segments received = %d\n", udp_pkt_cnt);
		  udp_done = 1;
		}
	    }
	}
      if (tp_done && udp_done)
	threadExit ();
    }
}

int
main (argc, argv)
     int argc;
     char **argv;
{
  int c;

  while ((c = getopt (argc, argv, "A:BCDGLM:R:STa:b:uU")) != -1)
    {
      switch (c)
	{

	case 'a':
	  ackfloor = atoi (optarg);
	  break;

	case 'A':
	  ackdelay = atoi (optarg);
	  break;

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

	default:
	  goto usage;

	}
    }

  /* Boilerplate code here */
  init_scheduler ();
  scheduler.run_queue[0] = create_thread (tp);

  /* Here is the only customization needed/allowed - adding user thread(s) */
  scheduler.run_queue[1] = create_thread (responder_application);

  (void) scps_Init ();

  if (rate_control)
    scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_RATE,
		     &rate_control, sizeof (rate_control));

  if (route_mtu)
    scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_MTU,
		     &route_mtu, sizeof (route_mtu));

  start_threads ();
  printf ("\ndone!\n");
  exit (0);

usage:
  fprintf (stderr, Usage);
  exit (1);
}
