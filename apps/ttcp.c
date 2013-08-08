/*
 *	T T C P . C
 *
 * Test TCP connection.  Makes a connection on port 5001
 * and transfers fabricated buffers or data copied from stdin.
 *
 * Usable on 4.2, 4.3, and 4.1a systems by defining one of
 * BSD42 BSD43 (BSD41a)
 * Machines using System V with BSD sockets should define SYSV.
 *
 * Modified for operation under 4.2BSD, 18 Dec 84
 *      T.C. Slattery, USNA
 * Minor improvements, Mike Muuss and Terry Slattery, 16-Oct-85.
 * Modified in 1989 at Silicon Graphics, Inc.
 *	catch SIGPIPE to be able to print stats when receiver has died 
 *	for tcp, don't look for sentinel during reads to allow small transfers
 *	INCREASed default buffer size to 8K, nbuf to 2K to transfer 16MB
 *	moved default port to 5001, beyond IPPORT_USERRESERVED
 *	make sinkmode default because it is more popular, 
 *		-s now means don't sink/source 
 *	count number of read/write system calls to see effects of 
 *		blocking from full socket buffers
 *	for tcp, -D option turns off buffered writes (sets TCP_NODELAY sockopt)
 *	buffer alignment options, -A and -O
 *	print stats in a format that's a bit easier to use with grep & awk
 *	for SYSV, mimic BSD routines to use most of the existing timing code
 * Modified by Steve Miller of the University of Maryland, College Park
 *	-b sets the socket buffer size (SCPS_SO_SNDBUF/SCPS_SO_RCVBUF)
 * Modified Sept. 1989 at Silicon Graphics, Inc.
 *	restored -s sense at request of tcs@brl
 * Modified Oct. 1991 at Silicon Graphics, Inc.
 *	use getopt(3) for option processing, add -f and -T options.
 *	SGI IRIX 3.3 and 4.0 releases don't need #define SYSV.
 * Modified July 1996 at the MITRE Corp.
 *      use SCPS sockets.
 *
 * Distribution Status -
 *      Public Domain.  Distribution Unlimited.
 */

#define BSD43
/* #define BSD42 */
/* #define BSD41a */
/* #define SYSV *//* required on SGI IRIX releases before 3.3 */

#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <unistd.h>

#include <errno.h>
#ifdef NOT_DEFINED
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif /* NOT_DEFINED */

#include <sys/time.h>		/* struct timeval */

#include <stdlib.h>
#include <string.h>

#if defined(SYSV)
#include <sys/times.h>
#include <sys/param.h>
struct rusage
  {
    struct timeval ru_utime, ru_stime;
  };
#define RUSAGE_SELF 0
#else /* defined(SYSV) */
#include <sys/resource.h>
#endif /* defined(SYSV) */

#ifndef RUSAGE_SELF
#define RUSAGE_SELF 0
#endif /* RUSAGE_SET */

#include "scps.h"

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: ttcp.c,v $ -- $Revision: 1.18 $\n";
#endif

void pinger (void);
void echoer (void);
void catcher (void);
int udp_WriteTo (int sockid, byte * dp, int len, uint32_t ina, word port);


struct sockaddr_in sinme;
struct sockaddr_in sinhim;
struct sockaddr_in frominet;

int global_argc;
char **global_argv;

int domain, fromlen;
int fd, nfd;			/* fd of network socket */

int buflen = 8 * 1024;		/* length of buffer */
char *buf;			/* ptr to dynamic buffer */
int nbuf = 2 * 1024;		/* number of buffers to send in sinkmode */

int bufoffset = 0;		/* align buffer to this */
int bufalign = 16 * 1024;	/* modulo this */
short ackbehave = -1;		/* default ack behavior */
int udp = 0;			/* 0 = tcp, !0 = udp */
int options = 0;		/* socket options */
int zero = 0;			/* for 4.3 BSD style setsockopt() */
int one = 1;			/* for 4.3 BSD style setsockopt() */
short port = 5001;		/* TCP port number */
char *host;			/* ptr to name of host */
int trans;			/* 0=receive, !0=transmit mode */
int sinkmode = 0;		/* 0=normal I/O, !0=sink/source mode */
int verbose = 0;		/* 0=print basic info, 1=print cpu rate, proc
				 * resource usage. */
int rec_boundary = 0;		/* 0 = no boundary 1 = record boundary */
int priority = 0;		/* Priority */
int nodelay = 0;		/* set TCP_NODELAY socket option */
int b_flag = 0;			/* use mread() */
int sockbufsize = 0;		/* socket buffer size to use */
char fmt = 'K';			/* output format: k = kilobits, K = kilobytes,
				 *  m = megabits, M = megabytes, 
				 *  g = gigabits, G = gigabytes */
int touchdata = 0;		/* access data after reading */
int pingpong = 0;		/* perform a ping pong test */
int scps_vegas_alpha = 0;       /* value of alpha for vegas */
int scps_vegas_beta = 0;        /* value of beta for vegas */
int scps_vegas_gamma = 0;       /* value of gamma for vegas */
int scps_vegas_ss = 0;		/* 0 = double every time, otherwize double every */
				/* other time in SS */

int min, ave, max;		/* stats for pingpong */

int32_t BETS_Hole, BETS_Start;
int32_t Total_BETS = 0;
int BETS_Hits = 0;
int streamlen = 0;
int s_size = 0;
int passive;

#define CMDS_PER_BUF	10	/* Config parameter for pingpong */
#define CMD_SIZE	10	/* Config parameter for pingpong */

#define BETS         0x01
#define COMPRESS     0x02
#define CONGESTVAL   0x04
#define SNACK        0x08
#define TIMESTAMP    0x10
#define NODELAY      0x20
#define NOBLOCK      0x40
#define USE_SPANNER  0x080
#define PRIORITY     0x100

uint32_t rate_control = 0;	/* New rate control value */
int congestval = 0;		/* New congestion control value */
int scps_options = 0;
int32_t ackdelay = 0;
int route_mtu = 0;
int app_nl_default = 0;

struct hostent *addr;
extern char config_span_name[];
extern char config_local_name[];
char *local_name;
char *span_name;
extern int errno;
extern int optind;
extern char *optarg;
extern int scps_udp_port;	/* PDF added to change port nummbers */
extern int scps_udp_port1;	/* PDF added to change port nummbers */
extern char scps_version [];

char Usage[] = "\
Usage: ttcp -t [-options] host [ < in ]\n\
       ttcp -r [-options > out]\n\
Common options:\n\
	-l ##	length of bufs read from or written to network (default 8192)\n\
	-u	use UDP instead of TCP\n\
	-p ##	port number to send to or listen at (default 5001)\n\
	-q ##	port number 2 to send to or listen at (loop back only)\n\
	-s	-t: source a pattern to network\n\
		-r: sink (discard) all data from network\n\
	-A	align the start of buffers to this modulus (default 16384)\n\
	-O	start buffers at this offset from the modulus (default 0)\n\
	-v	verbose: print more statistics\n\
	-d	set SO_DEBUG socket option\n\
	-b ##	set socket buffer size (if supported)\n\
	-f X	format for rate: k,K = kilo{bit,byte}; m,M = mega; g,G = giga\n\
Options specific to -t:\n\
	-n##	number of source bufs written to network (default 2048)\n\
	-D	don't buffer TCP writes (sets TCP_NODELAY socket option)\n\
Options specific to -r:\n\
	-B	for -s, only output full blocks as specified by -l (for TAR)\n\
	-T	\"touch\": access each byte as it's read\n\
SCPS options: \n\
        -E enable BETS operation if supported by peer \n\
        -C enable COMPRESSED operation if supported by peer \n\
        -F ##  set default ACK behavior\n\
                  0 = strickly delayed acks\n\
                  1 = ACK every segment\n\
                  2 = ACK every other segment\n\
        -a ##  override the default delayed ack timer setting \n\
        -G ##  override the default Congestion Control Algorithm (TCP-Vegas)\n\
                  0 = Disable Congestion Control\n\
                  1 = Van Jacobson Congestion Control\n\
                  2 = TCP - Vegas Congestion Control\n\
        -g ##  Show start stragegy in Vegas \n\
                  0 - Double Cwnd every round trip (default) \n\
                  1 - Double Cwnd every other round trip (as defined in Brakmo's Paper) \n\
        -S     disable SNACK operation \n\
        -c     enable record boundary \n\
        -M     disable TIMESTAMPS \n\
        -m ##  Set the route_socket's MTU (in bytes) \n\
	-N     set the network layer \n\
		  1 IP \n\
		  2 SCPS NP \n\
        -R ##  set SCPS rate control value (in bps)\n\
	-H XX  choose source hostname\n\
	-e     perform a ping pong test \n\
	-W     set alpha for vegas CC \n\
	-X     set beta for vegas CC \n\
	-Y     set gamma for vegas CC \n\
        -g     slow start stragegy for vegas SS \n\
	-Q	Passive mode \n\
";

char stats[128];
double nbytes;			/* bytes on net */
uint32_t numCalls;		/* # of I/O system calls */
double cput, realt;		/* user, real time (seconds) */

void err ();
void mes ();
void pattern ();
void prep_timer ();
double read_timer ();
int Nread ();
int Nwrite ();
void delay ();
int mread ();
char *outfmt ();

void ttcp ();

void
sigpipe ()
{
}

int
main (argc, argv)
     int argc;
     char **argv;
{
  int c;

  if (argc < 2)
    goto usage;

  while ((c = getopt (argc, argv,
		      "decrstuvBCDEQIMPSTVZb:f:g:L:l:n:p:q:A:F:G:H:N:O:R:m:a:W:X:Y:")) !=
    -1)
    {
      switch (c)
	{
	case 'a':
	  ackdelay = atoi (optarg);
	  break;
	case 'c':
	  rec_boundary = 1;
	  break;
	case 'E':
	  scps_options |= BETS;
	  break;
	case 'B':
	  b_flag = 1;
	  break;
	case 'C':
	  scps_options |= COMPRESS;
	  break;
	case 'G':
	  scps_options |= CONGESTVAL;
	  congestval = (short) (atoi (optarg));
	  break;
	case 'g':
	  scps_vegas_ss = (int) (atoi (optarg));
	  break;
	case 'L':
	  scps_options |= PRIORITY;
	  priority = atoi (optarg);
	  printf ("priority = %d\n", priority);
	  break;
	case 'M':
	  scps_options |= TIMESTAMP;
	  break;
	case 'P':
	  scps_options |= USE_SPANNER;
	  break;
	case 'S':
	  scps_options |= SNACK;
	  break;
	case 'V':
	  printf ("%s\n", scps_version);
	  exit (1);
	case 'W':
	  scps_vegas_alpha = atoi (optarg);
	  break;
	case 'X':
	  scps_vegas_beta = atoi (optarg);
	  break;
	case 'Y':
	  scps_vegas_gamma = atoi (optarg);
	  break;
	case 'Q':
	  passive = 1;
	  break;
	case 't':
	  trans = 1;
	  break;
	case 'r':
	  trans = 0;
	  break;
	case 'd':
	  options |= SO_DEBUG;
	  break;
	case 'D':
/* #ifdef TCP_NODELAY */
	  nodelay = 1;
/* #else
      fprintf(stderr, 
	      "ttcp: -D option ignored: TCP_NODELAY socket option not supported\n");
#endif */
	  break;
	case 'n':
	  nbuf = atoi (optarg);
	  break;
	case 'l':
	  buflen = atoi (optarg);
	  break;
	case 's':
	  sinkmode = !sinkmode;
	  break;
	case 'p':
	  port = atoi (optarg);
	  scps_udp_port = port;
	  break;
	case 'q':
	  scps_udp_port1 = atoi (optarg);
	  break;
	case 'u':
	  udp = 1;
	  break;
	case 'v':
	  verbose = 1;
	  break;
	case 'A':
	  bufalign = atoi (optarg);
	  break;
	case 'F':
	  ackbehave = (short) (atoi (optarg));
	  break;
	case 'N':
	  app_nl_default = atoi (optarg);
	  break;
	case 'O':
	  bufoffset = atoi (optarg);
	  break;
	case 'Z':		/* All the toys */
	  {
	    scps_options |= TIMESTAMP;
	    scps_options |= SNACK;
	    scps_options |= BETS;
	    scps_options |= COMPRESS;
	  }
	  break;
	case 'b':
#if defined(SCPS_SO_SNDBUF) || defined(SCPS_SO_RCVBUF)
	  sockbufsize = atoi (optarg);
#else /* defined(SCPS_SO_SNDBUF) || defined(SCPS_SO_RCVBUF) */
	  fprintf (stderr,
		   "ttcp: -b option ignored: SCPS_SO_SNDBUF/SCPS_SO_RCVBUF socket options not supported\n");
#endif /* defined(SCPS_SO_SNDBUF) || defined(SCPS_SO_RCVBUF) */
	  break;
	case 'f':
	  fmt = *optarg;
	  break;
	case 'T':
	  touchdata = 1;
	  break;
	case 'm':
	  route_mtu = atoi (optarg);
	  break;
	case 'R':
	  rate_control = atoi (optarg);
	  break;
	case 'e':
	  pingpong = 1;
	  break;
	case 'H':
		local_name = optarg;
		memcpy (&config_local_name, local_name,
		strlen (local_name));
	break;
	default:
	  goto usage;
	}
    }

  if (scps_options & USE_SPANNER)
    {
      span_name = argv[optind++];
      memcpy (&config_span_name, span_name,
	      strlen (span_name));
    }
 if (passive) {        
                if (trans) {  
                        trans = 0;
                } else {
                        trans = 1;
                }
  }

  if (trans)
    {
      if (optind == argc)
	goto usage;
      else
	host = argv[optind];
    }

  init_scheduler ();
  scheduler.run_queue[0] = create_thread (tp);
  scheduler.run_queue[1] = create_thread (ttcp);
  (void) scps_Init ();
  if (rate_control)
    scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_RATE,
		     &rate_control, sizeof (rate_control));
  if (route_mtu)
    scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_MTU,
		     &route_mtu, sizeof (route_mtu));

  start_threads ();
  exit (0);

usage:
  fprintf (stderr, Usage);
  exit (1);

}

void
ttcp ()
{
  uint32_t addr_tmp;

  static int going = 0;

  if (trans)
    {
      /* xmitr */

      if (rate_control)
	scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_RATE,
			 &rate_control, sizeof (rate_control));

      memset ((char *) &sinhim, 0, sizeof (sinhim));

      if (atoi (host) > 0)
	{
	  /* Numeric */
	  sinhim.sin_family = AF_INET;
#if defined(cray)
	  addr_tmp = inet_addr (host);
	  sinhim.sin_addr = addr_tmp;
#else /*  defined(cray) */
	  sinhim.sin_addr.s_addr = inet_addr (host);
#endif /*  defined(cray) */
	}
      else
	{
	  if ((addr = gethostbyname (host)) == NULL)
	    err ("bad hostname");
	  sinhim.sin_family = addr->h_addrtype;
	  memcpy ((char *) &addr_tmp, addr->h_addr, addr->h_length);
#if defined(cray)
	  sinhim.sin_addr = addr_tmp;
#else /*  defined(cray) */
	  sinhim.sin_addr.s_addr = addr_tmp;
#endif /*  defined(cray) */
	}
      sinhim.sin_port = htons (port);
      sinme.sin_port = 0;	/* free choice */
    }
  else
    {
      /* rcvr */
      sinme.sin_port = htons (port);
    }


  if (udp && buflen < 5)
    {
      buflen = 5;		/* send more than the sentinel size */
    }

  if ((buf = (char *) malloc (buflen + bufalign)) == (char *) NULL)
    err ("malloc");
  if (bufalign != 0)
    buf += (bufalign - ((int) buf % bufalign) + bufoffset) % bufalign;

  if (trans)
    {
      fprintf (stderr,
	       "ttcp-t: buflen=%d, nbuf=%d, align=%d/%d, port=%d",
	       buflen, nbuf, bufalign, bufoffset, port);
      if (sockbufsize)
	fprintf (stderr, ", sockbufsize=%d", sockbufsize);
      fprintf (stderr, "  %s  -> %s\n", udp ? "udp" : "scpstp", host);
    }
  else
    {
      fprintf (stderr,
	       "ttcp-r: buflen=%d, nbuf=%d, align=%d/%d, port=%d",
	       buflen, nbuf, bufalign, bufoffset, port);
      if (sockbufsize)
	fprintf (stderr, ", sockbufsize=%d", sockbufsize);
      fprintf (stderr, "  %s\n", udp ? "udp" : "scpstp");
    }

  if (rec_boundary)
    {
      if ((fd = scps_socket (AF_INET, SOCK_SEQPACKET, 0)) < 0)
	err ("socket");
      mes ("socket");

    }
  else
    {
      if ((fd = scps_socket (AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0)) < 0)
	err ("socket");
      mes ("socket");
    }
  if (scps_bind (fd, (struct sockaddr *) &sinme, sizeof (sinme)) < 0)
    err ("bind");

  /* Change the default behavior for the SCPS optional capabilities */
  if (scps_options & TIMESTAMP)
    scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_TIMESTAMP,
		     &zero, sizeof (zero));

  if (scps_options & COMPRESS)
    scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_COMPRESS,
		     &one, sizeof (one));

  if (scps_options & SNACK)
    scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_SNACK,
		     &zero, sizeof (zero));

  if (scps_options & BETS)
    scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_BETS,
		     &one, sizeof (one));

  if (scps_options & CONGESTVAL)
    {
      switch (congestval)
	{
	case 0:
	  scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_CONGEST,
			   &zero, sizeof (zero));
	  break;
	case 1:
	  scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_VJ_CONGEST,
			   &one, sizeof (one));
	  break;
	case 2:
	  scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_VEGAS_CONGEST,
			   &one, sizeof (one));
	  break;
	}
    }

  if (scps_vegas_alpha) {
    scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_VEGAS_ALPHA,
		     &scps_vegas_alpha, sizeof (scps_vegas_alpha));
  }

  if (scps_vegas_beta) {
    scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_VEGAS_BETA,
		     &scps_vegas_beta, sizeof (scps_vegas_beta));
  }

  if (scps_vegas_gamma) {
    scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_VEGAS_GAMMA,
		     &scps_vegas_gamma, sizeof (scps_vegas_gamma));
  }

  scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_VEGAS_SS,
		     &scps_vegas_ss, sizeof (scps_vegas_ss));

  if (scps_options & PRIORITY)
    {
      scps_setsockopt (fd, NP_PROTO_NP, SCPS_SO_PRECEDENCE,
		       &priority, sizeof (priority));
    }

  if (ackdelay)
    {
      scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_ACKDELAY,
		       &ackdelay, sizeof (ackdelay));
      /* Don't ack more often than the ackdelay - we don't have a seperate arg */
      scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_ACKFLOOR,
		       &ackdelay, sizeof (ackdelay));
    }

  /* Set the default Ack behavior if it is different than compiled value */
  if (ackbehave >= 0)
    scps_setsockopt (fd, PROTO_SCPSTP, SCPSTP_ACKBEHAVE,
		     &ackbehave, sizeof (ackbehave));

  if (app_nl_default)
    scps_setsockopt (fd, SCPS_SOCKET, SCPS_SO_NLDEFAULT,
		     &app_nl_default, sizeof (app_nl_default));

#if defined(SCPS_SO_SNDBUF) || defined(SCPS_SO_RCVBUF)
  if (sockbufsize)
    {
	  if (scps_setsockopt (fd, SCPS_SOCKET, SCPS_SO_SNDBUF, &sockbufsize,
			       sizeof sockbufsize) < 0)
	    err ("setsockopt: sndbuf");
	  mes ("sndbuf");
	  if (scps_setsockopt (fd, SCPS_SOCKET, SCPS_SO_RCVBUF, &sockbufsize,
			       sizeof sockbufsize) < 0)
	    err ("setsockopt: rcvbuf");
	  mes ("rcvbuf");
    }
#endif /* defined(SCPS_SO_SNDBUF) || defined(SCPS_SO_RCVBUF) */

  if (!udp)
    {
      signal (SIGPIPE, sigpipe);
      if (trans)
	{
	  /* We are the client if transmitting */
	  if (options)
	    {
#if defined(BSD42)
	      if (scps_setsockopt (fd, SCPS_SOCKET, options, 0, 0) < 0)
#else /* defined(BSD42) */
	      if (scps_setsockopt (fd, SCPS_SOCKET, options, &one, sizeof
		  (one)) < 0)
#endif /* defined(BSD42) */
		err ("setsockopt");
	    }
#ifdef TCP_NODELAY
	  if (nodelay)
	    {
	      struct protoent *p;
	      p = scps_getprotobyname ("scpstp");
	      if (p && scps_setsockopt (fd, p->p_proto, SCPSTP_NODELAY,
					&one, sizeof (one)) < 0)
		err ("setsockopt: nodelay");
	      mes ("nodelay");
	    }
#endif /* TCO_NODELAY */
	  if (scps_connect (fd, (struct sockaddr *) &sinhim, sizeof
	      (sinhim)) < 0)
	    err ("connect");
	  mes ("connect");
	}
      else
	{
	  /* otherwise, we are the server and 
	   * should listen for the connections
	   */
#if defined(ultrix) || defined(sgi)
	  scps_listen (fd, 1);	/* workaround for alleged u4.2 bug */
#else /* defined(ultrix) || defined(sgi) */
	  scps_listen (fd, 0);	/* allow a queue of 0 */
#endif /* defined(ultrix) || defined(sgi) */
	  if (options)
	    {
#if defined(BSD42)
	      if (scps_setsockopt (fd, SCPS_SOCKET, options, 0, 0) < 0)
#else /* defined(BSD42) */
	      if (scps_setsockopt (fd, SCPS_SOCKET, options, &one, sizeof
		  (one)) < 0)
#endif /* defined(BSD42) */
		err ("setsockopt");
	    }
	  fromlen = sizeof (frominet);
	  domain = AF_INET;

	  if ((nfd = scps_accept (fd, &frominet, &fromlen)) < 0)
	    err ("accept");

	  {
	    struct sockaddr_in peer;
	    int peerlen = sizeof (peer);

	    if (scps_getpeername (nfd, (struct sockaddr_in *) &peer,
				  &peerlen) < 0)
	      {
		err ("getpeername");

	      }
	    fprintf (stderr, "ttcp-r: accept from %s\n",
		     inet_ntoa (peer.sin_addr));
	  }
	}
    }
  if (passive) {        
                if (trans) {  
                        trans = 0;
			nfd=fd;
                } else {
                        trans = 1;
			fd=nfd;
                }
  } 
  prep_timer ();
  errno = 0;
  if (sinkmode)
    {
      register int cnt;
      if (trans)
	{
	  pattern (buf, buflen);
	  if (udp)
	    (void) Nwrite (fd, buf, 4);		/* rcvr start */

	  if (pingpong)
	    {
	      pinger ();
	      goto donewithit;
	    }

	  while (nbuf-- && Nwrite (fd, buf, buflen) == buflen)
	    nbytes += buflen;
	  if (udp)
	    (void) Nwrite (fd, buf, 4);		/* rcvr end */
	}
      else
	{
	  if (udp)
	    {
	      while ((cnt = Nread (fd, buf, buflen)) >= 0)
		{
		  if (!(going) && (cnt))
		    {
		      going = 1;
		      nbytes += cnt;
		      prep_timer ();
		    }
		  else if (cnt <= 4)
		    {
		      errno = 0;
		      if (going)
			break;	/* "EOF" */
		      going = 1;
		      prep_timer ();
		    }
		  else
		    nbytes += cnt;
		}
	    }
	  else
	    {
	      if (pingpong)
		{
		  echoer ();
		  goto donewithit;
		}

	      while ((cnt = Nread (nfd, buf, buflen)) != 0)
		if (cnt > 0)
		  nbytes += cnt;
	    }
	}
    }
  else
    {
      register int cnt;
      errno = 0;
      if (trans)
	{
	  while ((cnt = read (0, buf, buflen)) > 0 &&
		 Nwrite (fd, buf, cnt) == cnt)
	    {
	      /* fprintf(stderr,"called Nwrite\n"); */
	      nbytes += cnt;
	    }
	}
      else
	{
	  if (udp)
	    {
	      while ((cnt = Nread (fd, buf, buflen)) >= 0 &&
		     write (1, buf, cnt) == cnt)
		nbytes += cnt;
	    }
	  else
	    {
	      while ((cnt = Nread (nfd, buf, buflen)) != 0 &&
		     ((cnt > 0) ? (write (1, buf, cnt) == cnt) : TRUE))
		if (cnt > 0)
		  nbytes += cnt;
	    }
	}
      errno = 0;
    }
  if (errno)
    err ("IO");
  (void) read_timer (stats, sizeof (stats));
  if (udp && trans)
    {
      (void) Nwrite (fd, buf, 4);	/* rcvr end */
      (void) Nwrite (fd, buf, 4);	/* rcvr end */
      (void) Nwrite (fd, buf, 4);	/* rcvr end */
      (void) Nwrite (fd, buf, 4);	/* rcvr end */
    }
  if (cput <= 0.0)
    cput = 0.001;
  if (realt <= 0.0)
    realt = 0.001;
  fprintf (stderr,
	   "ttcp%s: %.0f bytes in %.2f real seconds = %s/sec +++\n",
	   trans ? "-t" : "-r",
	   nbytes, realt, outfmt (nbytes / realt));
  if (verbose)
    {
      fprintf (stderr,
	       "ttcp%s: %.0f bytes in %.2f CPU seconds = %s/cpu sec\n",
	       trans ? "-t" : "-r",
	       nbytes, cput, outfmt (nbytes / cput));
    }
  fprintf (stderr,
	   "ttcp%s: %ld I/O calls, msec/call = %.2f, calls/sec = %.2f\n",
	   trans ? "-t" : "-r",
	   numCalls,
	   1024.0 * realt / ((double) numCalls),
	   ((double) numCalls) / realt);
  fprintf (stderr, "ttcp%s: %s\n", trans ? "-t" : "-r", stats);
  if (verbose)
    {
      fprintf (stderr,
	       "ttcp%s: buffer address %#x\n",
	       trans ? "-t" : "-r",
	       (unsigned int) buf);
    }

donewithit:

  scps_close (fd);
  if (nfd)
    scps_close (nfd);
  threadExit ();

}

void
err (s)
     char *s;
{
  fprintf (stderr, "ttcp%s: ", trans ? "-t" : "-r");
  perror (s);
  fprintf (stderr, "errno=%d\n", errno);
  threadExit ();
}

void
mes (s)
     char *s;
{
  fprintf (stderr, "ttcp%s: %s\n", trans ? "-t" : "-r", s);
}

void
pattern (cp, cnt)
     register char *cp;
     register int cnt;
{
  register char c;
  c = 0;
  while (cnt-- > 0)
    {
      while (!isprint ((c & 0x7F)))
	c++;
      *cp++ = (c++ & 0x7F);
    }
}

char *
outfmt (b)
     double b;
{
  static char obuf[50];
  switch (fmt)
    {
    case 'G':
      sprintf (obuf, "%.2f GB", b / 1024.0 / 1024.0 / 1024.0);
      break;
    default:
    case 'K':
      sprintf (obuf, "%.2f KB", b / 1024.0);
      break;
    case 'M':
      sprintf (obuf, "%.2f MB", b / 1024.0 / 1024.0);
      break;
    case 'g':
      sprintf (obuf, "%.2f Gbit", b * 8.0 / 1024.0 / 1024.0 / 1024.0);
      break;
    case 'k':
      sprintf (obuf, "%.2f Kbit", b * 8.0 / 1024.0);
      break;
    case 'm':
      sprintf (obuf, "%.2f Mbit", b * 8.0 / 1024.0 / 1024.0);
      break;
    }
  return obuf;
}

static struct timeval time0;	/* Time at which timing started */
static struct rusage ru0;	/* Resource utilization at the start */

static void prusage ();
static void tvadd ();
static void tvsub ();
static void psecs ();

#if defined(SYSV)
/*ARGSUSED*/
static
getrusage (ignored, ru)
     int ignored;
     register struct rusage *ru;
{
  struct tms buf;

  times (&buf);

  /* Assumption: HZ <= 2147 (LONG_MAX/1000000) */
  ru->ru_stime.tv_sec = buf.tms_stime / HZ;
  ru->ru_stime.tv_usec = ((buf.tms_stime % HZ) * 1000000) / HZ;
  ru->ru_utime.tv_sec = buf.tms_utime / HZ;
  ru->ru_utime.tv_usec = ((buf.tms_utime % HZ) * 1000000) / HZ;
}

/*ARGSUSED*/
static
gettimeofday (tp, zp)
     struct timeval *tp;
     struct timezone *zp;
{
  tp->tv_sec = time (0);
  tp->tv_usec = 0;
}
#endif /* SYSV */

/*
 *			P R E P _ T I M E R
 */
void
prep_timer ()
{
  gettimeofday (&time0, (struct timezone *) 0);
  getrusage (RUSAGE_SELF, &ru0);
}

/*
 *			R E A D _ T I M E R
 * 
 */
double
read_timer (str, len)
     char *str;
{
  struct timeval timedol;
  struct rusage ru1;
  struct timeval td;
  struct timeval tend, tstart;
  char line[132];

  getrusage (RUSAGE_SELF, &ru1);
  gettimeofday (&timedol, (struct timezone *) 0);
  prusage (&ru0, &ru1, &timedol, &time0, line);
  (void) strncpy (str, line, len);

  /* Get real time */
  tvsub (&td, &timedol, &time0);
  realt = td.tv_sec + ((double) td.tv_usec) / 1000000;

  /* Get CPU time (user+sys) */
  tvadd (&tend, &ru1.ru_utime, &ru1.ru_stime);
  tvadd (&tstart, &ru0.ru_utime, &ru0.ru_stime);
  tvsub (&td, &tend, &tstart);
  cput = td.tv_sec + ((double) td.tv_usec) / 1000000;
  if (cput < 0.00001)
    cput = 0.00001;
  return (cput);
}

static void
prusage (r0, r1, e, b, outp)
     register struct rusage *r0, *r1;
     struct timeval *e, *b;
     char *outp;
{
  struct timeval tdiff;
  register time_t t;
  register char *cp;
  register int i;
  int ms;

  t = (r1->ru_utime.tv_sec - r0->ru_utime.tv_sec) * 100 +
    (r1->ru_utime.tv_usec - r0->ru_utime.tv_usec) / 10000 +
    (r1->ru_stime.tv_sec - r0->ru_stime.tv_sec) * 100 +
    (r1->ru_stime.tv_usec - r0->ru_stime.tv_usec) / 10000;
  ms = (e->tv_sec - b->tv_sec) * 100 + (e->tv_usec - b->tv_usec) / 10000;

#define END(x)	{while(*x) x++;}
#if defined(SYSV)
  cp = "%Uuser %Ssys %Ereal %P";
#else /* defined(SYSV) */
#if defined(sgi)		/* IRIX 3.3 will show 0 for %M,%F,%R,%C */
  cp = "%Uuser %Ssys %Ereal %P %Mmaxrss %F+%Rpf %Ccsw";
#else /* defined(sgi) */
  cp = "%Uuser %Ssys %Ereal %P %Xi+%Dd %Mmaxrss %F+%Rpf %Ccsw";
#endif /* defined(sgi) */
#endif /* defined(SYSV) */
  for (; *cp; cp++)
    {
      if (*cp != '%')
	*outp++ = *cp;
      else if (cp[1])
	switch (*++cp)
	  {

	  case 'U':
	    tvsub (&tdiff, &r1->ru_utime, &r0->ru_utime);
	    sprintf (outp, "%d.%01d", (unsigned int) tdiff.tv_sec, (unsigned
		     int) tdiff.tv_usec / 100000);
	    END (outp);
	    break;

	  case 'S':
	    tvsub (&tdiff, &r1->ru_stime, &r0->ru_stime);
	    sprintf (outp, "%d.%01d", (unsigned int) tdiff.tv_sec, (unsigned
		     int) tdiff.tv_usec / 100000);
	    END (outp);
	    break;

	  case 'E':
	    psecs (ms / 100, outp);
	    END (outp);
	    break;

	  case 'P':
	    sprintf (outp, "%d%%", (int) (t * 100 / ((ms ? ms : 1))));
	    END (outp);
	    break;

#if !defined(SYSV)
	  case 'W':
	    i = r1->ru_nswap - r0->ru_nswap;
	    sprintf (outp, "%d", i);
	    END (outp);
	    break;

	  case 'X':
	    sprintf (outp, "%d", (unsigned int) (t == 0 ? 0 : (r1->ru_ixrss
							       -
						 r0->ru_ixrss) / t));
	    END (outp);
	    break;

	  case 'D':
	    sprintf (outp, "%d", (unsigned int) (t == 0 ? 0 :
						 (r1->ru_idrss +
						  r1->ru_isrss -
						  (r0->ru_idrss +
						 r0->ru_isrss)) / t));
	    END (outp);
	    break;

	  case 'K':
	    sprintf (outp, "%ld", t == 0 ? 0 :
		     ((r1->ru_ixrss + r1->ru_isrss + r1->ru_idrss) -
		      (r0->ru_ixrss + r0->ru_idrss + r0->ru_isrss)) / t);
	    END (outp);
	    break;

	  case 'M':
	    sprintf (outp, "%ld", r1->ru_maxrss / 2);
	    END (outp);
	    break;

	  case 'F':
	    sprintf (outp, "%ld", r1->ru_majflt - r0->ru_majflt);
	    END (outp);
	    break;

	  case 'R':
	    sprintf (outp, "%ld", r1->ru_minflt - r0->ru_minflt);
	    END (outp);
	    break;

	  case 'I':
	    sprintf (outp, "%ld", r1->ru_inblock - r0->ru_inblock);
	    END (outp);
	    break;

	  case 'O':
	    sprintf (outp, "%ld", r1->ru_oublock - r0->ru_oublock);
	    END (outp);
	    break;
	  case 'C':
	    sprintf (outp, "%ld+%ld", r1->ru_nvcsw - r0->ru_nvcsw,
		     r1->ru_nivcsw - r0->ru_nivcsw);
	    END (outp);
	    break;
#endif /* !SYSV */
	  }
    }
  *outp = '\0';
}

static void
tvadd (tsum, t0, t1)
     struct timeval *tsum, *t0, *t1;
{

  tsum->tv_sec = t0->tv_sec + t1->tv_sec;
  tsum->tv_usec = t0->tv_usec + t1->tv_usec;
  if (tsum->tv_usec > 1000000)
    tsum->tv_sec++, tsum->tv_usec -= 1000000;
}

static void
tvsub (tdiff, t1, t0)
     struct timeval *tdiff, *t1, *t0;
{

  tdiff->tv_sec = t1->tv_sec - t0->tv_sec;
  tdiff->tv_usec = t1->tv_usec - t0->tv_usec;
  if (tdiff->tv_usec < 0)
    tdiff->tv_sec--, tdiff->tv_usec += 1000000;
}

static void
psecs (l, cp)
     int32_t l;
     register char *cp;
{
  register int i;

  i = l / 3600;
  if (i)
    {
      sprintf (cp, "%d:", i);
      END (cp);
      i = l % 3600;
      sprintf (cp, "%d%d", (i / 60) / 10, (i / 60) % 10);
      END (cp);
    }
  else
    {
      i = l;
      sprintf (cp, "%d", i / 60);
      END (cp);
    }
  i %= 60;
  *cp++ = ':';
  sprintf (cp, "%d%d", i / 10, i % 10);
}

/*
 *			N R E A D
 */
int
Nread (fd, buf, count)
     int fd;
     void *buf;
     int count;
{
  register int cnt;
  errno = 0;
  if (udp)
    {
      cnt = scps_read (fd, buf, count);
      numCalls++;
    }
  else
    {
      if (b_flag)
	cnt = mread (fd, buf, count);	/* fill buf */
      else
	{
	  cnt = scps_read (fd, buf, count);
	  numCalls++;
	  errno = 0;
	}
      if (touchdata && cnt > 0)
	{
	  register int c = cnt, sum;
	  register char *b = buf;
	  while (c--)
	    sum += *b++;
	}
    }
  if (cnt < 0)
    {
      int error;

      error = GET_ERR ();

      if (error == SCPS_EBETS)
	{
	  BETS_Hits++;
	  BETS_Hole = 0;
	  scps_getsockopt (fd, SCPS_SOCKET, SCPS_SO_BETS_RHOLE_SIZE,
			   (char *) &BETS_Hole, (int *) &s_size);
	  scps_getsockopt (fd, SCPS_SOCKET, SCPS_SO_BETS_RHOLE_START,
			   (char *) &BETS_Start, (int *) &s_size);
	  printf ("BETS Hole reported of length %ld at byte: %ld\n",
		  BETS_Hole, BETS_Start);
	  if ((int) BETS_Hole < 0)
	    {
	      BETS_Hole = -((int) BETS_Hole);
	    }
	  streamlen += BETS_Hole;
	  Total_BETS += BETS_Hole;
	  memset ((char *) buf, 0, BETS_Hole);
	  cnt = BETS_Hole;
	}
      if (error == SCPS_EWOULDBLOCK)
	{
	}
      /* cnt = 0; */
    }
  return (cnt);
}

/*
 *			N W R I T E
 */
int
Nwrite (fd, buf, count)
     int fd;
     void *buf;
     int count;
{
  register int cnt;
  errno = 0;
  if (udp)
    {
    again:
      /* cnt = sendto( fd, buf, count, 0, &sinhim, sizeof(sinhim) ); */
      cnt = udp_WriteTo (fd, buf, count, sinhim.sin_addr.s_addr,
			 sinhim.sin_port);
      numCalls++;
      if (cnt < 0 && ((errno = GET_ERR ()) == SCPS_ENOBUFS))
	{
	  delay (18000);
	  errno = 0;
	  goto again;
	}
    }
  else
    {
      cnt = scps_write (fd, buf, count);
      errno = GET_ERR ();
      numCalls++;
      errno = 0;
    }
  return (cnt);
}

void
delay (us)
{
  struct timeval tv;

  tv.tv_sec = 0;
  tv.tv_usec = us;
  (void) select (1, (fd_set *) 0, (fd_set *) 0, (fd_set *) 0, &tv);
}

/*
 *			M R E A D
 *
 * This function performs the function of a read(II) but will
 * call read(II) multiple times in order to get the requested
 * number of characters.  This can be necessary because
 * network connections don't deliver data with the same
 * grouping as it is written with.  Written by Robert S. Miles, BRL.
 */
int
mread (fd, bufp, n)
     int fd;
     register char *bufp;
     unsigned n;
{
  register unsigned count = 0;
  register int nread;
  errno = 0;

  do
    {
      nread = scps_read (fd, bufp, n - count);
      numCalls++;
      errno = GET_ERR ();
      if (nread < 0)
	{
	  errno = GET_ERR ();
	  perror ("ttcp_mread");
	  return (-1);
	}
      if (nread == 0)
	{
	  errno = 0;
	  return ((int) count);
	}
      count += (unsigned) nread;
      bufp += nread;
    }
  while (count < n);
  errno = 0;
  return ((int) count);
}

void
pinger ()
{
  int i;

  min = 10000;
  max = 0;
  ave = 0;

  sprintf (buf, "%d %d ", nbuf, buflen);
  Nwrite (fd, buf, 20);

  for (i = 0; i < nbuf; i++)
    {
      gettimeofday ((struct timeval *) buf,
		    (struct timezone *) NULL);
      sprintf (buf + sizeof (struct timeval), "%d", i);
      Nwrite (fd, buf, buflen);
      catcher ();
    }

  printf ("min = %d ms, max = %d ms, average = %d ms\n", min, max, ave / nbuf);
  fflush (stdout);
}

void
catcher ()

{
  struct timeval cur_time;
  struct timeval time_sent;
  struct timeval diff;
  int len = 0;
  int ret = 0;
  int first = 1;
  int32_t triptime;
  int seq_num;

  while (len < buflen)
    {
      ret = Nread (fd, buf, buflen);
      if (ret < 0)
	{
	  printf ("PDF error = %d %d\n", ret, GET_ERR ());
	  exit (-1);
	}

      len += ret;
      if (first)
	{
	  memcpy (&time_sent, buf, sizeof (struct timeval));
	  sscanf (buf + sizeof (struct timeval), "%d", &seq_num);
	  first = 0;
	}
    }

  gettimeofday (&cur_time, (struct timezone *) NULL);
  tvsub (&diff, &cur_time, &time_sent);
  triptime = (diff.tv_sec * 1000000 + diff.tv_usec) / 1000;
  if (verbose)
    printf ("Sequence number %d: %d bytes received time = %ld ms\n",
	    seq_num, len, triptime);

  if (triptime < min)
    min = triptime;

  if (triptime > max)
    max = triptime;

  ave += triptime;

  return;
}


void
echoer ()

{
  int len;
  int i;
  int seq_num;
  struct timeval time_sent;
  int ret;


  len = Nread (nfd, buf, 20);
  sscanf (buf, "%d %d", &nbuf, &buflen);

  if ((buf = (char *) malloc (buflen + bufalign)) == (char *) NULL)
    err ("malloc");

  for (i = 0; i < nbuf; i++)
    {
      int first = 1;

      len = 0;
      while (len < buflen)
	{
	  ret = Nread (nfd, buf, buflen);
	  if (ret < 0)
	    {
	      printf ("PDF error = %d %d\n", ret, GET_ERR ());
	      exit (1);
	    }

	  len += ret;
	  if (first)
	    {
	      memcpy (&time_sent, buf, sizeof (struct timeval));
	      sscanf (buf + sizeof (struct timeval), "%d", &seq_num);
	      first = 0;
	    }
	}

      memcpy (buf, &time_sent, sizeof (struct timeval));
      sprintf (buf + sizeof (struct timeval), "%d", seq_num);
      Nwrite (nfd, buf, buflen);
      if (verbose)
	printf ("Sequence number = %d: %d bytes received and echoed back\n",
		seq_num, len);
    }
}
