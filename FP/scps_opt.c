/*
  This is unclassified Government software.

  The SCPS File Protocol (SCPS-FP) software was developed under
  contract to the Jet Propulsion Laboratory, an operating division of
  the California Institute of Technology and is available for use by
  the public without need of a licence.

  DISCLAIMER:

  THE SCPS-FP SOFTWARE AND RELATED MATERIALS ARE PROVIDED "AS-IS"
  WITHOUT WARRANTY OR INDEMNITY OF ANY KIND INCLUDING ANY WARRANTIES
  OF USE, PEROFMRNACE, OR MERCHANTABILITY OR FITNESS FOR A PRTICULAR
  USE OR PURPOSE (as set forth in UCC section 2312-2313) OR FOR ANY
  PURPOSE WHATSOEVER.

  USER BEARS ALL RISK RELATING TO USE, QUALITY, AND PERFORMANCE OF THE
  SOFTWARE.

  The Jet Propulsion Laboratory, the California Institute of
  Technology, and the United States government retain a paid-up
  royalty free world wide license in this product.

  SAIC Disclaimer:
    (1) SAIC assumes no legal responsibility for the source code and
        its subsequent use.
    (2) No warranty or representation is expressed or implied.
    (3) Portions (e.g. Washington University FTP Replacement Daemon)
        are copyright (c) Regents of the University of California.
	All rights reserved.  Restrictions included in said copyright
	are also applicable to this release.

*/

/*
 * This file is to add the scps_options to the FP and potentially other
 * applications.
 */

#ifndef NOTTP
#include "../include/scps.h"

#include <stdio.h>
#include <errno.h>


#define BETS         0x01
#define COMPRESS     0x02
#define CONGESTVAL   0x04
#define SNACK        0x08
#define TIMESTAMP    0x10
#define NODELAY      0x20
#define NOBLOCK      0x40
#define USE_SPANNER  0x080
#define PRIORITY     0x100

int options = 0;                /* socket options */
int zero = 0;                   /* for 4.3 BSD style setsockopt() */
int one = 1;                    /* for 4.3 BSD style setsockopt() */
int rec_boundary = 0;           /* 0 = no boundary 1 = record boundary */
short ackbehave = -1;           /* default ack behavior */
int32_t BETS_Hole, BETS_Start;
int32_t Total_BETS = 0;
int BETS_Hits = 0;
char *a_host = "\0";;
int scps_vegas_alpha = 0;
int scps_vegas_beta = 0;
int scps_vegas_gamma = 0;
int scps_vegas_ss = 0;
int app_nl_default;
int sockbufsize = 0;

extern int optind;
extern char *optarg;
extern char scps_version [];
extern char config_span_name[];
extern char config_local_name[];
char *local_name;
char *span_name; 

uint32_t rate_control = 0; /* New rate control value */
int congestval = 0;             /* New congestion control value */
int scps_options = 0;
int32_t ackdelay = 0;
int route_mtu = 0;

char Usage[] = "Usage:  applicaton [options] \n\
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
        -N     network layer \n\
                  1 = IP \n\
                  2 = SCPS NP \n\
        -m ##  Set the route_sockets MTU (in bytes) \n\
        -R ##  set SCPS rate control value (in bps)\n\
	-H XX  choose source hostname\n\
        -W     set alpha for vegas CC \n\
        -X     set beta for vegas CC \n\
        -Y     set gamma for vegas CC \n\
";

void
parse_options (argc, argv)
int argc;
char **argv;

{
  int c;

  while ((c = getopt (argc, argv,
              "decrstuvBCDEIMPSTVZb:f:g:L:l:n:p:q:A:F:G:H:N:O:R:m:a:W:X:Y:")) != -1) { 
      switch (c) 
        { 
        case 'a':
          ackdelay = atol (optarg);
          break;
        case 'c': 
          rec_boundary = 1;
          break;
        case 'E':
          scps_options |= BETS;
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
        case 'M':
          scps_options |= TIMESTAMP;
          break;
        case 'S':
          scps_options |= SNACK;
          break;
        case 'V':
          printf ("%s\n", scps_version);
          exit (1);
        case 'W':
          scps_vegas_alpha = (atoi (optarg));
          break;
        case 'X':
          scps_vegas_beta = (atoi (optarg));
          break;
        case 'Y':
          scps_vegas_gamma = (atoi (optarg));
          break;
        case 'N':
          app_nl_default = (atoi (optarg));
          break;
        case 'F':  
          ackbehave = (short) (atoi (optarg));
          break;
        case 'Z':               /* All the toys */
          {
            scps_options |= TIMESTAMP;
            scps_options |= SNACK;
            scps_options |= BETS;
            scps_options |= COMPRESS;
          }
          break;
        case 'm':
          route_mtu = atoi (optarg);
          break;
        case 'R':
          rate_control = atol (optarg);
          break;
	case 'H':
		local_name = optarg;
		memcpy (&config_local_name, local_name,
		strlen (local_name));
	break;
        case 'b':
#if defined(SCPS_SO_SNDBUF) || defined(SCPS_SO_RCVBUF)
          sockbufsize = atoi (optarg);
#else /* defined(SCPS_SO_SNDBUF) || defined(SCPS_SO_RCVBUF) */
          fprintf (stderr,
                   "ttcp: -b option ignored: SCPS_SO_SNDBUF/SCPS_SO_RCVBUF socket options not supported\n");    
#endif /* defined(SCPS_SO_SNDBUF) || defined(SCPS_SO_RCVBUF) */
          break; 
        default:
          goto usage;
        }
    }

    if (optind != argc) 
        a_host = argv[optind];

    return;

usage:
  fprintf (stderr, Usage);
  exit (1);


}

enable_options (s)
int s;

{


  /* Change the default behavior for the SCPS optional capabilities */
  if (scps_options & TIMESTAMP)
    scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_TIMESTAMP,
                     &zero, sizeof (zero));
                     
  if (scps_options & COMPRESS)
    scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_COMPRESS,
                     &one, sizeof (one));
        
  if (scps_options & SNACK)
    scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_SNACK,
                     &zero, sizeof (zero));

  if (scps_options & BETS)
    scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_BETS,
                     &one, sizeof (one));

  if (scps_options & CONGESTVAL)
    {
      switch (congestval)
        {
        case 0:
          scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_CONGEST,
                           &zero, sizeof (zero));
          break;
        case 1:
          scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_VJ_CONGEST,
                           &one, sizeof (one));
          break;
        case 2:
          scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_VEGAS_CONGEST,
                           &one, sizeof (one));
          break;
        }
    }
  if (ackdelay)
    {
      scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_ACKDELAY,
                       &ackdelay, sizeof (ackdelay));

      scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_ACKFLOOR,
                       &ackdelay, sizeof (ackdelay));
    }
    
  if (rate_control)
    scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_RATE,
                     &rate_control, sizeof (rate_control));

  if (route_mtu)
    scps_setsockopt (route_sock, SCPS_ROUTE, SCPS_MTU,
                     &route_mtu, sizeof (route_mtu));

  /* Set the default Ack behavior if it is different than compiled value */
  if (ackbehave >= 0)
    scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_ACKBEHAVE,
                     &ackbehave, sizeof (ackbehave));

  if (scps_vegas_alpha) {
    scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_VEGAS_ALPHA,
                     &scps_vegas_alpha, sizeof (scps_vegas_alpha));
  }

  if (scps_vegas_beta) {
    scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_VEGAS_BETA,
                     &scps_vegas_beta, sizeof (scps_vegas_beta));
  }

  if (scps_vegas_gamma) {
    scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_VEGAS_GAMMA,
                     &scps_vegas_gamma, sizeof (scps_vegas_gamma));
  }
          
  scps_setsockopt (s, PROTO_SCPSTP, SCPSTP_VEGAS_SS,
                   &scps_vegas_ss, sizeof (scps_vegas_ss));

  if (app_nl_default) { 
    scps_setsockopt (s, SCPS_SOCKET, SCPS_SO_NLDEFAULT,
                     &app_nl_default, sizeof (app_nl_default)); 
  }

#if defined(SCPS_SO_SNDBUF) || defined(SCPS_SO_RCVBUF)
  if (sockbufsize)
    { 
          if (scps_setsockopt (s, SCPS_SOCKET, SCPS_SO_SNDBUF, &sockbufsize,
                               sizeof sockbufsize) < 0)
            err ("setsockopt: sndbuf");
          if (scps_setsockopt (s, SCPS_SOCKET, SCPS_SO_RCVBUF, &sockbufsize,
                               sizeof sockbufsize) < 0)
            err ("setsockopt: rcvbuf");
    }   
#endif /* defined(SCPS_SO_SNDBUF) || defined(SCPS_SO_RCVBUF) */

}

#endif /* NOTTP */
