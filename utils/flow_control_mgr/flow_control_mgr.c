/*
 * flow_control_mgr:
 * 	flow_control_mgr 
 */

#ifndef __STDC__
#define const
#endif

#ifndef lint
static const char rcsid[] = "$Id: flow_control_mgr.c,v 1.1 2009/07/27 12:59:51 feighery Exp $";
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include "flow_control_mgr.h"


#if defined(__linux__) && defined(__powerpc__) \
    && (__GLIBC__ == 2 && __GLIBC_MINOR__ == 0)
/* kludge alert! */
#undef __GLIBC__
#endif
#include <sys/socket.h>		/* *BSD, Linux, NeXT, Ultrix etc. */
#ifndef __linux__
#include <net/if.h>
#include <net/ppp_defs.h>
#include <net/if_ppp.h>
#else
/* Linux */
#if __GLIBC__ >= 2
#include <asm/types.h>		/* glibc 2 conflicts with linux/types.h */
#include <net/if.h>
#else
#include <linux/types.h>
#include <linux/if.h>
#endif
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#endif /* __linux__ */

#define MTU 1500

char    *gateway_host;
int	route_id;
int	interval;
int	thresh;
int	increment;
int	infinite;
int	unit;
int	s;			/* socket or /dev/ppp file descriptor */
int	signalled;		/* set if alarm goes off "early" */
char	*progname;
char	*interface;

int 	vflag = 0;
int 	pflag = 0;
int	dflag = 0;

char *gw_route_cmdr_path = NULL;

static void usage __P((void));

// PDF XXX Added this function declaration
int main __P((int, char *argv[]));


static void
init_socket ()

{
	udp_init_socket ();
}


static void
display_msg (flow_control_p)
	struct flow_control_struct *flow_control_p;

{
	printf ("Received flow control message\n");
	printf ("\tVersion number is %u\n", flow_control_p->version);
	printf ("\tCommand is %u\n", flow_control_p->command);
	printf ("\tSequence number is %u\n", flow_control_p->seq_num);
	printf ("\tFlow id is %u\n", flow_control_p->flow_id);
	printf ("\tAmount %u\n", ntohs (flow_control_p->amount));
	printf ("\tSignaler IP address %x\n", ntohl (flow_control_p->signal_addr));
	printf ("\tPEP IP address Version number is %x\n", ntohl (flow_control_p->pep_addr));
	printf ("\tLength of authentication string %d\n", flow_control_p->len_auth_string);
}


static void
seng_signal (flow_control_p)
	struct flow_control_struct *flow_control_p;

{
	char pep_addr [MSG_LEN];
	char *pep_addr_p = &pep_addr[0];

	char msg [MSG_LEN];
        char *msg_p = &msg[0];


	pep_addr_p = inet_ntoa (flow_control_p->pep_addr);

	sprintf (msg_p,"%s -A M -G %s -r %d -F %d\n", gw_route_cmdr_path,
		 pep_addr_p, flow_control_p->flow_id,
		 ntohs (flow_control_p->amount));
	if (vflag) {
		printf ("Issuing the following command\n");
		printf ("\t%s\n\n", msg_p);
	}

	if (pflag) {
		system (msg_p);
	}
}

static void
main_loop ()

{
    struct flow_control_struct flow_control_msg;
    struct flow_control_struct *flow_control_p = &flow_control_msg;

    while (1) {
	udp_socket_read ((char *) flow_control_p);

	if (vflag) {
		display_msg (flow_control_p);
	}

	if (pflag) {
		seng_signal (flow_control_p);
	}

    }
}


static void
usage()
{
    fprintf(stderr, "Usage: %s\n",
	    progname);
    exit(1);
}


int
main(argc, argv)
    int argc;
    char *argv[];
{
    int c;
#ifdef STREAMS
    char *dev;
#endif

    if ((progname = strrchr(argv[0], '/')) == NULL)
	progname = argv[0];
    else
	++progname;

    while ((c = getopt(argc, argv, "b:g:s:r:vdpi:t:w:")) != -1) {
	switch (c) {
	case 'i':
	    increment = atoi(optarg);
	    break;
	case 't':
	    thresh = atoi(optarg);
	    break;
	case 'w':
	    interval = atoi(optarg);
	    if (interval <= 0)
		usage();
	    break;

	case 'g':
		gateway_host = optarg;
		break;

	case 'b':
		gw_route_cmdr_path = optarg;
		break;

	case 'v':
		vflag = 1;
		break;

	case 'd':
		dflag = 1;
		break;

	case 'p':
		pflag = 1;
		break;

	case 'r':
		route_id = atoi (optarg);
		break;
	default:
	    usage();
	}
    }

    if (!gw_route_cmdr_path) {
	printf ("ERROR, gw_route_cmdr_path (option -b is not defined\n");
	exit (0);
    }

    argc -= optind;
    argv += optind;

    if (dflag) {
	printf ("Establishing UDP socket\n");
    }
    init_socket ();

    if (dflag) {
	printf ("Entering main while loop\n");
    }
    main_loop ();

    exit(0);
}
