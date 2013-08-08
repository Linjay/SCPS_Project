/*
 * get ppp current queue length:
 * 	ppp_current_tx_len [-a|-d] [-v|-r|-z] [-c count] [-w wait] [interface]
 */

#ifndef __STDC__
#define const
#endif

#ifndef lint
static const char rcsid[] = "$Id: ppp_current_tx_len.c,v 1.1 2005/10/21 18:41:30 feighery Exp $";
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
#define IF_LIST_MAX 	10
char	*if_list [IF_LIST_MAX];
int	if_list_len = 0;

int 	vflag = 0;
int	cflag = 0;

#if defined(SUNOS4) || defined(ULTRIX) || defined(NeXT)
extern int optind;
extern char *optarg;
#endif

static void usage __P((void));
static void catchalarm __P((int));

// PDF XXX Added this function declaration
static int get_ppp_qlen __P((char *));
static void intpr __P((void));

int main __P((int, char *argv[]));

static void
usage()
{
    fprintf(stderr, "Usage: %s -g scps_addresss [-v -c] -r route_id -i interval -t thresh -w wait [interface]\n",
	    progname);
    exit(1);
}

/*
 * Called if an interval expires before intpr has completed a loop.
 * Sets a flag to not wait for the alarm.
 */
static void
catchalarm(arg)
    int arg;
{
    signalled = 1;
}


static int
get_if_status (if_name)
	char *if_name;
{
    struct ifreq ifr;
#ifdef __linux__
#undef  ifr_name
#define ifr_name ifr_ifrn.ifrn_name
#endif
        memset (&ifr, 0, sizeof (ifr));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
	    return(0);
	} else {
		if ((ifr.ifr_flags & IFF_UP) == 0) {
			return (0);
		}
		
		if ((ifr.ifr_flags & IFF_RUNNING) == 0) {
			return (0);
		}
		
		return (1);	
	}
}


static int
get_ppp_qlen(if_name)
	char *if_name;
{
    int len;
    struct ifpppstatsreq req;

    len = 0;
    memset (&req, 0, sizeof (req));
  
#ifdef __linux__
    req.stats_ptr = (caddr_t) &req.stats;
#undef ifr_name
#define ifr_name ifr__name
#endif

    strncpy(req.ifr_name, if_name, sizeof(req.ifr_name));
    if (ioctl(s, SIOCGPPPQLEN, &req) < 0) {
	fprintf(stderr, "%s: ", progname);
	if (errno == ENOTTY) {
	    fprintf(stderr, "kernel support missing\n");
	} else {
printf ("PDF %s\n", if_name);
	    } perror("couldn't get PPP statistics");
	return (-1);
    } else {
	return (req.stats.p.ppp_discards);
    }
}


#define KBPS(n)		((n) / (interval * 1000.0))

/*
 * Print a running summary of interface statistics.
 * Repeat display every interval seconds, showing statistics
 * collected over that interval.  Assumes that interval is non-zero.
 * First line printed is cumulative.
 */
static void
intpr()
{
    sigset_t oldmask, mask;
    int qlen;
    int status;
    unsigned char gw_route_cmdr_cmd [100];
    int b_increment;
    int i;
    int total_q_len = 0;
    int total_q_reporting = 0;
    int avg_q_len = 0;
    int link_status = 1;

    while (1) {

	(void)signal(SIGALRM, catchalarm);
	signalled = 0;
	(void)alarm(interval);

	total_q_len = 0;
	total_q_reporting = 0;
	avg_q_len = 0;

	if (vflag) {
		printf ("\n");
	} 

	for (i = 0; i < if_list_len; i++) {

		interface = if_list [i];
	        status = get_if_status (interface);

		if (vflag) {
			printf ("Checking status of interface %s %d\n", interface, status);
		} 
	
		if (status) {
      	  		qlen = get_ppp_qlen(interface);

			if (vflag) {
				printf ("         Length of interface %s %d\n", interface, qlen);
			} 
	
			if (qlen < 0) {
				b_increment = 0;
			} else {
				total_q_len += qlen;
				total_q_reporting ++;
			}
		}	
 	}


	if (total_q_reporting) {
		avg_q_len = total_q_len / total_q_reporting;

      		if (avg_q_len < thresh){
    	  		b_increment = increment * MTU;
		} else {
			b_increment = 0;
		}
	
		if (link_status == 0) {
			link_status =1;

			if (vflag) {
				printf ("Link is transitioning from down to up\n");
			}

			if (cflag) {
		     	   sprintf (gw_route_cmdr_cmd,"gw_route_cmdr -A V -G %s -r %d", gateway_host, route_id);
      	 		   system (gw_route_cmdr_cmd);
			   if (vflag) {
      	 		 	printf ("%s\n", gw_route_cmdr_cmd);
			   }
			}

		}
		if (vflag) {
			printf ("The queue length is (%d) increment (%d) thresh (%d) gw (%s) route_id (%d) \n",avg_q_len, b_increment, thresh, gateway_host, route_id);
		}

		if (cflag && b_increment) {
		        sprintf (gw_route_cmdr_cmd,"gw_route_cmdr -A M -G %s -r %d -F %d", gateway_host, route_id, b_increment);
      	 	 	system (gw_route_cmdr_cmd);
			if (vflag) {
      	 		 	printf ("%s\n", gw_route_cmdr_cmd);
			 }
		}

	} else {
		if (link_status == 1) {
			link_status = 0;

			if (vflag) {
				printf ("Link is transitioning from up to down\n");
			}

			if (cflag) {
			   sprintf (gw_route_cmdr_cmd,"gw_route_cmdr -A U -G %s -r %d", gateway_host, route_id);
      	 	    	   system (gw_route_cmdr_cmd);
			   if (vflag) {
      	 		 	printf ("%s\n", gw_route_cmdr_cmd);
			   }
			}

		}

		if (vflag) {
			printf ("No Queues are reporting \n");
		} 

	}

	sigemptyset(&mask);
	sigaddset(&mask, SIGALRM);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);
	if (!signalled) {
	    sigemptyset(&mask);
	    sigsuspend(&mask);
	}
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
	signalled = 0;
	(void)alarm(interval);

    }
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

    {
	int x;
	for (x = 0; x < IF_LIST_MAX; x++) {
		if_list [x] = malloc (50);
	}

    }

    if ((progname = strrchr(argv[0], '/')) == NULL)
	progname = argv[0];
    else
	++progname;

    while ((c = getopt(argc, argv, "g:s:r:vci:t:w:")) != -1) {
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

	case 'v':
		vflag = 1;
		break;

	case 'c':
		cflag = 1;
		break;

	case 'r':
		route_id = atoi (optarg);
		break;
	default:
	    usage();
	}
    }
    argc -= optind;
    argv += optind;

    if (!interval)
	interval = 1;


    while (argc > 0) {
	memcpy (if_list[if_list_len], argv[0], sizeof (argv[0]));
        argc -= 1;
        argv += 1;
	if_list_len ++;
    }

   interface = if_list [0];


        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            fprintf(stderr, "%s: ", progname);
            perror("couldn't create IP socket");
            exit(1);
        }  

    intpr();
    exit(0);
}
