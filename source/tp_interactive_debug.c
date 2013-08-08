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

#include <errno.h>       /* obligatory includes */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "tp_debugPort.h"
 
#define PORTNUM 49987 /* random port number, we need something */
#define MAXHOSTNAME 100
 
#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_interactive_debug.c,v $ -- $Revision: 1.4 $\n";
#endif

void fireman(), do_something();
int getLine(char *buf, int max);
int read_data(int s, char *buf,int n);
int processAnswer(debugPortInfo *a);
int printSocket(tp_Socket *s, char *prefix);
int call_socket(char *hostname, int portnum);
int write_data(int s, char *buf, int n);
int printRoute(route *r, char *prefix);

extern char *optarg;

int main(int argc, char **argv)
{
  int c;
  char theHost[100];
	char buf[1000];
	debugPortInfo theAnswer;
	int s;
	int retVal;
	int num_written;
	int num_read;

	while ( (c=getopt(argc, argv, "?H:"))!=-1 ) {
	  switch (c) {
	  case 'h':
		goto usage;
	  case 'H':
	    strcpy(theHost, optarg);
	    break;
	  default:
	    goto usage;
	  }
	}

	  printf("Attempting to attach to host %s\n", theHost);
	s = call_socket(theHost, PORTNUM);
	if ( s<0 ) {
		printf("call_socket returned %d\n", s);
		exit(-1);
	}
	printf("call_socket OK (%d).\n", s);
	fcntl(s, F_SETFL, O_NONBLOCK);
	/*
	 * Read off any bogus stuff.
	 */
	do {
		num_read = read_data(s, buf, 1000);
	} while ( num_read>0 );
	while (1) {
		printf("# ");
//		while ( (retVal = scanf("%s", buf))>0 ) {
		while ( (retVal = getLine(buf, 1000))>0 ) {
			printf("Writing <%s> to socket...\n", buf);
			strcat(buf, "\n");
			num_written = write_data(s, buf, strlen(buf));
			if ( num_written!=strlen(buf) ) {
				printf("problem in write_data.\n");
				exit(-1);
			}
			if ( strncmp(buf, "quit", 4)==0 ) {
				printf("Detected quit.\n");
				retVal = EOF;
				break;
			}
			/* how do I say: "i want to read n bytes but if there's
			 * not n bytes there I don't want to read nothin'?
			 */
			system("sleep 2");
			num_read = read_data(s, (char *) &theAnswer, sizeof(debugPortInfo));
			printf("Read %d bytes back (expected %d).\n", num_read, sizeof(debugPortInfo));
			if ( num_read==sizeof(debugPortInfo) ) {
				processAnswer(&theAnswer);
			}
			num_read = read_data(s, buf, 1000);
			if ( num_read>0 ) {
				printf("Read %d bytes of mung afterwards.\n", num_read);
			}
			printf("# ");
		}
		if ( retVal==EOF ) break;
	}
	buf[0] = EOF;
	write_data(s, buf, 1);
	printf("Client exiting.\n");
	return(0);
usage:
	printf("\n%s [-h hostname]\n", argv[0]);
	printf("\n  This program will allow you to interact with the SCPS stack of a program\n");
	printf(  "  provided it was compiled with the appropriate debugging options.\n");
	printf(  "  Once connected, you can issue commands to the remote application.\n");
	printf("\n");
	printf("\nCOMMANDS:\n");
	printf("  ls		List active sockets.\n");
	printf("  si x		Get info about socket x, where x is an index in the socket list.\n");	
	printf("\n");
}

int
processAnswer(debugPortInfo *a)
{
	int i;
	switch(a->infoType) {
	case debugAnswer_socket:
		printf("Received a debugAnswer_socket\n");
		printSocket((tp_Socket *) &a->data.theSocketInfo.theSocket, "  ");
		printRoute((route *) &a->data.theSocketInfo.theRoute, "--");
		printf("\n");
		break;
	case debugAnswer_list:
		printf("Received a debugAnswer_list\n");
		for ( i=0; a->data.theList[i].myPort>0; i++ ) {
			printf(" %3d:  myPort(%8d) hisPort(%8d)\n",
				i,
				a->data.theList[i].myPort,
				a->data.theList[i].hisPort);
		}
		break;
	default:
		printf("Unknown response type from tp_debugPort (%d)\n", a->infoType);
		break;
	}
	return(0);
}

int
printSocket(tp_Socket *s, char *prefix)
{
	printf("%smyPort(%d) hisPort(%d)\n", prefix, ntohs(s->myport), ntohs(s->hisport));
	printf("%ssockid(%d) sockFlags(%lx) s_errno(%d)\n", prefix, s->sockid, s->sockFlags, s->s_errno);
	printf("%sstate(%d) state_prev(%d)\n", prefix, s->state, s->state_prev);
	printf("%sinitial_seqnum(%lu) initial_seqnum_rec(%lu)\n", prefix, s->initial_seqnum, s->initial_seqnum_rec);
	printf("%sacknum(%lu) seqnum(%lu) snduna(%lu) seqsent(%lu)\n", prefix, s->acknum, s->seqnum, s->snduna, s->seqsent);
	printf("%shigh_hole_seq(%lu) high_seq(%lu) high_congestion_seq(%lu)\n", prefix,
		s->high_hole_seq, s->high_seq, s->high_congestion_seq);
	printf("%ssndwin(%lu) rcvwin(%lu)\n", prefix, s->sndwin, s->rcvwin);
	return(0);
}

int
printRoute(route *r, char *prefix)
{
	printf("%sbytes_per_interval(%ld) current_credit(%ld) max_credit(%ld) max_burst_bytes(%ld)\n", prefix, 
		r->bytes_per_interval, r->current_credit, r->max_credit, r->max_burst_bytes);
	printf("%sinterval(%ld) time(%lu) prev_time(%lu) MTU(%u) flags(%lx)\n", prefix,
		r->interval, r->time, r->prev_time, r->MTU, r->flags);
	printf("%srtt(%ld) rtt_var(%ld) initial_RTO(%ld) sendpipe(%ld) recvpipe(%ld)\n", prefix,
		r->rtt, r->rtt_var, r->initial_RTO, r->sendpipe, r->recvpipe);
	return(0);
}


int call_socket(char *hostname, int portnum)
{ struct sockaddr_in sa;
  struct hostent     *hp;
  int s;

  if ((hp= gethostbyname(hostname)) == NULL) { /* do we know the host's */
    errno= ECONNREFUSED;                       /* address? */
    return(-1);                                /* no */
  }

  bzero(&sa,sizeof(sa));
  bcopy(hp->h_addr,(char *)&sa.sin_addr,hp->h_length); /* set address */
  sa.sin_family= hp->h_addrtype;
  sa.sin_port= htons((u_short)portnum);

  if ((s= socket(hp->h_addrtype,SOCK_STREAM,0)) < 0)   /* get socket */
    return(-1);
  if (connect(s,(struct sockaddr *) &sa, sizeof(struct sockaddr)) < 0) {                  /* connect */
    close(s);
    return(-1);
  }
  return(s);
}

int
getLine(char *buf, int max)
{
	int offset = 0;
	while ( offset<max-1 ) {
		buf[offset++] = getchar();
		if ( buf[offset-1]=='\n' ) {
			buf[offset-1] = '\0';
			return(strlen(buf));
		}
	}
	buf[max-1] = '\0';
	return(strlen(buf));
}


int write_data(int s, char *buf, int n)
{ int bcount,          /* counts bytes read */
      bw;              /* bytes written this pass */

  bcount= 0;
  bw= 0;
  while (bcount < n) {             /* loop until full buffer */
    if ((bw = write(s,buf,1)) > 0) {
      bcount += bw;                /* increment byte counter */
      buf += bw;                   /* move buffer ptr for next read */
    }
    if (bw < 0)                    /* signal an error to the caller */
      return(-1);
  }
  return(bcount);
}
 
int read_line(int s, char *buf, int n)
{
  static char dbitempBuf[1000];
  static int bcount = 0;        /* counts bytes read */
  int br;              		/* bytes read this pass */

  if ( s<0 ) return(0);
  br= 0;
  while (bcount < n) {             /* loop until full buffer */
    if ((br = read(s, &(dbitempBuf[bcount]), 1)) > 0) {
      bcount += br;                /* increment byte counter */
      /*
       * When we see a cr, that's a whole line so we copy to buf
       * and bail
       */
      if ( dbitempBuf[bcount-1]=='\n' ) {
	dbitempBuf[bcount-1] = '\0';
	bcount = 0;
	strcpy(buf, dbitempBuf);
	return(strlen(buf));
      }
      if ( dbitempBuf[bcount-1]==EOF ) return(EOF);
    }
    if (br < 0) {                   /* signal an error to the caller */
      if ( errno==EAGAIN ) return(0);
      else return(-1);
    }
  }
  return(bcount);
}

int read_data(int s, char *buf, int n)
{ int bcount,          /* counts bytes read */
      br;              /* bytes read this pass */

  bcount= 0;
  br= 0;
  while (bcount < n) {             /* loop until full buffer */
    if ((br= read(s,buf,n-bcount)) > 0) {
      bcount += br;                /* increment byte counter */
      buf += br;                   /* move buffer ptr for next read */
    }   
    if (br < 0)                    /* signal an error to the caller */
      return(-1);
  }
  return(bcount);       
}

