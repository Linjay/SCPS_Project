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
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include "scpstp.h"
#include "tp_debug.h"
#include "tp_debugPort.h"
 
#define MAXHOSTNAME 100
 
#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_debugPort.c,v $ -- $Revision: 1.5 $\n";
#endif

char fooBuffer[1000];

int do_something();
void tp_debugPortSetup();
int establish(u_short portnum);
int get_connection(int s);
int read_line(int s, char *buf, int n);
int processFooBuffer(char *buffer);
int write_data(int s, char *buf, int n);
 
extern tp_Socket *tp_allsocs;

int tpDebugSocket = -1;
int tpDebugAcceptSocket = -1;

#ifdef DEFINE_MAIN
int main(int argc, char **argv)
{
	static int i;
	tp_debugPortSetup();
	while ( 1 ) {
		printf("%7d -- <%s>\n", i++, fooBuffer);
		if ( i++ == 100000 ) {
			if ( tp_debugPortService()<0 ) {
				close(tpDebugAcceptSocket);
				tpDebugAcceptSocket = -1;
//				close(tpDebugSocket);
//				tp_debugPortSetup();
			}
			i = 0;
		}
	}
}
#endif /* DEFINE_MAIN */

void
tp_debugPortSetup()
{
  if ( tpDebugSocket>0 ) return;
  printf("Setting up tp_debugPort on port %d.\n", DEBUG_INTERACTIVE_PORT);
  if ((tpDebugSocket = establish(DEBUG_INTERACTIVE_PORT)) < 0) {  /* plug in the phone */
    perror("establish");
    exit(1);
  }
  printf("socket established on port %d\n", DEBUG_INTERACTIVE_PORT);
  fcntl(tpDebugSocket, F_SETFL, O_NONBLOCK);
  tpDebugAcceptSocket = -1;
}
 
int
tp_debugPortService()
{
	int retVal = -1;
	/*
	 * If not set up, set up.
	 */
	tp_debugPortSetup();

	/*
	 * If not connected, see if there's a request.
	 */
	if ( tpDebugAcceptSocket<0 ) {
	    if ((tpDebugAcceptSocket = get_connection(tpDebugSocket)) < 0) { /* get a connection */
 	      if (errno == EWOULDBLOCK) return(0);
	      if (errno == EINTR)             /* EINTR might happen on accept(), */
		return(0);                    /* try again later */
	      perror("accept");               /* bad */
	      exit(1);
	    } else {
		printf("tp_debugPort received connection.\n");
	        fcntl(tpDebugAcceptSocket, F_SETFL, O_NONBLOCK);
	    }
	}

	/*
	 * If we get here, we've got a debug console talking to us.
	 */
	retVal = do_something(tpDebugAcceptSocket);
//	printf("%7d -- <%s>\r", foobar++, fooBuffer);
	if ( strlen(fooBuffer)>0 ) {
		processFooBuffer(fooBuffer);
		fooBuffer[0] = '\0';
	}
	fflush(stdout);
	return(retVal);
}

int
processFooBuffer(char *buffer)
{
	tp_Socket *s;
	debugPortInfo theAnswer;
	int i;
	int wasProcessed = 1;
	char tempBuf[1000];
	int socketID;

	memset(&theAnswer, 0, sizeof(debugPortInfo));
	/*
	 * List open sockets.
	 */
	if ( strcmp(buffer, "ls")==0 ) {
		printf("  Building socket list:\n");
		for ( i=0, s=tp_allsocs; s!=NULL; s=s->next, i++ ) {
			theAnswer.infoType = debugAnswer_list;
			theAnswer.data.theList[i].myPort = ntohs(s->myport);
			theAnswer.data.theList[i].hisPort = ntohs(s->hisport);
			printf("    myPort(%d) hisPort(%d)\n", ntohs(s->myport), ntohs(s->hisport));
		}
		theAnswer.data.theList[i].myPort = -1;
		theAnswer.data.theList[i].hisPort = -1;
	} else if (strncmp(buffer, "si", 2)==0 ) {
		printf("I think a tp_Socket is %d bytes.\n", sizeof(tp_Socket));
		if ( sscanf(buffer, "%s %d", tempBuf, &socketID)==2 ) {
			for ( i=0, s=tp_allsocs; i<socketID && s!=NULL; s=s->next, i++ ) ;
			if ( s==NULL ) return(0);
			theAnswer.infoType = debugAnswer_socket;
			printf("Copying %d bytes\n", sizeof(struct _tp_socket));
			memcpy(&theAnswer.data.theSocketInfo.theSocket, s, sizeof(tp_Socket));
			memcpy(&theAnswer.data.theSocketInfo.theRoute, s->rt_route, sizeof(route));
		} else {
			wasProcessed = 0;
		}
	} else {
		wasProcessed = 0;
	}
	/*
	 *
	 */
	if ( wasProcessed ) {
		printf("Processed command --%s--\n", buffer);
		fflush(stdout);
		write_data(tpDebugAcceptSocket, (char *) &theAnswer, sizeof(theAnswer));
	} else {
		printf("tp_debugPort:: unknown command --%s--\n", buffer);
	}
	buffer[0] = '\0';
	return(0);
}

 
/* code to establish a socket; originally from bzs@bu-cs.bu.edu
 */
 
int establish(u_short portnum)
{ char   myname[MAXHOSTNAME+1];
  int    s;
  struct sockaddr_in sa;
  struct hostent *hp;
 
  bzero(&sa,sizeof(struct sockaddr_in));      /* clear our address */
  gethostname(myname,MAXHOSTNAME);            /* who are we? */
  hp= gethostbyname(myname);                  /* get our address info */
  if (hp == NULL)                             /* we don't exist !? */
    return(-1);
  sa.sin_family= hp->h_addrtype;              /* this is our host address */
  sa.sin_port= htons(portnum);                /* this is our port number */
  if ((s= socket(AF_INET,SOCK_STREAM,0)) < 0) /* create socket */
    return(-1);
  if (bind(s,(struct sockaddr *) &sa, sizeof(sa)) < 0) {
    close(s);
    return(-1);                               /* bind address to socket */
  }
  listen(s, 3);                               /* max # of queued connects */
  return(s);
}
 
int get_connection(int s)
{ struct sockaddr_in isa; /* address of socket */
  int i;                  /* size of address */
  int t;                  /* socket of connection */
 
  i = sizeof(isa);                   /* find socket's address */
  getsockname(s,(struct sockaddr *) &isa, &i);            /* for accept() */
 
  if ((t = accept(s,(struct sockaddr *) &isa,&i)) < 0)   /* accept connection if there is one */
    return(-1);
  return(t);
}
 
/* as children die we should get catch their returns or else we get
 * zombies, A Bad Thing.  fireman() catches falling children.
 */
 
void fireman()
{ union wait wstatus;
 
  while(wait3((int *) &wstatus,WNOHANG,NULL) > 0)
      ;
}
 
/* this is the function that plays with the socket.  it will be called
 * after getting a connection.
 */
 
int do_something(s)
int s;
{
  int numRead;
  while (1) {
	numRead = read_line(s, fooBuffer, 500);
	if ( numRead==EOF ) {
		printf("do_something exiting due to EOF.\n");
		return(-1);
	}
	if ( numRead==0 ) break;
	if ( strncmp(fooBuffer, "quit", 4)==0 ) {
		printf("do_something exiting due to quit.\n");
		return(-1);
	}
  }
  return(0);
}

int read_data(s,buf,n)
int  s;                /* connected socket */
char *buf;             /* pointer to the buffer */
int  n;                /* number of characters (bytes) we want */
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
