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
/********************************************************************/
/*  Created by      :                                               */
/*                     Steven R. Sides                              */
/*                     steven.r.sides@cpmx.saic.com                 */
/*                     Sunday, July 23, 1995  02:50 PM              */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             sfp.c                                        */
/*                                                                  */
/* Description:                                                     */
/*    Parses the input command line for SCPS-FP commands from the   */
/*    user.  Executes them by searching the command table and       */
/*    calling the appropriate routine.                              */
/*                                                                  */
/*
 * $Id: sfp.c,v 1.16 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/sfp.c,v 1.16 2007/04/19 15:09:36 feighery Exp $
 * 
 *    Change History:
 * $Log: sfp.c,v $
 * Revision 1.16  2007/04/19 15:09:36  feighery
 * This version makes the gateway code (and only the gateway code) safe for
 * 64 bit architectures.  Before we were very sloppy and use a long and int
 * interchangeable.  As part of this change, it was required to make the
 * gateway code single threaded;  therefore gateway_single_thread=yes is the
 * default.  -- PDF
 *
 * Revision 1.15  2002/09/23 19:52:15  scps
 * Added the following pieces of code for this rev
 *
 * 1)  Rewrote the readme tun based on user feedback
 *
 * 2)  Added ability to disable the rule generation for gateway operating
 *
 * 3)  Added support for OpenBSD based on user feedback.
 *
 *         PDF
 *
 * Revision 1.14  2000/10/23 14:02:37  scps
 * Cleaned to the FP directory so it would compile cleanly  -- PDF
 *
 * Revision 1.13  1999/11/22 16:14:34  scps
 * Removed disclaimer comment blocks from revision logs.
 *
 * Revision 1.12  1999/11/22 15:52:45  scps
 * Changed FP discaimers --keith
 *
 *
 * Revision 1.11  1999/11/05 20:19:55  kscott
 * cal fflush after printing the prompt...
 *
 * Revision 1.10  1999/07/07 14:05:31  scps
 * Modified the FP files so the RATE and MTU command line parameters would
 * be set properly for both the control and the data connection. -- PDF
 *
 * Revision 1.9  1999/05/18 18:55:37  scps
 * Added command line options to the FP for users to be able to modify
 * the SCPS TP parameters.  --- PDF
 *
 * Revision 1.8  1999/03/23 20:24:37  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.7  1999/03/02 21:08:10  scps
 * Changed RI to compile under linux - PDF
 *
 * Revision 1.6.2.1  1998/12/29 14:27:35  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/29 13:51:45  scps
 * Monolithic update to 1.1.6
 *
 * Revision 1.6  1998/12/01 16:44:39  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.5  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.4  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 * 
 * Revision 1.3  1997/08/15 19:50:22  steven
 * Adding Proxy
 * 
 * Revision 1.2  1997/06/16 14:09:30  steven
 * Added sizes MEDIUM and LARGE.
 * 
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *
 ********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>    /* stat struct only */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/ftp.h>    /* contains symbolic constants only */
#include <arpa/telnet.h> /* for IAC, IP, and DM */
#include <arpa/inet.h>
#include <unistd.h>      /* for close(fd) (also works with sockfds) */
#include <limits.h>      /* for ULONG_MAX */
#include "edit.h"
#include "crc.h"
#include "libc.h"
#include "rx_avail.h"
#include "tpif.h"
#include "prtstat.h"

#define FP_BUFSIZ BUFSIZ

#define PROMPT "sfp> "
#define PRERR Lprerr(__FILE__, __LINE__)

#if ( !defined(__BSD__) && !defined(LINUX) )
typedef void sig_t;
#endif

/* #define PORT 2121 */

/* extern int tp-dontblock;     only works for tp-read() and tp-write() */
/* extern int socktimeout       0 if sockets should not timeout         */
#if defined(LARGE)
extern int proxflag;
#endif
extern char *builddate;
extern char *buildtime;
extern char *buildsize;         /* Implementation level */

#ifdef MSVC
extern int _fmode;
WORD wVersionRequested; 
WSADATA wsaData; 
#endif

extern int sortupdt(char *fn);
extern void debugclose(void);
extern void debuglog(char *fmt, ...);
extern int cmdquit(int argc, char *argv[]);
#ifdef SMALL
extern int cmdca_initialize();
#endif
#ifdef MEDIUM
extern void mibread(void);
extern int cmdca_initialize();
extern int cmdcb_initialize();
#endif
#ifdef LARGE
extern void mibread(void);
extern int cmdca_initialize();
extern int cmdcb_initialize();
extern int cmdcc_initialize();
extern int parsepasv(char *replystr);
#endif


#ifndef NOTTP
/* Running with TP, argc and argv need to be passed to
 * client app via globals.  */
int gargc;                  /* global argc */
char **gargv;               /* global argc */
#endif

int hash_size = 200;

struct cmd *cmdtaba = NULL;
struct cmd *cmdtabb = NULL;
struct cmd *cmdtabc = NULL;
struct cmd *cmdtabd = NULL;

char msgbuf[MBSIZE];
char reply_string[RSSIZE];
struct sockaddr_in hisctladdr;
char *hostname;                    /* name of host                    */
extern char *a_host ;               /* name of host                    */
int sctrl;                         /* control socket                  */
int sdata;                         /* data socket                     */
int connected = 0;                 /* non-zero if an FTP conn is open */
int code;                          /* reply code from server          */
int autorestart;                   /* autorestart mode flag           */
int numautor;                      /* number of times to attempt auto */
                                   /* restart                         */
int restart_point;                 /* byte in file to read/write next */
int quitting;                      /* ugly flag to tell getreply()    */
                                   /* that the program is terminating */
int bets;
int betsfill;
extern char autouser[];            /* for expansion later             */
extern char autopass[];
extern char autodir[];

int port;                          /* Port to talk on.                */
int verbose;
int proxy;
int hash;
short type;                        /* transfer type i.e. ASCII,       */
                                   /* BINARY, etc.                    */
short mode;
short struc;
char buf[BSIZE];                   /* data transfer buffer            */
int bufsize;
int abortop;                       /* Set true by the SIGINT routine. (^C)
                                    * Lets the user abort transfer
                                    * operations.  */
int interruptop;                   /* Set true by the SIGTSTP routine (^Z)
                                    * (or maybe ^Y) Lets the user interrupt
                                    * transfer operations.  */
int user_interrupted;    
int lastsize;                      /* If they don't specify a number in
                                    * the restart command, use this.   */
int get_string;                    /* True if getting a string from console.
                                    * this is used to issue a warning if
                                    * they hit Ctrl-C on the command line. */
int debug;                         /* Berkeley debug mode */
int ldebug;                        /* My debug mode low level. */
int flags;                         /* flags for spcs_send() and recv() */

char cmdline[CMDLNSIZE];           /* keyboard input */ 
int margc;                         /* used to pass arguments to cmd handler */ 
int uargc;  
char *margv[MAXARGS];              /* pointers to arguments */


/* lostpeer -
 *    I lost the peer.  Shutdown everything.
 */
sig_t lostpeer()
{
  if (sctrl >= 0) {
    scps_close(sctrl);
    sctrl = -1;
  }
  if (sdata >= 0) {
    scps_close(sdata);
    sdata = -1;
  }
  connected = 0;
} /* lostpeer() */


/* getcmd -
 *     Look up a command in the command tables.  Allow
 *     abbreviation.
 *
 *     Needs to be hooked into lookup_execute().
 */
struct cmd *getcmd(char *name)
{
  struct cmd *cmdpp[5];
  int l;
  char *p, *q;
  struct cmd *c, *found;
  int nmatches, longest;

  cmdpp[0] = cmdtaba;
  cmdpp[1] = cmdtabb;
  cmdpp[2] = cmdtabc;
  cmdpp[3] = cmdtabd;
  longest = 0;
  nmatches = 0;
  found = 0;
  for (l = 0; cmdpp[l]; l++)
    for (c = cmdpp[l]; (p = c->c_name); c++) {
      for (q = name; *q == *p++; q++)
        if (*q == 0)    /* exact match? */
          return (c);
      if (!*q) {      /* the name was a prefix */
        if (q - name > longest) {
          longest = q - name;
          nmatches = 1;
          found = c;
        } else if (q - name == longest)
          nmatches++;
      }
    }
  if (nmatches > 1)
    return ((struct cmd *)-1);
  return (found);
} /* getcmd() */


/* getreply -
 *    Get a reply from the server.
 *    On exit, user_int = 1 if user interrupted, 0 otherwise.
 *
 *    Socket (sctrl) is passed globally.
 */
int getreply(int expecteof, int *user_int)
{
   register int n;
   register int dig;
   register char *cp;
   char c;
   int done;
   int kill = 3;
   int originalcode = 0, continuation = 0;
   int count;

#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif
   *user_int = 0;
   debuglog("getreply()");
   for (;;) {
      dig = n = code = 0;
      cp = reply_string;
      done = 0;
      while (!done) {
         for (;;) {
           /* tp-dontblock = 1; */
           if (rcvdata_avail(sctrl)) {
             count = scps_recv(sctrl, &c, 1, flags);
             if (count || errno) {
               break;
             }
           }
           if (abortop) {
             if ((--kill) == 1)
               printf("One more to kill program.\n");
             if (kill == 0) {
               debugclose();
               exit(0);
             }
             abortop = 0;
             *user_int = 1;
             if (quitting) {
               debugclose();
               exit(0);
             }
             scps_send(sctrl, "ABOR\r\n", 6, flags);
             if (debug) {
               printf("---> ABOR\n");
             }
             debuglog("ABOR.1");
           }
           if (interruptop) {
             interruptop = 0;
             *user_int = 1;
             scps_send(sctrl, "INTR\r\n", 6, flags);
             if (debug) {
               printf("---> INTR\n");
             }
             debuglog("INTR.1");
           }
         } /* for */
         if (count && !(done = c == '\n')) {
#if defined(LARGE)
           if (proxflag && (dig == 0))
             printf("%s:",hostname);
#endif
           Lputchar(c);
         }
         dig++;
         if (count == 0) {
            if (expecteof) {
               code = 221;
               (void)Lfflush(stdout);
               return (0);
            }
            lostpeer();
            Lstrout("421 Service not available, "
                    "remote server has closed connection\n");
            (void) Lfflush(stdout);
            code = 421;
            return(4);
         } /* if (count == 0) */
         if (dig < 4 && Lisdigit(c))
            code = code * 10 + (c - '0');
         if (dig == 4 && c == '-') {
            if (continuation)
               code = 0;
            continuation++;
         }
         if (n == 0)
            n = c;
         if (cp < &reply_string[sizeof(reply_string) - 1])
            *cp++ = c;
      } /* while */
      (void) Lputchar(c);
#if defined(LARGE)
      if (227 == code)
        parsepasv(reply_string);
#endif
      if (debug) {
        debuglog(reply_string);
        /* lstrout(&c, 1); */
      }
      (void) Lfflush (stdout);
      if (continuation && code != originalcode) {
         if (originalcode == 0)
            originalcode = code;
         continue;
      } /* if */
      *cp = '\0';
      if (code == 421 || originalcode == 421)
         lostpeer();

#ifdef DO_TIMING
      (void) prtstat_gettime (&end_sec, &end_usec);
      (void) print_timestat("getreply","Socket","get reply",
                             start_sec, start_usec,
                             end_sec, end_usec, 0, 0);
#endif
      return (n - '0');
   } /* for */
} /* getreply() */


/* sendcommand -
 *    Issue an FTP command, and wait for the reply.
 *
 *    Return the hundreds digit of the reply code.
 */
int sendcommand(char *cmd)
{
  int ui;
  int result;
#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (debug)
    printf("---> %s\n", cmd);

  scps_send(sctrl, cmd, Lstrlen(cmd), flags);
  scps_send(sctrl, "\r\n", 2, flags);
 
#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat("sendcommand","Socket",cmd,
                           start_sec, start_usec,
                           end_sec, end_usec, 0, 0);
#endif

  result = getreply(0, &ui);
  if (ui)
    return (5);
  else
    return (result);
} /* sendcommand() */


/* hookup -
 *    Connects to the specified host and port.
 *    Returns the address of the hostname.
 */
char *hookup(char *host, int port)
{
   register struct hostent *hp = 0;
   static char hostnamebuf[80];
   int ret;
   int ui;
#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
#endif


   Lbzero((char *)&hisctladdr, sizeof (hisctladdr));
   hisctladdr.sin_addr.s_addr = Linet_addr(host);
   if (hisctladdr.sin_addr.s_addr != -1) {
      hisctladdr.sin_family = AF_INET;
      (void) Lstrncpy(hostnamebuf, host, sizeof(hostnamebuf));
   } else {
      hp = Lgethostbyname(host);
      if (hp == NULL) {
         printf("'%s': no such host\n", host);
         code = -1;
         return((char *) 0);
      }
      hisctladdr.sin_family = hp->h_addrtype;
      Lstrncpy((char *)&hisctladdr.sin_addr,
               hp->h_addr_list[0],
               hp->h_length);
      (void) Lstrncpy(hostnamebuf, (char *)hp->h_name, sizeof(hostnamebuf));
   }
   hostname = hostnamebuf;
   sctrl = scps_socket(hisctladdr.sin_family, SOCK_STREAM, 0);
   if (sctrl < 0) {
      Lperror("FP: socket");
      code = -1;
      return ((char *) 0);
   }
#ifndef NOTTP
  enable_options (sctrl);
#endif /* NOTTP */

#ifdef MSVC
   hisctladdr.sin_port = htons((u_short)port);
#else
   hisctladdr.sin_port = htons(port);
#endif

#ifdef DO_TIMING
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif
#if defined(SYSV) || defined(__BSD__) || defined(MSVC) || defined(LINUX)
   if (scps_connect(sctrl, (struct sockaddr *)&hisctladdr,
                     sizeof (hisctladdr)) < 0) {
#else
   if (scps_connect(sctrl, &hisctladdr,
                     sizeof (hisctladdr)) < 0) {
#endif
      nsprintf(msgbuf, sizeof(msgbuf),
        "Could not connect to %s.\n",
        hostname);
      Lstrout(msgbuf);
      goto bad;
   } /* no wookie */

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("hookup","Socket",
                          "connect",
                          start_sec, start_usec,
                          end_sec, end_usec, 0, 0);
#endif
   nsprintf(msgbuf, sizeof(msgbuf),
     "Connected to %s.\n", hostname);
   Lstrout(msgbuf);

   if ((ret = getreply(0, &ui)) > 2) {  /* read startup message from server */
      code = -1;
      goto bad;
   }
   return (hostname);

bad:
   (void) scps_close(sctrl);
   sctrl = -1;
   return ((char *)0);

} /* hookup() */


/* sig_abort -
 *     User selected ^C.  Received the SIGINT signal.
 *     Set the abort flag.
 */
void sig_abort(int sig)
{
  /*   
   *   debuglog("Ctrl-C (%d)", abortop);
   *   switch (abortop) {
   *     case 2:
   *       Lstrout("\n(Ctrl-C -- one more to kill program)\n");
   *       break;
   *
   *     case 1:
   *       debugclose();
   *       exit(1);
   *
   *     default:
   *       break;
   *   }
   *   abortop--;
   */
  debuglog("Ctrl-C");
  abortop = 1;
#ifdef LINUX
  signal(SIGINT, sig_abort);
#endif
} /* sig_abort() */


/* sig_intr -
 *     User selected ^Z.  Received the SIGTSTP.
 *     Set the interrupt flag.
 */
void sig_intr(int sig)
{
  debuglog("Ctrl-Z or Ctrl-Y");
  interruptop = 1;
#ifdef LINUX
  signal(SIGTSTP, sig_intr);
#endif
} /* sig_intr() */


/* nb_getc -
 *    Non-blocking getc().  (stdin is configured
 *    at startup to be non-blocking.)
 *    get one character from stdin.  If there
 *    was a character available, returns 1.  Otherwise
 *    return 0.  */
int nb_getc(chp)
  char *chp;
{
  int res;

  res = fread(chp, 1, 1, stdin);
  if ((res != 0) && (res != 1))
    /* could put some error return here */
    return 0;
  else
    return res;
} /* nb_getc() */


/* nb_gets -
 *    Non-blocking gets().
 */
char * nb_gets(char *str)
{
  int strp = 0;
  char throwaway;
  int nwrcnt;         /* network read count */
  int netcheck = 1;

  for (;;) {
    if (connected && netcheck) {
      if (rcvdata_avail(sctrl)) {
        nwrcnt = scps_recv(sctrl, &throwaway, 1, flags);
        if (nwrcnt) {
          printf("%c", throwaway);
        } else {
          /* select said "Data is available", but when I read
           * it there was nothing there.  That means the other
           * side closed the connection.     */
          if (errno)
            perror("control conn");
          netcheck = 0;
          connected = 0;
          scps_close(sctrl);
          sctrl = -1;
        } /* if read anything */
      }
    } /* if netcheck */
    
    if (abortop) {
      abortop = 0;
      cmdquit(0, NULL);
      exit(0);
    }

    strp += nb_getc(&(str[strp]));
    str[strp] = '\0';
    if ((strp != 0) && (str[strp-1] == '\n')) {
      str[strp-1] = '\0';
      return (NULL);
    } 
#ifdef NOTTP
#else
    sched();
#endif
  } /* for(;;) (while no <LF>) */
} /* nb_gets() */


/* makemargv -
 *    Take the command line stored in cmdline[] and create       
 *    margv, uargc, and margc.                                   
 *
 *    Please excuse the use of globals (margv, margc, etc.)
 *    This code is already debugged, and I'm kind of pressed
 *    for time.
 *
 *    returns margc.
 */
int makemargv(char *cmdline)
{
  char *cl;
  int onblank; 

  cl = cmdline; 
  onblank = 1;
  margc = 0; 
  /* make margc and margv */
  while (*cl) {
    if (onblank) {
      if (*cl != ' ') {
        margv[margc++] = cl; 
        if (margc == MAXARGS)
          break; 
        onblank = 0;
      } 
    } else { 
      if (*cl == ' ') {
        *cl = '\0'; 
        onblank = 1; 
      }
    }
    cl++;
  } /* while */
  return margc;
} /* makemargv() */


/* lookup_execute -
 *    Look up the command in the command table, and execute      
 *    it.                                                        
 *    Returns 1 if found and did something.
 *    Returns 0 if not found.
 *    Returns -1 if found and an error occurred in execution.
 */
int lookup_execute(int argc, char *argv[], struct cmd *cmdp)
{
  int found = 0;

  Lstrtolower(argv[0]);
  /* search for the command in the table */
  while (cmdp->c_name) {
    if (0 == Lstrcmp(cmdp->c_name, argv[0])) {
      /* OK.  I found it. */
      if (cmdp->c_conn && !connected) {
        Lstrout("Not connected\n");
        found = -1;
        break;
      }
      found = 1;
      if ((*cmdp->c_func)(argc, argv) < 0)
        found = -1;
      break;
    }
    cmdp++;
  }
  return found;
} /* lookup_execute() */


/* onoff -
 *
 */
char *onoff(int bool)
{
   return (bool ? "on" : "off");
} /* onoff() */


/* client_app -
 *    Performs client functions.
 *    - Reads line from keyboard.
 *    - Parses it.
 *    - Looks up the command, and executes it.
 */
void client_app(void)
{
  int lresult;
  struct cmd *cmdpp[5];
  int l;
#ifndef NOTTP
  /* Running over TP: */
  char *host;

  if (strlen (a_host)) {
    host = hookup(a_host, port);
    if (host) {
      connected = 1;
    }
  }

#ifdef XXX
  if (gargc > 2) {
    port = atoi(gargv[2]);
    if (port <= 0) {
      printf("%s: bad port number-- %s\n", gargv[1], gargv[2]);
      printf ("usage: %s host-name [port]\n", gargv[0]);
      code = -1;
      /* not good to just die, when running over TP, but
       * I can't think of anything else to do right now.  */
      exit(1);
    }
    port = htons(port);
  }
#endif XXX
#endif
  cmdpp[0] = cmdtaba;
  cmdpp[1] = cmdtabb;
  cmdpp[2] = cmdtabc;
  cmdpp[3] = cmdtabd;
  while (1) {
    printf(PROMPT); fflush(stdout);
    debuglog("Prompt: %s", PROMPT);
    nb_gets(cmdline);
    debuglog(cmdline);
    /* margv and margc are global */
    if (makemargv(cmdline)) {
      for (lresult = l = 0; lresult == 0 && cmdpp[l]; l++)
        lresult = lookup_execute(margc, margv, cmdpp[l]);
      if (lresult == 0) {
        Lstrout(margv[0]);
        Lstrout("?\n");
      }
    }
  }
} /* client_app() */


/* fp_initialize -
 *    Initialize all global variables, call init_socks().     
 */
void fp_initialize()
{
  cmdline[0] = '\0';
  sctrl = -1;
  sdata = -1;
  /* init_socks(); */
} /* fp_initialize() */


/*  conn_init -
 *     Initialize connection but don't step on things that
 *     have to do with proxy mode.
 */
void conn_init()
{
  abortop = 0;
  interruptop = 0;
  user_interrupted = 0;
  lastsize = -1;                   /* If they don't specify a number */
  get_string = 0;                  /* True if getting a string from console. */
  sctrl = -1;
  sdata = -1;
  connected = 0;
  code = -1;
  debug = 0;
  ldebug = 0;                      /* My low level debug mode. */
  flags = 0;                       /* flags for spcs_send() and recv() */
  autorestart = 0;
  numautor = 3;
  restart_point = 0;
  hash = 1;
  autouser[0] = '\0';
  autopass[0] = '\0';
  autodir[0] = '\0';
  verbose = 1;      
  /* tp-dontblock = 0; */
  type = TYPE_I;           /* Image.  BINARY, that is. */
  quitting = 0;            /* flag to terminate the program on Ctrl-C */
  /* socktimeout = 0;         don't time sockets out. */
  hash_size = 200;
  port = PORT;             /* set the default port */
#ifndef SMALL
  mibread();
#endif
} /* conn_init() */


/* client_initialize -
 *    Initialize everything to defaults.
 */
int client_initialize()
{
  conn_init();
  proxy = 0;
  fp_initialize();
  Linitialize();
  return (0);
} /* lient_initialize() */


/* main -
 *    Issues the sign-on message, initializes things, and 
 *    calls the client command processing routine.
 */
int main(int argc, char *argv[])
{
  char *host;
  int ires;

  ires = client_initialize();   /* Initializes lots of things including port */

#ifdef MSVC
  _fmode = _O_BINARY;
  if (ires) {
    printf("Could not initialize.  Problem with WINSOCK.DLL\n");
    exit(1);
  }
#endif

#ifdef NOTTP
  if (argc > 2) {
    port = atoi(argv[2]);
    if (port <= 0) {
      printf("%s: bad port number-- %s\n", argv[1], argv[2]);
      printf ("usage: %s host-name [port]\n", argv[0]);
      code = -1;
      exit(1);
    }
#ifdef MSVC
    port = htons((u_short)port);
#else
    port = htons(port);
#endif
  }
#endif

  printf("SCPS-FP Micro-Client [last modified: %s %s]\n", builddate, buildtime);
  printf("Implementation: %s\n", buildsize);
#ifdef NOTTP
  Lstrout("running over UNIX sockets\r\n");
#else
  Lstrout("running over SCPS-TP sockets\r\n");
#endif
  signal(SIGINT, sig_abort);
#ifndef MSVC
  signal(SIGTSTP, sig_intr);
  signal(SIGPIPE, SIG_IGN);
#endif

#ifndef NOTTP
parse_options (argc, argv);
#endif /* NOTTP */

#ifdef SMALL
  cmdca_initialize();
#else
#ifdef MEDIUM
  cmdca_initialize();
  cmdcb_initialize();
#else
#ifdef LARGE
  cmdca_initialize();
  cmdcb_initialize();
  cmdcc_initialize();
#else
#endif
#endif
#endif

#ifdef NOTTP

/*
  if (argc > 1) {
    host = hookup(argv[1], port);
    if (host) {
      connected = 1;
    }
  }
*/

  /* go be a client */
  client_app();
#ifdef MSVC
  WSACleanup();
#endif
  return (0);
#else

  gargc = argc;
  gargv = argv;
  /* Initialize SCPS thread structures */
  init_scheduler();
  scheduler.run_queue[0] = create_thread(tp);
  scheduler.run_queue[1] = create_thread(client_app);
  (void) scps_Init();
  start_threads();
  exit(0);

#endif
} /* main() */
