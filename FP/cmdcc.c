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
/*                     Tuesday, June 10, 1997 11:11 am              */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/*   This is unclassified Government software.
 *
 *   The SCPS File Protocol (SCPS-FP) software was developed under
 *   contract to the Jet Propulsion Laboratory, an operating division of
 *   the California Institute of Technology and is available for use by
 *   the public without need of a licence.
 *
 *   DISCLAIMER:
 *
 *   THE SCPS-FP SOFTWARE AND RELATED MATERIALS ARE PROVIDED "AS-IS"
 *   WITHOUT WARRANTY OR INDEMNITY OF ANY KIND INCLUDING ANY WARRANTIES
 *   OF USE, PEROFMRNACE, OR MERCHANTABILITY OR FITNESS FOR A PRTICULAR
 *   USE OR PURPOSE (as set forth in UCC section 2312-2313) OR FOR ANY
 *   PURPOSE WHATSOEVER.
 *
 *   USER BEARS ALL RISK RELATING TO USE, QUALITY, AND PERFORMANCE OF THE
 *   SOFTWARE.
 *
 *   The Jet Propulsion Laboratory, the California Institute of
 *   Technology, and the United States government retain a paid-up
 *   royalty free world wide license in this product.
 *
 *   SAIC Disclaimer:
 *     (1) SAIC assumes no legal responsibility for the source code and
 *         its subsequent use.
 *     (2) No warranty or representation is expressed or implied.
 *     (3) Portions (e.g. Washington University FTP Replacement Daemon)
 *         are copyright (c) Regents of the University of California.
 *         All rights reserved.  Restrictions included in said copyright
 *         are also applicable to this release.
 *
 */

/********************************************************************
 * Module:             cmdcc.c                                      *
 *                                                                  *
 * Description:                                                     *
 *    Client commands, set C.  These commands are used in the FTP   *
 *    RFC 1123 compatibility implementation.                        *
 *
 * $Id: cmdcc.c,v 1.11 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/cmdcc.c,v 1.11 2007/04/19 15:09:36 feighery Exp $
 * 
 * Change History:
 * $Log: cmdcc.c,v $
 * Revision 1.11  2007/04/19 15:09:36  feighery
 * This version makes the gateway code (and only the gateway code) safe for
 * 64 bit architectures.  Before we were very sloppy and use a long and int
 * interchangeable.  As part of this change, it was required to make the
 * gateway code single threaded;  therefore gateway_single_thread=yes is the
 * default.  -- PDF
 *
 * Revision 1.10  2002/09/23 19:52:14  scps
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
 * Revision 1.9  2000/10/23 14:02:36  scps
 * Cleaned to the FP directory so it would compile cleanly  -- PDF
 *
 * Revision 1.8  1999/11/22 15:52:41  scps
 * Changed FP discaimers to read as follows:
 *
 * ---------------------------------------------
 *
 * 		--keith
 *
 * Revision 1.7  1999/03/23 20:24:34  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.6.2.1  1998/12/29 14:27:28  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:36  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.3  1997/09/18 17:57:16  steven
 * Red-3 except files of CCSDS packets.
 *
 * Revision 1.2  1997/08/21 16:33:26  steven
 * Changed copyright notice.
 *
 * Revision 1.1  1997/06/16 14:09:30  steven
 * Initial revision
 * 
 */

static char rcsid[] = "$Id: cmdcc.c,v 1.11 2007/04/19 15:09:36 feighery Exp $";

#include "libc.h"
#include <string.h>
#include <signal.h>
#include <arpa/ftp.h>
#include <netinet/in.h>    /* For struct sockaddr_in */
#include <unistd.h>
#include "tpif.h"

#define PRIMARY 0
#define PROXY   1

#ifndef __BSD__
typedef void sig_t;
#endif

extern sig_t lostpeer();
extern int quitting;
extern int proxy;
extern int connected;
extern int verbose;
extern int debug;
extern int type;
extern int code;
extern int flags;
extern char *hostname;
extern struct sockaddr_in hisctladdr;
extern struct cmd *cmdtabc;
extern char *onoff(int bool);
extern int another(int *pargc, char ***pargv, char *prompt);
extern void debuglog (char *fmt, ...);

int sendcommand(char *);
struct cmd *getcmd(char *);
void pswitch(int flag);
int getreply(int expecteof, int *user_int);


int abrtflag;
int proxflag;
int ptflag;
int ptabflg;
int nothing;

struct sockaddr_in myctladdr;
int curtype;
int cpend;
int sunique;
int runique;
int mcase;
char pasv[64];
int passivemode;
int options;

extern struct  types {
  char  *t_name;
  char  *t_mode;
  int t_type;
  char  *t_arg;
} types[];

/* telnet things */
#define	IAC	255		/* interpret as command: */
#define	IP	244		/* interrupt process--permanently */
#define	DM	242		/* data mark--for connect. cleaning */

/*
 *  Translation table stuff.
 * int ntflag;
 * char *ntin;
 * char *ntout;
 * 
 *  Filename mapping stuff.
 * int mapflag;
 * char *mapin;
 * char *mapout;
 */
/* int abortprox; */


/*  parsepasv -
 *     Parse the PASV reply string.
 *     Converts from whatever form is there to
 *     "ddd,ddd,ddd,ddd,ddd,ddd"
 *     Returns 1 on error, 0 on no error.
 */
int parsepasv(char *replystr)
{
#define TOKENS "EnterigPasvMod:-\t\r\n ()"
  char *addr;

  addr = strtok(replystr, TOKENS);
  addr = strtok(NULL, TOKENS);
  strcpy(pasv, addr);
  return 0;
} /* parsepasv() */


/*  changetype -
 *     
 */
void changetype(int newtype, int show)
{
  struct types *p;
  int oldverbose = verbose;
  char msgbuf[80];

  if (newtype == 0)
    newtype = TYPE_I;
  if (newtype == curtype)
    return;
  if (debug == 0 && show == 0)
    verbose = 0;
  for (p = types; p->t_name; p++)
    if (newtype == p->t_type)
      break;
  if (p->t_name == 0) {
    printf("ftp: internal error: unknown type %d\n", newtype);
    return;
  }
  sprintf(msgbuf, "TYPE %s", p->t_mode);
  if (sendcommand(msgbuf) == COMPLETE)
    curtype = newtype;
  verbose = oldverbose;
} /* changetype() */


/*  warn -
 *     Issue a warning to stderr.
 */
void warn(char *str)
{
  fwrite(str, 1, strlen(str), stderr);
  fwrite("\n", 1, 1, stderr);
  fflush(stderr);
} /* warn() */


/*  empty -
 *     
 */
int
empty(struct fd_set *mask, int sec)
{
	struct timeval t;

	t.tv_sec = (int32_t) sec;
	t.tv_usec = 0;
	return (select(32, mask, (struct fd_set *) 0, (struct fd_set *) 0, &t));
} /* empty() */


/*  abort_remote -
 *     Issue the ABOR command.
 */
void abort_remote(FILE *din)
{
	char buf[BUFSIZ];
	int nfnd;
	struct fd_set mask;

	/*
	 * send IAC in urgent mode instead of DM because 4.3BSD places oob mark
	 * after urgent byte rather than before as is protocol now
	 */
	sprintf(buf, "%c%c%c", IAC, IP, IAC);
  scps_send(sctrl, buf, 3, flags);
  sprintf(buf, "%cABOR\r\n", DM);
  scps_send(sctrl, buf, strlen(buf), flags);
	FD_ZERO(&mask);
	FD_SET(sctrl, &mask);
	if (sdata != -1) {
		FD_SET(sdata, &mask);
	}
	if ((nfnd = empty(&mask, 10)) <= 0) {
		if (nfnd < 0) {
			warn("abort");
		}
		if (ptabflg)
			code = -1;
		lostpeer();
	}
	if (din && FD_ISSET(fileno(din), &mask)) {
		while (scps_recv(fileno(din), buf, BUFSIZ, flags) > 0)
			/* LOOP */;
	}
	if (getreply(0, &nothing) == ERROR && code == 552) {
		/* 552 needed for nic style abort */
		(void) getreply(0, &nothing);
	}
	(void) getreply(0, &nothing);
} /* abort_remote() */


/*  proxtrans -
 *     Perform a proxy transfer.
 */
void proxtrans(char *cmd, char *local, char *remote)
{
  /*  void (*oldintr)(int); */
  int secndflag = 0, prox_type, nfnd;
  char *cmd2;
  struct fd_set mask;
  char msgbuf[80];

  if (strcmp(cmd, "retr"))
    cmd2 = "retr";
  else
    cmd2 = sunique ? "stou" : "stor";
  if ((prox_type = type) == 0)
      prox_type = TYPE_I;
  if (curtype != prox_type)
    changetype(prox_type, 1);
  if (sendcommand("PASV") != COMPLETE) {
    printf("proxy server does not support third party transfers.\n");
    return;
  }
  pswitch(PRIMARY);
  if (!connected) {
    printf("No primary connection\n");
    pswitch(PROXY);
    code = -1;
    return;
  }
  if (curtype != prox_type)
    changetype(prox_type, 1);
  sprintf(msgbuf, "PORT %s", pasv);
  if (sendcommand(msgbuf) != COMPLETE) {
    pswitch(PROXY);
    return;
  }
  /*
   *if (setjmp(ptabort))
   *  goto abort;
   * oldintr = signal(SIGINT, abortpt);
   */
  sprintf(msgbuf, "%s %s", cmd, remote);
  if (sendcommand(msgbuf) != PRELIM) {
    /* (void) signal(SIGINT, oldintr); */
    pswitch(PROXY);
    return;
  }
  sleep(2);
  pswitch(PROXY);
  secndflag++;
  sprintf(msgbuf, "%s %s", cmd2, local);
  if (sendcommand(msgbuf) != PRELIM)
    goto abort;
  ptflag++;
  (void) getreply(0, &nothing);
  pswitch(PRIMARY);
  (void) getreply(0, &nothing);
  /* (void) signal(SIGINT, oldintr); */
  
  pswitch(PROXY);
  ptflag = 0;
  printf("local: %s remote: %s\n", local, remote);
  return;
abort:
  (void) signal(SIGINT, SIG_IGN);
  ptflag = 0;
  if (strcmp(cmd, "retr") && !proxy)
    pswitch(PROXY);
  else if (!strcmp(cmd, "retr") && proxy)
    pswitch(PRIMARY);
  if (!cpend && !secndflag) {  /* only here if cmd = "STOR" (proxy=1) */
    sprintf(msgbuf, "%s %s", cmd2, local);
    if (sendcommand(msgbuf) != PRELIM) {
      pswitch(PRIMARY);
      if (cpend)
        abort_remote((FILE *) NULL);
    }
    pswitch(PROXY);
    if (ptabflg)
      code = -1;
    /* (void) signal(SIGINT, oldintr); */
    
    return;
  }
  if (cpend)
    abort_remote((FILE *) NULL);
  pswitch(!proxy);
  if (!cpend && !secndflag) {  /* only if cmd = "retr" (proxy=1) */
    sprintf(msgbuf, "%s %s", cmd2, local);
    if (sendcommand(msgbuf) != PRELIM) {
      pswitch(PRIMARY);
      if (cpend)
        abort_remote((FILE *) NULL);
      pswitch(PROXY);
      if (ptabflg)
        code = -1;
      /* (void) signal(SIGINT, oldintr); */
      
      return;
    }
  }
  if (cpend)
    abort_remote((FILE *) NULL);
  pswitch(!proxy);
  if (cpend) {
    FD_ZERO(&mask);
    FD_SET(sctrl, &mask);
    if ((nfnd = empty(&mask, 10)) <= 0) {
      if (nfnd < 0) {
        warn("abort");
      }
      if (ptabflg)
        code = -1;
      lostpeer();
    }
    (void) getreply(0, &nothing);
    (void) getreply(0, &nothing);
  }
  if (proxy)
    pswitch(PRIMARY);
  pswitch(PROXY);
  if (ptabflg)
    code = -1;
  /* (void) signal(SIGINT, oldintr); */
  
} /* proxtrans() */

  
  /* proxabort -
 *     
 */
void proxabort(int sig)
{
  if (sig == SIGSEGV)
    abort();
  else
    exit(1);
} /* proxabort() */


/* cmdappend -
 *     
 */
int cmdappend(int argc, char *argv[])
{
  return 0;
} /* cmdappend() */


/* cmdrhelp -
 *     
 */
int cmdrhelp(int argc, char *argv[])
{
  return (COMPLETE == sendcommand("HELP") ? 0 : -1);
} /* cmdrhelp() */


/* cmdmode -
 *     Set the file transfer mode
 */
int cmdmode(int argc, char *argv[])
{
  extern char modehelp[];

  if (argc == 1) {
    printf("mode = stream\n");
    return (0);
  }
  if (argc == 2) {

    Lstrtolower(argv[1]);
    if (0 == Lstrcmp("stream", argv[1])) {
      char msgbuf[40];

      nsprintf(msgbuf, sizeof(msgbuf), "MODE %d", MODE_S);
      return (COMPLETE == sendcommand(msgbuf) ? 0 : -1);
    } else
      printf("We only support stream mode.\n");
  } else {
    printf("%s?\n", argv[0]);
    printf("mode help: %s\n", modehelp);
  }
  return (0);
} /* cmdmode() */


/* setstruct -
 *     
 */
int cmdstruct(int argc, char *argv[])
{
  extern char structhelp[];

  if (argc == 1) {
    printf("struct = stream\n");
    return (0);
  }
  if (argc == 2) {

    Lstrtolower(argv[1]);
    if (0 == Lstrcmp("file", argv[1])) {
      char msgbuf[40];

      nsprintf(msgbuf, sizeof(msgbuf), "STRU %d", STRU_F);
      return (COMPLETE == sendcommand(msgbuf) ? 0 : -1);
    } else
      printf("We only support file structure.\n");
  } else {
    printf("%s?\n", argv[0]);
    printf("struct help: %s\n", structhelp);
  }
  return (0);
} /* setstruct() */


/* cmdpassive -
 *     
 */
int cmdpassive(int argc, char *argv[])
{
  passivemode = !passivemode;
  printf("Passive mode %s.\n", onoff(passivemode));
  code = passivemode;
  return 0;
} /* cmdpassive() */


void
psabort()
{
  abrtflag++;
}


/* pswitch -
 *     Proxy switch--switch to the other server.
 *
 *     flag = 1: switch to proxy connection
 *     flag = 0: switch to primary connection
 */
void pswitch(int flag)
{
  void (*oldintr)(int);
  static struct comvars {
    int connect;
    char name[MAXPATHLEN];
    struct sockaddr_in mctl;
    struct sockaddr_in hctl;
    int csock;
    int tpe;
    int curtpe;
    int cpnd;
    int sunqe;
    int runqe;
    int mcse;
    int ntflg;
    int bts;                /* BETS */
    int ars;                /* Autorestart */
    char nti[17];
    char nto[17];
    int mapflg;
    char mi[MAXPATHLEN];
    char mo[MAXPATHLEN];
  } proxstruct, tmpstruct;
  struct comvars *ip, *op;

  abrtflag = 0;
  oldintr = signal(SIGINT, psabort);
  if (flag) {
    if (proxy)
      return;
    ip = &tmpstruct;
    op = &proxstruct;
    proxy++;
  } else {
    if (!proxy)
      return;
    ip = &proxstruct;
    op = &tmpstruct;
    proxy = 0;
  }
  ip->connect = connected;
  connected = op->connect;
  if (hostname) {
    (void) strncpy(ip->name, hostname, sizeof(ip->name) - 1);
    ip->name[strlen(ip->name)] = '\0';
  } else
    ip->name[0] = 0;
  hostname = op->name;
  ip->hctl = hisctladdr;
  hisctladdr = op->hctl;
  ip->mctl = myctladdr;
  myctladdr = op->mctl;
  ip->csock = sctrl;
  sctrl = op->csock;
  ip->tpe = type;
  type = op->tpe;
  ip->curtpe = curtype;
  curtype = op->curtpe;
  ip->cpnd = cpend;
  cpend = op->cpnd;
  ip->sunqe = sunique;
  sunique = op->sunqe;
  ip->runqe = runique;
  runique = op->runqe;
  ip->mcse = mcase;
  mcase = op->mcse;
  /*
   * Translation table stuff.
   *
   * ip->ntflg = ntflag;
   * ntflag = op->ntflg;
   * (void) strncpy(ip->nti, ntin, 16);
   * (ip->nti)[strlen(ip->nti)] = '\0';
   * (void) strcpy(ntin, op->nti);
   * (void) strncpy(ip->nto, ntout, 16);
   * (ip->nto)[strlen(ip->nto)] = '\0';
   * (void) strcpy(ntout, op->nto);
   *
   * Filename mapping stuff. 
   * ip->mapflg = mapflag;
   * mapflag = op->mapflg;
   * (void) strncpy(ip->mi, mapin, MAXPATHLEN - 1);
   * (ip->mi)[strlen(ip->mi)] = '\0';
   * (void) strcpy(mapin, op->mi);
   * (void) strncpy(ip->mo, mapout, MAXPATHLEN - 1);
   * (ip->mo)[strlen(ip->mo)] = '\0';
   * (void) strcpy(mapout, op->mo);
   */
  (void) signal(SIGINT, oldintr);
  if (abrtflag) {
    abrtflag = 0;
    (*oldintr)(SIGINT);
  }
} /* pswitch() */


/* cmdproxy -
 *     
 */
int cmdproxy(int argc, char *argv[])
{
  struct cmd *c;

  if (argc < 2 && !another(&argc, &argv, "command")) {
    printf("usage: %s command\n", argv[0]);
    code = -1;
    return 0;
  }
  c = getcmd(argv[1]);
  if (c == (struct cmd *) -1) {
    printf("?Ambiguous command\n");
    (void) fflush(stdout);
    code = -1;
    return 0;
  }
  if (c == 0) {
    printf("?Invalid command\n");
    (void) fflush(stdout);
    code = -1;
    return 0;
  }
  if (!c->c_proxy) {
    printf("?Invalid proxy command\n");
    (void) fflush(stdout);
    code = -1;
    return 0;
  }
  /*if (setjmp(abortprox)) {
   *  code = -1;
   *  return 0;
   *}
   * oldintr = signal(SIGINT, proxabort);
   */
  pswitch(PROXY);
  if (c->c_conn && !connected) {
    printf("Not connected\n");
    (void) fflush(stdout);
    pswitch(PRIMARY);
    /* (void) signal(SIGINT, oldintr); */
    code = -1;
    return 0;
  }
  (*c->c_func)(argc-1, argv+1);
  if (connected)
    proxflag = 1;                  /* Display the hostname before each reply       */
  else
    proxflag = 0;                  /* Don't display the hostname before each reply */
  pswitch(PRIMARY);
  /* (void) signal(SIGINT, oldintr); */
  return 0;
} /* cmdproxy() */


/* cmdquit -
 *    Quit
 *    Also quit the proxy connection if there is one.
 *    Never returns
 */
int cmdquit(int argc, char *argv[])
{
  int downin = 15;
#ifndef NOTTP
  char msg[80];
#endif
  int result;
#ifdef DO_TIMING
    int32_t end_sec, end_usec;
    int32_t start_sec, start_usec;
#endif

  if (argc == 2) {
    result = Latoi(argv[1]);
    if (result < 3 || result > 900) {
      printf("Invalid downin: %d.  Set to %d\n", result, downin);
    } else {
      downin = result;
    }
  }
  if (connected) {
    quitting = 1;
    result = sendcommand("QUIT");
    debuglog("%d <- QUIT", result);
  }
#ifdef DO_TIMING
    (void) prtstat_gettime (&start_sec, &start_usec);
#endif

#ifndef NOTTP
  /* scps_shutdownall(); */
  nsprintf(msg, sizeof(msg), "Terminating in %d seconds.\n", downin);
  Lstrout(msg);
#endif

#ifdef DO_TIMING
    (void) prtstat_gettime (&end_sec, &end_usec);
    (void) print_timestat("cmdquit","User_cmd", "quit",
                           start_sec,start_usec,
                           end_sec,end_usec, 0, 0);
#endif

  /* scps_sleep(downin); */
  Lexit(0);

#ifdef MSVC
  /*  I don't like to see warnings.  */
  return (0);
#endif
  return 0;
} /* cmdquit() */


int cmdsunique(int argc, char *argv[])
{
  sunique = !sunique;
  printf("Store unique %s.\n", onoff(sunique));
  code = sunique;
  return (0);
}


int cmdrunique(int argc, char *argv[])
{

  runique = !runique;
  printf("Receive unique %s.\n", onoff(runique));
  code = runique;
  return (0);
}


char appendhelp[]  = "append to a file";
char remotehelp[]  = "get help from remote server";
char modehelp[]    = "set the file transfer mode: 'mode stream'";
char structhelp[]  = "set the file transfer structure: 'struct file'";
char passivehelp[] = "enter passive transfer mode";
char proxyhelp[]   = "issue command on alternate connection";
char suniquehelp[] = "toggle store unique on remote machine";
char runiquehelp[] = "toggle store unique for local files";

/*  c_name, c_help, c_conn, c_proxy, c_func */
static struct cmd ccmdtab[] = {
  { "rhelp",   remotehelp,  1, 0, cmdrhelp   },
  { "append",  appendhelp,  1, 1, cmdappend  },
  { "mode",    modehelp,    1, 1, cmdmode    },
  { "struct",  structhelp,  1, 1, cmdstruct  },
  { "passive", passivehelp, 0, 0, cmdpassive },
  { "proxy",   proxyhelp,   0, 1, cmdproxy   },
  { "sunique", suniquehelp, 0, 1, cmdsunique },
  { "runique", runiquehelp, 0, 1, cmdrunique },
  { 0 }
};

/* cmdcc_initialize -
 */
void cmdcc_initialize(void)
{
  cmdtabc = ccmdtab;
} /* cmdcc_initialize() */


