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
/*                     Wednesday, June 26, 1996 1:01 pm             */
/*                                                                  */
/*  Modified by     :                                               */
/*                                                                  */
/********************************************************************/
/********************************************************************/
/* Module:             cmdca.c                                      */
/*                                                                  */
/* Description:                                                     */
/*    Client commands, set A.  These commands are used in the base  */
/*    implementation.                                               */
/*
 * $Id: cmdca.c,v 1.16 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/cmdca.c,v 1.16 2007/04/19 15:09:36 feighery Exp $
 * $Id: cmdca.c,v 1.16 2007/04/19 15:09:36 feighery Exp $
 * $Header: /home/cvsroot/SCPS_RI/FP/cmdca.c,v 1.16 2007/04/19 15:09:36 feighery Exp $
 *
 *    Change History:
 * $Log: cmdca.c,v $
 * Revision 1.16  2007/04/19 15:09:36  feighery
 * This version makes the gateway code (and only the gateway code) safe for
 * 64 bit architectures.  Before we were very sloppy and use a long and int
 * interchangeable.  As part of this change, it was required to make the
 * gateway code single threaded;  therefore gateway_single_thread=yes is the
 * default.  -- PDF
 *
 * Revision 1.15  2002/09/23 19:52:14  scps
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
 * Revision 1.14  2000/10/23 14:02:36  scps
 * Cleaned to the FP directory so it would compile cleanly  -- PDF
 *
 * Revision 1.13  1999/11/22 16:14:32  scps
 * Removed disclaimer comment blocks from revision logs.
 *
 * Revision 1.12  1999/11/22 15:52:41  scps
 * Changed FP discaimers 
 *
 * Revision 1.11  1999/07/07 14:05:31  scps
 * Modified the FP files so the RATE and MTU command line parameters would
 * be set properly for both the control and the data connection. -- PDF
 *
 * Revision 1.10  1999/05/18 18:55:36  scps
 * Added command line options to the FP for users to be able to modify
 * the SCPS TP parameters.  --- PDF
 *
 * Revision 1.9  1999/03/23 20:24:33  scps
 * Merged reference implementation with gateway-1-1-6-k branch.
 *
 * Revision 1.8  1999/03/05 21:03:16  scps
 * Removed the outdated tp_RTTSLOP stuff, it was being used as rttvar, and
 * was always 0...
 * Revision 1.6.2.3  1999/01/22 19:37:48  scps
 * Changes the persist timer to exponentially backoff from 5 to 60 as per
 * the spec.  -  PDF
 *
 * Revision 1.6.2.2  1999/01/22 15:02:29  scps
 * There was a problem with the FP in CVS I had to perform a update and a new
 * commit. -- PDF
 *
 * Removed a lot of "-1" from RTO calculations, they seemed inappropriate.
 *
 * Added initial_RTO and initial variance to route structure.
 *
 * Added more RTOMAX clamps.
 *
 * lots of changes to the debug structure...
 *
 * FP mods:
 *         Updated cmdca.c to print the _CORRECT_ transfer time.
 *
 * Revision 1.7  1999/03/02 19:49:44  scps
 * Ruhai testing fixes to run under linux.
 *
 * Revision 1.6.2.1  1998/12/29 14:27:27  scps
 * Monolithic update to include gateway code.
 *
 * Revision 1.6  1998/12/01 16:44:35  scps
 * Update to version 1.1.6 --ks
 *
 * Revision 1.5.1.2  1997/11/25 01:35:05  steven
 * Call sleep() before quitting.  Split debug into debug and ldebug
 *
 * Revision 1.5.1.1  1997/11/20 17:36:33  steven
 * removed references to MSVC40
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
 * Added size LARGE.
 *
 * Revision 1.1  1997/02/28 21:25:57  steven
 * Initial revision
 *                                                                  */
/********************************************************************/

#ifdef MSVC
#include <winsock.h>
#undef ERROR
#include "ftp.h"
#else
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>         /* for struct timeval */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/ftp.h>         /* contains symbolic constants only */
#include <arpa/telnet.h>      /* for IAC, IP, and DM */
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <limits.h>           /* for ULONG_MAX */
#include <string.h>
#include <sys/stat.h>         /* stat struct only */
#include <errno.h>
#include "tpif.h"
#include "libc.h"             /* FP client library prototypes */

#ifdef LARGE
extern int sunique;
#endif

/* Reserved filename for record operations. */
#define RESERVEDNAME "roSCPSFP"

int sendcommand(char *cmd);
int getreply(int expecteof, int *user_int);
void debuglog (char *fmt, ...);
int asciicopyfmfs (FILE *infile, int outs, u_long *bytecount);

int crc(FILE *fd, u_long *cval, u_long *clen);
void crcblock(char *buf, u_long len, u_long *iocrc);
char * nb_gets(char *str);
char *onoff(int bool);
int cmdhash(int argc, char *argv[]);
char *hookup(char *host, int port);
int sortupdt(char *filename);
int edit(char *ofile, char *nfile, char *dfile);


extern struct cmd *cmdtaba;
extern struct cmd *cmdtabb;
extern struct cmd *cmdtabc;
extern struct cmd *cmdtabd;

extern int port;                   /* port to talk on.                 */
extern int sdata;                  /* data socket                      */
extern int restart_point;          /* byte in file to read/write next  */
extern int connected;              /* non-zero if an FTP conn is open  */
extern int flags;                  /* passed to scps_send() and recv() */
extern int verbose;                /* flag for verbose output */
extern int code;                   /* reply code from server           */
extern int autorestart;            /* autorestart mode flag            */
extern int numautor;               /* number of times to attempt auto  */
                                   /* restart                          */
extern short type;                 /* transfer type i.e. ASCII,        */
                                   /* BINARY, etc.                     */
extern int abortop;                /* Set true by the SIGINT routine. (^C)
                                    * Lets the user abort transfer
                                    * operations.                      */
extern int interruptop;            /* Set true by the SIGTSTP routine (^Z)
                                    * (or maybe ^Y) Lets the user interrupt
                                    * transfer operations.             */
/* extern int user_interrupted; */
extern int debug;                  /* Berkeley debug mode */
extern int ldebug;                 /* My debug mode low level. */
extern int proxy;
extern int hash_size;
extern int hash;                   /* non-zero for hash mark printing */
extern int lastsize;               /* If they don't specify a number in
                                    * the restart command, use this.   */
extern int quitting;               /* ugly flag to tell getreply()    */
                                   /* that the program is terminating */
extern char *autouser;
extern char *autopass;
extern char *autodir;

extern char msgbuf[MBSIZE];
extern char reply_string[RSSIZE];
extern char buf[BSIZE];            /* data transfer buffer            */
extern struct sockaddr_in hisctladdr;

#if !defined(NOTTP)
extern int bets;
#endif

int srp(FILE *outf, u_long requested_rp, u_long *new_offset);
int frp(FILE *inf, u_long *restart_point);

#ifndef EPIPE
#define EPIPE           32              /* Broken pipe */
#endif
#define PRERR Lprerr(__FILE__, __LINE__)

struct sockaddr_in data_addr;
#if defined(LARGE)
extern int passivemode;
extern int options;
extern char pasv[64];
#endif

struct  types {
  char  *t_name;
  char  *t_mode;
  int t_type;
  char  *t_arg;
} types[] = {
  { "ascii",  "A",  TYPE_A, 0 },
  { "binary", "I",  TYPE_I, 0 },
  { "image",  "I",  TYPE_I, 0 },
  { "ebcdic", "E",  TYPE_E, 0 },
  { NULL }
};


/* ptransfer -
 *    Print transfer statistics.
 */
int ptransfer(char *direction,
              int32_t bytes,
              int32_t filesize,
              struct timeval *t0,
              struct timeval *t1)
{
  struct timeval tdiff;

  if (verbose == 0)
    return (0);
  if ((type == TYPE_A) && filesize) {
    nsprintf(msgbuf, sizeof(msgbuf), "ASCII mode: %d bytes %s (size: %d)\n", bytes, direction, filesize);
    Lstrout (msgbuf);
    tdiff.tv_sec = t1->tv_sec - t0->tv_sec; 
    tdiff.tv_usec = t1->tv_usec - t0->tv_usec;
    if (tdiff.tv_usec < 0)
      tdiff.tv_sec--, tdiff.tv_usec += 1000000;
 
    nsprintf (msgbuf, sizeof (msgbuf), "It took %d.%d seconds\n",
                tdiff.tv_sec, tdiff.tv_usec);
    Lstrout(msgbuf);
  } else {
    nsprintf(msgbuf, sizeof(msgbuf), "%d bytes %s\n", bytes, direction);
    Lstrout(msgbuf);
  tdiff.tv_sec = t1->tv_sec - t0->tv_sec;
  tdiff.tv_usec = t1->tv_usec - t0->tv_usec;
  if (tdiff.tv_usec < 0)
    tdiff.tv_sec--, tdiff.tv_usec += 1000000;

    sprintf (msgbuf, "It took %d.%06d seconds\n",  tdiff.tv_sec, tdiff.tv_usec);
    /*nsprintf(msgbuf, sizeof(msgbuf), "It took %d.%06d seconds\n", tdiff.tv_sec, tdiff.tv_usec); */
    Lstrout(msgbuf);
  }
  return 0;
} /* ptransfer() */


#if defined(SMALL) || defined(MEDIUM)
/* proxtrans -
 *    dummy
 */
int proxtrans(char *cmd, char *local, char *remote)
{
  return (0);
} /* proxtrans() */
#else
int proxtrans(char *cmd, char *local, char *remote);
#endif


/* initconn -
 *    Get set to accept a data connection.
 *    Issue the PORT command.
 *
 *    Returns 0 on success, and 1 on failure.
 */
int initconn()
{
#ifdef __BSD__
#define IPTOS_THROUGHPUT 1
#endif
  int one = 1;
  char msgbuf[80];
  register char *p, *a;

#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
#endif

#if defined(LARGE)
 	u_long a1,a2,a3,a4,p1,p2;

  if (passivemode) {
    sdata = socket(AF_INET, SOCK_STREAM, 0);
    if (sdata < 0) {
      perror("ftp: socket");
      return(1);
    }
    if (options & SO_DEBUG &&
        setsockopt(sdata, SOL_SOCKET, SO_DEBUG, (char *)&one,
             sizeof (one)) < 0)
      perror("ftp: setsockopt (ignored)");
    if (sendcommand("PASV") != COMPLETE) {
      printf("Passive mode refused.\n");
      return(1);
    }

    /*
     * What we've got at this point is a string of comma separated
     * one-byte unsigned integer values, separated by commas.
     * The first four are the an IP address. The fifth is the MSB
     * of the port number, the sixth is the LSB. From that we'll
     * prepare a sockaddr_in.
     */

    if (sscanf(pasv,"%d,%d,%d,%d,%d,%d",&a1,&a2,&a3,&a4,&p1,&p2) != 6) {
      printf("Passive mode address scan failure. Shouldn't happen!\n");
      return(1);
    };

    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = htonl((a1 << 24) | (a2 << 16) |
              (a3 << 8) | a4);
    data_addr.sin_port = htons((p1 << 8) | p2);

    if (connect(sdata, (struct sockaddr *) &data_addr,
        sizeof(data_addr))<0) {
      perror("ftp: connect");
      return(1);
    }
#ifdef IP_TOS
    one = IPTOS_THROUGHPUT;
    if (setsockopt(sdata, IPPROTO_IP, IP_TOS, (char *)&one,
        sizeof(one)) < 0)
      perror("ftp: setsockopt TOS (ignored)");
#endif
    return(0);
  }
#endif

  Lgetaddrnport(&data_addr);
  if (sdata != -1) {
    (void) scps_close(sdata);
    sdata = -1;
  }

#ifdef DO_TIMING
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif
  sdata = scps_socket(AF_INET, SOCK_STREAM, 0);
  if (sdata < 0) {
    Lperror("FP: socket");
    return (1);
  }
#ifndef NOTTP
  enable_options (sdata);
#endif /* NOTTP */

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("initconn","Socket",
                          "socket",
                          start_sec, start_usec,
                          end_sec, end_usec, 0, 0);
#endif

#ifdef DO_TIMING
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

#if !defined(NOTTP)
  /* BETS is TP specific. */
  if (bets)
    scps_setsockopt(sdata, PROTO_SCPSTP, SCPSTP_BETS, &one, sizeof(one));
#endif
  setsockopt(sdata, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
  if (scps_bind(sdata, (struct sockaddr *)&data_addr, sizeof (data_addr)) < 0) {
    Lperror("FP: bind");
    goto bad;
  }

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("initconn","Socket",
                          "bind",
                          start_sec, start_usec,
                          end_sec, end_usec, 0, 0);
#endif

#ifdef DO_TIMING
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (scps_listen(sdata, 1) < 0)
    Lperror("FP: listen");

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("initconn","Socket",
                          "listen",
                          start_sec, start_usec,
                          end_sec, end_usec, 0, 0);
#endif

  /*  scps_setto(sdata, 60);   set timeout */

  a = (char *)&data_addr.sin_addr;
  p = (char *)&data_addr.sin_port;
#define  UC(b) (((int)b)&0xff)
  nsprintf(msgbuf, sizeof(msgbuf),
           "PORT %d,%d,%d,%d,%d,%d",
            UC(a[0]), UC(a[1]), UC(a[2]), UC(a[3]),
            UC(p[0]), UC(p[1]));
  if (COMPLETE != sendcommand(msgbuf))
    goto bad;
  return (0);

bad:
   scps_close(sdata), sdata = -1;
   return (1);
} /* initconn() */


/* dataconn -
 *    Accept a data connection.  Return the socket number
 *    or -1 (if error).  mode is not used
 */
int dataconn(char *mode)
{
   struct sockaddr_in from;
   int s, fromlen = sizeof (from);

#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

#if defined(SYSV) || defined(__BSD__) || defined(MSVC) || defined(LINUX)
   s = scps_accept(sdata, (struct sockaddr *)&from, &fromlen);
#else
   s = scps_accept(sdata, &from, &fromlen);
#endif

   if (s < 0) {
      Lperror("FP: accept");
      PRERR;
      (void) scps_close(sdata), sdata = -1;
      return (-1);
   }

   (void) scps_close(sdata);
   sdata = s;

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("dataconn","Socket",
                          "accept",
                          start_sec, start_usec,
                          end_sec, end_usec, 0, 0);
#endif

   return (sdata);
} /* dataconn() */


/* restartsession -
 *    When a dataconnection aborts, or times out,
 *    reestablish the control connection if necessary, and
 *    restart the command.
 */
int restartsession(cmd, restarted, remote)
  char *cmd;
  int *restarted;
  char *remote;   /* remote file name */
{
  int  n;
  int  ui;   /* user interrupted */
  char *p;
  struct stat stbuf;


  *restarted = 0;
  Lstrout("Restarting . . .\n");
  n = sendcommand("NOOP");
  if (n == COMPLETE) {
    /* The control connection is still there. */
    if (0 == Lstrcmp(cmd, "STOR")) {
      /* get the restart point */
      nsprintf(msgbuf, sizeof(msgbuf), "SIZE %s", remote);
      n = sendcommand(msgbuf);
      if (n == COMPLETE) {
        *restarted = 1;
        /* make sure it's termimated */
        reply_string[sizeof(reply_string)-1] = '\0';
        p = Lstrstr(reply_string, "SIZE ");
        if (p != NULL) {
          /* OK.  Now I can set the restart point */
          p += 5;
        }
      } /* did SIZE OK */
    } else {
      /* If the command is not STOR, "remote"
       * is actually the local file. */
      n = Lstat(remote, &stbuf);
      if (n < 0) {
        Lperror(remote);
        return (0);
      }
      restart_point = stbuf.st_size;
      *restarted = 1;
    }
    return (0);
  }
  Lstrout("Opening control connection . . .\n");
  scps_close(sctrl);
  connected = 0;

  sctrl = scps_socket(AF_INET, SOCK_STREAM, 0);
  if (sctrl < 0) {
    return (0);
  }

#ifndef NOTTP
  enable_options (sctrl);
#endif /* NOTTP */

#if defined(SYSV) || defined(__BSD__) || defined(MSVC) || defined(LINUX)
  n = scps_connect(sctrl, (struct sockaddr *)&hisctladdr, sizeof(hisctladdr));
#else
  n = scps_connect(sctrl, &hisctladdr, sizeof(hisctladdr));
#endif
  if (n < 0) {
    scps_close(sctrl);
    sctrl = -1;
    *restarted = 0;
    return (0);
  }
  n = getreply(0, &ui);
  if (code == 220) {
    /* OK.  I am connected and I have the 220 reply code */
    n = COMPLETE;
#if defined(LARGE)
    if (*autouser) {
      nsprintf(msgbuf, sizeof(msgbuf), "USER %s", autouser);
      n = sendcommand(msgbuf);
    }
    if (n == CONTINUE) {
      if (*autopass) {
        nsprintf(msgbuf, sizeof(msgbuf), "PASS %s", autopass);
        n = sendcommand(msgbuf);
      }
      if (n == COMPLETE) {
        if (*autodir) {
          nsprintf(msgbuf, sizeof(msgbuf), "CWD %s", autodir);
          n = sendcommand(msgbuf);
        }
        if (n == COMPLETE) {
          nsprintf(msgbuf, sizeof(msgbuf), "TYPE %s", types[type].t_mode);
          n = sendcommand(msgbuf);
#endif
          if (n == COMPLETE) {
            if (0 == Lstrcmp(cmd, "STOR")) {
              nsprintf(msgbuf, sizeof(msgbuf), "SIZE %s", remote);
              n = sendcommand(msgbuf);
              if (n == COMPLETE) {
                /* make sure it's terminated */
                reply_string[sizeof(reply_string)-1] = '\0';
                p = Lstrstr(reply_string, "SIZE ");
                if (p != NULL) {
                  /* OK.  Now I can set the restart point */
                  p += 5;
                }
                *restarted = 1;
              } /* did SIZE OK */
            } else {
              n = Lstat(remote, &stbuf);
              if (n < 0) {
                Lperror(remote);
              } else {
                restart_point = stbuf.st_size;
                *restarted = 1;
              } /* Lstat() OK */
            } /* retr or stor */
          } /* type OK  */
#if defined(LARGE)
        } /* cwd OK   */
      } /* pass OK  */
    } /* user OK  */
#endif
  } /* have 220 */

  if (*restarted == 0) {
    scps_close(sctrl);
    sctrl = -1;
  }
  return (0);
} /* restartsession() */


int recvrequest(char *cmd,
                char *local,
                char *remote,
                char *mode,
                int   printnames,
                int  *engageautorestart)
{
#if defined(MEDIUM) || defined(LARGE)
  extern int asciicopytofs(int ins, FILE *outfile, u_long *bytecount);
#endif
  FILE *fout = 0;
  int is_retr = 0;
  u_long bytes = 0;
  int32_t filesize;
  u_long hashbytes = 0;
  int c, d;
  struct timeval start, stop;
  int user_interrupted;
  int statres;                /* for rollback */
  struct stat st;             /* for rollback */
  char tmpname[SCPS_L_tmpnam];/* for rollback */
  int derr = 0;               /* for rollback */
  int serrno;                 /* save errno   */

#ifdef DO_TIMING
  int32_t start_sec, start_usec;
  int32_t first_sec = 0;
  int32_t first_usec = 0;
  int32_t end_sec, end_usec;
  int32_t delta_time = 0;
#endif

  *engageautorestart = 0;
  is_retr = Lstrcmp(cmd, "retr") == 0;
  if (is_retr && verbose && printnames) {
    nsprintf(msgbuf, sizeof(msgbuf),
       "local: %s remote: %s\n", local, remote);
    Lstrout(msgbuf);
  }
  if (proxy && is_retr) {
    proxtrans(cmd, local, remote);
    return (0);
  }
  if (initconn()) {
    code = -1;
    return (0);
  }
  if (abortop || interruptop) {
    abortop = 0;
    interruptop = 0;
    return (0);
  }
  if (is_retr && restart_point) {
    nsprintf(msgbuf, sizeof(msgbuf),
        "REST %d", (int32_t) restart_point);
    if (sendcommand(msgbuf) != CONTINUE)
      return (0);
  }
  if (remote) {
    nsprintf(msgbuf, sizeof(msgbuf),
        "%s %s", cmd, remote);
    if (sendcommand(msgbuf) != PRELIM) {
      return (0);
    }
  } else {
    if (sendcommand(cmd) != PRELIM) {
      return (0);
    } /* if PRELIM */
  }
  sdata = dataconn("r");
  if (sdata == -1) {
    scps_send(sctrl, "ABOR\r\n", 6, flags);
    debuglog("ABOR.2");
    return (0);
  }
  if (restart_point) {
    /* Save the partial file in case an error occurs. */
    if (NULL == Ltmpnam(tmpname)) {
      printf("Couldn't create temp file.\n");
      return (0);
    }
    fcopy(local, tmpname);
  } else {
    statres = Lstat(local, &st);
    if (0 == statres) {
      /* Save the file in case anything goes wrogn. */
      if (NULL == Ltmpnam(tmpname)) {
        printf("Couldn't create temp file.\n");
        return (0);
      }
      Lrename(local, tmpname);
    }
  }
  fout = Lfopen(local, mode);
  if (fout == NULL) {
    Lperror(local);
    (void) scps_close(sdata);
    sdata = -1;
    scps_send(sctrl, "ABOR\r\n", 6, flags);
    debuglog("ABOR.3");
    return (0);
  }
  Lgettimeofday(&start, (struct timezone *)0);
  switch (type) {
    case TYPE_I:
    case TYPE_L:
      if (restart_point &&
          Lfseek(fout, (int32_t) restart_point, 0) < 0) {
        Lperror(local);
        Lfclose(fout);
        scps_close(sdata);
        sdata = -1;
        return (0);
      }
      errno = d = 0;

#ifdef DO_TIMING
      (void) prtstat_gettime (&start_sec, &start_usec);
      first_sec = start_sec;
      first_usec = start_usec;
#endif

      /* throw away the <cr> (TinyTCP only)
       * In early versions, a byte of data was
       * required to establish the connection.
       * The connection is now fully established
       * at the TP level.
      scps_recv(sdata, buf, 1, flags);
       */
      /* user_interrupted = 0; */
      while ((c = scps_recv(sdata, buf, sizeof(buf), flags)) > 0) {

#ifdef DO_TIMING
        (void) prtstat_gettime (&end_sec, &end_usec);
        if (&end_usec < &start_usec)
        {
           delta_time += (end_sec - 1 - start_sec) * 1000000 +
                         (end_usec + 1000000 - start_usec);
        }
        else
        {
           delta_time += (end_sec - start_sec) * 1000000 +
                         (end_usec - start_usec);
        }
#endif

        if ((d = Lfwrite(buf, c, 1, fout)) < 0)
          break;
        if (abortop) {
          abortop = 0;
          derr = 3;
          scps_send(sctrl, "ABOR\r\n", 6, flags);
          if (debug) {
            printf("---> ABOR\n");
          }
          goto ai;
        }
        if (interruptop) {
          interruptop = 0;
          derr = 2;
          scps_send(sctrl, "INTR\r\n", 6, flags);
          if (debug) {
            printf("---> INTR\n");
          }
          goto ai;
        }

        bytes += c;

#ifdef DO_TIMING
        (void) prtstat_gettime (&start_sec, &start_usec);
#endif
        if (bytes - hashbytes >= hash_size) {
          if (hash) {
            printf ("#");
            fflush (stdout);
          }
          hashbytes = bytes;
        }
      } /* while */
      serrno = errno;  /* save errno */
#ifdef DO_TIMING

      (void) print_timestat ("recvrequest","Socket",
                              "recv binary data",
                              first_sec,
                              first_usec,
                              end_sec,
                              end_usec,
                              delta_time,
                              bytes);
      errno = serrno;
#endif
      debuglog("errno: %d  c: %d", errno, c);
      errno = serrno;
      if (c < 0) {
         /* error on the data connection */
#ifdef LINUX
         /* When Linux is in a system call, and
          * get SIGINT or SIGTSTP, it returns EINTR
          * from the sys call.  */
         if (errno == EINTR) {
            if (interruptop) {
              derr = 2;
              interruptop = 0;
              /* They should never hit both ^C and ^Z
               * but what if they do?
               abortop = 0;
               */
              scps_send(sctrl, "INTR\r\n", 6, flags);
              if (debug) {
                printf("---> INTR\n");
              }
            } else if (abortop) {
              derr = 3;
              abortop = 0;
              scps_send(sctrl, "ABOR\r\n", 6, flags);
              if (debug) {
                printf("---> ABOR\n");
              }
            } else {
              derr = 2;
              scps_send(sctrl, "INTR\r\n", 6, flags);
              if (debug) {
                printf("---> INTR\n");
              }
            }
            goto ai;
         }
#endif
         if (errno != EPIPE) {
            derr = 1;              /* turn on rollback flag */
            *engageautorestart = 1;
            Lperror("netin");
            goto done;
         }
         bytes = -1;
      }
      if (d < c) {
         /* error from the file system */
         if (d < 0) {
            derr = 1;              /* turn on rollback flag */
            Lperror(local);
            goto done;
         } else {
            nsprintf(msgbuf, sizeof(msgbuf),
                     "%s: short write\n", local);
            Lstrout(msgbuf);
         }
      }
      break;   /* end case TYPE_I */
#if defined(MEDIUM) || defined(LARGE)
    case TYPE_A:
      if (restart_point && srp(fout, restart_point, NULL)) {
        /* error setting the restart point. */
        Lperror(local);
        Lfclose(fout);
        scps_close(sdata);
        sdata = -1;
        return (0);
      }
      derr = asciicopytofs(sdata, fout, &bytes);
      debuglog("derr: %d", derr);
      if (derr == 2 || derr == 3)
        goto ai;
      break;   /* end case TYPE_A */
#endif
   } /* switch */
done:
   filesize = ftell(fout);
   Lfclose(fout);
   if (restart_point) {
      restart_point = 0;
      remove(tmpname);
   } else {
      if (0 == derr) {
        /* no error */
        if (0 == statres) {
          remove(tmpname);
        }
      } else {
        if (0 == statres) {
          /* error on receive.  There was no
           * interrupt or abort, or execution
           * would not be here.  */
          remove(local);
          Lrename(tmpname, local);
        } else {
          remove(local);
        }
      }
   } /* if autorestart */
   (void) Lgettimeofday(&stop, (struct timezone *)0);

#ifdef DO_TIMING
   (void) prtstat_gettime (&start_sec, &start_usec);
#endif
   (void) scps_close(sdata);
   sdata = -1;

#ifdef DO_TIMING
   (void) prtstat_gettime (&end_sec, &end_usec);
   (void) print_timestat ("recvrequest","Socket",
                           "close",
                           start_sec,
                           start_usec,
                           end_sec,
                           end_usec,0,0);
#endif

   if (hash)
     printf("\n");
   (void) getreply(0, &user_interrupted);
   if (bytes > 0 && is_retr && 0 == user_interrupted)
      ptransfer("received", bytes, filesize, &start, &stop);
   return (0);

ai:                        /* abort/interrupt */
  /*  tp-flush(sctrl); */
  (void) getreply(0, &user_interrupted);
  code = -1;
  if (sdata >= 0) {
    (void) scps_close(sdata);
    sdata = -1;
  }
  if (fout)
    Lfclose(fout);
  if (restart_point) {
    restart_point = 0;
    /* Rollback if necessary*/
    if (3 == derr) {
        remove(local);
        Lrename(tmpname, local);
    } else if (2 == derr) {
      /* Interrupted again. */
      remove(tmpname);
    } /* if abort else */
  } else {
    /* autorestart is disabled: roll back */
    if (3 == derr) {
      if (0 == statres) {
        /* user aborted: restore original file */
        remove(local);
        Lrename(tmpname, local);
      } else {
        /* There was no original file: throw away
         * the partially received file. */
        remove(local);
      }
    } else {
      if (0 == statres) {
        /* If there was a file by that name
         * delete the temp file. */
        remove(tmpname);
      } /* if file existed */
    } /* if abort else */
  } /* if autorestart */
  return 0;
} /* recvrequest() */


/* autorrecvrequest -
 *    Receive a file.  Do autorestart if enabled, and there
 *    is an error on the data channel during the transfer.
 */
int autorrecvrequest(char *cmd,
                     char *local,
                     char *remote,
                     char *mode,
                     int   printnames)
{
  int ear = 0;
  int numr = numautor;
  int gosend = -1;

  do {
    /* If autorestart is enabled, keep trying to perform
     * the operation until the retry count has expired
     * or the operation succeeds */
    if (ear) {
      restartsession(cmd, &gosend, local);
      sleep(5);
    } /* if engage autorestart */

    if (gosend) {
      /* The first time through the mode might be "w".
       * If the transfer gets restarted, the mode must
       * be "r+" or the received data gets blown away.  */
      if (gosend < 0)
        recvrequest(cmd, local, remote, mode, printnames, &ear);
      else
        recvrequest(cmd, local, remote, "r+", printnames, &ear);
    }
    numr--;
  } while (ear &&
           numr &&
           autorestart);
  return (ear);
} /* autorrecvrequest() */


/* getit -
 *    Get one file.
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int getit(int argc, char *argv[], char *mode)
{
#ifdef DO_TIMING
   int32_t end_sec, end_usec;
   int32_t start_sec, start_usec;
   (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (argc == 2) {
    argc++;
    argv[2] = argv[1];
  } else {
    if (argc != 3) {
      nsprintf(msgbuf, sizeof(msgbuf),
         "usage: %s remote-file [ local-file ]\n", argv[0]);
      Lstrout(msgbuf);
      code = -1;
      return (0);
    }
  }

  autorrecvrequest("retr", argv[2], argv[1], mode, 1);
  restart_point = 0;

#ifdef DO_TIMING
    (void) prtstat_gettime (&end_sec, &end_usec);
    (void) print_timestat("getit","User_cmd", "get",
                           start_sec,start_usec,
                           end_sec,end_usec, 0, 0);
#endif
  return (0);

} /* getit() */


/* sendrequest -
 *    User issued the put command.
 *    Do it.
 */
int sendrequest(cmd, local, remote, printnames, engageautorestart)
  char *cmd, *local, *remote;
  int printnames;
  int *engageautorestart;
{
#if defined(MEDIUM) || defined(LARGE)
  int copyresult;
#endif
  register int c, d;
  FILE *fin = 0;
  char buf[BSIZE], *bufp;
  u_long bytes = 0;
  int32_t hashbytes = 0;
  int32_t filesize;
  struct stat st;
  struct timeval start, stop;
  char *mode;
  int user_interrupted;
#ifdef DO_TIMING
   int serrno;
   int32_t start_sec, start_usec;
   int32_t first_sec = 0;
   int32_t first_usec = 0;
   int32_t end_sec, end_usec;
   int32_t delta_time = 0;
#endif

  if (verbose && printnames) {

  }
  if (proxy) {
    proxtrans(cmd, local, remote);
    return (0);
  }
  mode = "w";
  fin = Lfopen(local, "r");
  if (fin == NULL) {
    Lperror(local);
    code = -1;
    return (0);
  }
  if (Lstat(local, &st) < 0 ||
      (st.st_mode&S_IFMT) != S_IFREG) {
    nsprintf(msgbuf, sizeof(msgbuf),
        "%s: not a plain file.\n", local);
    Lstrout(msgbuf);
    Lfclose(fin);
    code = -1;
    return (0);
  }
  if (initconn()) {
    code = -1;
    Lfclose(fin);
    return (0);
  }
  if (abortop || interruptop) {
    abortop = 0;
    interruptop = 0;
    return (0);
  }
  if (restart_point) {
    if (Lfseek(fin, (int32_t) restart_point, 0) < 0) {
      Lperror(local);
      restart_point = 0;
      Lfclose(fin);
      return (0);
    }
    nsprintf(msgbuf, sizeof(msgbuf),
        "REST %d", restart_point);
    if (sendcommand(msgbuf) != CONTINUE) {
      restart_point = 0;
      Lfclose(fin);
      return (0);
    }
    restart_point = 0;
    mode = "r+w";
  }
  if (abortop || interruptop) {
    abortop = 0;
    interruptop = 0;
    return (0);
  }
  if (remote) {
    nsprintf(msgbuf, sizeof(msgbuf),
        "%s %s", cmd, remote);
    if (sendcommand(msgbuf) != PRELIM) {
      Lfclose(fin);
      return (0);
    }
  } else {
    if (sendcommand(cmd) != PRELIM) {
      Lfclose(fin);
      return (0);
    }
  }
  sdata = dataconn(mode);
  if (sdata == -1)
    goto abort;
  Lgettimeofday(&start, (struct timezone *)0);
  switch (type) {

    case TYPE_I:
    case TYPE_L:
      errno = d = 0;
      /*  user_interrupted = 0; */
      while ((c = Lfread(buf, 1, sizeof(buf), fin)) > 0) {
        bytes += c;
        for (bufp = buf; c > 0; c -= d, bufp += d) {
#ifdef DO_TIMING
          (void) prtstat_gettime (&start_sec, &start_usec);
          if (first_sec == 0 && first_usec == 0)
          {
             first_sec = start_sec;
             first_usec = start_usec;
          }
#endif
          if ((d = scps_send(sdata, bufp, c, flags)) <= 0)
            break;
#ifdef DO_TIMING
          else
          {
            (void) prtstat_gettime (&end_sec, &end_usec);
            if (&end_usec < &start_usec)
            {
               delta_time += (end_sec - 1 - start_sec) * 1000000 +
                             (end_usec + 1000000 - start_usec);
            }
            else
            {
               delta_time += (end_sec - start_sec) * 1000000 +
                             (end_usec - start_usec);
            }
          }
#endif

#ifdef DO_TIMING
          (void) prtstat_gettime (&start_sec, &start_usec);
#endif
          if (abortop) {
            abortop = 0;
            /*  user_interrupted = 1; */
            if (debug) {
              printf("---> ABOR\n");
            }
            debuglog("ABOR.5");
            goto abort;
          }
          if (interruptop) {
            interruptop = 0;
            /*  user_interrupted = 1; */
            if (debug) {
              printf("---> INTR\n");
            }
            debuglog("INTR");
            goto interrupt;
          }
        } /* for all bytes read */
        if (bytes - hashbytes >= hash_size) {
          if (hash) {
            printf ("#");
            fflush (stdout);
          }
          hashbytes = bytes;
        }
      } /* while more to read */

#ifdef DO_TIMING
      serrno = errno;
      (void) print_timestat ("sendrequest","Socket",
                              "send binary data",
                              first_sec,
                              first_usec,
                              end_sec,
                              end_usec,
                              delta_time,
                              bytes);
      errno = serrno;
#endif
      *engageautorestart = 0;
      debuglog("errno: %d  c: %d   d: %d", errno, c, d);
      if (c < 0)
        Lperror(local);
      if (d <= 0) {
        if (d == 0) {
          Lstrout("netout: write returned 0?\n");
        } else if (errno != EPIPE) {
          Lperror("netout");
          *engageautorestart = 1;
        } /* if non-pipe error on data conn */
        bytes = -1;
      } else {
        /* tp-flush(sdata); */
      }
      break;

#if defined(MEDIUM) || defined(LARGE)
    case TYPE_A:
      copyresult = asciicopyfmfs(fin, sdata, &bytes);
      switch (copyresult) {
        case 2:
          goto interrupt;
        case 3:
          goto abort;
      }
      break;
#endif

  } /* switch */
  Lgettimeofday(&stop, (struct timezone *)0);
  filesize = ftell(fin);
  Lfclose(fin);

#ifdef DO_TIMING
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  scps_close(sdata);
  sdata = -1;

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat ("sendrequest","Socket",
                         "close",
                          start_sec,
                          start_usec,
                          end_sec,
                          end_usec,0,0);
#endif

  if (hash)
    printf("\n");

  getreply(0, &user_interrupted);
                          /* Sometimes the entire file is
                           * buffered up, and the ^Z or ^C
                           * comes when sitting in the
                           * recv() to get the final reply.
                           * In that case getreply() exits
                           * with user_interrupted set. */
  if (bytes > 0 && 0 == user_interrupted)
    ptransfer("sent", bytes, filesize, &start, &stop);
  return (0);

abort:
  scps_send(sctrl, "ABOR\r\n", 6, flags);
  goto ai;

interrupt:
  scps_send(sctrl, "INTR\r\n", 6, flags);
ai:

  /* Lgettimeofday(&stop, (struct timezone *)0); */
  /*  tp-flush(sctrl); */
  if (hash)
    printf("\n");
  getreply(0, &user_interrupted);
  code = -1;
  if (sdata >= 0) {
    scps_close(sdata);
    sdata = -1;
  }
  Lfclose(fin);
  return 0;
} /* sendrequest() */


/* autorsendrequest -
 *    Calls sendrequest().  Does autorestart if enabled and
 *    necessary.
 *    returns 0 if the file was successfully sent, 1 otherwise.
 */
int autorsendrequest(cmd, local, remote, printnames)
  char *cmd, *local, *remote;
  int printnames;
{
  int ear = 0;
  int numr = numautor;
  int gosend = 1;


  do {
    /* If autorestart is enabled, keep trying to perform
     * the operation until the retry count has expired
     * or the operation succeeds */
    if (ear) {
      restartsession(cmd, &gosend, remote);
      sleep(5);
    } /* if engage autorestart */

    if (gosend) {
      sendrequest(cmd, local, remote, printnames, &ear);
    }
    numr--;
  } while (ear &&
           numr &&
           autorestart);

  return (ear);
} /* autorsendrequest() */


/* =============================================================== */
/* raread prototype                                                */
/* =============================================================== */
#define MAX_SEGMENTS   20


/* raread and raupdt let the user read and write individual
 * segments (records or octets) in the remote file.  Segments
 * are specified on the command line, comma separated, no
 * spaces, hyphen delimited ranges.  For example, CMDS.C
 * converts "3-4,1,9,5-6" to "1-1 3-4 5-6 9-9". */
struct seg_range {
   u_long low;
   u_long high;
};


/* raread_usage - Tells how to use raread.
 *
 */
void raread_usage (char *name)
{
  nsprintf(msgbuf, sizeof(msgbuf),
   "usage: \n%s remote_path local_path segments force_read\n", name);
  Lstrout(msgbuf);
} /* end raread_usage */


/* rareadseg_cmp - Compares the low part of seg1 with that of seg2.
 *                 Returns a negative value if seg1.low is less than
 *                 seg2.low, 0 if they are equal, and a positive
 *                 value if seg1.low is greater than seg2.low
 *
 *                 Comparison routine for Lqsort().
 */
int rareadseg_cmp (const void *seg1, const void *seg2)
{
   return (((struct seg_range *)seg1)->low - ((struct seg_range *)seg2)->low);
} /* rareadseg_cmp */


/* When they specify a set of records to read, this module converts
 * everything to ranges.  We call these ranges of *segments* because
 * they could refer to lines (ASCII mode) or octets (BINARY mode)
 */

/* Validates parameters passed to raread.  Returns boolean
 * representations of the specified options or an integer
 * indicating which parameter was invalid. */


/* Splits a path spec into path, fn.  Caller
 * must ensure that there is room in path and
 * fn to receive their components.   */
void path_fn (char *fullpath, char *path, char *fn);


/* Checks ranges */

/* ra_segs_ok - Checks ranges to make sure they are valid.
 *              Deletes duplicate ranges, ranges that overlap, etc.
 * Returns 0 if OK, 1 otherwise.
 *   Returns 1 if:
 *     a low is greater than a high.
 *     found a character that is not in "0123456789-,".
 *     found the low part of a range with no high.
 *     too many segments specified.
 *     any of the ranges overlap.
 */
int ra_segs_ok (char *segstr, int *seg_count, struct seg_range *segs)
{
   struct seg_range *first_seg = segs;
   char one[15];   /* holds a number for conversion */
   int oi = 0;     /* one index */
   int on_low = 1; /* true if I'm reading the low number */
   int iWorki, iWorkj;
   char segments[Lstrlen(segstr)+20];
   char *whereEOF;


   Lstrtolower(segstr);
   if (NULL != (whereEOF = Lstrstr(segstr, "eof"))) {
      if (NULL != Lstrstr(whereEOF + 1, "eof"))
         /* there can only be one eof */
         return 1;
      Lstrncpy(segments, segstr, whereEOF-segstr);
      segments[whereEOF-segstr] = '\0';
      Lstrcat(segments, "4294967295");
      Lstrcat(segments, whereEOF+3);
   } else {
      Lstrncpy (segments, segstr, Lstrlen(segstr)+1);
   }

   /* use my copy of the segments string.
    * the caller can do what he wants with
    * his pointer */
   segstr = segments;
   *seg_count = 0;
   for (;;) {
      switch (*segstr) {
         case '-':
            if (oi == 0)
               return (1);
            if (on_low == 0)
               /* should always be on low here. */
               return (1);
            if ((segs->low = Latoi(one)) == ULONG_MAX)
               return (1);
            on_low = 0;   /* go do the high one */
            oi = 0;
            break;

         case '\0':
         case ',':
            if (oi == 0)
               return (1);
            if (*seg_count == MAX_SEGMENTS)
               return (1);
            if (on_low == 0) {
               segs->high = Latoi(one);
               segs++;
               on_low = 1;
            } else {
               if ((segs->low = Latoi(one)) == ULONG_MAX)
                  return (1);
               segs->high = segs->low;
               segs++;
            }
            (*seg_count)++;
            if (*segstr == '\0')
               goto RPARSE_DONE;
            oi = 0;
            break;

         default:
            if (Lisdigit(*segstr)) {
               if (oi < 15) {
                  one[oi++] = *segstr;
                  one[oi] = '\0';
               }
               else
                  return (1);
            }
            else
               return (1);
            break;

      } /* switch */
      segstr++;
   } /* for */
RPARSE_DONE:
   if (*seg_count == 0)
      return (1);  /* there weren't any segments */
   for (iWorki = 0; iWorki < *seg_count; iWorki++) {
      if (first_seg[iWorki].low > first_seg[iWorki].high)
         /*  low must always be less than high */
         return (1);
   } /* for low high check */
   /* Make sure none of the ranges overlap */
   for (iWorki = 0; iWorki < *seg_count; iWorki++) {
       for (iWorkj = 0; iWorkj < *seg_count; iWorkj++) {
          if (iWorki == iWorkj)
             continue;
          if (first_seg[iWorki].low > first_seg[iWorkj].low &&
              first_seg[iWorki].low < first_seg[iWorkj].high) {
             /* Found a low that is inside another range */
             return (1);
          } /* if */
          if (first_seg[iWorki].low  == first_seg[iWorkj].low  ||
              first_seg[iWorki].low  == first_seg[iWorkj].high)
             /* I need this test in case they say "3,3-5" or
              * "3-5,5"  Found a range that starts on the same number. */
             return (1);
       }
   } /* for */
   /*  OK  we're ready to go.  Sort 'em and return.  */
   Lqsort (first_seg, *seg_count, sizeof(struct seg_range), rareadseg_cmp);
   return (0);
} /* ra_segs_ok */


/* raread_pok - Checks parameters passed to raread().
 *
 *              local-path (argv[2]) must be openable and writeable.
 *              segment-ids (argv[3]) must contain only digits, hyphens
 *                 and commas.  Sequences must be in the form n-n.
 *                 Numbers are interpreted as decimal.  Left number
 *                 of a sequence must be less than the right number.
 *                 "eof" is replaced by ULONG_MAX.
 *              forced-read-option (argv[4]) must be in "yYnN"
 *
 *  Returns 0 if no error.  Otherwise the returned value indicates
 *  which parameter is invalid.  Writes the segment range count and
 *  ranges to *seg_count and *segs respectively.  The length of
 *  segs[] is MAX_SEGMENTS.
 */
int raread_pok (int argc,
                char *argv[],
                int *seg_count,
                struct seg_range *segs,
                int *optforced_rd)
{
  struct stat statbuf;

  if (argc < 4) {
    if (argc == 0)
      return (1);
    return (argc);
  }
  /* make sure the path names are a valid length */
  if (Lstrlen(argv[1]) > MAXPATHLEN)
    return (1);
  if (Lstrlen(argv[2]) > MAXPATHLEN)
    return (2);
  if (0 != ra_segs_ok(argv[3], seg_count, segs))
    return (3);
  /* Check the local file name. */
  /* ASCII or BINARY doesn't matter here.  I'm just seeing
   * if I can write to it. */
  if (0 == Lstat(argv[2], &statbuf)) {
    /* Oops.  There's something there. */
    if ((statbuf.st_mode & S_IWRITE) != S_IWRITE) {
      nsprintf(msgbuf, sizeof(msgbuf),
          "Could not open '%s' with write access\n", argv[2]);
      Lstrout(msgbuf);
      return (2);
    }
  } /* if something there */
  if (argc == 4) {
    *optforced_rd = 0;
    return (0);
  }
  Lstrtolower(argv[4]);
  if (NULL == Lstrstr("yn", argv[4])) {
    return (4);
  } else
    *optforced_rd = (argv[4][0] == 'y');
  if (argc > 5)
    Lstrout("Extra parameter(s) ignored.\n");

  return (0);
} /* end raread_pok */


/* readrequest - Issue "CWD" if necessary, then
 *               create control file,
 *               issue "STOR" to send it,
 *               issue "READ", and
 *               read records, or errors.
 */
void readrequest (char *rpath,
                  char *rname,
                  char *lpathname,
                  int optforced_read,
                  int seg_count,
                  struct seg_range *segs)
{
  char tmp[SCPS_L_tmpnam];
  char msgbuf[80];
  short oldtype;
  FILE *ctrlf;
  unsigned short record_count;

  /* change directory if necessary */
  if (*rpath) {
    nsprintf(msgbuf, sizeof(msgbuf), "%s %s", "CWD", rpath);
    if (COMPLETE != sendcommand (msgbuf))
      return;
  } /* if need CWD */
  oldtype = type;
  if (TYPE_I != type) {
    type = TYPE_I;
    if (COMPLETE != sendcommand("TYPE I"))
      goto readabort;
  }

  if (NULL == Ltmpnam(tmp)) {
    printf("Could not create temporary name.\n");
    goto readabort;
  }
  if (NULL == (ctrlf = Lfopen(tmp, "w"))) {
    printf("Could not open temporary file.\n");
    goto readabort;
  }
  printf("tmp:'%s'\n", tmp);
  fputs(rname, ctrlf);
  fputs("\n", ctrlf);
  if (optforced_read) fputs("Y\n", ctrlf); else fputs("N\n", ctrlf);
  record_count = (unsigned short)(htons((short)seg_count));
  fwrite(&record_count, 1, sizeof(record_count), ctrlf);
  fputs("\n", ctrlf);
  for (; seg_count; seg_count--, segs++) {
    nsprintf(msgbuf, sizeof(msgbuf), "%d-%d\n", segs->low, segs->high);
    fputs(msgbuf, ctrlf);
  }
  fputs("\n\xff\x2", ctrlf);
  Lfclose(ctrlf);
  ctrlf = NULL;
  /* I would like to issue STOU here and have STOU return
   * reply code of 228 if successful.  That way I wouldn't
   * need a reserved filename.  It would be easy to
   * add code in sfp.c:getreply() to parse the reply
   * to get the unique filename to issue the READ
   * command.  In the future, consider modifying the spec
   * to have STOU return 228 if successful.  */
  if (autorsendrequest("STOR", tmp, RESERVEDNAME, 1))
    goto readabort;
  /* remove(tmp); */

  autorrecvrequest("READ", lpathname, RESERVEDNAME, "w", 1);

readabort:
  if (type != oldtype) {
    nsprintf(msgbuf, sizeof(msgbuf), "TYPE %s", types[oldtype].t_name);
    if (COMPLETE == sendcommand(msgbuf))
      type = oldtype;
  }
  if (ctrlf) Lfclose(ctrlf);
  return;
} /* end readrequest */


/* raread - Reads individual segments from the specified remote
 *          file.
 */
int raread(int argc, char *argv[])
{
   int parmerr;
   int optforced_read;
   int seg_count;
   struct seg_range segs[MAX_SEGMENTS];
   char remote_path[MAXPATHLEN];
   char remote_fn[MAXPATHLEN];
   char *localf;                   /* local file name */


   parmerr = raread_pok(argc, argv, &seg_count, segs, &optforced_read);
   if (parmerr) {
      raread_usage (argv[0]);
      return (0);
   }
   /* raread_pok checked the length of argv[1].  Its length
    * is OK.  */
   path_fn (argv[1], remote_path, remote_fn);
   localf = argv[2];
   readrequest(remote_path,
               remote_fn,
               localf,
               optforced_read,
               seg_count,
               segs);
   return 0;
} /* end raread */


/* path_fn - Splits a full path into path and fn */
void path_fn (char *fullpath, char *path, char *fn)
{
  char *pWork = fullpath + Lstrlen(fullpath) - 1;


  *path = '\0';   /* Maybe no path is specified. */
  while (pWork != fullpath && *pWork != '/' && *pWork != '\\')
    /*  Search backward from the end of the string for a
     *  directory specifier */
    pWork--;
  if (pWork == fullpath) {
    /* no path was specified */
    Lstrncpy(fn, fullpath, Lstrlen(fullpath)+1);
  } else {
    Lstrncpy(path, fullpath, pWork-fullpath);
    path[pWork-fullpath] = '\0';
    Lstrncpy(fn, pWork+1, Lstrlen(pWork+1)+1);
  }
} /* path_fn */


/* raupdt_pok - Checks out the parameters passed to raupdt.
 *              local files must be readable.  There must be
 *              the correct number of parameters.  I must be
 *              able to calculate the CRC.
 *
 * Returns  0  If everything went OK
 *         -1  If the user said "No don't overwrite that file".
 *          1  If caller should print usage message  */
int raupdt_pok(int argc, char *argv[], u_long *crcval)
{
   char msgbuf[80];
   char resp[4];
   FILE *testfile;
   FILE *crcfd;
   int crcres;
   u_long crclen;  /* I just throw this away */


   if (argc != 6)
      return (1);
   testfile = Lfopen(argv[4], "r");
   if (testfile != NULL) {
      Lfclose(testfile);
      nsprintf(msgbuf, sizeof(msgbuf), "%s: overwrite %s?", argv[0], argv[4]);
      printf(msgbuf);
      nb_gets(resp);
      Lstrtolower(resp);
      if (resp[0] != 'y')
         return (-1);
   }
   crcfd = Lfopen(argv[3], "r");
   if (crcfd < 0) {
      nsprintf(msgbuf, sizeof(msgbuf),
            "%s: couldn't open '%s'\n", argv[0], argv[3]);
      Lstrout(msgbuf);
      return (-1);
   }
   /* Get the CRC of the local original file. */
   crcres = crc(crcfd, crcval, &crclen);
   Lfclose(crcfd);
   if (crcres) {
      nsprintf(msgbuf, sizeof(msgbuf),
            "%s: couldn't calculate CRC on '%s'\n", argv[0], argv[3]);
      Lstrout(msgbuf);
      return (-1);
   }
   testfile = Lfopen(argv[5], "r");
   if (testfile == NULL) {
      nsprintf(msgbuf, sizeof(msgbuf),
            "%s: couldn't open '%s'\n", argv[0], argv[5]);
      Lstrout(msgbuf);
      return (-1);
   }
   Lfclose (testfile);
   if (Lstrlen(argv[1]) > MAXPATHLEN) {
      /* I check the length because in a few microseconds
       * I'm going to call path_fn() so I can do the
       * CWD on the remote side as per spec. */
      nsprintf(msgbuf, sizeof(msgbuf),
            "%s: '%s' too long\n", argv[0], argv[1]);
      Lstrout(msgbuf);
      return (-1);
   }
   return (0);
} /* raupdt_pok() */


/* raupdt_usage - Gives a very brief description of the command */
void raupdt_usage(char *name)
{
   char msgbuf[80];

   nsprintf(msgbuf, sizeof(msgbuf),
       "usage: %s remotein remoteout localin localout deltafile\n", name);
   Lstrout(msgbuf);
} /* raupdt_usage */


/* updtrequest - Issue "CWD" if necessary, then
 *               create control file (update script),
 *               issue "STOR" to send it,
 *               issue "UPDT"
 */
void updtrequest (char *rpath,
                  char *rname_orig,
                  char *rname_new,
                  u_long crcval,
                  char *dname)
{
   register int c;
   char message[40];
   char ctlline[40];             /* for sending the control file */
   char tmpname[SCPS_L_tmpnam];
   FILE *ctrlf = NULL;
   FILE *fin = NULL;
#ifdef DO_TIMING
   int32_t start_sec, start_usec;
   int32_t end_sec, end_usec;
#endif

   /* change directory if necessary */
   if (*rpath) {
      nsprintf(message, sizeof(message),"%s %s", "CWD", rpath);
      if (COMPLETE != sendcommand(message))
         return;
   } /* if need CWD */
   if (NULL == Ltmpnam(tmpname)) {
      printf("Couldn't create temp file.\n");
      return;
   }
   if (NULL == (ctrlf = Lfopen(tmpname, "w"))) {
      printf("Couldn't open temp file '%s' for writing.\n", tmpname);
      return;
   }
   fwrite(rname_orig, 1, Lstrlen(rname_orig), ctrlf);
   fwrite("\n", 1, 1, ctrlf);
   fwrite(rname_new, 1, Lstrlen(rname_new), ctrlf);
   fwrite("\n", 1, 1, ctrlf);
   nsprintf(ctlline, sizeof(ctlline), "%d\n", crcval);
   fwrite(ctlline, 1, Lstrlen(ctlline), ctrlf);
   if (NULL == (fin = Lfopen(dname, "r"))) {
      printf("Couldn't open script file '%s' for reading.\n", dname);
      goto updtabort;
   }
   while (0 != (c = Lfread(buf, 1, sizeof(buf), fin)))
     Lfwrite(buf, 1, c, ctrlf);
   Lfwrite("\xff\x2", 1, 2, ctrlf);
   Lfclose(fin);
   Lfclose(ctrlf);
   autorsendrequest("STOR", tmpname, RESERVEDNAME, 1);
   sendcommand("UPDT "RESERVEDNAME);

   return;

updtabort:
   if (fin) Lfclose(fin);
   if (ctrlf) Lfclose(ctrlf);
   return;
} /* updtrequest */


/* cmdarst -
 *    no operation.
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int cmdarst(int argc, char *argv[])
{

#ifdef DO_TIMING
  int result;
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

#ifdef DO_TIMING
  result = sendcommand("ARST");
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat("cmdarst","User_cmd", "autorestart",
                          start_sec,start_usec,
                          end_sec,end_usec, 0, 0);
  return (result);
#else
  return (sendcommand("ARST"));
#endif

} /* cmdarst() */


/* cmdclose -
 *    Close the control connection.
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int cmdclose(int argc, char *argv[])
{

#ifdef DO_TIMING
    int32_t end_sec, end_usec;
    int32_t start_sec, start_usec;
    (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  connected = 0;
  if (sdata >= 0)
    scps_close(sdata);
  if (sctrl >= 0)
    scps_close(sctrl);

#ifdef DO_TIMING
    (void) prtstat_gettime (&end_sec, &end_usec);
    (void) print_timestat("cmdclose","User_cmd", "close",
                           start_sec,start_usec,
                           end_sec,end_usec, 0, 0);
#endif
  return (0);
} /* cmdclose() */


/* cmddebug -
 *     Toggle debug modes
 */
int cmddebug(int argc, char *argv[])
{
  debug = !debug;
  if (debug)
    printf("Debugging On.\n");
  else
    printf("Debugging Off.\n");
  return 0;
} /* cmddebug() */


/* cmdldebug -
 *     Toggle debug modes
 */
int cmdldebug(int argc, char *argv[])
{
  ldebug = !ldebug;
  if (ldebug)
    printf("Low level debugging On.  Writing .log file.\n");
  else
    printf("Low level debugging Off.\n");
  return 0;
} /* cmdldebug() */


/* cmddelete -
 *
 */
int cmddelete(int argc, char *argv[])
{
  char cmdbuf[80];

  if (argc < 2) {
    printf("Please specify a filename\n");
    return (0);
  }
  cmdbuf[0] = '\0';
  strcat(cmdbuf, "DELE ");
  strcat(cmdbuf, argv[1]);
  return (sendcommand(cmdbuf));
} /* cmddelete */


/* cmdget -
 *    get a file from the server.
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int cmdget(int argc, char *argv[])
{
  return getit(argc, argv, restart_point ? "r+w" : "w");
} /* cmdget() */


/* cmdhash -
 *
 */
int cmdhash(int argc, char *argv[])
{
  hash = !hash;
  printf("Hash mark printing %s.", onoff(hash));
  if (hash)
    printf("  %d bytes per hash mark.\n", hash_size);
  else
    printf("\n");
  return (0);
} /* cmdhash */


/* str_cmp -
 *     To get rid of a warning.
 */
int str_cmp (const void *s1, const void *s2)
{
  return (strcmp(s1, s2));
} /* str_cmp() */


/* cmdhelp -
 *     display help information.
 */
/*ARGSUSED*/
#define HELPFMT "%-14s  %s\n"
int cmdhelp(int argc, char *argv[])
{
  struct cmd *cmdpp[5];
  int j, w, l;
  int columns, width, ncmds, witem;
  struct cmd *c;
  char *m, *mp;

  if (argc == 1) {
#ifdef SMALL
    printf(HELPFMT, "Command", "Description");
    printf(HELPFMT, "-------------", "----------------------------------------");
    for (c = cmdtab; c->c_name; c++) {
      printf(HELPFMT, c->c_name, c->c_help);
    } /* for */
#else

  printf("Commands are:\n\n");
  bzero(cmdpp, sizeof(cmdpp));
  cmdpp[0] = cmdtaba;
  cmdpp[1] = cmdtabb;
  cmdpp[2] = cmdtabc;
  cmdpp[3] = cmdtabd;
  for (l = 0, ncmds = 0, width = 0; cmdpp[l]; l++) {
    for (c = cmdpp[l]; c->c_name; c++) {
      int len = strlen(c->c_name);

      if (len > width)
        width = len;
      ncmds++;
    }
  }
  witem = width+1;
  if ((m = malloc((witem)*ncmds))) {
    int i, lines;

    mp = m;
    for (l = 0; cmdpp[l]; l++) {
      for (c = cmdpp[l]; c->c_name; c++) {
        strcpy(mp, c->c_name);
        mp += witem;
      }
    }
    Lqsort(m, ncmds, witem, str_cmp);
    width = (width + 8) &~ 7;
    columns = 80 / width;
    if (columns == 0)
      columns = 1;
    lines = (ncmds + columns - 1) / columns;
    for (i = 0; i < lines; i++) {
      for (j = 0; ; j++) {
        int index;

        index = j * lines + i;
        mp = m + (index * witem);
        printf(mp);

        if (mp + lines * witem >= m + ncmds * witem) {
          printf("\n");
          break;
        }

        w = strlen(mp);
        while (w < width) {
          w = (w + 8) &~ 7;
          (void) putchar('\t');
        }
      }
    }
    free(m);
  } else {
    int tail = 0;

    width = (width + 8) &~ 7;
    columns = 80 / width;
    if (columns == 0)
      columns = 1;
    j = 0;
    for (l = 0; cmdpp[l]; l++) {
      for (c = cmdpp[l]; c->c_name; c++) {
        printf("%s", c->c_name);
        tail = 1;
        j += 1;
        if (j == columns) {
          (void) putchar('\n');
          j = 0;
          tail = 0;
          continue;
        }
        w = strlen(c->c_name);
        while (w < width) {
          w = (w + 8) &~ 7;
          (void) putchar('\t');
        }
      }
    }
    if (tail)
      (void) putchar('\n');
  }
  return 0;
#endif
  } else {
#ifdef SMALL
    for (c = cmdtab; c->c_name; c++) {
      if (0 == strcmp(c->c_name, argv[1])) {
        printf(HELPFMT, c->c_name, c->c_help);
        return 0;
      }
    } /* for */
#else
    cmdpp[0] = cmdtaba;
    cmdpp[1] = cmdtabb;
    cmdpp[2] = cmdtabc;
    cmdpp[3] = cmdtabd;
    for (l = 0; cmdpp[l]; l++) {
      for (c = cmdpp[l]; c->c_name; c++) {
        if (0 == strcmp(c->c_name, argv[1])) {
          printf(HELPFMT, c->c_name, c->c_help);
          return 0;
        }
      }
    }
#endif
    printf("%s?\n", argv[1]);
  }
  return 0;
} /* cmdhelp() */


/* cmdidle -
 *    set the number of idle seconds.
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int cmdidle(int argc, char *argv[])
{
  char cmdbuf[80];

#ifdef DO_TIMING
  int result;
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (argc < 2) {
    Lstrout("Please specify number of idle seconds.\n");
    return 0;
  }
  sprintf(cmdbuf, "IDLE %s", argv[1]);

#ifdef DO_TIMING
  result = sendcommand(cmdbuf);

  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat("cmdidle","User_cmd", "timeout",
                          start_sec,start_usec,
                          end_sec,end_usec, 0, 0);
  return (result);
#else
  return (sendcommand(cmdbuf));
#endif

} /* cmdidle() */


/* cmdlsize -
 *     Gets the size of a local file.
 *
 *     Returns 0.
 */
int cmdlsize(int argc, char *argv[])
{
  struct stat stbuf;

  if (argc < 2) {
    printf("Please specify a filename\n");
    return (0);
  }
  if (stat(argv[1], &stbuf) < 0 ||
      (stbuf.st_mode&S_IFMT) != S_IFREG) {
    printf("Error getting the size of '%s'\n", argv[1]);
    lastsize = -1;
  } else {
    lastsize = stbuf.st_size;
    printf("Size of '%s': %d bytes\n", argv[1], lastsize);
  }
  return (0);
} /* cmdlsize() */


/* cmdnars -
 *    no operation.
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int cmdnars(int argc, char *argv[])
{

#ifdef DO_TIMING
  int result;
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

#ifdef DO_TIMING
  result = sendcommand("NARS");
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat("cmdnars","User_cmd", "noautorest",
                          start_sec,start_usec,
                          end_sec,end_usec, 0, 0);
  return (result);
#else
  return (COMPLETE == sendcommand("NARS") ? 0 : -1);
#endif
} /* cmdnars() */


/* cmdnoop -
 *    no operation.
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int cmdnoop(int argc, char *argv[])
{
  return (COMPLETE == sendcommand("NOOP") ? 0 : -1);
} /* cmdnoop() */


/* cmdopen -
 *    Do the open command.
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
/*ARGSUSED*/
int cmdopen(int argc, char *argv[])
{
  void conn_init();
#ifdef DO_TIMING
    int32_t end_sec, end_usec;
    int32_t start_sec, start_usec;
    (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (connected) {
    Lstrout("Already connected.\n");
    return 0;
  }
  /* Need conn_init() here to set proxy defaults. */
  conn_init();
  if (hookup(argv[1], port)) {
    connected = 1;
#ifdef DO_TIMING
    (void) prtstat_gettime (&end_sec, &end_usec);
    (void) print_timestat("cmdopen","User_cmd", "open",
                           start_sec,start_usec,
                           end_sec,end_usec, 0, 0);
#endif
    return 0;
  } else {
    return -1;
  } /* if */
} /* cmdopen() */


/*cmdput -
 *    Store a single file on the server.
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int cmdput(int argc, char *argv[])
{
#ifdef DO_TIMING
   int32_t end_sec, end_usec;
   int32_t start_sec, start_usec;
   (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (argc == 2) {
    argc++;
    argv[2] = argv[1];
  } else {
    if (argc != 3) {
      nsprintf(msgbuf, sizeof(msgbuf),
         "usage: %s remote-file [ local-file ]\n", argv[0]);
      Lstrout(msgbuf);
      code = -1;
      return (0);
    }
  }
#if defined(SMALL) || defined(MEDIUM)
  autorsendrequest("STOR", argv[1], argv[2], 1);
#endif
#ifdef LARGE
   autorsendrequest(sunique ? "STOU" : "STOR", argv[1], argv[2], 1);
#endif

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat("put","User_cmd", "put",
                         start_sec,start_usec,
                         end_sec,end_usec, 0, 0);
#endif
  return 0;
} /* cmdput() */


#ifndef NOTTP
/* scps_sleep -
 *    Do nothing for sec seconds.  While you're waiting, call
 *    sched().
 */
int scps_sleep(sec)
  int sec;
{
  struct timeval start, stop;

  debuglog("sleep(%d)\n", sec);

  Lgettimeofday(&start, (struct timezone *)0);
  while (1) {
    Lgettimeofday(&stop, (struct timezone *)0);
    if (stop.tv_sec - start.tv_sec > sec)
      break;
    sched();   /* yield to TP */
  } /* while */
} /* scps_sleep() */
#endif


#if defined(LARGE)
int cmdquit(int argc, char *argv[]);
#else

/* cmdquit -
 *    Quit
 *    Never returns
 */
int cmdquit(int argc, char *argv[])
{
  int downin = 5;
#ifndef NOTTP
  char msg[80];
#endif
  int result;
#ifdef DO_TIMING
    int32_t end_sec, end_usec;
    int32_t start_sec, start_usec;
#endif

#ifndef NOTTP
  if (argc == 2) {
    result = atoi(argv[1]);
    if (result < 3 || result > 900)
      printf("Invalid downin: %d.  Set to %d\n", result, downin);
    else
      downin = result;
  }
#endif
  if (connected) {
    quitting = 1;
    result = sendcommand("QUIT");
    debuglog("%d <- QUIT", result);
#ifndef NOTTP
    /* "read" the close. */
    while (scps_recv(sctrl, msg, sizeof(msg), flags));
    debuglog("0 <- scps_recv(sctrl)");
#endif
  }
#ifdef DO_TIMING
    (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  scps_close(sctrl);
  sctrl = -1;

#ifdef DO_TIMING
    (void) prtstat_gettime (&end_sec, &end_usec);
    (void) print_timestat("cmdquit","User_cmd", "quit",
                           start_sec,start_usec,
                           end_sec,end_usec, 0, 0);
#endif

#ifndef NOTTP
  printf("Terminating in %d seconds.\n", downin);
  scps_sleep(downin);
#endif

  Lexit(0);

#ifdef MSVC
  /*  I don't like to see warnings.  */
  return (0);
#endif
  return 0;
} /* cmdquit() */
#endif


/* cmdquote -
 *     issues an arbitrary command
 */
int cmdquote(int argc, char *argv[])
{
  char cmdbuf[512];
  int i;

  for (i = 1, cmdbuf[0] = '\0'; ; i++) {
    strcat(cmdbuf, argv[i]);
    if (i + 1 == argc)
      break;
    strcat(cmdbuf, " ");
  } /* for */
  return (sendcommand(cmdbuf));
} /* cmdquote() */


/* cmdread -
 *    Record read (raread command).
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int cmdread(int argc, char *argv[])
{
#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  raread(argc, argv);

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat("raread","User_cmd", "raread",
                         start_sec,start_usec,
                         end_sec,end_usec, 0, 0);
#endif
  return (0);
} /* cmdread() */


/* cmdupdt -
 *    User requested a record update.  Verifies the arguments
 *    and performs the operation.
 *
 *    Sends information to the server that causes it to
 *    update a file.
 *
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int cmdupdt(int argc, char *argv[])
{
   char msgbuf[80];
   int parmerr;
   u_long crcval;
   char remote_path[MAXPATHLEN];
   char remote_fn[MAXPATHLEN];
   int editres;

#ifdef DO_TIMING
   int32_t end_sec, end_usec;
   int32_t start_sec, start_usec;
   (void) prtstat_gettime (&start_sec, &start_usec);
#endif

   parmerr = raupdt_pok(argc, argv, &crcval);
   if (parmerr) {
      raupdt_usage(argv[0]);
      return (0);
   }
   if (0 != sortupdt(argv[5])) {
      Lstrout("Couldn't sort the update signals\n");
      return (0);
   }
   if (0 != (editres = edit(argv[3], argv[4], argv[5]))) {
      /* if the edit didn't work on the local file,
       * it won't work on the remote file, so don't
       * even go to the trouble of establishing a
       * data connection. */
      nsprintf(msgbuf, sizeof(msgbuf),
            "Error updating the local file (%d)\n", editres);
      Lstrout(msgbuf);
      return (0);
   }
   /* split path and file name to facilitate
    * CWD in updtrequest().  Lengths have
    * been checked. */
   path_fn(argv[1], remote_path, remote_fn);
   updtrequest(remote_path, remote_fn, argv[2], crcval, argv[5]);

#ifdef DO_TIMING
    (void) prtstat_gettime (&end_sec, &end_usec);
    (void) print_timestat("raupdt","User_cmd", "raupdt",
                        start_sec,start_usec,
                        end_sec,end_usec, 0, 0);
#endif

   return (0);
} /* cmdupdt() */


/* cmdrestart -
 *     Issue the REST command.
 *
 *     Returns -1 if some error occurred.
 *     Returns 0 otherwise.
 */
int cmdrestart(int argc, char *argv[])
{
#ifdef DO_TIMING
  int result;
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (argc == 1) {
    if (lastsize == -1) {
      printf("No last size.  Please issue the SIZE or LSIZE command.\n");
      return (0);
    } else {
      restart_point = lastsize;
      /* only use lastsize once. */
      lastsize = -1;
    }
  } else {
    restart_point = atoi(argv[1]);
  }
  printf("restarting at %d. execute get or put to initiate transfer\n", restart_point);

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat("restart","User_cmd", "restart",
                        start_sec,start_usec,
                        end_sec,end_usec, 0, 0);
#endif
  return(0);
} /* cmdrestart() */


/* cmdsize -
 *     Issues the size command.
 *
 *     Returns -1 if some error occurred.
 *     Returns 0 otherwise.
 */
int cmdsize(int argc, char *argv[])
{
  char cmdbuf[512];
  int result;
  char *p;

#ifdef DO_TIMING
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

  if (argc < 2) {
    printf("Please specify a file name\n");
    return (0);
  }
  cmdbuf[0] = '\0';
  strcat(cmdbuf, "SIZE ");
  strcat(cmdbuf, argv[1]);
  result = sendcommand(cmdbuf);
  if (result == COMPLETE) {
    reply_string[sizeof(reply_string)-1] = '\0';
    p = strstr(reply_string, "SIZE ");
    if (p != NULL) {
      /* OK.  Now I can save the restart point */
      lastsize = atoi(p+5);
    }
  }

#ifdef DO_TIMING
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat("sizecmd","User_cmd", "size",
                         start_sec,start_usec,
                         end_sec,end_usec, 0, 0);
#endif
  return 0;
} /* cmdsize() */


/* cmdsite -
 *
 */
int cmdsite(int argc, char *argv[])
{
  char cmdbuf[80];

  if (argc == 1) {
    printf("No command to issue.\n");
    return (0);
  } else {
    cmdbuf[0] = '\0';
    strcat(cmdbuf, "SITE ");
    for (argc--, argv++; ; argc--, argv++) {
      strcat(cmdbuf, argv[0]);
      if (argc == 1)
        break;
      strcat(cmdbuf, " ");
    }
  }
  return (sendcommand(cmdbuf));
} /* cmdsite() */


/* cmdsupp -
 *    Issue SUPP--suppress reply text.
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int cmdsupp(int argc, char *argv[])
{
#ifdef DO_TIMING
  int result;
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

#ifdef DO_TIMING
  result = sendcommand("SUPP");
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat("cmdsupp","User_cmd", "suppress",
                          start_sec,start_usec,
                          end_sec,end_usec, 0, 0);
  return (result);
#else
  return (sendcommand("SUPP"));
#endif
} /* cmdsupp() */


/* cmdnsup -
 *    Issue NSUP--replies have text.
 *    Returns -1 if some error occurred.
 *    Returns 0 otherwise.
 */
int cmdnsup(int argc, char *argv[])
{
#ifdef DO_TIMING
  int result;
  int32_t end_sec, end_usec;
  int32_t start_sec, start_usec;
  (void) prtstat_gettime (&start_sec, &start_usec);
#endif

#ifdef DO_TIMING
  result = sendcommand("NSUP");
  (void) prtstat_gettime (&end_sec, &end_usec);
  (void) print_timestat("cmdnsup","User_cmd", "unsuppress",
                          start_sec,start_usec,
                          end_sec,end_usec, 0, 0);
  return (result);
#else
  return (sendcommand("NSUP"));
#endif
} /* cmdnsup() */


char openhelp[] = "open an FP connection: 'open hostname'";
char closehelp[] = "close an FP connection: 'close'";
char quithelp[] = "exit this FP client: 'quit'";
char gethelp[] = "receive a file: 'get filename [localname]'";
char puthelp[] = "send a file: 'put filename [remotename]'";
char rareadhelp[] = "record rd: 'raread rname lname segs force'";
char raupdthelp[] = "record updt: 'raupdt rnamei rnameo lnamei lnameo updtname'";
char noophelp[] = "no operation";
char suppresshelp[] = "cause server to suppress reply text";
char unsuppresshelp[] = "cause server to issue reply text";
char quotehelp[] = "send arbitrary command to server: 'quote cmd [parm1] [parm2]'";
char autorestarthelp[] = "enable autorestart";
char noautoresthelp[] = "disable autorestart";
char idlehelp[] = "set server's idle timeout in sec.: 'idle decimal-n'";
char helphelp[] = "display this information: 'help [command]'";
char sizehelp[] = "query for the size of a remote file: 'size remotename'";
char lsizehelp[] = "query for the size of a local file: 'lsize localname'";
char restarthelp[] = "set the restart point of a file: 'restart [restart_point_in_bytes]'";
char debughelp[] = "toggle debug mode";
char ldebughelp[] = "toggle writing to log file";
char deletehelp[] = "delete a file: 'delete filename'";
char hashhelp[] = "toggle hash mark printing during transfers";
char sitehelp[] = "issue a site specific command: 'site command'";


/*  c_name,      c_help, c_conn, c_proxy, c_func */
static struct cmd cmdtab[] = {
  { "autorestart", autorestarthelp, 1, 1, cmdarst    },
  { "close",       closehelp,       1, 1, cmdclose   },
  { "debug",       debughelp,       0, 0, cmddebug   },
  { "ldebug",      ldebughelp,      0, 0, cmdldebug   },
  { "delete",      deletehelp,      1, 1, cmddelete  },
  { "get",         gethelp,         1, 1, cmdget     },
  { "hash",        hashhelp,        0, 0, cmdhash    },
  { "help",        helphelp,        0, 0, cmdhelp    },
  { "idle",        idlehelp,        1, 1, cmdidle    },
  { "lsize",       lsizehelp,       0, 0, cmdlsize   },
  { "noautorest",  noautoresthelp,  1, 1, cmdnars    },
  { "noop",        noophelp,        1, 1, cmdnoop    },
  { "open",        openhelp,        0, 1, cmdopen    },
  { "put",         puthelp,         1, 1, cmdput     },
  { "quit",        quithelp,        0, 0, cmdquit    },
  { "quote",       quotehelp,       1, 1, cmdquote   },
  { "raread",      rareadhelp,      1, 1, cmdread    },
  { "raupdt",      raupdthelp,      1, 1, cmdupdt    },
  { "restart",     restarthelp,     1, 1, cmdrestart },
  { "size",        sizehelp,        1, 1, cmdsize    },
  { "site",        sitehelp,        1, 1, cmdsite    },
  { "suppress",    suppresshelp,    1, 1, cmdsupp    },
  { "unsuppress",  unsuppresshelp,  1, 1, cmdnsup    },
  { 0 }
};


/* cmdca_initialize -
 *     Client command set A initialization.
 */
void cmdca_initialize(void)
{
  cmdtaba = cmdtab;
} /* cmdca_initialize() */


