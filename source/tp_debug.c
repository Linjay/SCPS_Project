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

#define TPDEBUG_C
#include "scps.h"
#include "scpstp.h"
#include "scpsudp.h"
#include "tp_debug.h"
#include "scps_errorNames.h"
#undef TPDEBUG_C
#include "gmt2local.h"
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>	/* varargs */
#include <string.h>	/* memset */


/* Added for scrub_holes (at bottom of file ) */
/* #include "scpserrno.h" */
#include <sys/types.h>
#include "thread.h"
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "buffer.h"

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_debug.c,v $ -- $Revision: 1.26 $\n";
#endif

char *strcat (char *s, const char *s2);
char *stringNow ();
char *stringNow2 ();
char tempLogString[1024];

extern tp_Socket *tp_allsocs;	/* Pointer to first TP socket */

#include "scps_ip.h"

#ifdef SCPSSP
#include "scps_sp.h"
int sp_ind (scps_sp_rqts * sp_rqts, short length, int *offset);
#endif /* SCPSSP */

#ifdef Sparc
#include <sys/mman.h>
extern int fprintf (FILE * fp, const char *s,...);
extern int printf (const char *s,...);
extern void fclose (FILE * fp);
extern void fflush (FILE * fp);
extern int gettimeofday (struct timeval *tp, struct timezone *tzp);
#endif /* Sparc */

/*
 * The new logging machinery.
 * For every log type (enum LOGFILE_IDENT) we track a number of files.
 * Each tracked file has some private storage (LOGDATASIZE bytes) since
 * static variables, all together now, "are not thread-safe!"
 */
#define MAXLOGFILES 200
#define LOGDATASIZE 512

typedef struct logPair {
  tp_Socket *s;
  char data[LOGDATASIZE];
  FILE *fp;
} logPair;

typedef struct logFileType {
  char name[100];
  int numFiles;
  logPair theFiles[MAXLOGFILES];
} logFileType;

logFileType acknumFiles;
logFileType logFiles;
logFileType logRateFiles;
logFileType sequenceFiles;
logFileType stateFiles;
logFileType timingFiles;
logFileType trimFiles;
logFileType xplotFiles;
logFileType gatewayFiles;

const int CLUSTER_DE_QUEUED = 999;
const int CLUSTER_QUEUED = 333;
const int CLUSTER_UNKNOWN = 666;
int call_chain_depth = 0;
#define CALL_CHAIN_SIZE 50

// static char callChain[CALL_CHAIN_SIZE][100];

#define CHECKING_FREE_CLUSTER_LIST  13
#define CHECKING_FREE_MBUFF_LIST		99
#define CHECKING_OUT_SEQ						33
#define CHECKING_RECEIVE_BUFF				55
#define CHECKING_APP_RBUFF					44
#define CHECKING_UNDEFINED					0

// #define MAX_WALK 100000
#define MAX_WALK -1
char mbufErrorCondition[20] = "UNKNOWN";

static int thiszone = -1;
static int checking = CHECKING_UNDEFINED;

static int logfiles_inited = 0;

#ifdef NOT_DEFINED
double xplot_small_char (char *color, char c, double time, uint32_t seq);
#endif
logPair * findLogPair(tp_Socket *s, LOGFILE_IDENT ident);

static void
initLogFileTypes()
{
  if ( logfiles_inited ) return;
  /* Clear everything.  Important to clear the data. */
  memset(&acknumFiles,	0, sizeof(logFileType));
  memset(&logFiles,	0, sizeof(logFileType));
  memset(&logRateFiles, 0, sizeof(logFileType));
  memset(&sequenceFiles,0, sizeof(logFileType));
  memset(&stateFiles,	0, sizeof(logFileType));
  memset(&timingFiles,	0, sizeof(logFileType));
  memset(&trimFiles,	0, sizeof(logFileType));
  memset(&xplotFiles,	0, sizeof(logFileType));
  memset(&gatewayFiles,	0, sizeof(logFileType));
  /* Set file names. */
  xplotFiles.numFiles = 0;	sprintf(xplotFiles.name, "xplotFile_");
  gatewayFiles.numFiles = 0;	sprintf(gatewayFiles.name, "gatewayFile_");
  trimFiles.numFiles = 0;	sprintf(trimFiles.name,  "trimFile_");
  logFiles.numFiles = 0;	sprintf(logFiles.name,   "logfile_");
  logRateFiles.numFiles = 0;	sprintf(logRateFiles.name, "logRateFile_");
  stateFiles.numFiles = 0;	sprintf(stateFiles.name, "stateFile_");
  acknumFiles.numFiles = 0;	sprintf(acknumFiles.name,"acknumFile_");
  timingFiles.numFiles = 0;	sprintf(timingFiles.name,"timingFile_");
  sequenceFiles.numFiles = 0;	sprintf(sequenceFiles.name, "sequenceFile_");
  logfiles_inited = 1;
}


#define XPLOT_INIT_VALUE 0xF0ACCAFA

typedef struct xplotInfo {
  uint32_t initialized;
  /* */
  uint32_t last_rate_value;
  char	        last_rate_update[50];
  /* */
  uint32_t last_cwnd_value;
  uint32_t last_prevcwnd_value;
  char	        last_cwnd_update[50];
  /* */
  uint32_t last_snd_awnd_value;
  uint32_t last_snd_una_value;
  char          last_ack_update[50];
} xplotInfo;

void
initXplotInfo(tp_Socket *s, xplotInfo *xi)
{
  xi->initialized = XPLOT_INIT_VALUE;
  xi->last_rate_value = 0;
  strcpy(xi->last_rate_update, stringNow2());
  xi->last_cwnd_value = s->snd_cwnd + s->snduna;;
  xi->last_prevcwnd_value = s->snd_prevcwnd + s->snduna;
  strcpy(xi->last_cwnd_update, stringNow2());
  /* */
  strcpy(xi->last_ack_update, stringNow2());
  xi->last_snd_una_value = s->snduna;
  xi->last_snd_awnd_value = s->snduna;
  xi->initialized = XPLOT_INIT_VALUE;
}


void
SCPS_logRate(route *r)
{
  logPair *		theLogPair = NULL;
  xplotInfo *		theInfo = NULL;
  tp_Socket *		s;
  char			curTime[100];

  /*
   * Have to run through all sockets looking for ones that use this route.
   */
  sprintf(curTime, stringNow2());
  for (s = tp_allsocs; s; s = s->next) {
    if ( s==NULL ) break;
    theLogPair = findLogPair(s, xplot);
    if ( theLogPair==NULL ) continue;
    if ( s->rt_route!=r ) continue;
    
    theInfo = (xplotInfo *) &(theLogPair->data);
    if ( theInfo->last_rate_value==s->rt_route->current_credit ) return;
    if ( theInfo->initialized==XPLOT_INIT_VALUE ) {
      /* Log rate to xplot file here. */
      if ( theInfo->last_rate_value!=s->rt_route->current_credit ) {
	logEventv(s, xplot, ";Rate control.\nblue\nline %s %u %s %u\n",
		  theInfo->last_rate_update,
		  s->initial_seqnum + theInfo->last_rate_value,
		  curTime,
		  s->initial_seqnum + theInfo->last_rate_value);
	logEventv(s, xplot, "line %s %u %s %u\n",
		  curTime, s->initial_seqnum + theInfo->last_rate_value,
		  curTime, s->initial_seqnum + s->rt_route->current_credit);
      }
    } else {
      initXplotInfo(s, (xplotInfo *) theInfo);
    }
    strcpy(theInfo->last_rate_update, curTime);
    theInfo->last_rate_value = r->current_credit;
  }
}

void
logPACKET(tp_Socket *s, char *file, int line, uint32_t start, uint32_t len)
{
  logPair *              theLogPair = NULL;
  xplotInfo *            theInfo = NULL;
  char                   curTime[50];

  theLogPair = findLogPair(s, xplot);
  if ( theLogPair==NULL ) {
    return;
  }
  sprintf(curTime, stringNow2());
  theInfo = (xplotInfo *) &(theLogPair->data);

  if ( theInfo->initialized==XPLOT_INIT_VALUE ) {
    logEventv(s, xplot, "white\nline %s %u %s %u\n",
	      curTime, start, curTime, start+len);
    logEventv(s, xplot, "uarrow %s %u\ndarrow %s %u\n",
	      curTime, start+len, curTime, start);
    /*
     * Need to plot SYN, FIN: later.
     */
  } else {
    initXplotInfo(s, (xplotInfo *) theInfo);
  }
}

/*
 * Print xplot information pertinent to an incoming ACK.  This
 * includes plotting snd_una (the green line), snd_awnd(the yellow line)
 * and any dupack ticks. 
 *
 * Need to add SNACK info.
 */
void
logACK(tp_Socket *s, unsigned int acknum, char *file, int line)
{
  logPair *              theLogPair = NULL;
  xplotInfo *            theInfo = NULL;
  char                   curTime[50];

  theLogPair = findLogPair(s, xplot);
  if ( theLogPair==NULL ) {
    return;
  }
  sprintf(curTime, stringNow2());
  theInfo = (xplotInfo *) &(theLogPair->data);

  if ( theInfo->initialized==XPLOT_INIT_VALUE ) {
    /*
     * snduna (the green line)
     */
    logEventv(s, xplot, "; snd_una\n");
    logEventv(s, xplot, "green\nline %s %u %s %u\n",
	      theInfo->last_ack_update, theInfo->last_snd_una_value,
	      curTime,                  theInfo->last_snd_una_value);
    if ( theInfo->last_snd_una_value != s->snduna ) {
      logEventv(s, xplot, "line %s %u %s %u\n",
		curTime, theInfo->last_snd_una_value,
		curTime, acknum);
    }
    /*
     * dupack ticks
     */
    if ( theInfo->last_snd_una_value==s->snduna ) {
      logEventv(s, xplot, "dtick %s %u\n",
		curTime, acknum);
      logEventv(s, xplot, "yellow\nutick %s %u\n",
		curTime, s->lastuwein);
    }
    /*
     * awnd (the yellow line)
     */
    logEventv(s, xplot, "yellow\nline %s %u %s %u\n",
	      theInfo->last_ack_update, theInfo->last_snd_awnd_value,
	      curTime, theInfo->last_snd_awnd_value);
    if ( theInfo->last_snd_awnd_value != s->lastuwein ) {
      logEventv(s, xplot, "line %s %u %s %u\n",
		curTime, theInfo->last_snd_awnd_value,
		curTime, s->lastuwein);
    }
  } else {
    initXplotInfo(s, (xplotInfo *) theInfo);
  }
  strcpy(theInfo->last_ack_update, curTime);
  theInfo->last_snd_awnd_value = s->lastuwein;
  theInfo->last_snd_una_value = acknum;
}


void
logCWND(tp_Socket *s, char *file, int line)
{
  logPair *		theLogPair = NULL;
  xplotInfo *		theInfo = NULL;
  char			curTime[50];

  theLogPair = findLogPair(s, xplot);
  if ( theLogPair==NULL ) {
    return;
  }

  sprintf(curTime, stringNow2());
  theInfo = (xplotInfo *) &(theLogPair->data);
  if ( theInfo->initialized==XPLOT_INIT_VALUE ) {
    /* logEventv(s, xplot, ";\n;logEvent(s, xplot) at %s::%d\n",
     * file, line);
     * logEventv(s, xplot, ";Previous values: last_cwnd_value(%ul)\n",
     * theInfo->last_cwnd_value);
     * logEventv(s, xplot, ";snd_una(%lu) snd_cwnd(%d) snd_prevcwnd(%d)\n",
     * s->snduna, s->snd_cwnd, s->snd_prevcwnd);
     */
    logEventv(s, xplot, "blue\nline %s %u %s %u\n",
	      theInfo->last_cwnd_update, theInfo->last_cwnd_value,
	      curTime, theInfo->last_cwnd_value);
    logEventv(s, xplot, "line %s %u %s %u\n",
	      curTime, theInfo->last_cwnd_value,
	      curTime, s->snd_cwnd+s->snduna);
    logEventv(s, xplot, "magenta\nline %s %u %s %u\n",
	      theInfo->last_cwnd_update, theInfo->last_prevcwnd_value,
	      curTime, theInfo->last_prevcwnd_value);
    logEventv(s, xplot, "line %s %u %s %u\n",
	      curTime, theInfo->last_prevcwnd_value,
	      curTime, s->snd_prevcwnd+s->snduna);
  } else {
    initXplotInfo(s, (xplotInfo *) theInfo);
  }
  strcpy(theInfo->last_cwnd_update, curTime);
  theInfo->last_cwnd_value = s->snd_cwnd + s->snduna;
  theInfo->last_prevcwnd_value = s->snd_prevcwnd + s->snduna;
}


logPair *
findLogPair(tp_Socket *s, LOGFILE_IDENT ident)
{
  int i;
  logFileType *theFile;
  if ( !logfiles_inited ) {
    initLogFileTypes();
  }
  switch ( ident ) {
  case xplot: theFile = &xplotFiles; break;
  case e_gateway: theFile = &gatewayFiles; break;
  case trim: theFile = &trimFiles; break;
  case SCPS_log: theFile = &logFiles; break;
  case logRate: theFile = &logRateFiles; break;
  case state: theFile = &stateFiles; break;
  case acknum: theFile = &acknumFiles; break;
  case timing: theFile = &timingFiles; break;
  case sequence: theFile = &sequenceFiles; break;
  default:
    printf("Unknown LOGFILE_IDENT type %d.  Ignoring\n", ident);
    return(NULL);
  }
  /* Find the socket in the list of logFiles. */
  for ( i=0; i<theFile->numFiles; i++ ) {
    if ( theFile->theFiles[i].s==s ) {
      break;
    }
  }
  if ( theFile->numFiles>=MAXLOGFILES ) {
    printf("Can't have that many (%d) log files open simultaneously.\n",
	   theFile->numFiles);
    return(NULL);
  }
  /*
   * If we didn't find a structure corresponding to this connection and
   * this type of log file, try to open one.
   */
  if ( i==theFile->numFiles ) {
    char newName[100];
    i = theFile->numFiles;
    sprintf(newName, "%s%d_%d", theFile->name, ntohs(s->myport), ntohs(s->hisport));
    theFile->theFiles[i].fp = fopen(newName, "w");
    if ( theFile->theFiles[i].fp==NULL ) {
      printf("Can't open file %s for writing.\n", newName);
      return(NULL);
    } else {
      char prefix[20];
      printf("File %s open.\n", newName);
      theFile->theFiles[i].s = s;
      theFile->numFiles++;
      /*
       * Write some comments so that we can easily plot just what
       * we write without having to run tcptrace
       */
      if ( strncmp(newName, "xplotFile", 9)==0 ) {
#ifdef DEBUG_TCPTRACE
	strcpy(prefix, "");
#else
	strcpy(prefix, ";");
#endif

	logEventv(s, xplot, "%stimeval unsigned\n", prefix);
	logEventv(s, xplot, "%stitle\n%sSCPS debug xplot\n", prefix, prefix);
	logEventv(s, xplot, "%sxlabel\n%stime\n%sylabel\n%ssequence number\n",
		  prefix, prefix, prefix, prefix);
      }
    }
  }
  return(&theFile->theFiles[i]);
}

void
logEventv(tp_Socket *s, LOGFILE_IDENT ident, char *string, ...)
{
  va_list ap;
  logPair *theLogInfo = NULL;
  
#ifdef DEBUG_LOG_FILES_OFF
  return;
#endif /* DEBUG_LOG_FILES_OFF */
  theLogInfo = findLogPair(s, ident);
  if ( theLogInfo==NULL ) {
    printf("Can't find log info.\n");
    return;
  }
  va_start(ap, string);
  vfprintf(theLogInfo->fp, string, ap);
  va_end(ap);
  fflush(theLogInfo->fp);
}

void
logEvent(tp_Socket *s, LOGFILE_IDENT ident, char *string)
{
  int i;
  logFileType *theFile = NULL;
  static int inited = 0;
  if ( !inited ) {
    inited = 1;
    initLogFileTypes();
  }
  switch ( ident ) {
  case xplot: theFile = &xplotFiles; break;
  case e_gateway: theFile = &gatewayFiles; break;
  case trim: theFile = &trimFiles; break;
  case SCPS_log: theFile = &logFiles; break;
  case logRate: theFile = &logRateFiles; break;
  case state: theFile = &stateFiles; break;
  case acknum: theFile = &acknumFiles; break;
  case timing: theFile = &timingFiles; break;
  case sequence: theFile = &sequenceFiles; break;
  default:
    printf("Unknown LOGFILE_IDENT type %d.  Ignoring\n", ident);
    return;
  }
  /* Find the socket in the list of logFiles. */
  for ( i=0; i<theFile->numFiles; i++ ) {
    if ( theFile->theFiles[i].s==s ) {
      fprintf(theFile->theFiles[i].fp, string);
      fflush(theFile->theFiles[i].fp);
      return;
    }
  }
  if ( theFile->numFiles<MAXLOGFILES ) {
    char newName[100];
    sprintf(newName, "%s%d_%d", theFile->name, ntohs(s->myport), ntohs(s->hisport));
    theFile->theFiles[i].fp = fopen(newName, "w");
    if ( theFile->theFiles[i].fp==NULL ) {
      printf("Can't open file %s for writing.\n", newName);
      return;
    } else {
      printf("File %s open.\n", newName);
    }
    theFile->theFiles[i].s = s;
    theFile->numFiles++;
    fprintf(theFile->theFiles[i].fp, string);
    fflush(theFile->theFiles[i].fp);
  } else {
    printf("Can't have that many (%d) log files open simultaneously.\n",
	   theFile->numFiles);
    return;
  }
}

stateNamePair stateNamePairs[] =
{
  {tp_StateNASCENT, "NASCENT"},
  {tp_StateLISTEN, "LISTEN"},
  {tp_StateSYNSENT, "SYNSENT"},
  {tp_StateSYNREC, "SYNREC"},
  {tp_StateESTAB, "ESTAB"},
  {tp_StateCLOSEWT, "CLOSEWAIT"},
  {tp_StateWANTTOCLOSE, "WANTTOCLOSE"},
  {tp_StateWANTTOLAST, "WANTTOLAST"},
  {tp_StateFINWT1PEND, "FINWT1PEND"},
  {tp_StateFINWTDETOUR, "FINWTDETOUR"},
  {tp_StateLASTACKPEND, "LASTACKPEND"},
  {tp_StateFINWT1, "FINWT1"},
  {tp_StateFINWT2, "FINWT2"},
  {tp_StateCLOSING, "CLOSING"},
  {tp_StateLASTACK, "LASTACK"},
  {tp_StateTIMEWT, "TIMEWAIT"},
  {tp_StateCLOSED, "CLOSED"}
};

tp_Socket *G_SOCK = NULL;

char timingStartString[100];

#define BAD_POINTER_VALUE	0x00FFFFFF

void
printState (int theState, struct _tp_socket *s, char *file, int line)
{
  if (stateNamePairs[theState].stateNumber != theState)
    {
      logEventv(s, state, "%s Error in stateNamePairs.\n", stringNow ());
    }
  logEventv(s, state, "%s socket %p %s changes state to %s\n",
	    stringNow (), s, printPorts (s), stateNamePairs[theState].stateName);
}

void
printAcknum (uint32_t a, struct _tp_socket *s, char *file, int line)
{
  static uint32_t biggestSeen = 0;
  if (a <= biggestSeen)
    return;
  biggestSeen = a;
  logEventv(s, acknum, "%s Acknum for socket %p %s advances to %lu\n",
	    stringNow (), s, printPorts (s), a);
}

char *
printPorts (struct _tp_socket *s)
{
  static char foo[500];
  if (s == NULL)
    {
      sprintf (foo, "m(x), h(y)");
    }
  else
    {
      sprintf (foo, "m(%d) h(%d)", ntohs (s->myport), ntohs (s->hisport));
    }
  return (foo);
}

void
tp_buffer_report (int sockid)
{
  tp_Socket *s = (tp_Socket *) scheduler.sockets[sockid].ptr;

  printf ("Closing Summary Report: ==========================\n");
  printf ("System Memory: \n");
  printf ("                   Total Clusters Created = %d Clusters\n",
	  (int) sys_memory.clust_created);
  printf ("Receive_Buffer: \n");
  printf ("                   Max size allowed = %d Clusters\n",
	  s->app_rbuff->max_elements);
  printf ("                   Max size seen = %d Clusters\n",
	  s->app_rbuff->biggest_elements);
  printf ("Send_Buffer: \n");
  printf ("                   Max size allowed = %d Clusters\n",
	  s->app_sbuff->max_elements);
  printf ("                   Max size seen = %d Clusters\n",
	  s->app_sbuff->biggest_elements);
  printf ("============================================\n");
}

void
udp_buffer_report (int sockid)
{
  udp_Socket *s = (udp_Socket *) scheduler.sockets[sockid].ptr;

  printf ("UDP Closing Summary Report: ==================\n");
  printf ("Receive_Buffer: \n");
  printf ("                   Max size allowed = %d Clusters\n",
	  s->app_rbuff->max_elements);
  printf ("                   Max size seen = %d Clusters\n",
	  s->app_rbuff->biggest_elements);
  printf ("Send_Buffer: \n");
  printf ("                   Max size allowed = %d Clusters\n",
	  s->app_sbuff->max_elements);
  printf ("                   Max size seen = %d Clusters\n",
	  s->app_sbuff->biggest_elements);
  printf ("==============================================\n");
}

int
breakMe ()
{
  int foo = 32;
  foo++;
  return (foo % 5);
}

int
badPointer (void *foo, char *file, int line)
{
  return(0);
  if (foo > (void *) BAD_POINTER_VALUE)
    {
      printf ("BAD pointer (%p) at line %d in file %s.\n", foo, line, file);
      fflush (stdout);
      breakMe ();
      return (1);
    }
  return (0);
}

/* status should be one of:
 *	CLUSTER_DE_QUEUED
 *	CLUSTER_QUEUED
 *	CLUSTER_UNKNOWN
 */
int
verify_cl_chain (struct _cl_chain *chain, int status, char *file, int line,
		 tp_Socket * s)
{
  struct mbcluster *mbcluster;
  int num_clusters;
  int found_read_head;
  int found_write_head;
  int errors = 0;

  BAD_POINTER (s);
  if (chain->size > chain->max_size)
    {
      errors++;
      printf ("verify_cl_chain: size(%ld)>max_size(%ld) in %s at line %d\n",
	      chain->size, chain->max_size, file, line);
      fflush (stdout);
    }
  if (chain->size < 0)
    {
      errors++;
      printf ("verify_cl_chain: size(%ld)<0 in file %s at line %d\n",
	      chain->size, file, line);
      fflush (stdout);
    }
  /* Out_Seq_size is set but never used by anything and is suspected
     * to be bogus. --KS
     * if ( chain->Out_Seq_size>chain->max_size ) {
     *   printf("WARNING:  _cl_chain->Out_Seq_size>_cl_chain->max_size\n");
     *   fflush(stdout);
     * }
   */
  if (chain->num_elements < 0)
    {
      errors++;
      printf ("verify_cl_clain: num_elements < 0\n");
    }
  if (chain->write_off < 0)
    {
      errors++;
      printf ("verify_cl_clain: write_off(%ld)<0\n", chain->write_off);
    }
  if (chain->read_off < 0)
    {
      errors++;
      printf ("verify_cl_clain: read_off(%ld)<0\n", chain->read_off);
    }

  found_read_head = 0;
  found_write_head = 0;
  num_clusters = 0;
  if ((!chain->start) && (num_clusters > 0))
    {
      errors++;
      printf
	("verify_cl_chain: Error %d elements advertised, but no start!\n", chain->num_elements);
    }

  /* Check forward threading */
  BAD_POINTER (chain->start);
  if ((mbcluster = chain->start))
    {
      num_clusters = 1;

      while (mbcluster)
	{
	  if (num_clusters > 10000)
	    {
	      errors++;
	      printf("%s Seen more than 10,000 clusters in verify_cl_chain.\n",
		 stringNow ());
	      print_chain_from_cluster (mbcluster);
	      abort ();
	    }

	  num_clusters++;
	  errors += verify_mbcluster (mbcluster, status, file, line, s);
	  if (mbcluster == chain->read_head)
	    found_read_head = 1;
	  if (mbcluster == chain->write_head)
	    found_write_head = 1;
	  if (mbcluster->c_next == NULL)
	    {
	      if (mbcluster != chain->last)
		{
		  errors++;
		  printf("%s verify_cl_chain: last cluster in forward chain(%p) != chain->last(%p) file<%s> line<%d>\n",
		     stringNow (), mbcluster, chain->last, file, line);
		  print_chain_from_cluster (mbcluster);
		}
	    }
	  mbcluster = mbcluster->c_next;
	}
      num_clusters--;
      if (num_clusters != chain->num_elements)
	{
	  errors++;
	  printf
	    ("verify_cl_chain: We only counted %d of %d clusters in the forward chain!\n",
	     num_clusters, chain->num_elements);
	}
      if ((chain->read_head != NULL) && !found_read_head)
	{
	  errors++;
	  printf
	    ("verify_cl_chain: couldn't find read head (%p) in forward search of %d elements.\n",
	     chain->read_head, chain->num_elements);
	}
      if ((chain->write_head != NULL) && !found_write_head)
	{
	  errors++;
	  printf
	    ("verify_cl_chain: couldn't find write head (%p) in forward search of %d elements.\n",
	     chain->write_head, chain->num_elements);
	}
    }

  /* Check reverse threading */

  BAD_POINTER (chain->last);
  if ((mbcluster = chain->last))
    {
      num_clusters = 1;
      found_read_head = 0;
      found_write_head = 0;

      while (mbcluster)
	{
	  num_clusters++;
	  errors += verify_mbcluster (mbcluster, status, file, line, s);
	  if (mbcluster == chain->read_head)
	    found_read_head = 1;
	  if (mbcluster == chain->write_head)
	    found_write_head = 1;
	  if (mbcluster->c_prev == NULL)
	    {
	      if ((chain->start) && (mbcluster != chain->start))
		{
		  errors++;
		  printf
		    ("%s verify_cl_chain: last cluster in reverse chain(%p) != chain->start(%p)\n",
		     stringNow (), mbcluster, chain->start);
		  print_chain_from_cluster (mbcluster);
		}
	    }
	  mbcluster = mbcluster->c_prev;
	}
      num_clusters--;

      if (num_clusters < chain->num_elements)
	{
	  errors++;
	  printf
	    ("verify_cl_chain: We only counted %d of %d clusters in the reverse chain!\n",
	     num_clusters, chain->num_elements);
	}
      if ((chain->read_head != NULL) && !found_read_head &&
	  (chain->num_elements > 0))
	{
	  errors++;
	  printf
	    ("verify_cl_chain: couldn't find read head (%p) in reverse search of %d elements.\n",
	     chain->read_head, chain->num_elements);
	}
      if ((chain->write_head != NULL) && !found_write_head &&
	  (chain->num_elements > 0))
	{
	  errors++;
	  printf
	    ("verify_cl_chain: couldn't find write head (%p) in reverse search of %d elements.\n",
	     chain->write_head, chain->num_elements);
	}
    }
  else if ((chain->start != NULL) || (chain->num_elements != 0))
    {
      errors++;
      printf ("verify_cl_chain: There is no last element for app_rbuff!\n");
    }
  else
    {
      /* OK */
    }

  BAD_POINTER (chain->read_head);
  BAD_POINTER (chain->write_head);
  if (chain->read_off > SMCLBYTES)
    {
      errors++;
      printf ("verify_cl_chain: read_off of %ld looks suspicious.\n", chain->read_off);
    }
  if (chain->write_off > SMCLBYTES)
    {
      errors++;
      printf ("verify_cl_chain: write_off of %ld looks suspicious.\n", chain->write_off);
    }
  if (errors)
    {
      printf ("%s errors detected in cl_chain(%p) %s %d\n",
	      stringNow (), s, file, line);
      fflush (stdout);
    }
  return (1);
}

int
print_buffer (struct _buffer *b)
{
//      printf("=== Buffer at %p start(%p) last(%p) parent(%p):\n",
//                                b, b->start, b->last, b->parent);
//      print_mbuf_chain(b->start);
  return (0);
}

int
print_mbuf_chain (struct mbuff *m, char *file, int line)
{
  int index = 0;
  int errors = 0;
  printf ("=== mbuff chain starting at %p\n", m);
  fflush (stdout);
  while (m)
    {
      index++;
      printf ("Walked %s more than %d:: mbuff at %p forward(%p) reverse(%p) parent(%p)",
	      mbufErrorCondition, MAX_WALK,
	      m, m->m_next, m->m_prev, m->parent);
      if ( m->parent==&sys_memory.fblist ) {
	printf("[FREE LIST]");
      }
      printf("\n");
      if (m->m_hdr.mh_flags & M_EXT)
	{
	  errors++;
	  printf ("file<%s> line<%d> ext_buf (mbcluster *) for mbuff at %p is at %p:\n",
		  file, line,
		  m, m->M_dat.MH.MH_ext.ext_buf);
	  print_chain_from_cluster ((struct mbcluster *) m->M_dat.MH.MH_ext.ext_buf);
	}
      m = m->m_next;
    }
  return (errors);
}

int
mbcluster_pointer_walk (struct mbcluster *c)
{
  int numWalked = 0;
  struct mbcluster *temp = c;
  struct mbcluster *tempEnd;
  BAD_POINTER (temp);
  if (temp == NULL)
    return (0);
  while (temp->c_next)
    {
      BAD_POINTER (temp->c_next);
      temp = temp->c_next;
      numWalked++;
    }
  tempEnd = temp;
  numWalked = 0;
  while (temp->c_prev )
    {
      BAD_POINTER (temp->c_prev);
      if (numWalked > MAX_WALK && MAX_WALK>0)
	{
	  printf ("Walked more than %d mbcluster_pointer_walk\n", MAX_WALK);
	  fflush (stdout);
	}
      temp = temp->c_prev;
      numWalked++;
    }
  return (0);
}

/*
 * Return the number of buffers found or a negative number on error.
 */
int
mbuff_pointer_walk (struct mbuff *m, int size, char *file, int line)
{
  int error = 0;
  int numForward = 0;
  int numReverse = 0;
  struct mbuff *temp = m;
  BAD_POINTER (temp);
  if (temp == NULL)
    return (0);
  numForward = numReverse = 1;
  while ( temp->m_next )
    {
      BAD_POINTER (temp->m_next);
      if (numForward++ > size && size>0)
	{
	  printf
	    ("Walked forward more than %d mbuff_pointer_walk %s %d\n",
	     size, file, line);
	  fflush (stdout);
	  print_mbuf_chain (m, file, line);
	  error = 1;
	}
      temp = temp->m_next;
    }
  while (temp->m_prev)
    {
      BAD_POINTER (temp->m_prev);
      if (numReverse++ > size && size>0)
	{
	  printf ("Walked back more than %d mbuff_pointer_walk %s %d\n",
		  size, file, line);
	  fflush (stdout);
	  print_mbuf_chain (m, file, line);
	  error = 1;
	}
      temp = temp->m_prev;
    }
  if ( numForward!=numReverse ) {
	printf("%s %d mbuff_pointer_walk: numForward(%d)!=numReverse(%d)\n", file, line, numForward, numReverse);
  }
  if ( error ) return(-1);
  return (numForward);
}

int
verify_sys_lists (char *file, int line)
{
  int numMbuffs;
  BAD_POINTER (sys_memory.fblist.start);
  BAD_POINTER (sys_memory.fblist.last);
  checking = CHECKING_FREE_CLUSTER_LIST;
  mbcluster_pointer_walk (sys_memory.fclist.start);
  checking = CHECKING_FREE_MBUFF_LIST;
  if ((sys_memory.fblist.b_size ==0) && (sys_memory.fblist.start == NULL) && 
      (sys_memory.fblist.last) )  {
    checking = CHECKING_UNDEFINED;
    return (0);
  }
  numMbuffs = mbuff_pointer_walk (sys_memory.fblist.start, sys_memory.fblist.b_size, file, line); 
      
  if ( (numMbuffs>=0) && (numMbuffs!=sys_memory.fblist.b_size) ) {
	printf("%s %d: b_size(%ld) doesn't match number in list for sys_memory.fblist(%d)\n",
	       file, line, sys_memory.fblist.b_size, numMbuffs);
	printf("        start(%p) last(%p)\n", sys_memory.fblist.start, sys_memory.fblist.last);
  }
  if ( (sys_memory.fblist.start==NULL)&&(sys_memory.fblist.last==NULL)&&(sys_memory.fblist.b_size>0) ) {
	printf("Pat's test failed at %s::%d\n", file, line);
  }
  checking = CHECKING_UNDEFINED;
  return (0);
}

/*
 * See if the last pointer in the sockets receive_buff matches
 * the last mbuff in the receive_buff chain.
 */
int
bug_hunt (tp_Socket * s, char *file, int line)
{
  int error = 0;
  if (s == NULL)
    s = G_SOCK;
  BAD_POINTER (s);
  verify_sys_lists (file, line);
  if (s != NULL) {
    BAD_POINTER (s->app_rbuff);
    BAD_POINTER (s->receive_buff);
    BAD_POINTER (s->Out_Seq);
    if ( verify_buffer (s->send_buff, file, line) ) {
      printf("Buffer that failed: s->send_buff\n");
      error = 1;
    }
    checking = CHECKING_RECEIVE_BUFF;
    if ( verify_buffer (s->receive_buff, file, line) ) {
      printf("Buffer that failed: s->receive_buff\n");
      error = 1;
    }
    checking = CHECKING_OUT_SEQ;
    if ( verify_buffer (s->Out_Seq, file, line) ) {
      printf("Buffer that failed: s->Out_Seq\n");
      error = 1;
    }
    checking = CHECKING_APP_RBUFF;
    verify_cl_chain (s->app_rbuff, CLUSTER_UNKNOWN, file, line, s);
    verify_cl_chain (s->app_sbuff, CLUSTER_UNKNOWN, file, line, s);
    checking = CHECKING_UNDEFINED;

    /*
     * Check integrity of readable and writable socket lists (GATEWAY version)
     */
#ifdef GATEWAY_SELECT
#ifdef NOT_YET
    /*
     * This is bad since partially open sockets aren't on tp_allsocs.
     */
    if ( s->thread->write_socks ) {
      for ( tmp=(tp_Socket *) (s->thread->write_socks); tmp; tmp=tmp->write_next ) {
	if ( !isValidSocket(tmp) ) {
	  printf("Invalid socket found on write_socks list.\n");
	  error = 1;
	}
	if ( tmp->write_parent!=(caddr_t *) &(s->thread->write_socks) ) {
	  printf("Bad write_parent for socket on write_socks list.\n");
	  error = 1;
	}
	if ( tmp->write_next && tmp->write_next->write_prev!=tmp ) {
	  printf("Bad linkages in write_socks list.\n");
	  error = 1;
	}
	if ( tmp->write_prev && tmp->write_prev->write_next!=tmp ) {
	  printf("Bad linkages in write_socks list.\n");
	  error = 1;
	}
      }
    }
    if ( s->thread->read_socks ) {
      for ( tmp=(tp_Socket *) (s->thread->read_socks); tmp; tmp=tmp->read_next ) {
	if ( !isValidSocket(tmp) ) {
	  printf("Invalid socket found on read_socks list.\n");
	  error = 1;
	}
	if ( tmp->write_parent!=(caddr_t *) &(s->thread->write_socks) ) {
	  printf("Bad write_parent for socket on write_socks list.\n");
	  error = 1;
	}
	if ( tmp->read_next && tmp->read_next->read_prev!=tmp ) {
	  printf("Bad linkages in read_socks list.\n");
	  error = 1;
	}
	if ( tmp->read_prev && tmp->read_prev->read_next!=tmp ) {
	  printf("Bad linkages in read_socks list.\n");
	  error = 1;
	}
      }
    }
#endif /* NOT_YET */
#endif /* GATEWAY_SELECT */
  }
  if ( error ) {
    printf("Bug Hunt failure at file<%s> line<%d>\n", file, line);
  }
  fflush (stdout);
  return (0);
}

int
print_check ()
{
  if (!G_SOCK)
    {
      return (0);
    }
  printf ("\n");
  printf ("Printing info for socket %p\n", G_SOCK);
  printf ("  app_rbuff (cl_chain *) is: %p start(%p) last(%p)\n",
	  G_SOCK->app_rbuff, G_SOCK->app_rbuff->start, G_SOCK->app_rbuff->last);
  print_chain_from_cluster (G_SOCK->app_rbuff->start);
  printf ("  receive_buff (buffer *) is	%p\n", G_SOCK->receive_buff);
  print_buffer (G_SOCK->receive_buff);
  printf ("====== End of socket %p =========\n\n", G_SOCK);
  fflush (stdout);
  return (0);
}

int
print_cluster_chain (struct _cl_chain *c)
{
  printf ("cluster_chain at %p start(%p) last(%p)\n",
	  c, c->start, c->last);
  print_chain_from_cluster (c->start);
  return (0);
}

/* Given an mbcluster, try to print the whole chain. */
int
print_chain_from_cluster (struct mbcluster *c)
{
  struct mbcluster *temp;
  char tempChar[100];
  temp = c;
  return(0);
  while (temp->c_prev)
    temp = temp->c_prev;
  while (temp)
    {
      int i;
      memcpy (tempChar, temp->c_data, 10);
      tempChar[10] = '\0';
      for (i = 0; i < 10; i++)
	{
	  if (!isalnum (tempChar[i]))
	    tempChar[i] = ' ';
	}
      if (temp->c_prev && temp->c_prev->c_next != temp)
	{
	  printf ("<");
	}
      else
	{
	  printf (" ");
	}
      if (temp->c_next && temp->c_next->c_prev != temp)
	{
	  printf (">");
	}
      else
	{
	  printf (" ");
	}
      printf
	(" mbcluster element at %p forward:%p reverse:%p parent:%p [%s]\n",
	 temp, temp->c_next, temp->c_prev, temp->parent, tempChar);
      fflush (stdout);
      temp = temp->c_next;
    }
  fflush (stdout);
  return (0);
}


int
mbclusterIsInChain (struct mbcluster *m, struct _cl_chain *c)
{
  struct mbcluster *temp;
  temp = c->start;
  while (temp)
    {
      if (temp == m)
	return (1);
      temp = temp->c_next;
    }
  return (0);
}

/* status should be one of:
 *	CLUSTER_DE_QUEUED
 *	CLUSTER_QUEUED
 *	CLUSTER_UNKNOWN
 */
int
verify_mbcluster (struct mbcluster *m, int status, char *file, int line,
		  tp_Socket * s)
{
  int error = 0;

  BAD_POINTER (m);
  if (m == NULL)
    return (0);
  BAD_POINTER (m->c_next);
  BAD_POINTER (m->c_prev);
  BAD_POINTER (m->parent);

  if (m->c_next && (m->c_next->c_prev != m))
    {
      /*
       * We can do better checking of linkages if we're given a sockeet because... sometimes
       * the chain isn't truly doubly linked.  For example, if there's data on
       * snd_una that has been read out of the applications send buffer
       * s->app_sbuff, then the clusters pointed to by s->send_buff->snd_una may
       * have a forward path to s->app_sbuff, but there may be NO REVERSE PATH from
       * clusters pointed to by s->app_sbuff back to the clusters pointed to by
       * s->send_buff->snd_una.
       */
      if (s)
	{
	  /*
	   * We may be in the condition stated above.  For now we will declare the
	   * structure OK if
	   *
	   *    The broken backwards link is pointed to by s->app_sbuff->start or s->app_rbuff->start
	   */
	  printf ("verify_mbcluster: full check.\n");
	  if (!mbclusterIsInChain (m, s->app_sbuff) && !mbclusterIsInChain
	      (m, s->app_rbuff))
	    {
	      printf
		("verify_mbcluster: broken reverse link in chain in file %s at line %d.\n",
		 file, line);
	      printf ("mbcluster(%p) has:\n", m);
	      print_chain_from_cluster (m);
	      if (G_SOCK)
		{
		  printf ("G_SOCK has:\n");
		  if (G_SOCK->receive_buff->start)
		    {
		      if (G_SOCK->receive_buff->start->m_flags == 0x01)
			{
			  print_chain_from_cluster ((struct mbcluster *) G_SOCK->receive_buff->start->m_ext.ext_buf);
			  fflush (stdout);
			}
		      printf ("ERROR CONDITION\n");
		      print_check ();
		    }
		}
	      error++;
	    }
	}
      else
	{
	  /*
	     * We can only check for the most bogus of events.
	     * If the next guy has a reverse link that's not NULL AND not us,
	     * that's probably an error.
	   */
	  if (m->c_next && m->c_next->c_prev && m->c_next->c_prev != m)
	    {
	      printf
		("verify_mbcluster: broken reverse link in chain in file %s at line %d.\n",
		 file, line);
	      printf ("mbcluster(%p) has:\n", m);
	      print_chain_from_cluster (m);
	      if (G_SOCK)
		{
		  printf ("G_SOCK has:\n");
		  if (G_SOCK->receive_buff->start)
		    {
		      if (G_SOCK->receive_buff->start->m_flags == 0x01)
			{
			  print_chain_from_cluster ((struct mbcluster *) G_SOCK->receive_buff->start->m_ext.ext_buf);
			  fflush (stdout);
			}
		      printf ("ERROR CONDITION\n");
		      print_check ();
		    }
		}
	      error++;
	    }
	}
    }
  /*
   * This should always work.
   */
  if (m->c_prev && (m->c_prev->c_next != m))
    {
      printf
	("verify_mbcluster: broken forward link in chain in file %s at line %d.\n",
	 file, line);
      printf ("mbcluster(%p) has\n", m);
      print_chain_from_cluster (m);
      if (G_SOCK)
	{
	  printf ("G_SOCK has:\n");
	  if (G_SOCK->receive_buff->start->m_flags == 0x01)
	    {
	      print_chain_from_cluster ((struct mbcluster *) G_SOCK->receive_buff->start->m_ext.ext_buf);
	      fflush (stdout);
	    }
	  printf ("ERROR CONDITION\n");
	  print_check ();
	}
      error++;
    }
  if (m->tail > SMCLBYTES)
    {
      printf ("verify_mbcluster: tail(%d) > SMCLBYTES(%d)\n", m->tail, SMCLBYTES);
    }
  if ((m->c_count < 0) || (m->c_count > 1000))
    {
      printf ("verify_mbcluster: c_count (%d) is suspicious\n", m->c_count);
    }
  /* The following are listed in the mbcluster definition as "used for debugging", so I
     * suspect that they're bogus for now.
   */
  if ((m->mbuffs < 0) || (m->mbuffs > 1000))
    {
      printf ("verify_mbcluster: mbuffs (%d) is suspicious\n", m->mbuffs);
    }
  if (status != CLUSTER_UNKNOWN)
    {
      if (!m->de_queued && (status == CLUSTER_DE_QUEUED))
	{
	  printf
	    ("verify_mbcluster: de_queued is NOT set in a cluster we think IS on the free list.\n");
	}
      if (m->de_queued && (status == CLUSTER_QUEUED))
	{
	  printf
	    ("verify_mbcluster: de_queued IS set in a cluster we think IS NOT on the free list.\n");
	}
    }
  /* I don't do anything with m->was_outseq. */
  if (error)
    {
      printf
	("verify_mbcluster(%p): errors detected in file %s at line %d.\n",
	 m, file, line);
    }
  return (error);
}

/* In addition to simply verifying the buffer b, verify_Receive_Buff also makes
 * sure that the size of the data in the mbuffers matches the size advertised.
 */
int
verify_Receive_Buff (struct _buffer *b)
{
  int element_num, data_size, error;
  struct mbuff *ptr, *last_ptr;

  error = 0;
  verify_buffer (b, "", 0);
//  if ( ((tp_Socket *)b->parent)->receive_buff != b) {
//              printf("verify_receive_buff: b doesn't seem to be a receive buffer for it parent.\n");
//  }
  fflush (stdout);

  last_ptr = NULL;
  ptr = b->start;

  element_num = 0;
  data_size = 0;
  while (ptr)
    {
      element_num++;

      data_size += ptr->m_plen;
      if (ptr->m_ext.ext_buf == NULL)
	{
	  printf
	    ("verify_Receive_Buff: Element #%d (seq# %lu)(%x) has no external buffer attached!\n",
	     element_num, ptr->m_seq, ptr->m_plen);
	}
      last_ptr = ptr;
      ptr = ptr->m_next;
    }

  if (error)
    {
      printf ("verify_receive_buff:Error(s) detected\n");
    }
  fflush (stdout);
  return (1);
}


/* Verify the internal structures of a struct _buffer */
/* Return positive integer on error. */
int
verify_buffer (struct _buffer *b, char *file, int line)
{
  int element_num, error;
  struct mbuff *ptr, *last_ptr;
  struct _hole_element *h;

  error = 0;

  if (b->b_size > b->max_size)
    {
      printf ("verify_buffer (%p): size(%ld)>max_size(%ld)\n", b, b->b_size, b->max_size);
      error++;
    }
  if ((b->num_elements < 0) || (b->num_elements > 10000))
    {
      printf ("verify_buffer (%p): num_elements(%d) looks suspicious\n", b, b->num_elements);
      error++;
    }
  if (b->num_elements > b->max_elements)
    {
      printf ("verify_buffer (%p): num_elements(%d)>max_elements(%d)\n", b,
	      b->num_elements, b->max_elements);
      error++;
    }

  /* Don't do anything with biggest for now.            */
  /* Don't do anything with data_size for now.          */
  /* Don't do anything with biggest_elements for now.   */
  /* Don't do anything with flags for now.              */

  BAD_POINTER (b->start);
  BAD_POINTER (b->last);
  BAD_POINTER (b->snd_una);
  BAD_POINTER (b->send);
  BAD_POINTER (b->holes);
/*  BAD_POINTER (b->parent); */

  last_ptr = NULL;
  ptr = b->start;

  if ((!(ptr)) && (b->b_size > 0))
    {
      printf
	("verify_buffer (%p): Screwed! You have a size, but no start!\n", b);
      printf ("                size = %ld, last = %p\n", b->b_size, b->last);
      error++;
    }

  for (h = b->holes; h != NULL; h = h->next)
    {
      verify_hole (h, file, line);
    }

  element_num = 0;
  while (ptr)
    {
      element_num++;
      error += verify_mbuff (ptr, file, line);
      if (ptr->parent != b)
	{
#ifdef UNDEFINED
//                      if ( ((tp_Socket *)b->parent)->receive_buff==b ) {
//                              /* the buffer we're verifying is a receive_buff */
//                              if ( ((tp_Socket *)b->parent)->Out_Seq==ptr->parent ) {
///*                                    printf("verify_buffer (%p): mbuff %p (seq# %lu) is on receive_buff(%p) with parent Out_Seq(%p)\n",
// *                                                             b, ptr, ptr->m_seq, b, ptr->parent);
// */
//                              } else {
//                                      printf("verify_buffer (%p): mbuff %p (seq# %lu) is on receive_buff(%p) with parent ???(%p)\n",
//                                                               b, ptr, ptr->m_seq, b, ptr->parent);
//                                      error++;
//                              }
//                      }
#endif /* UNDEFINED */
	}
      last_ptr = ptr;
      ptr = ptr->m_next;
    }

  if (element_num != b->b_size)
    {
/*     printf("verify_buffer (%p):We found %d elements, but b->size was %ld\n", b, element_num, b->size);
 *     error++;
 */
    }

  if (last_ptr != b->last)
    {
      printf
	("verify_buffer (%p): Last_ptr (%p) doesn't match b->last (%p)\n",
	 b, last_ptr, b->last);
      error++;
    }

  if (error)
    {
      printf
	("verify_buffer (%p) :Error(s) detected in file %s at line %d\n",
	 b, file, line);
      fflush (stdout);
      return (-1);
    }
  fflush (stdout);
  return (error);
}

int
verify_mbuff (struct mbuff *m, char *file, int line)
{
  int error = 0;
  int advertised_size = 0;
  struct mbcluster *temp_ptr = NULL;
  BAD_POINTER (m);
  if (m == NULL)
    return (0);
  BAD_POINTER (m->parent);
  BAD_POINTER (m->m_prev);
  BAD_POINTER (m->m_next);
  if ((m->m_prev) && (m->m_prev->m_next != m))
    {
      printf ("verify_mbuff(%d): Broken links in chain!\n", checking);
      printf
	("               (seq# %lu)(%p) previous neighbor points to %p\n",
	 m->m_seq, m, m->m_prev->m_next);
      error++;
    }
  if ((m->m_next != NULL) && (m->m_next->m_prev != m))
    {
      printf ("verify_mbuff(%d): Broken links in chain!\n", checking);
      printf
	("               (seq# %lu)(%p) next neighbor points back to %p\n",
	 m->m_seq, m, m->m_next->m_prev);
      error++;
    }
  /* Do I need to check one of m_flags before looking at m_plen?
   * m_plen expands to M_dat.MH.MH_pkthdr.len and M_dat and M_dat is outside
   * the union in the mbuff structure...
   */
  if (m->m_plen < 0)
    {
      printf ("verify_mbuff: checking(%d) seq#(abs=%lu) mbuff(%p) has a data_length of %d \n %s ",
	      checking,
	      m->m_seq,
	      m,
	      m->m_plen,
	      (m->m_flags & M_EXT) ? "M_EXT is set." : "M_EXT is not set.");
      error++;
    }
  if (m->m_flags & M_EXT)
    {
      /* This mbuff points to a cluster.  Check that too. */
      BAD_POINTER (m->m_ext.ext_buf);
      error += verify_mbcluster ((struct mbcluster *) m->m_ext.ext_buf,
				 CLUSTER_UNKNOWN, file, line, NULL);

      /* Check to see that there is enough cluster range to match advertized */
      advertised_size = m->m_plen;
      temp_ptr = (struct mbcluster *) m->m_ext.ext_buf;
      advertised_size -= (SMCLBYTES - m->m_ext.offset);
      while (advertised_size > 0)
	{
	  temp_ptr = temp_ptr->c_next;
	  advertised_size -= SMCLBYTES;
	  if ((temp_ptr == NULL) && (advertised_size > 0))
	    {
	      printf
		("verify_mbuff(%d): (seq# %lu - offset %u) (%p) should have %d bytes of data attached, but we seem to be %d bytes short!\n",
		 checking, m->m_seq, m->m_ext.offset, m, m->m_plen, advertised_size);
	      advertised_size = 0;
	    }
	}
    }
  fflush (stdout);
  if (error)
    {
      printf
	("verify_mbuff(%d) (buf=%p): errors detected in file %s at line %d.\n",
	 checking, m, file, line);
    }
  return (error);
}

/* This is NOT COMPLETE YET (sockets are BIG) */
/* See the BUG_HUNT macro. */
int
verify_Socket (tp_Socket * s)
{
  printf ("%s %s verify_socket not implemented yet.  Try BUG_HUNT?\n",
	  stringNow (), printPorts (s));
  return (0);
}

char *
flagsString (int flags)
{
  static char foo[100];
  foo[0] = '\0';
  if (flags & tp_FlagFIN)
    strcat (foo, "FIN ");
  if (flags & tp_FlagSYN)
    strcat (foo, "SYN ");
  if (flags & tp_FlagRST)
    strcat (foo, "RST ");
  if (flags & tp_FlagPUSH)
    strcat (foo, "PSH ");
  if (flags & tp_FlagACK)
    strcat (foo, "ACK ");
  if (flags & tp_FlagURG)
    strcat (foo, "URG ");
  if (flags & tp_FlagEOR)
    strcat (foo, "EOR ");
  if (flags & tp_FlagDO)
    strcat (foo, "DO  ");
  return (foo);
}

void
print_now ()
{
  struct timeval foo;
  struct timezone bar;
  gettimeofday (&foo, &bar);
  ts_print (&foo);
}

char *
stringNow2 ()
{
  static char tempString[100];
  struct timeval foo;
  gettimeofday (&foo, NULL);
  sprintf (tempString, "%lu.%06lu", foo.tv_sec, foo.tv_usec);
  return (tempString);
}

char *
stringNow3 (double offset)
{
#define NUMINDICES 15
  double bar;
  static int index = 0;
  static char tempString[NUMINDICES][100];
  struct timeval foo;
  index = (index + 1) % NUMINDICES;
  gettimeofday (&foo, NULL);
  bar = foo.tv_sec + (double) foo.tv_usec / 1000000;
  bar += offset;
  sprintf (tempString[index], "%f", bar);
  return (tempString[index]);
}

char *
stringNow ()
{
  static char tempString[100];
  struct timeval foo;
  struct timezone bar;
  int tflag = 1;
  register int s;
  gettimeofday (&foo, &bar);

  if (thiszone < 0)
    {
      thiszone = gmt2local (0);
    }
  if (tflag > 0)
    {
      /* Default */
      s = (foo.tv_sec + thiszone) % 86400;
      (void) sprintf (tempString, "%02d:%02d:%02d.%06u ",
		      s / 3600, (s % 3600) / 60, s % 60, (unsigned int) foo.tv_usec);
    }
  else if (tflag < 0)
    {
      /* Unix timeval style */
      (void) sprintf (tempString, "%u.%06u ",
		      (unsigned int) foo.tv_sec, (unsigned int) foo.tv_usec);
    }
  return (tempString);
}

/*
 * Print the timestamp
 */
void
ts_print (register const struct timeval *tvp)
{
  (void) printf ("%s", stringNow ());
}


int
fileExists (char *name)
{
  FILE *foo = NULL;
  static int bar = 0;
  if (bar == 0)
    {
      foo = fopen (name, "r");
      if (foo != NULL)
	{
	  fclose (foo);
	  return (1);
	}
    }
  return (0);
}

int
mbuffIsOnList (struct mbuff *m, struct mbuff *mlist)
{
  struct mbuff *temp = mlist;
  while (temp)
    {
      if (temp == m)
	return (1);
      temp = temp->m_next;
    }
  return (0);
}

int
verify_buffer_holes (struct _buffer *b, char *file, int line)
{
  struct _hole_element *h;
  int foo = 0;
  int error = 0;
  for (h = b->holes, foo = 0; h != NULL; h = h->next, foo++)
    {
//    printf("hole element[%d](%p)\n", foo, h);
      error += verify_hole (h, file, line);
    }
  if (!error)
    {
//    printf("%s verify_buffer_holes passed.\n", stringNow());
    }
  return (error);
}

int
verify_hole (struct _hole_element *h, char *file, int line)
{
  int error = 0;
  struct mbuff *temp = h->hole_start;

  if (SEQ_GT (temp->m_seq, h->hole_end_seq))
    {
      printf
	("%s hole's first mbuff starts at %lu, hole ends at %u %s %d!!\n",
	 stringNow (), temp->m_seq, h->hole_end_seq, file, line);
      return (1);
    }
  return (0);

  while (temp)
    {
      /*
       * It is suspicious if the mbuffer is not fully contained by
       * the hole (hole_start_seq < buffer < hole_end_seq
       */
      if (SEQ_LT (temp->m_seq, h->hole_start_seq)
	  || SEQ_GEQ (temp->m_seq + temp->m_ext.len, h->hole_end_seq))
	{
	  printf ("%s mbuff on hole list not in hole space %s %d.\n",
		  stringNow (), file, line);
	  printf ("    hole_start_seq(%u), hole_end_seq(%u), m_seq(%lu)\n",
		  h->hole_start_seq, h->hole_end_seq, temp->m_seq);
	  error++;
	}
      temp = temp->m_next;
    }
  return (error);
}

/* Scrub holes - a routine to walk hole structures 
 * and find anomalies 
 */

#define VERBOSE

#define TEST_1_FAIL 1
#define TEST_2_FAIL 2
#define TEST_3_FAIL 4
#define TEST_4_FAIL 8
#define TEST_5_FAIL 16
#define TEST_6_FAIL 32
#define TEST_7_FAIL 64
#define TEST_8_FAIL 128
#define TEST_9_FAIL 256

int
scrub_holes (tp_Socket * s, char *file, int line)
{
  int retval = 0;
  int done = 0;
  int len = 0;
  int hole_idx = 0;
  struct _hole_element *hole;
  struct mbuff *mbuff;
  uint32_t prev_start_seq = -1;
  uint32_t prev_end_seq = -1;


  /* Is the starting sequence number in the hole equal to the starting 
   * sequence number in hole_start?
   */

  if ((s->send_buff->holes))
    {
      for (hole = s->send_buff->holes; hole; hole = hole->next)
	{
	  hole_idx++;

	  if (hole == s->send_buff->holes)
	    {
	      prev_start_seq = hole->hole_start_seq;
	      prev_end_seq = hole->hole_end_seq;
	    }
	  else
	    {
	      /* If the new one doesn't end after the old one, something
	       * is screwed up. */
	      if (!(SEQ_GT (hole->hole_start_seq, prev_end_seq)))
		{
		  retval |= TEST_9_FAIL;
#ifdef VERBOSE
		  logEventv(s, trim,
			    "%s  HOLE SCRUB ERROR:  Hole overlap error:  %s, %d\n",
			    stringNow (), file, line);
		  logEventv(s, trim, "     hole index = %d\n", hole_idx);
		  logEventv(s, trim, 
			   "     Previous hole start, end (%lu, %lu), current hole start, end (%u, %u)\n",
			   prev_start_seq, prev_end_seq,
			   hole->hole_start_seq, hole->hole_end_seq);
#endif /* VERBOSE */
		  /* old ends after new, old starts after new 
		   *    -> misordered list */
		  if (SEQ_GT (prev_start_seq, hole->hole_start_seq))
		    {
#ifdef VERBOSE
		      logEventv(s, trim, 
			       "%s  HOLE SCRUB ERROR:  Misordered list: %s, %d\n",
			       stringNow (), file, line);
		      logEventv(s, trim,
			       "     hole = %p, hole->prev = %p\n", hole, hole->prev);
#endif /* VERBOSE */
		    }
		  if (prev_start_seq == hole->hole_start_seq)
		    {
#ifdef VERBOSE
		      logEventv(s, trim,
			       "%s  HOLE SCRUB ERROR:  Duplicate hole: %s, %d\n",
			       stringNow (), file, line);
		      logEventv(s, trim,
			       "     hole = %p, hole->prev = %p\n", hole, hole->prev);
#endif /* VERBOSE */
		    }
		  if (prev_end_seq == hole->hole_end_seq)
		    {
#ifdef VERBOSE
		      logEventv(s, trim,
			       "%s  HOLE SCRUB ERROR:  Holes end at same point:  %s, %d\n",
			       stringNow (), file, line);
		      logEventv(s, trim,
			       "     hole = %p, hole->prev = %p\n", hole, hole->prev);
#endif /* VERBOSE */
		    }

		}
	    }
	  if (hole->hole_start_seq != hole->hole_start->m_seq)
	    {
#ifdef VERBOSE
	      logEventv(s, trim,
		       "%s  HOLE SCRUB ERROR:  Starting sequence number mismatch: %s, %d\n",
		       stringNow (), file, line);
	      logEventv(s, trim,
		       "     hole = %p, mbuffer = %p\n", hole, hole->hole_start);
	      logEventv(s, trim,
		       "     hole->hole_start_seq = %u, mbuffer->m_seq = %lu\n",
		       hole->hole_start_seq, hole->hole_start->m_seq);
#endif /* VERBOSE */
	      retval |= TEST_1_FAIL;
	    }

/*  Is the calculated ending sequence number of the hole consistent with
 *  the recorded ending sequence number?
 */
	  if ((hole->hole_start_seq + hole->length) != hole->hole_end_seq)
	    {
#ifdef VERBOSE
	      logEventv(s, trim,
		       "%s HOLE SCRUB ERROR:  Ending sequence number mismatch: %s, %d\n",
		       stringNow (), file, line);
	      logEventv(s, trim, "     hole = %p\n", hole);
	      logEventv(s, trim, "     Expected = %lu, Got = %u\n",
		       hole->hole_start_seq + hole->length,
		       hole->hole_end_seq);
	      logEventv(s, trim,
		       "     hole->hole_start_seq = %u, len = %ld, hole_end_seq = %u\n",
		       hole->hole_start_seq, hole->length, hole->hole_end_seq);
	      logEventv(s, trim,
		       "     hole_idx = %d\n", hole_idx);
#endif /* VERBOSE */
	      retval |= TEST_2_FAIL;
	    }
	  if (hole->hole_end_seq !=
	      (hole->hole_end->m_seq + hole->hole_end->m_ext.len))
	    {
	      /* Above test checks for ending alignment, below test checks for
	       * containment.
	       */
	      if ((SEQ_GT (hole->hole_end_seq, hole->hole_end->m_seq + hole->hole_end->m_ext.len))
		  || (SEQ_LT (hole->hole_end_seq, hole->hole_end->m_seq)))
		{
#ifdef VERBOSE
		  logEventv(s, trim,
			   "%s  HOLE SCRUB ERROR:  Ending sequence number mismatch 2: %s, %d\n",
			   stringNow (), file, line);
		  logEventv(s, trim, "     Expected %u, Got %lu\n", hole->hole_end_seq,
			   (hole->hole_end->m_seq + hole->hole_end->m_ext.len));
		  logEventv(s, trim, "     Is hole_end pointing to the next-to-last mbuffer?\n");
		  logEventv(s, trim, "     hole_end_seq (%u)", hole->hole_end_seq);
		  if (hole->hole_end && hole->hole_end->m_next)
		    {
		      logEventv(s, trim,
			       ", hole_end->next's last seq (%lu)\n",
			       hole->hole_end->m_next->m_seq + hole->hole_end->m_next->m_ext.len);
		    }
		  logEventv(s, trim, "\n     hole_idx = %d\n", hole_idx);
#endif /* VERBOSE */
		  retval |= TEST_3_FAIL;
		}
	    }

	  done = len = 0;
	  for (mbuff = hole->hole_start;
	       ((mbuff) && (done == 0) &&
		(SEQ_LT (mbuff->m_seq, hole->hole_end_seq)));
	       mbuff = mbuff->m_next)
	    {
	      if (mbuff == hole->hole_end)
		done = 1;

	      if (mbuff->parent != s->send_buff)
		{
#ifdef VERBOSE
		  logEventv(s, trim, 
			   "%s  HOLE SCRUB ERROR:  Hole parent mismatch: %s, %d\n",
			   stringNow (), file, line);
		  logEventv(s, trim, "     hole = %p, mbuff = %p\n", hole, mbuff);
		  logEventv(s, trim, "     Expected = %p, Got = %p\n",
			   s->send_buff, mbuff->parent);
#endif /* VERBOSE */
		  retval |= TEST_4_FAIL;
		}
	      len += mbuff->m_ext.len;

/* Have all mbuffs in the chain been sent at least once? */
	      if (mbuff->m_ts == 1)
		{
#ifdef VERBOSE
		  logEventv(s, trim, 
			   "%s  HOLE SCRUB ERROR:  Unsent mbuffer in hole: %s, %d\n",
			   stringNow (), file, line);
		  logEventv(s, trim, "     hole = %p, mbuff = %p\n", hole, mbuff);
#endif /* VERBOSE */
		  retval |= TEST_7_FAIL;

		}
	    }			/* for each mbuff in the hole */

/* Is the chain of mbuffs unbroken from hole_start to hole_end? */
	  if (done != 1)
	    {
#ifdef VERBOSE
	      logEventv(s, trim,
		       "%s  HOLE SCRUB ERROR:  mbuff chain broken: %s, %d\n",
		       stringNow (), file, line);
	      logEventv(s, trim, "     hole = %p, mbuff = %p\n", hole, mbuff);
#endif /* VERBOSE */
	      retval |= TEST_5_FAIL;
	    }
	  if (len < (int) hole->length)
	    {
#ifdef VERBOSE
	      logEventv(s, trim,
		       "%s  HOLE SCRUB ERROR:  mbuff chain length error: %s, %d\n",
		       stringNow (), file, line);
	      logEventv(s, trim, "     hole = %p, mbuff = %p\n", hole, mbuff);
	      logEventv(s, trim, "     Expected = %ld, Got = %d\n",
		       hole->length, len);
#endif /* VERBOSE */
	      retval |= TEST_6_FAIL;

	    }
	  if (SEQ_GT (hole->hole_start_seq, s->max_seqsent))
	    {
#ifdef VERBOSE
	      logEventv(s, trim,
		       "%s  HOLE SCRUB ERROR: hole_start_seq beyond max_seqsent: %s, %d\n",
		       stringNow (), file, line);
	      logEventv(s, trim, "     hole = %p, mbuff = %p\n", hole, mbuff);
	      logEventv(s, trim, "     hole_start_seq = %u, max_seqsent = %lu\n",
		       hole->hole_start_seq, s->max_seqsent);
#endif /* VERBOSE */
	      retval |= TEST_8_FAIL;

	    }
	}
    }
  if (retval)
    logEventv(s, trim, "%s  %d total holes checked\n", stringNow (), hole_idx);
  return (retval);
}

void
printHoleChain (struct _hole_element *list)
{
  int i = 0;
  while (list != NULL)
    {

      /* FIX ME: no socket pointer... */
      /* logEventv(s, trim,"     hole[%d]:  start_seq(%u), end_seq(%u)\n",
       *       i, list->hole_start_seq, list->hole_end_seq); 
       */
      i++;
      list = list->next;
    }
}

void
debug_seqnum (tp_Socket * s, struct mbuff *mbuffer)
{
  /*
   * This prints the sequence number of every outgoing packet.
   */
  const int suspicion_value = 1;
  const int packetsize = 1448;
  static int32_t highest_seen = 0;
  /*      static FILE *fp = NULL; */
  /* char file[] = __FILE__;
   *   int line = 0;
   */
  struct mbuff *m = mbuffer;
  uint32_t bigseq;
  tp_Header *th;

  if (mbuffer == NULL)
    return;
  th = (tp_Header *) (m->m_pktdat + s->th_off);

  logEventv(s, sequence, "Initial sequence Number: %lu\n", s->initial_seqnum);

  bigseq = SEQ_GT (ntohl (th->seqnum), m->m_seq) ? ntohl (th->seqnum) : m->m_seq;
  if (SEQ_GT (bigseq, highest_seen + (suspicion_value * packetsize)))
    {
      printf
	("%s  Hmmm in tp_next_to_send, m_seq(%lu) th->seqnum(%lu), highest_seen(%lu)\n",
	 stringNow (),
	 m->m_seq - s->initial_seqnum,
	 ntohl (th->seqnum) - s->initial_seqnum,
	 highest_seen - (s->initial_seqnum));
    }
  logEventv(s, sequence,
	    "%s %s seqnum_th(abs=%lu, rel=%lu) %c seqnum_mb(abs=%lu, rel=%lu) highest(%lu) %s %d\n",
	    stringNow (), printPorts (s),
	    ntohl (th->seqnum),
	    ntohl (th->seqnum) - (s->initial_seqnum),
	    (ntohl (th->seqnum) != m->m_seq) ? '*' : ' ',
	    m->m_seq, m->m_seq - (s->initial_seqnum),
	    highest_seen - s->initial_seqnum,
	    "tp_next_to_send", __LINE__);
  if (SEQ_GT (bigseq, highest_seen + (suspicion_value *
				      packetsize)))
    {
      logEventv(s, sequence,
		"%s  Hmmm, m_seq(%lu) th->seqnum(%lu), highest_seen(%lu)\n",
		stringNow (),
		(m->m_seq) - (s->initial_seqnum),
		(ntohl (th->seqnum)) - (s->initial_seqnum),
		highest_seen - s->initial_seqnum);
    }
  if (SEQ_GT (bigseq, highest_seen) || !highest_seen)
    {
      highest_seen = ntohl (th->seqnum);
    }
}

int
isValidSocket(tp_Socket *s)
{
  tp_Socket *tmp;
  for ( tmp=tp_allsocs; tmp!=NULL; tmp=tmp->next ) {
    if ( tmp==s ) return(1);
  }
  return(0);
}

#ifdef NOT_DEFINED
double
xplot_string (char *color, char *text, double time, uint32_t seq)
{
  int i;
  double theTime;
  if (time == 0)
    {
      theTime = atof (stringNow2 ());
    }
  else
    {
      theTime = time;
    }
  for (i = 0; i < strlen (text); i++)
    {
      time = xplot_small_char (color, text[i], time, seq);
    }
  return (time);
}
#else /* NOT_DEFINED */
double
xplot_string (char *color, char *text, double time, uint32_t seq)
{
  return(0);
}
#endif /* NOT_DEFINED */

#ifdef NOT_DEFINED
double
xplot_small_char (char *color, char c, double time, uint32_t seq)
{
#define width	50		/* uS */
#define height	50		/* bytes */
#define space    5		/* uS */
  double theTime;
  int i;

  if (time == 0)
    {
      theTime = atof (stringNow2 ());
    }
  else
    {
      theTime = time;
    }
  xplotFileOpen ();
  if (color != NULL)
    {
      fprintf (xplotFile, "%s\n", color);
    }
  switch (c)
    {
    case '0':
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq, theTime + width, seq);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq, theTime, seq + height);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime + width, seq, theTime + width, seq + height);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height, theTime + width, seq + height);
      return (theTime + width + space);
    case '1':
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime + width, seq, theTime + width, seq + height);
      return (theTime + width + space);
    case '2':
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height, theTime + width, seq + height);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime + width, seq + height, theTime + width, seq + height
	       / 2);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height / 2, theTime + width, seq + height / 2);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height / 2, theTime, seq);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq, theTime + width, seq);
      return (theTime + width + space);
    case '3':
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height, theTime + width, seq + height);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime + width, seq + height, theTime + width, seq + height
	       / 2);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height / 2, theTime + width, seq + height / 2);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime + width, seq + height / 2, theTime + width, seq);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq, theTime + width, seq);
      return (theTime + width + space);
    case '4':
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime + width, seq + height, theTime, seq + height / 2);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height / 2, theTime + width, seq + height / 2);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime + width, seq + height, theTime + width, seq + height);
      return (theTime + width + space);
    case '5':
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height, theTime + width, seq + height);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height, theTime, seq + height / 2);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height / 2, theTime + width, seq + height / 2);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime + width, seq + height / 2, theTime + width, seq);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq, theTime + width, seq);
      return (theTime + width + space);
    case '6':
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height, theTime + width, seq + height);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq, theTime, seq + height);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height / 2, theTime + width, seq + height / 2);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime + width, seq + height / 2, theTime + width, seq);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq, theTime + width, seq);
      return (theTime + width + space);
    case '7':
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height, theTime + width, seq + height);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime + width, seq + height, theTime + width, seq);
      return (theTime + width + space);
    case '8':
      xplot_small_char (NULL, '3', time, seq);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq, theTime, seq + height);
      return (theTime + width + space);
    case '9':
      xplot_small_char (NULL, '3', time, seq);
      fprintf (xplotFile, "line %f %lu %f %lu\n",
	       theTime, seq + height / 2, theTime, seq + height);
      return (theTime + width + space);
    default:
      for (i = 0; i < height; i += 3)
	{
	  fprintf (xplotFile, "line %f %lu %f %lu\n",
		   theTime, seq + i, theTime + width, seq + i);
	}
      return (theTime + width + space);
    }
}
#endif /* NOT_DEFINED */


char *
scps_errorNameFromID(int errorID)
{
  /*
   * The error name list, generated by the makefile when debugging is on,
   * is terminated by an entry with error ID = -1 and the value 'Unknown Error'
   */
  int i = 0;
  while ( errorNames[i].number!=-1 ) {
    if ( errorNames[i].number==errorID ) {
      break;
    }
  }
  return(errorNames[i].name);
}

void
SET_ERR_FUNCTION(int error, char *file, int line)
{
  scheduler.current->SCPS_errno = error;
  if ( error!=0 ) {
    printf("%s %d sets SCPS_errno to %d", file, line, error);
    /* If we were configured with --debug=yes then we have the error
     * names, not just the numbers.
     */
#ifdef DEBUG_SUPPORT
    printf("(%s)", scps_errorNameFromID(error));
#endif
  }
  printf("\n");
}

