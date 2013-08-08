#ifndef _mib_h
#define _mib_h

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

typedef struct _np_mib
  {
    int npOutRequests;
    int npOutDiscards;
    int npOutNoRoutes;
    int npInReceives;
    int npInBadLength;
    int npInBadVersion;
    int npInBadAddress;
    int npInBadChecksum;
    int npInAddrErrors;
    int npInUnknownProtos;
    int npInDiscards;
    int npInDelivers;
    int npForwDatagrams;
    short npHopDiscard;
    int npTTLDiscard;
    int npTimeToLive;
    short npDefaultHopCount;
    unsigned char npInCongThreshold;	/*   [0..100] */
    unsigned char npInCongPurgeExtent;
    unsigned char npOutCongThreshold;
    unsigned char npOutCongPurgeExtent;		/* [0..100] */
    unsigned char npForwarding;
    char *npAddrTable;
    char *npAddrEntry;
    scps_np_addr *npAdEntSCPSAddr;
    int npAdEntIfIndex;
    scps_np_addr *npDefaultDestSCPSAddr;	/* READ ONLY */
    char *npExtendedToMediaTable;
    char *npExtendedToMediaEntry;
    int npExtendedToMediaIfIndex;
    scps_np_addr *npExtendedToMediaNetAddress;
    char *npExtendedToMediaPhysAddress;
    unsigned char npExtendedToMediaType;
    char *npIPv6ToMediaTable;
    char *npIPv6ToMediaEntry;
    int npIPv6ToMediaIfIndex;
    int npIPv6ToMediaNetAddress[2];
    char *npIPv6ToMediaPhysAddress;
    unsigned char npIPv6ToMediaType;

/** MIB Requirements for SCMP **/
    /* Statistics */
    unsigned int scmpInMsgs;
    unsigned int scmpInErrors;
    unsigned int scmpInDestUnreachs;
    unsigned int scmpInTimeExcds;
    unsigned int scmpInParmProbs;
    unsigned int scmpInSrcQuenchs;
    unsigned int scmpInCorrExps;
    unsigned int scmpInRedirects;
    unsigned int scmpInEchos;
    unsigned int scmpInEchoReps;
    unsigned int scmpOutMsgs;
    unsigned int scmpOutErrors;
    unsigned int scmpOutDestUnreachs;
    unsigned int scmpOutTimeExcds;
    unsigned int scmpOutParmProbs;
    unsigned int scmpOutSrcQuenchs;
    unsigned int scmpOutCorrExps;
    unsigned int scmpOurRedirects;
    unsigned int scmpOutEchos;
    unsigned int scmpOutEchoReps;	/* end counters */

    /* Configuration Parameters */
    int scmpSrchQuenchRate;
    int scmpErrorRate;
    int scmpQueryRate;

/** MIB Requirements for SCPS Routing Databases **/
/*
      ESRoutingTable  npESRouteTable;

      MCRoutingTable  npMCRouteTable;

      PathRoutingTable npPathRouteTable; 
*/

  }
np_mib;

#ifdef UNDEFINED
typedef struct _npRouteEntry
  {
    scps_np_addr npRouteDest;
    int npRouteIfIndex;
    scps_np_addr npRouteNextHop;
    int npRouteMetric1;
    int npRouteMetric2;
    int npRoutemMetric3;
    int npRouteMetric4;
    int npRouteMetric5;
    unsigned char npRouteType;
    unsigned char npRouteProto;
    unsigned int npRouteAge;
    unsigned int npRouteMTU;
    char *npRouteSendBPS;
    char *npRouteRcvPipe;
    char *npRouteSendPipe;
    unsigned int npRouteSSThresh;
    unsigned int npRouteRTT;
    int npRouteRTTVar;
    unsigned char npRouteAvail;
    unsigned char npRouteCorrupt;
    BOOL npRouteCongest;
    char *npRouteInfo;

  }
npRouteEntry;

typedef struct
  {
    scps_np_addr npRouteDest;
      npRouteIfIndex;
      npRouteNextHop;
    int npRouteMetric1;
    int npRouteMetric2;
    int npRoutemMetric3;
    int npRouteMetric4;
    int npRouteMetric5;
    unsigned char npRouteType;
    unsigned char npRouteProto;
    unsigned int npRouteAge;
    unsigned int npRouteMTU;
    char *npRouteSendBPS;
    char *npRouteRcvPipe;
    char *npRouteSendPipe;
    unsigned int npRouteSSThresh;
    unsigned int npRouteRTT;
    int npRouteRTTVar;
    unsigned char npRouteAvail;
    unsigned char npRouteCorrupt;
    BOOL npRouteCongest;
    char *npRouteInfo;

  }
_npMultiNextHopRouteEntry;

_npMultiNextHopRouteEntry npMultiNextHopRouteEntry;

#endif /* UNDEFINED */

/** WARNING! IF THESE VALUES ARE CHANGED, THE CODE
*** IN SCPS_NP.C: scps_np_get_template MUST ALSO BE
*** CHANGED, SINCE THE ADDRESS PLACEMENT IN THE HDR
*** DEPENDS ON THESE VALUES.
**/

#endif /* _mib_h */
