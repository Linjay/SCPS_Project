#ifndef __scps_constants_h__
#define __scps_constants_h__
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

const uint32_t INTER_PACKET_GAP = 375;     /* Inter packet (start-to-start)gap (375 usec) */

const uint32_t tp_TICK = 100000;	/* 100 ms tick (273/4096) */

const uint32_t tp_ACKDELAY = 200000;	/* 200ms ack delay  */
const uint32_t tp_ACKFLOOR = 50000;	/* Don't ack more often than this */
const uint32_t tp_RTOMIN = 250000;		/* 250 msec min rto */
const uint32_t tp_RTOMAX = 64000000;		/* 64 sec max rto */
const uint32_t tp_RETRANSMITTIME = 250000;		/* rexmit call interval */
const uint32_t tp_PERSISTTIME = 1000000;	/* us until probe sent */
const uint32_t tp_TIMEOUT = 32;	/* max rexmits during a connection */
const uint32_t tp_LONGTIMEOUT = 32;	/* max rexmits for opens */
const uint32_t tp_MAXPERSIST_CTR  = 32;	/* max persistance during a connection */
const uint32_t tp_RTOPERSIST_MAX  = 60 * 1000 * 1000;	/* max persistance during a connection */
#ifdef GATEWAY
const uint32_t tp_2MSLTIMEOUT = 10;        /* 2 MSL in seconds */
#else /* GATEWAY */
const uint32_t tp_2MSLTIMEOUT = 60;        /* 2 MSL in seconds */
#endif /* GATEWAY */
const uint32_t tp_KATIMEOUT   = 15 * 60;    /* KeepAlive Timer */

const uint32_t BETS_RECEIVE_TIMEOUT = 0x100001;
const unsigned int BETS_MAXIMUM_TRANSMISSIONS = 20;

const unsigned int DEFAULT_ACK_FREQ = 2;	/* Default Ack behavior */

const uint32_t tp_BIGTIME = 0x0fffffff;	/* A large value of time */
const uint32_t HASH_SIZE = 100000;		/* bytes between hash marks */

const uint32_t BUFFER_SIZE = 32768;

const unsigned short tp_MFX_RETRANSMISSION_COUNT = 3;	/* cycle seg n times */
const uint32_t MFX_RETRANSMISSION_INTERLEAVE = 10000;	/* 10 ms */
#endif /* __scps_constants_h__ */
