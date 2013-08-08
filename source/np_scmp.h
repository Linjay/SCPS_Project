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

/*
 * Definition of type and code field values
 */
#define SCMP_ECHOREPLY		0	/* echo reply */
#define SCMP_UNREACH            3	/* dest unreachable; codes: */
#define		SCMP_UNREACH_NET	0	/* bad net */
#define		SCMP_UNREACH_HOST	1	/* bad host */
#define		SCMP_UNREACH_PROTOCOL	2	/* bad protocol */
#define		SCMP_UNREACH_PORT	3	/* bad port */
#define		SCMP_UNREACH_NEEDFRAG	4	/* datagram too large */
#define		SCMP_UNREACH_UNHOST	7	/* unknown dest host */
#define		SCMP_UNREACH_QOSNET	11	/* for QoS and net */
#define		SCMP_UNREACH_QOSHOST	12	/* for QoS and host */
#define		SCMP_UNREACH_ADMIN	13	/* for admin filter */
#define		SCMP_UNREACH_HOSTPREC	14	/* for host precedence */
#define		SCMP_UNREACH_MINPREC	15	/* for too-low prec */
#define		SCMP_UNREACH_LINKOUT	16	/* for link outage */
#define SCMP_SOURCEQUENCH	4	/* packet lost, slow down */
#define SCMP_REDIRECT		5	/* shorter route; codes: */
#define		SCMP_REDIRECT_HOST	1	/* for host */
#define 	SCMP_REDIRECT_QOSHOST	3	/* for QoS and host */
#define 	SCMP_REDIRECT_LINK	4	/* link now available */
#define SCMP_ECHO		8	/* echo service */
#define SCMP_TIMXCEED		11	/* time exceeded */
#define SCMP_PARAMPROB		12	/* np header bad */
#define SCMP_CORRUPT		19	/* corruption experienced */
#define NONE                    -1	/* no code defined */
