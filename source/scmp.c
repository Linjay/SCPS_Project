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
 * SCPS Control Message Protocol - an ICMP clone
 */
#include "scps.h"
#include "scpstp.h"

#ifdef SCMP_TEST
#include "scmp.h"
#include "scmp_var.h"
#endif /* SCMP_TEST */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: scmp.c,v $ -- $Revision: 1.9 $\n";
#endif

extern route *def_route;

#ifdef NOT_DEFINED
/* Note: fix scmp_handler to use rqts structure */
void
scmp_Handler (scps_np_rqts * rqts, int len, tp_Header * tp)
{
  u_char link_state;
  in_Header *ip;

  link_state = *((u_char *) ip + in_GetHdrlenBytes (ip));

  if (link_state)
    def_route->flags |= RT_LINK_AVAIL;
  else
    def_route->flags &= ~RT_LINK_AVAIL;
}
#endif /* NOT_DEFINED */

#ifdef SCMP_TEST
void
scmp_error (oip, type, code, dest)
     in_Header *oip;
     int type, code;
     uint32_t dest;
{
  in_Header *nip;
  word oiplen = in_GetHdrlenBytes (oip);
  struct icmp *icp;
  word icmplen, len;

#ifdef ICMPPRINTFS
  if (icmpprintfs)
    printf ("icmp_error(%x, %d, %d)\n", oip, type, code);
#endif /* ICMPPRINTFS */

  if (type != ICMP_REDIRECT)
    icmpstat.icps_error++;

  if ((in_GetProtocol (oip) == SCMP) &&
      (type != ICMP_REDIRECT) &&
      (!ICMP_INFOTYPE (((struct icmp *) ((caddr_t) oip + oiplen))->icmp_type)))
    {
      icmpstat.icps_oldicmp++;
      return;
    }

  icmplen = oiplen + min (8, (oip->length - oiplen));
  len = icmplen + ICMP_MINLEN;

  icp = (struct icmp *) (out_buf + oiplen);

  if ((u_int) type > ICMP_MAXTYPE)
    {
      printf ("PANIC:  scmp_error\n");
      exit (1);
    }

  icmpstat.icps_outhist[type]++;
  icp->icmp_type = type;
  if (type == ICMP_REDIRECT)
    {
      icp->icmp_gw_addr = dest;
    }
  else
    {
      icp->icmp_void = 0;
      /* Overlay icmp_void field */
      if (type == ICMP_PARAMPROB)
	{
	  icp->icmp_pptr = code;
	  code = 0;
	}
      else if ((type == ICMP_UNREACH) &&
	       (code == ICMP_UNREACH_NEEDFRAG) &&
	       destifp)
	{
	  icp->icmp_nextmtu = htons (destifp->if_mtu);
	}
    }
  icp->icmp_code = code;

  bcopy ((caddr_t) oip, (caddr_t) & (icp->icmp_ip), icmplen);
  bcopy ((caddr_t) oip, (caddr_t) & out_data, sizeof (in_Header));

  len += sizeof (in_Header);
  nip = (in_Header *) out_data;
  nip->length = len;
  nip->vht = 0x4500;
  nip->ttlProtocol = (250 << 8) + SCMP;

  icmp_reflect (nip);
}

#endif /* SCMP_TEST */
