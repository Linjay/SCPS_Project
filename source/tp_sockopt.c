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

#include <string.h>
#include "scps.h"
#include "scpstp.h"
#include "scpsudp.h"

#ifdef USESCPSNP
int scps_np_get_template (scps_np_rqts * rqts,
			  scps_np_template * templ);
#endif /* USESCPSNP */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_sockopt.c,v $ -- $Revision: 1.41 $\n";
#endif

//extern void *memset (void *s, int c, size_t n);

/* 
 * A SCPS analog of the setsockopt call; 
 * It starts off a little braindead and gets worse...
 */
int
scps_setsockopt (int sockid, int level, int optname, void *optval, int optlen)
{
  u_int intarg;
  caddr_t s = scheduler.sockets[sockid].ptr;


  if ((!(s)) /*|| ((level != SCPS_ROUTE)) */
#ifndef GATEWAY
		&&  (((tp_Socket *) s)->thread != scheduler.current)
#endif /* GATEWAY */
    ) {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  switch (level)
    {
    case SCPS_SOCKET:
      {
	switch (optname)
	  {
	  case SCPS_SO_RCVBUF:
	    {			/* Set the current receive buffer size */
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  if (!(((tp_Socket *) s)->app_rbuff))
		    {		/* If there isn't already a buffer, create one. */
		      ((tp_Socket *) s)->app_rbuff = chain_init (intarg);
		      ((tp_Socket *) s)->rcvwin =
			((tp_Socket *) s)->app_rbuff->max_size - 1;
		      if (!(((tp_Socket *) s)->receive_buff))
			{
			  ((tp_Socket *) s)->receive_buff =
			    buff_init (MAX_MBUFFS, s);
			  ((tp_Socket *) s)->Out_Seq =
			    buff_init (MAX_MBUFFS, s);
			}
		    }
		  else
		    {
		      ((tp_Socket *) s)->app_rbuff->max_size = intarg;
		      ((tp_Socket *) s)->rcvwin =
			((tp_Socket *) s)->app_rbuff->max_size - 1;
		      ((tp_Socket *) s)->app_rbuff->max_elements =
			(intarg / SMCLBYTES) + 2;
		    }

#ifdef OPT_SCALE
		  /* If we're doing window scaling and haven't sent a SYN
		   * yet, can go ahead and recompute the window scale factor.
		   * Since this is set only on the SYN, if the SYN's gone
		   * out, must not change the value, regardless of the buffer
		   * size.
		   */
		  if ((((tp_Socket *) s)->state < tp_StateSYNSENT) &&
		      (((tp_Socket *) s)->sockFlags & TF_REQ_SCALE))
		    {
		      ((tp_Socket *) s)->request_r_scale = 0;
		      while ((((tp_Socket *) s)->request_r_scale <
			      TP_MAX_WINSHIFT) &&
			     ((TP_MAXWIN << ((tp_Socket *)
					     s)->request_r_scale) <
			      ((tp_Socket *) s)->app_rbuff->max_size))
			((tp_Socket *) s)->request_r_scale++;
		    }
#endif /* OPT_SCALE */
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

	  case SCPS_SO_SNDBUF:
	    {			/* Set the current send buffer size */
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  if (!(((tp_Socket *) s)->app_sbuff))
		    {		/* If there isn't already a buffer, create one. */
		      ((tp_Socket *) s)->app_sbuff = chain_init (intarg);
		      if (!(((tp_Socket *) s)->send_buff))
			((tp_Socket *) s)->send_buff =
			  buff_init (MAX_MBUFFS, s);
		    }
		  else
		    {
		      ((tp_Socket *) s)->app_sbuff->max_size = (intarg);
		      ((tp_Socket *) s)->app_sbuff->max_elements =
			(intarg / SMCLBYTES) + 2;
		    }
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPS_SO_NBLOCK:
	    {
	      if (optlen == sizeof (u_int))
		{
		  if (*(int *) optval)
		    ((tp_Socket *) s)->sockFlags &= ~SOCK_BL;
		  else
		    ((tp_Socket *) s)->sockFlags |= SOCK_BL;
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPS_SO_NDELAY:
	    {
	      if (optlen == sizeof (u_int))
		{
		  if (*(int *) optval) {
		    ((tp_Socket *) s)->sockFlags |= SOCK_NDELAY;
		  } else {
		    ((tp_Socket *) s)->sockFlags &= ~SOCK_NDELAY;
		  }
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPS_SO_NLDEFAULT:
	    {
	      if (optlen == sizeof (u_int)) {
		    memcpy (&intarg, optval, optlen);

		    if ((intarg == NL_PROTOCOL_IPV4) ||
		        (intarg == NL_PROTOCOL_NP)) {

		      ((tp_Socket *) s)->np_rqts.nl_protocol = intarg;
#ifdef SCPSSP
		      ((tp_Socket *) s)->sp_rqts.np_rqts.nl_protocol = intarg;

#endif /* SCPSSP */
		      return (0);
		    }
	      }

	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  default:
	    SET_ERR (SCPS_ENOPROTOOPT);
	    return (-1);
	  }
      }
      break;

#ifdef USESCPSNP

    case NP_PROTO_NP:
      {
	switch (optname)
	  {
	  case SCPS_SO_NPTIMESTAMP:
	    {
	      if (optlen == sizeof (int))
		{
		  if (*(int *) optval > MAX_TS_DEFINES)
		    {
		      SET_ERR (SCPS_EINVAL);
		      return (-1);
		    }
		  memcpy (&((tp_Socket *) s)->np_rqts.timestamp,
			  optval, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);

	      break;
	    }

	  case SCPS_SO_CHECKSUM:
	    {
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  ((tp_Socket *) s)->np_rqts.cksum = intarg;
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);

	      break;
	    }

	  case SCPS_SO_PRECEDENCE:
	    {
	      if (optlen == sizeof (int))
		{
		  if (intarg > MAX_PREC)
		    {
		      SET_ERR (SCPS_EINVAL);
		      return (-1);
		    }
		  memcpy (&intarg, optval, optlen);
		  ((tp_Socket *) s)->np_rqts.bqos.precedence = intarg;
		  ((tp_Socket *) s)->np_size =
		    scps_np_get_template (&(((tp_Socket *) s)->np_rqts),
					  &(((tp_Socket *) s)->templ));
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }
	  default:
	    SET_ERR (SCPS_ENOPROTOOPT);
	    return (-1);
	    break;
	  }
	break;
      }
#endif /* USESCPSNP */

#ifdef SCPSSP

    case NP_PROTO_SP:
      {
	switch (optname)
	  {
	  case SCPS_SO_CONFIDENTIALITY:
	    {
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (intarg)
		    ((tp_Socket *) s)->sp_rqts.sprqts |= (CONFIDENTIALITY & 0xFF);
		  else
		    ((tp_Socket *) s)->sp_rqts.sprqts |= (CONFIDENTIALITY & 0x00);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);

	      break;
	    }

	  case SCPS_SO_AUTHENTICATION:
	    {
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (intarg)
		    ((tp_Socket *) s)->sp_rqts.sprqts |= (AUTHENTICATION & 0xFF);
		  else
		    ((tp_Socket *) s)->sp_rqts.sprqts |= (AUTHENTICATION & 0x00);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);

	      break;
	    }

	  case SCPS_SO_SECURITY_LABEL:
	    {
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (intarg)
		    ((tp_Socket *) s)->sp_rqts.sprqts |= (SECURITY_LABEL & 0xFF);
		  else
		    ((tp_Socket *) s)->sp_rqts.sprqts |= (SECURITY_LABEL & 0x00);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);

	      break;
	    }
	  case SCPS_SO_INTEGRITY:
	    {
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (intarg)
		    ((tp_Socket *) s)->sp_rqts.sprqts |= (INTEGRITY & 0xFF);
		  else
		    ((tp_Socket *) s)->sp_rqts.sprqts |= (INTEGRITY & 0x00);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);

	      break;
	    }
	  default:
	    SET_ERR (SCPS_ENOPROTOOPT);
	    return (-1);
	    break;
	  }
	break;
      }
#endif /* SCPSSP */

    case PROTO_SCPSTP:
      {
	if ( (((tp_Socket *) s)->Initialized != SCPSTP) &&
             (((tp_Socket *) s)->Initialized != SCPSROUTE) )
	  {
	    SET_ERR (SCPS_EPROTONOSUPPORT);
	    return (-1);
	  }

	switch (optname)
	  {
	  case SCPSTP_MAXSEG:
	    {
	      if (optlen == sizeof (short))
		{
		  memcpy (&(((tp_Socket *) s)->maxseg), optval, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

	  case SCPSTP_NODELAY:
	    {
	      if (optlen == sizeof (u_int))
		{
		  if (*(int *) optval) {
		    ((tp_Socket *) s)->sockFlags |= SOCK_NDELAY;
		  } else {
		    ((tp_Socket *) s)->sockFlags &= ~SOCK_NDELAY;
		  }
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPSTP_ACKDELAY:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  intarg = (intarg * 1000);
		  memcpy (&(((tp_Socket *) s)->ACKDELAY), &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

	  case SCPSTP_ACKFLOOR:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  intarg = (intarg * 1000);
		  memcpy (&(((tp_Socket *) s)->ACKFLOOR), &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

	  case SCPSTP_ACKBEHAVE:
	    {
	      if (optlen == sizeof (short))
		{
		  memcpy (&(((tp_Socket *) s)->ack_freq), optval, optlen);
                  if ((((tp_Socket *) s)->ack_freq) == 0) {
                        ((tp_Socket *) s)->otimers [Del_Ack]->immediate = 1;
                  }
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

	  case SCPSTP_RTOMIN:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  intarg = (intarg * 1000);
		  memcpy (&(((tp_Socket *) s)->RTOMIN), &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

	  case SCPSTP_RTOMAX:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  intarg = (intarg * 1000);
		  memcpy (&(((tp_Socket *) s)->RTOMAX), &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;
	  case SCPSTP_RETRANSMITTIME:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  intarg = (intarg * 1000);
		  memcpy (&(((tp_Socket *) s)->RETRANSMITTIME),
			  &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

	  case SCPSTP_PERSISTTIME:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  intarg = (intarg * 1000);
		  memcpy (&(((tp_Socket *) s)->PERSISTTIME),
			  &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

	  case SCPSTP_MAXPERSIST_CTR:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  memcpy (&(((tp_Socket *) s)->MAXPERSIST_CTR),
			  &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }

	  case SCPSTP_RTOPERSIST_MAX:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  memcpy (&(((tp_Socket *) s)->RTOPERSIST_MAX),
			  &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }

	  case SCPSTP_RTO_TO_PERSIST_CTR:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  memcpy (&(((tp_Socket *) s)->RTO_TO_PERSIST_CTR),
			  &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }

	  case SCPSTP_EMBARGO_FAST_RXMIT_CTR:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  memcpy (&(((tp_Socket *) s)->EMBARGO_FAST_RXMIT_CTR),
			  &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }

	  case SCPSTP_TIMEOUT:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  intarg = (intarg * 1000);
		  memcpy (&(((tp_Socket *) s)->TIMEOUT), &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

	  case SCPSTP_LONGTIMEOUT:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  intarg = (intarg * 1000);
		  memcpy (&(((tp_Socket *) s)->LONGTIMEOUT), &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

	  case SCPSTP_2MSLTIMEOUT:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  /* intarg = (intarg * 1000); */
		  memcpy (&(((tp_Socket *) s)->TWOMSLTIMEOUT), &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

	  case SCPSTP_BETS_RTIMEOUT:
	    {
	      if (!(((tp_Socket *) s)->capabilities & CAP_BETS))
		{
		  SET_ERR (SCPS_EOPNOTSUPP);
		  return (-1);
		}

	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  if (intarg < ((tp_Socket *) s)->app_rbuff->max_size)
		    {
		      intarg = (intarg * 1000);
		      memcpy (&(((tp_Socket *) s)->BETS.Receive_Timeout),
			      optval, optlen);
		      return (0);
		    }
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	    }
	    break;

#ifdef OPT_TSTMP
	  case SCPSTP_TIMESTAMP:
	    {			/* Set the timestamp capability of this socket */
	      if ((((tp_Socket *) s)->state > tp_StateNASCENT) &&
		  (((tp_Socket *) s)->state != tp_StateCLOSED))
		{
		  SET_ERR (SCPS_ESOCKOUTSTATE);
		  return (-1);	/* Can't set option after initiating conn */
		}
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval)
		    {
		      ((tp_Socket *) s)->capabilities |= CAP_TIMESTAMP;
		      ((tp_Socket *) s)->sockFlags |= TF_REQ_TSTMP;
		    }
		  else
		    {
		      ((tp_Socket *) s)->capabilities &= ~CAP_TIMESTAMP;
		      ((tp_Socket *) s)->sockFlags &= ~TF_REQ_TSTMP;
		    }
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }
#endif /* OPT_TSTMP */

#ifdef OPT_COMPRESS
	  case SCPSTP_COMPRESS:
	    {			/* Set the compression capability of this socket */
	      if ((((tp_Socket *) s)->state > tp_StateNASCENT) &&
		  (((tp_Socket *) s)->state != tp_StateCLOSED))
		{
		  SET_ERR (SCPS_ESOCKOUTSTATE);
		  return (-1);	/* Can't set option after initiating conn */
		}
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval)
		    ((tp_Socket *) s)->capabilities |= CAP_COMPRESS;
		  else
		    ((tp_Socket *) s)->capabilities &= ~CAP_COMPRESS;
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }
#endif /* OPT_COMPRESS */

#ifdef OPT_SNACK1
	  case SCPSTP_SNACK:
	    {			/* Set the SNACK capability of this socket */
	      if ((((tp_Socket *) s)->state > tp_StateNASCENT) &&
		  (((tp_Socket *) s)->state != tp_StateCLOSED))
		{
		  SET_ERR (SCPS_ESOCKOUTSTATE);
		  return (-1);	/* Can't set option after initiating conn */
		}
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval)
		    {
		      ((tp_Socket *) s)->capabilities |= CAP_SNACK;
		      ((tp_Socket *) s)->sockFlags |= TF_REQ_SNACK1;
		    }
		  else
		    {
		      ((tp_Socket *) s)->capabilities &= ~CAP_SNACK;
		      ((tp_Socket *) s)->sockFlags &= ~TF_REQ_SNACK1;
		    }
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPSTP_SNACK_DELAY:
	    {			/* Set the SNACK DELAY time of this socket */
	      if ((((tp_Socket *) s)->state > tp_StateNASCENT) &&
		  (((tp_Socket *) s)->state != tp_StateCLOSED))
		{
		  SET_ERR (SCPS_ESOCKOUTSTATE);
		  return (-1);	/* Can't set option after initiating conn */
		}
	    
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  intarg = (intarg * 1000);
		  memcpy (&(((tp_Socket *) s)->snack_delay), &intarg, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }
#endif /* OPT_SNACK1 */

#ifdef OPT_BETS
	  case SCPSTP_BETS:
	    {			/* Set the BETS capability of this socket */
	      if ((((tp_Socket *) s)->state > tp_StateNASCENT) &&
		  (((tp_Socket *) s)->state != tp_StateCLOSED))
		{
		  SET_ERR (SCPS_ESOCKOUTSTATE);
		  return (-1);	/* Can't set option after initiating conn */
		}
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval)
		    {
		      ((tp_Socket *) s)->capabilities |= CAP_BETS;
		      /* Initiailize the socket's BETS structures */
		      ((tp_Socket *) s)->BETS.Flags = BF_REQUEST_BETS;
		      ((tp_Socket *) s)->BETS.Hole_Size =
			((tp_Socket *) s)->BETS.Reported_Hole = 0;
		      ((tp_Socket *) s)->BETS.Receive_Timeout =
			((tp_Socket *) s)->BETS_RECEIVE_TIMEOUT;
		      ((tp_Socket *) s)->BETS.Threshold = 0;
		      ((tp_Socket *) s)->BETS.max_send_holes =
			BETS_MAX_SEND_HOLES;
		      ((tp_Socket *) s)->BETS.num_send_holes = 0;
		      memset (((tp_Socket *) s)->BETS.Send_Holes, 0,
			      sizeof (((tp_Socket *) s)->BETS.Send_Holes));
		    }
		  else
		    {
		      ((tp_Socket *) s)->capabilities &= ~CAP_BETS;
		      ((tp_Socket *) s)->BETS.Flags = 0;
		    }
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }
#endif /* OPT_BETS */

#ifdef CONGEST
	  case SCPSTP_CONGEST:
	    {			/* Set the Congestion capability of this socket */
	      if ((((tp_Socket *) s)->state > tp_StateNASCENT) &&
		  (((tp_Socket *) s)->state != tp_StateCLOSED))
		{
		  SET_ERR (SCPS_ESOCKOUTSTATE);
		  return (-1);	/* Can't set option after initiating conn */
		}
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval)
		    ((tp_Socket *) s)->capabilities |= CAP_CONGEST;
		  else
		    ((tp_Socket *) s)->capabilities &= ~CAP_CONGEST;
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPSTP_VEGAS_CONGEST:
	    {			/* If Congestion control enabled on this socket, set policy */

	      if ((((tp_Socket *) s)->state > tp_StateNASCENT) &&
		  (((tp_Socket *) s)->state != tp_StateCLOSED))
		{
		  SET_ERR (SCPS_ESOCKOUTSTATE);
		  return (-1);	/* Can't set option after initiating conn */
		}
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval)
		    ((tp_Socket *) s)->cong_algorithm =
		      VEGAS_CONGESTION_CONTROL;
		      return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPSTP_VJ_CONGEST:
	    {			/* If Congestion control enabled on this socket, set policy */

	      if ((((tp_Socket *) s)->state > tp_StateNASCENT) &&
		  (((tp_Socket *) s)->state != tp_StateCLOSED))
		{
		  SET_ERR (SCPS_ESOCKOUTSTATE);
		  return (-1);	/* Can't set option after initiating conn */
		}
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval)
		    ((tp_Socket *) s)->cong_algorithm =
		      VJ_CONGESTION_CONTROL;
		      return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPSTP_FLOW_CONTROL_CONGEST:
	    {			/* If Congestion control enabled on this socket, set policy */

	      if ((((tp_Socket *) s)->state > tp_StateNASCENT) &&
		  (((tp_Socket *) s)->state != tp_StateCLOSED))
		{
		  SET_ERR (SCPS_ESOCKOUTSTATE);
		  return (-1);	/* Can't set option after initiating conn */
		}
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval) {
		    ((tp_Socket *) s)->cong_algorithm =
		      FLOW_CONTROL_CONGESTION_CONTROL;
		    ((tp_Socket *) s)->capabilities &= ~CAP_CONGEST;
		     return (0);
                  }
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPSTP_VEGAS_ALPHA:
            {
                if (optlen == sizeof (int)) {
		    memcpy (&intarg, optval, optlen);
                    if (*(int *) optval) {
			((tp_Socket *) s)->VEGAS_ALPHA = intarg;
                        return (1);
                    }
		}
		SET_ERR (SCPS_EFAULT);
		return (-1);
		break;
	    }

	  case SCPSTP_VEGAS_BETA:
            {
                if (optlen == sizeof (int)) {
		    memcpy (&intarg, optval, optlen);
                    if (*(int *) optval) {
			((tp_Socket *) s)->VEGAS_BETA = intarg;
                        return (1);
                    }
		}
		SET_ERR (SCPS_EFAULT);
		return (-1);
		break;
	    }

	  case SCPSTP_VEGAS_GAMMA:
            {
                if (optlen == sizeof (int)) {
		    memcpy (&intarg, optval, optlen);
                    if (*(int *) optval) {
			((tp_Socket *) s)->VEGAS_GAMMA = intarg;
                        return (1);
                    }
		}
		SET_ERR (SCPS_EFAULT);
		return (-1);
		break;
	    }

	  case SCPSTP_VEGAS_SS:
            {
                if (optlen == sizeof (int)) {
		    memcpy (&intarg, optval, optlen);
                    if (*(int *) optval) {
			((tp_Socket *) s)->VEGAS_SS = intarg;
                        return (1);
                    }
		}
		SET_ERR (SCPS_EFAULT);
		return (-1);
		break;
	   }
#endif /* CONGEST */

	  default:
	    SET_ERR (SCPS_ENOPROTOOPT);
	    return (-1);
	    break;
	  }
	break;
      }

    case SCPS_ROUTE:
      {
	if ((((tp_Socket *) s)->Initialized != SCPSROUTE))
	  {
	    SET_ERR (SCPS_EPROTONOSUPPORT);
	    return (-1);
	  }
	switch (optname)
	  {
	  case SCPS_RATE:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
                  if (intarg < LOW_RATE_THRESH) {
                        ((tp_Socket *) s)->rt_route->bytes_per_interval = 0;
                        ((tp_Socket *) s)->rt_route->shifted_bytes_per_interval =
			(((intarg << LOW_RATE_SCALE_FACTOR) * 
			((tp_Socket *) s)->rt_route->interval)) / (10000.0 * 8.0);
		  } else if (intarg < 40000000)
		    {
		      ((tp_Socket *) s)->rt_route->bytes_per_interval =
			(intarg *
			 ((tp_Socket *) s)->rt_route->interval) / (10000 * 8);
		    } else {
		      ((tp_Socket *) s)->rt_route->bytes_per_interval =
			(intarg / 10000 / 8) *
			((tp_Socket *) s)->rt_route->interval;
		    }
		  ((tp_Socket *) s)->rt_route->max_credit =
		    max ((RATE_BUCKET_FACTOR * ((tp_Socket *) s)->rt_route->bytes_per_interval),
			 ((tp_Socket *) s)->rt_route->MTU * RATE_BUCKET_FACTOR);
		  ((tp_Socket *) s)->rt_route->current_credit =
		    max (((tp_Socket *) s)->rt_route->MTU * RATE_BUCKET_FACTOR,
			 ((tp_Socket *) s)->rt_route->bytes_per_interval);
		  ((tp_Socket *) s)->rt_route->max_burst_bytes =
		    ((tp_Socket *) s)->rt_route->MTU << 2;
		    ((tp_Socket *) s)->rt_route->rate = intarg;  
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPSTP_CONGEST:
	    {			/* Set the Congestion capability of this socket */
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval)
		    ((tp_Socket *) s)->capabilities |= CAP_CONGEST;
		  else {
		    ((tp_Socket *) s)->capabilities &= ~CAP_CONGEST;
		    ((tp_Socket *) s)->rt_route->cong_control =
		      NO_CONGESTION_CONTROL;
                  }
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPSTP_VEGAS_CONGEST:
	    {			/* If Congestion control enabled on this socket, set policy */
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval)
		    ((tp_Socket *) s)->rt_route->cong_control =
		      VEGAS_CONGESTION_CONTROL;
		      return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPSTP_VJ_CONGEST:
	    {			/* If Congestion control enabled on this socket, set policy */
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval)
		    ((tp_Socket *) s)->rt_route->cong_control =
		      VJ_CONGESTION_CONTROL;
		      return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPSTP_FLOW_CONTROL_CONGEST:
	    {			/* If Congestion control enabled on this socket, set policy */
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval) {
		    ((tp_Socket *) s)->rt_route->cong_control =
		      FLOW_CONTROL_CONGESTION_CONTROL;
		    ((tp_Socket *) s)->capabilities &= ~CAP_CONGEST;
		     return (0);
                  }
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
            }

	  case SCPS_TCPONLY:
	    {	
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
		  if (*(int *) optval) {
		    ((tp_Socket *) s)->capabilities |= CAP_CONGEST;
		    ((tp_Socket *) s)->rt_route->TCPONLY = 1;
		  } else {
		    ((tp_Socket *) s)->capabilities &= ~CAP_CONGEST;
		    ((tp_Socket *) s)->rt_route->TCPONLY = 0;
                  }
		  return (0);
		}
	    
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
            }

#ifdef MIN_RATE_THRESH
	  case SCPS_MIN_RATE:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
                  if (intarg < LOW_RATE_THRESH) {
                        ((tp_Socket *) s)->rt_route->min_bytes_per_interval = 0;
                        ((tp_Socket *) s)->rt_route->min_shifted_bytes_per_interval =
			(((intarg << LOW_RATE_SCALE_FACTOR) * 
			((tp_Socket *) s)->rt_route->interval)) / (10000.0 * 8.0);
		  } else if (intarg < 40000000)
		    {
		      ((tp_Socket *) s)->rt_route->min_bytes_per_interval =
			(intarg *
			 ((tp_Socket *) s)->rt_route->interval) / (10000 * 8);
		    } else {
		      ((tp_Socket *) s)->rt_route->min_bytes_per_interval =
			(intarg / 10000 / 8) *
			((tp_Socket *) s)->rt_route->interval;
		    }
		  ((tp_Socket *) s)->rt_route->min_current_credit =
		    max (((tp_Socket *) s)->rt_route->MTU * RATE_BUCKET_FACTOR,
			 ((tp_Socket *) s)->rt_route->min_bytes_per_interval);
		    ((tp_Socket *) s)->rt_route->min_rate = intarg;  
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }
#endif /* MIN_RATE_THRESH */

#ifdef FLOW_CONTROL_THRESH
	  case SCPS_FLOW_CONTROL:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
                      if (intarg == 0) {
		          ((tp_Socket *) s)->rt_route->flow_control = 0;  
                      }
                      if (intarg >= 0 ) {
#ifdef FLOW_CONTROL_SET
		          ((tp_Socket *) s)->rt_route->flow_control = intarg;
#else /* FLOW_CONTROL_SET */
		          ((tp_Socket *) s)->rt_route->flow_control += intarg;
#endif /* FLOW_CONTROL_SET */
                      }

		      if (((tp_Socket *) s)->rt_route->flow_control > ((tp_Socket *) s)->rt_route->flow_control_cap) {
		          ((tp_Socket *) s)->rt_route->flow_control = ((tp_Socket *) s)->rt_route->flow_control_cap;

		      }
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPS_FLOW_CONTROL_CAP:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
                      if (intarg == 0) {
		          ((tp_Socket *) s)->rt_route->flow_control_cap = 0;  
                      }
                      if (intarg >= 0 ) {
		          ((tp_Socket *) s)->rt_route->flow_control_cap = intarg;
                      }
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }
#endif /* FLOW_CONTROL_THRESH */

	  case SCPS_ENCRYPT_IPSEC:
	    {
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
                  if (intarg == 0) {
		          ((tp_Socket *) s)->rt_route->encrypt_ipsec = 0;  
		   } else {
		          ((tp_Socket *) s)->rt_route->encrypt_ipsec = 1;  
		   }
		} else {
	      		SET_ERR (SCPS_EFAULT);
	      		return (-1);
                }
	      break;
            }

	  case SCPS_ENCRYPT_PRE_OVERHEAD:
	    {
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
                  if (intarg == 0) {
		          ((tp_Socket *) s)->rt_route->encrypt_pre_overhead = 0;  
		   } else {
		          ((tp_Socket *) s)->rt_route->encrypt_pre_overhead = intarg;  
		   }
		} else {
	      		SET_ERR (SCPS_EFAULT);
	      		return (-1);
                }
	      break;
            }

	  case SCPS_ENCRYPT_BLOCK_SIZE:
	    {
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
                  if (intarg == 0) {
		          ((tp_Socket *) s)->rt_route->encrypt_block_size = 0;  
		   } else {
		          ((tp_Socket *) s)->rt_route->encrypt_block_size = intarg;  
		   }
		} else {
	      		SET_ERR (SCPS_EFAULT);
	      		return (-1);
                }
	      break;
	   }

	  case SCPS_ENCRYPT_POST_OVERHEAD:
	    {
	      if (optlen == sizeof (int))
		{
		  memcpy (&intarg, optval, optlen);
                  if (intarg == 0) {
		          ((tp_Socket *) s)->rt_route->encrypt_post_overhead = 0;  
		   } else {
		          ((tp_Socket *) s)->rt_route->encrypt_post_overhead = intarg;  
		   }
		} else {
	      		SET_ERR (SCPS_EFAULT);
	      		return (-1);
                }
	      break;
            }

	  case SCPS_MTU:
	    {
	      if (optlen == sizeof (unsigned int))
		{
		  memcpy (&intarg, optval, optlen);
		  ((tp_Socket *) s)->rt_route->MTU = intarg - ENCAP_HDR_LEN;
		  /* ((tp_Socket *)s)->rt_route->max_burst_bytes =
		     min(((tp_Socket *)s)->rt_route->max_burst_bytes,
		     (RATE_BUCKET_FACTOR * ((tp_Socket *)s)->rt_route->MTU)); */
		  if (intarg > ((tp_Socket *) s)->rt_route->max_credit)
		    ((tp_Socket *) s)->rt_route->max_credit =
		      max ((1.2 * ((tp_Socket *) s)->rt_route->bytes_per_interval),
			   ((tp_Socket *) s)->rt_route->MTU);
		  return (0);
		}

	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

          case SCPS_SMTU:
            {
              if (optlen == sizeof (unsigned int))
                {
                  memcpy (&intarg, optval, optlen);
                  ((tp_Socket *) s)->rt_route->SMTU = intarg - ENCAP_HDR_LEN;
                  /* ((tp_Socket *)s)->rt_route->max_burst_bytes =
                     min(((tp_Socket *)s)->rt_route->max_burst_bytes,
                     (RATE_BUCKET_FACTOR * ((tp_Socket *)s)->rt_route->SMTU)); */
                  if (intarg > ((tp_Socket *) s)->rt_route->max_credit)
                    ((tp_Socket *) s)->rt_route->max_credit =
                      max ((RATE_BUCKET_FACTOR * ((tp_Socket *) s)->rt_route->bytes_per_interval),
                           ((tp_Socket *) s)->rt_route->SMTU);
                  return (0);
                }

              SET_ERR (SCPS_EFAULT);
              return (-1);
              break;
            }

	  case SCPS_RTT:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  intarg = (intarg * 1000);
		  ((tp_Socket *) s)->rt_route->rtt = intarg;
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPS_IRTO:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  intarg = (intarg * 1000000);
		  ((tp_Socket *) s)->rt_route->initial_RTO = intarg;
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPS_MSS_FF:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  ((tp_Socket *) s)->rt_route->MSS_FF = intarg;
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPS_DIV_ADDR:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  ((tp_Socket *) s)->rt_route->DIV_ADDR = intarg;
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPS_DIV_PORT:
	    {
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  ((tp_Socket *) s)->rt_route->DIV_PORT = intarg;
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPS_SP_RQTS:
	    {
#ifdef SECURE_GATEWAY
	      if (optlen == sizeof (uint32_t))
		{
		  memcpy (&intarg, optval, optlen);
		  ((tp_Socket *) s)->rt_route->secure_gateway_rqts = intarg;
		  return (0);
		}
#endif /* SECURE_GATEWAY */
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  case SCPS_IFNAME:
	    {
	      if (optlen <= 16 )
		{
		  memcpy (&((tp_Socket *) s)->rt_route->IFNAME, optval, optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	    }

	  default:
	    SET_ERR (SCPS_ENOPROTOOPT);
	    return (-1);
	  }
      }
      break;

    default:
      SET_ERR (SCPS_EOPNOTSUPP);
      return (-1);
    }
}

/* A SCPS analog of the getsockopt call; It starts off a little braindead */
int
scps_getsockopt (int sockid, int level, int optname, void *optval, int *optlen)
{

  u_int intarg;

  caddr_t s = scheduler.sockets[sockid].ptr;

  if ((!(s)) /*|| (level != SCPS_ROUTE) */
#ifndef GATEWAY
     && (((tp_Socket *) s)->thread != scheduler.current)
#endif /*GATEWAY */
    ) {
      SET_ERR (SCPS_EBADF);
      return (-1);
    }

  switch (level)
    {
    case SCPS_SOCKET:
      {
	switch (optname)
	  {
	  case SCPS_SO_RCVBUF:
	    {			/* Return the current receive-buffer size */
	      if (((tp_Socket *) s)->app_rbuff)
		{
		  *optlen = sizeof (int32_t);
		  memcpy (optval,
			  &(((tp_Socket *) s)->app_rbuff->max_size), *optlen);
		  return (0);
		}
	      SET_ERR (SCPS_ENOPROTOOPT);
	      return (-1);
	    }
	    break;

	  case SCPS_SO_SNDBUF:
	    {			/* Return the current receive-buffer size */
	      if (((tp_Socket *) s)->app_sbuff)
		{
		  *optlen = sizeof (int32_t);
		  memcpy (optval,
			  &(((tp_Socket *) s)->app_sbuff->max_size), *optlen);
		  return (0);
		}
	      SET_ERR (SCPS_ENOPROTOOPT);
	      return (-1);
	    }
	    break;

	  case SCPS_SO_NBLOCK:
	    {
	      *optlen = sizeof (int);
	      if (((tp_Socket *) s)->sockFlags & SOCK_BL) {
		*(int *) optval = (int) 1;
	      } else {
		*(int *) optval = (int) 0;
	      }

	      return (0);
	      break;
	    }

	  case SCPS_SO_NDELAY:
	    {
	      *optlen = sizeof (int);
	      if (((tp_Socket *) s)->sockFlags & SOCK_NDELAY)
		*(int *) optval = (int) 1;
	      else
		*(int *) optval = (int) 0;
	      return (0);
	      break;
	    }

	  case SCPS_SO_BETS_RHOLE_SIZE:
	    {			/* Return the current BETS hole size and reset it to zero! */
	      if ((((tp_Socket *) s)->BETS.Flags & BF_BETS_OK) != BF_BETS_OK)
		{
		  SET_ERR (SCPS_ENOBETS);
		  return (-1);
		}
	      *optlen = sizeof (int32_t);
	      memcpy (optval, &(((tp_Socket *) s)->BETS.Reported_Hole), *optlen);
	      /* s->BETS.Reported_Hole = 0; */
	      return (0);
	    }
	    break;

	  case SCPS_SO_BETS_RHOLE_START:
	    {			/* Return the relative position of the hole in the octet stream */
	      if ((((tp_Socket *) s)->BETS.Flags & BF_BETS_OK) != BF_BETS_OK)
		{
		  SET_ERR (SCPS_ENOBETS);
		  return (-1);
		}
	      *optlen = sizeof (int32_t);
	      intarg = (int32_t) (((tp_Socket *) s)->BETS.Receive_Hole.Start -
				(((tp_Socket *) s)->BETS.Reported_Hole +
				 ((tp_Socket
				   *)
				  s)->BETS.InRecSeq));
	      memcpy (optval, &(intarg), *optlen);
	      return (0);
	    }
	  case SCPS_SO_BETS_NUM_SEND_HOLES:
	    {			/* Return the number of BETS_SEND_HOLES experienced */
	      if ((((tp_Socket *) s)->BETS.Flags & BF_BETS_OK) != BF_BETS_OK)
		{
		  SET_ERR (SCPS_ENOBETS);
		  return (-1);
		}
	      *optlen = sizeof (int);
	      memcpy (optval, &(((tp_Socket *) s)->BETS.num_send_holes), *optlen);
	      return (0);
	    }
	  case SCPS_SO_BETS_SEND_HOLES:
	    /*
	     * Note: This should flush the holes from the list 
	     * once the application has queried it. 
	     */
	    {			/* Copy the send-side BETS holes into a user provided data structure... */
	      if ((((tp_Socket *) s)->BETS.Flags & BF_BETS_OK) != BF_BETS_OK)
		{
		  SET_ERR (SCPS_ENOBETS);
		  return (-1);
		}
	      if ((((tp_Socket *) s)->BETS.num_send_holes * sizeof (struct
								    _Hole))
		  > *optlen)
		{
		  SET_ERR (SCPS_ENOMEM);
		  return (-1);
		}
	      else
		*optlen = (((tp_Socket *) s)->BETS.num_send_holes * sizeof (struct _Hole));
	      /* 
	       * Change the hole locations to be relative to 
	       * the octet count instead of sequence numbers 
	       */
	      for (intarg = 0; intarg < ((tp_Socket *) s)->BETS.num_send_holes;
		   intarg++)
		{
		  ((tp_Socket *) s)->BETS.Send_Holes[intarg].Start -=
		    ((tp_Socket *) s)->BETS.InSndSeq;
		  ((tp_Socket *) s)->BETS.Send_Holes[intarg].Finish -=
		    ((tp_Socket *) s)->BETS.InSndSeq;
		}
	      memcpy (optval, &(((tp_Socket *) s)->BETS.Send_Holes), *optlen);
	      return (0);
	    }
	  default:
	    SET_ERR (SCPS_EOPNOTSUPP);
	    return (-1);
	  }
      }
      break;

#ifdef SCSPNP

    case NP_PROTO_NP:
      {
	switch (optname)
	  {
	  case SCPS_SO_NPTIMESTAMP:
	    {
	      *optlen = sizeof (int);
	      memcpy (optval, &(((tp_Socket *) s)->np_rqts.timestamp), *optlen);
	      return (0);
	      break;
	    }
	  }

    case SCPS_SO_CHECKSUM:
	{
	  *optlen = sizeof (int);
	  memcpy (optval, &(((tp_Socket *) s)->np_rqts.cksum), *optlen);
	  return (0);
	  break;
	}

    case SCPS_SO_PRECEDENCE:
	{
	  *optlen = sizeof (int);
	  memcpy (optval,
		  &(((tp_Socket *) s)->np_rqts.np_bqos.precedence),
		  *optlen);
	  return (0);
	  break;
	}
    default:
	SET_ERR (SCPS_ENOPROTOOPT);
	return (-1);
	break;
      }
      break;
    }
#endif /* USESCPSNP */

case PROTO_SCPSTP:
  {

    if ( (((tp_Socket *) s)->Initialized != SCPSTP) &&
         (((tp_Socket *) s)->Initialized != SCPSROUTE) )
      {
	SET_ERR (SCPS_EPROTONOSUPPORT);
	return (-1);
      }

    switch (optname)
      {
      case SCPSTP_MAXSEG:
	{			/* Return the current maxseg-size */
	  *optlen = sizeof (short);
	  memcpy (optval, &(((tp_Socket *) s)->maxseg), *optlen);
	  return (0);
	  break;
	}

      case SCPSTP_NODELAY:
	{			/* Return whether or not the socket will exhibit blocking */
	  *optlen = sizeof (short);
	  *(int *) optval = (((tp_Socket *) s)->sockFlags & SCPSTP_NODELAY);
	  return (0);
	  break;
	}

      case SCPSTP_ACKDELAY:
	{			/* Return the current ack delay in ms */
	  *optlen = sizeof (uint32_t);
	  *(uint32_t *) optval =
	    ((((tp_Socket *) s)->ACKDELAY));
	  return (0);
	  break;
	}

      case SCPSTP_ACKFLOOR:
	{			/* Return the current AckFloor in ms */
	  *optlen = sizeof (uint32_t);
	  memcpy (optval, &(((tp_Socket *) s)->ACKFLOOR), *optlen);
	  return (0);
	  break;
	}

      case SCPSTP_ACKBEHAVE:
	{			/* Return the current ack_frequency behavior */
	  *optlen = sizeof (unsigned short);
	  memcpy (optval, &(((tp_Socket *) s)->ack_freq), *optlen);
	  return (0);
	}
	break;

      case SCPSTP_RTOMIN:
	{			/* Return the current maxseg-size */
	  *optlen = sizeof (uint32_t);
          {
		u_int intarg;
		intarg = (((tp_Socket *) s)->RTOMIN);
		intarg = (intarg / 1000);
		memcpy (optval, &intarg, *optlen);
          }
	  return (0);
	  break;
	}

      case SCPSTP_RTOMAX:
	{			/* Return the current maxseg-size */
	  *optlen = sizeof (uint32_t);
          {
		u_int intarg;
		intarg = (((tp_Socket *) s)->RTOMAX);
		intarg = (intarg / 1000);
		memcpy (optval, &intarg, *optlen);
          }
	  return (0);
	  break;
	}

	 case SCPSTP_MAXPERSIST_CTR:
	    {
	  	*optlen = sizeof (uint32_t);
                {
			u_int intarg;
			intarg = (((tp_Socket *) s)->MAXPERSIST_CTR);
			memcpy (optval, &intarg, *optlen);
		}
	        return (0);
	        break;
	  }

	 case SCPSTP_RTOPERSIST_MAX:
	    {
	  	*optlen = sizeof (uint32_t);
                {
			u_int intarg;
			intarg = (((tp_Socket *) s)->RTOPERSIST_MAX);
			memcpy (optval, &intarg, *optlen);
		}
	        return (0);
	        break;
	  }

	 case SCPSTP_RTO_TO_PERSIST_CTR:
	    {
	  	*optlen = sizeof (uint32_t);
                {
			u_int intarg;
			intarg = (((tp_Socket *) s)->RTO_TO_PERSIST_CTR);
			memcpy (optval, &intarg, *optlen);
		}
	        return (0);
	        break;
	  }

	  case SCPSTP_EMBARGO_FAST_RXMIT_CTR:
	    {
	  	*optlen = sizeof (uint32_t);
                {
			u_int intarg;
			intarg = (((tp_Socket *) s)->EMBARGO_FAST_RXMIT_CTR);
			memcpy (optval, &intarg, *optlen);
		}
	        return (0);
	        break;
	   }

      case SCPSTP_RETRANSMITTIME:
	{			/* Return the current maxseg-size */
	  *optlen = sizeof (uint32_t);
          {
		u_int intarg;
		intarg = (((tp_Socket *) s)->RETRANSMITTIME);
		intarg = (intarg / 1000);
		memcpy (optval, &intarg, *optlen);
          }
	  return (0);
	  break;
	}

      case SCPSTP_PERSISTTIME:
	{			/* Return the current maxseg-size */
	  *optlen = sizeof (uint32_t);
          {
		u_int intarg;
		intarg = (((tp_Socket *) s)->PERSISTTIME);
		intarg = (intarg / 1000);
		memcpy (optval, &intarg, *optlen);
          }
	  return (0);
	  break;
	}

      case SCPSTP_TIMEOUT:
	{			/* Return the current maxseg-size */
	  *optlen = sizeof (uint32_t);
          {
		u_int intarg;
		intarg = (((tp_Socket *) s)->TIMEOUT);
		intarg = (intarg / 1000);
		memcpy (optval, &intarg, *optlen);
          }
	  return (0);
	  break;
	}

      case SCPSTP_LONGTIMEOUT:
	{			/* Return the current maxseg-size */
	  *optlen = sizeof (uint32_t);
          {
		u_int intarg;
		intarg = (((tp_Socket *) s)->LONGTIMEOUT);
		intarg = (intarg / 1000);
		memcpy (optval, &intarg, *optlen);
          }
	  return (0);
	  break;
	}

      case SCPSTP_2MSLTIMEOUT:
	{			/* Return the current 2MSLTIMEOUT for the socket */
	  *optlen = sizeof (uint32_t);
	  *(uint32_t *) optval =
	    (((tp_Socket *) s)->TWOMSLTIMEOUT);
	  return (0);
	  break;
	}

      case SCPSTP_BETS_RTIMEOUT:
	{			/* Return the current maxseg-size */
	  *optlen = sizeof (uint32_t);
	  *(uint32_t *) optval =
	    (((tp_Socket *) s)->BETS.Receive_Timeout);
	  return (0);
	  break;
	}

#ifdef OPT_TSTMP
      case SCPSTP_TIMESTAMP:
	{
	  *optlen = sizeof (int);
	  *(int *) optval = (((tp_Socket *) s)->capabilities & CAP_TIMESTAMP);
	  if (*(int *)optval) {
		*(int *)optval = 1;
	  }
	  return (0);
	  break;
	}
#endif /* OPT_TSTMP */
#ifdef OPT_COMPRESS
      case SCPSTP_COMPRESS:
	{
	  *optlen = sizeof (int);
	  *(int *) optval = (((tp_Socket *) s)->capabilities & CAP_COMPRESS);
	  if (*(int *)optval) {
		*(int *)optval = 1;
	  }
	  return (0);
	  break;
	}
#endif /* OPT_COMPRESS */
#ifdef OPT_SNACK1
      case SCPSTP_SNACK:
	{
	  *optlen = sizeof (int);
	  *(int *) optval = (((tp_Socket *) s)->capabilities & CAP_SNACK);
	  if (*(int *)optval) {
		*(int *)optval = 1;
	  }
	  return (0);
	  break;
	}

      case SCPSTP_SNACK_DELAY:
	{
	  *optlen = sizeof (uint32_t);
          {
		u_int intarg;
		intarg = (((tp_Socket *) s)->snack_delay);
		intarg = (intarg / 1000);
		memcpy (optval, &intarg, *optlen);
          }
	  return (0);
	  break;
	}
#endif /* OPT_SNACK1 */
#ifdef OPT_BETS
      case SCPSTP_BETS:
	{
	  *optlen = sizeof (int);
	  *(int *) optval = (((tp_Socket *) s)->capabilities & CAP_BETS);
	  return (0);
	  break;
	}
#endif /* OPT_BETS */
#ifdef CONGEST
      case SCPSTP_CONGEST:
	{
	  *optlen = sizeof (int);
	  *(int *) optval = (((tp_Socket *) s)->capabilities & CAP_CONGEST);
	  return (0);
	  break;
	}
	/* Should add a capability to query congestion control algorithm */

       case SCPSTP_VEGAS_ALPHA:
	{
	  *optlen = sizeof (int);
	  *(int *) optval = (((tp_Socket *) s)->VEGAS_ALPHA);
	  return (0);
	  break;
	}

       case SCPSTP_VEGAS_BETA:
	{
	  *optlen = sizeof (int);
	  *(int *) optval = (((tp_Socket *) s)->VEGAS_BETA);
	  return (0);
	  break;
	}

       case SCPSTP_VEGAS_GAMMA:
	{
	  *optlen = sizeof (int);
	  *(int *) optval = (((tp_Socket *) s)->VEGAS_GAMMA);
	  return (0);
	  break;
	}

       case SCPSTP_VEGAS_SS:
	{
	  *optlen = sizeof (int);
	  *(int *) optval = (((tp_Socket *) s)->VEGAS_SS);
	  return (0);
	  break;
	}

#endif /* CONGEST */

      default:
	SET_ERR (SCPS_EOPNOTSUPP);
	return (-1);
      }
    break;
  }
case SCPS_ROUTE:
  {
    if ((((tp_Socket *) s)->Initialized != SCPSROUTE))
      {
	SET_ERR (SCPS_EPROTONOSUPPORT);
	return (-1);
      }
    switch (optname)
      {
      case SCPS_RATE:
	{
	  *optlen = sizeof (uint32_t);
	  intarg = ((((tp_Socket *) s)->rt_route->bytes_per_interval) * 8000)
	    / (((tp_Socket *) s)->rt_route->interval);
	  memcpy (optval, &intarg, *optlen);
	  return (0);
	  break;
	}

#ifdef MIN_RATE_THRESH
      case SCPS_MIN_RATE:
	{
	  *optlen = sizeof (uint32_t);
	  intarg = ((((tp_Socket *) s)->rt_route->min_bytes_per_interval) * 8000)
	    / (((tp_Socket *) s)->rt_route->interval);
	  memcpy (optval, &intarg, *optlen);
	  return (0);
	  break;
	}
#endif /* MIN_RATE_THRESH */

	case SCPS_TCPONLY:
	  {	
		*optlen = sizeof (uint32_t);
	  	*(int *) optval = ((tp_Socket *) s)->rt_route->TCPONLY;
		return (0);
  	  }
#ifdef FLOW_CONTROL_THRESH
      case SCPS_FLOW_CONTROL:
	{
	  *optlen = sizeof (uint32_t);
	  intarg = ((((tp_Socket *) s)->rt_route->flow_control) * 8000)
	    / (((tp_Socket *) s)->rt_route->interval);
	  memcpy (optval, &intarg, *optlen);
	  return (0);
	  break;
	}
#endif /* FLOW_CONTROL_THRESH */


      case SCPS_ENCRYPT_IPSEC:
	{
	  *optlen = sizeof (u_int);
	  intarg = ((tp_Socket *) s)->rt_route->encrypt_ipsec;
	  memcpy (optval, &intarg, *optlen);
	  return (0);
	  break;
	}

      case SCPS_ENCRYPT_PRE_OVERHEAD:
	{
	  *optlen = sizeof (u_int);
	  intarg = ((tp_Socket *) s)->rt_route->encrypt_pre_overhead;
	  memcpy (optval, &intarg, *optlen);
	  return (0);
	  break;
	}

      case SCPS_ENCRYPT_BLOCK_SIZE:
	{
	  *optlen = sizeof (u_int);
	  intarg = ((tp_Socket *) s)->rt_route->encrypt_block_size;
	  memcpy (optval, &intarg, *optlen);
	  return (0);
	  break;
	}

      case SCPS_ENCRYPT_POST_OVERHEAD:
	{
	  *optlen = sizeof (u_int);
	  intarg = ((tp_Socket *) s)->rt_route->encrypt_post_overhead;
	  memcpy (optval, &intarg, *optlen);
	  return (0);
	  break;
	}
      case SCPS_MTU:
	{
	  *optlen = sizeof (u_int);
	  intarg = ((tp_Socket *) s)->rt_route->MTU;
	  memcpy (optval, &intarg, *optlen);
	  return (0);
	  break;
	}

      case SCPS_SMTU:
        {
          *optlen = sizeof (u_int);
          intarg = ((tp_Socket *) s)->rt_route->SMTU;
          memcpy (optval, &intarg, *optlen);
          return (0);
          break;
        }

      case SCPS_RTT:
	{
	  *optlen = sizeof (uint32_t);
	  intarg = (((tp_Socket *) s)->rt_route->rtt * 1000);
	  memcpy (&intarg, optval, *optlen);
	  return (0);
	  break;
	}

      case SCPS_IRTO:
	{
	  *optlen = sizeof (uint32_t);
	  intarg = (((tp_Socket *) s)->rt_route->initial_RTO * 1000000);
	  memcpy (&intarg, optval, *optlen);
	  return (0);
	  break;
	}

      case SCPS_MSS_FF:
        {
          *optlen = sizeof (u_int);
          intarg = ((tp_Socket *) s)->rt_route->MSS_FF;
          memcpy (optval, &intarg, *optlen);
          return (0);
          break;
        }

      case SCPS_DIV_ADDR:
        {
          *optlen = sizeof (u_int);
          intarg = ((tp_Socket *) s)->rt_route->DIV_ADDR;
          memcpy (optval, &intarg, *optlen);
          return (0);
          break;
        }

      case SCPS_DIV_PORT:
        {
          *optlen = sizeof (u_int);
          intarg = ((tp_Socket *) s)->rt_route->DIV_PORT;
          memcpy (optval, &intarg, *optlen);
          return (0);
          break;
        }

       case SCPS_SP_RQTS:
	    {
#ifdef SECURE_GATEWAY
              *optlen = sizeof (uint32_t);
              intarg = ((tp_Socket *) s)->rt_route->secure_gateway_rqts;
	      return (0);
#else /* SECURE_GATEWAY */
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
#endif /* SECURE_GATEWAY */
	      break;
	    }

      case SCPS_IFNAME:
	{
	      if (*optlen <= 16 )
		{
		  memcpy (&((tp_Socket *) s)->rt_route->IFNAME, optval, *optlen);
		  return (0);
		}
	      SET_ERR (SCPS_EFAULT);
	      return (-1);
	      break;
	}

      default:
	SET_ERR (SCPS_EOPNOTSUPP);
	return (-1);
      }
  }
  break;
default:
  SET_ERR (SCPS_EOPNOTSUPP);
  return (-1);
}
}
