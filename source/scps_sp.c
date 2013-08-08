#ifdef SCPSSP
#define ANSI
/*
**      Space Communications Protocols Standards
**
**                                  Security Protocol   4/96
**
**
*/

/*
**
** First version October 1, 1995
** 
** Revised 4/96 to integrate with CCSDS path services
**
*/

/*
 * This software was developed by SPARTA, Inc and
 * was produced for the US Government under Contract
 * MDA904-95-C-50015 is subject to Department of Defense
 * Federal Acquisition Regulation Clause 252.227.7013,
 * Alt. 2, Clause 252.227.7013 and Federal Acquisition
 * Regulation Clause 52.227-14, Rights in Data - General
 *  
 *  
 * NOTICE
 *  
 *  
 * SPARTA PROVIDES THIS SOFTWARE "AS IS" AND MAKES NO
 * WARRANTY, EXPRESS OR IMPLIED, AS TO THE ACCURACY,
 * CAPABILITY, EFFICIENCY, OR FUNCTIONING OF THE PRODUCT.
 * IN NO EVENT WILL SPARTA BE LIABLE FOR ANY GENERAL,
 * CONSEQUENTIAL, INDIRECT, INCIDENTAL, EXEMPLARY, OR
 * SPECIAL DAMAGES, EVEN IF MITRE HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *  
 * You accept this software on the condition that you
 * indemnify and hold harmless SPARTA, its Board of
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
 */

/* For STRV make sure data is placed below 8000 for byte addressability
*/

/* Global variable for security requirements:
   Easily changed on STRV 
*/

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: scps_sp.c,v $ -- $Revision: 1.14 $\n";
#endif

int32_t processed, failures, received;

#include "scps.h"
#include "scps_np.h"
#include "scps_sadb.h"
#include "scps_sp.h"
#include "scpsnp_protos.h"

int ip_get_template (scps_np_rqts * rqts, ip_template * templ);
int ip_trequest (tp_Socket * s, struct mbuff *m, uint32_t * bytes_sent);

extern SA_data SA_table[4];
extern struct msghdr out_msg;

int sp_get_template (scps_sp_rqts * spreqs, sp_template * sp_temp);
int sp_trequest (tp_Socket * s, route * nroute, int *bytes_sent,
		 struct mbuff *m, int th_off);
int test_decrypt (char *prot_data, SA_data * SAinfo);
int get_SAinfo (scps_np_rqts * np_rqts, SA_data * SAinfo);

#ifdef SECURE_GATEWAY
#include "rs_config.h"
extern GW_ifs gw_ifs;
#endif /* SECURE_GATEWAY */

#ifdef DUMBOS
int
memcmp (adr1, adr2, length)
     char *adr1;
     char *adr2;
     int length;
{
  int i;
  for (i = 0; i < length; i++)
    if (*adr1++ != *adr2++)
      return (-1);
  return (0);
}

int
memcpy (adr1, adr2, length)
     char *adr1;
     char *adr2;
     int length;
{
  int i;
  for (i = 0; i < length; i++)
    *adr1++ = *adr2++;
  return;
}

int
memset (adr, val, length)
     char *adr;
     char val;
     int length;
{
  int i = 0;
  while (i++ < length)
    *adr++ = (char) val;
}

#endif /* DUMBOS */

#define MAX_PKTSIZE MAX_MTU

unsigned char ws[MAX_PKTSIZE];	/*  The memory buffer  */
int max_space;			/*   Its size          */
char sp_pdu[MAX_PKTSIZE];	/* A secured or 
				   processed data unit */

int sp_length;			/* Length of data unit */

#define  Clear_Header      ws[0]
#define  Protected_Header  ws[1]
#define  Protected_Data  (&ws[1])
#undef NOT_DEFINED
#ifdef NOT_DEFINED
/*============================== sp_request ================================*/
/*                                                                          */
/*                The fully connectionless API to scps_sp                   */
/*                                                                          */
/*==========================================================================*/
#ifdef ANSI
int
sp_request (scps_sp_rqts * rqts,
	    route * nroute,
	    short length,
	    char *data)
#else /* ANSI */
int
sp_request (rqts, nroute, length, data)
     scps_sp_rqts *rqts;
     route *nroute;
     short length;
     char *data;
#endif /* ANSI */
{
  int return_value;
  sp_template template;

  sp_get_template (rqts, &template);

  return_value = sp_trequest (&template, nroute, length, data);

  return (return_value);
}
#endif /* NOT_DEFINED */


/*============================= sp_get_template ============================*/
/*                                                                          */
/*   Build a template for connection oriented users, which will store the   */
/*  NP routing and SP security values.                                      */
/*                                                                          */
/*==========================================================================*/
#ifdef ANSI
int
sp_get_template (scps_sp_rqts * spreqs,
		 sp_template * sp_temp)
#else /* ANSI */
int
sp_get_template (spreqs, sp_temp)
     scps_sp_rqts *spreqs;
     sp_template *sp_temp;
#endif /* ANSI */
{

  spreqs->np_rqts.tpid = SP;

  switch (spreqs->np_rqts.nl_protocol) {
        case NL_PROTOCOL_IP:
                ip_get_template ((scps_np_rqts *) & (spreqs->np_rqts),
                                 &(sp_temp->ip_templ));
                break;
        case NL_PROTOCOL_NP:
                scps_np_get_template ((scps_np_rqts *) & (spreqs->np_rqts),
                                      &(sp_temp->np_templ));
                break;
    }

/* Store the np and security requirements */
  memcpy ((char *) &(sp_temp->np_rqts), (char *) &(spreqs->np_rqts), sizeof (scps_np_rqts));
  sp_temp->sp_rqts = (u_char) (spreqs->sprqts | ((spreqs->tpid & 0xF) << 4));

  return (0);
}


/*==============================  sp_request  ==============================*/
/*                                                                          */
/*                  Build a security protocol data unit                     */
/*                                                                          */
/*==========================================================================*/
#ifdef ANSI
int
sp_trequest (tp_Socket * s,
	     route * nroute,
	     int *bytes_sent,
	     struct mbuff *m,
	     int th_off)
#else /* ANSI */
int
sp_trequest (s, nroute, bytes_sent, m, th_off)
     tp_Socket *s;
     route *nroute;
     int *bytes_sent;
     struct mbuff *m;
     int th_off;
#endif /* ANSI */
{
  int sp_hdr_len = 0;
  int data_len;			/* For tracking the size of the SP PDU as it
				   is being constructed  */
  unsigned char lin_buff[MAX_MTU];
  unsigned int len = m->m_hdr.mh_len + m->M_dat.MH.MH_ext.len;
  int cc = 0;

/* sp_template *sp_temp = &(s -> sp_templ); */
  scps_sp_rqts *rqts;
  SA_data SAinfo;

/* Could check for overflow here... */

  memcpy ((char *) &lin_buff, m->m_pktdat + s->th_off, m->m_len);
  clust_copy ((struct mbcluster *) m->m_ext.ext_buf, (lin_buff + m->m_len),
	      m->m_ext.len, m->m_ext.offset);

  rqts = &(s->sp_rqts);

#ifdef SECURE_GATEWAY
  if (rqts->secure_gateway_rqts == SECURE_GATEWAY_NO_SECURITY) {
    s->np_rqts.tpid = s->sp_rqts.np_rqts.tpid = s->sp_rqts.tpid;

  switch (rqts->np_rqts.nl_protocol) {
        case NL_PROTOCOL_IP:
                s->np_size = ip_get_template (&(s->np_rqts), &(s->ip_templ));
                cc = ip_trequest (s, m, (uint32_t *) bytes_sent);
                break;     
        case NL_PROTOCOL_NP:
                s->np_size = scps_np_get_template (&(s->np_rqts), &(s->np_templ));
                cc = scps_np_trequest (s, NULL, NULL, *bytes_sent, m, s->th_off);    
                break; 
    }  

   return (cc);
  }
#endif /* SECURE_GATEWAY */

#ifdef NOT_DEFINED
/*  Set the timestamp in rqts->np_rqts:
 **   if timestamp is NULL, set " " " ".timestamp to fine time.
 **/
  memset ((char *) (rqts->np_rqts.timestamp.ts_val), 0, 4);
  if (ts == NULL)
    {
      struct timeval t1;
      gettimeofday (&t1, NULL);
      rqts->np_rqts.timestamp.ts_val[3] = (char) ((t1.tv_usec >> 16) & 0x0FF);
      rqts->np_rqts.timestamp.ts_val[2] = (char) ((t1.tv_usec >> 24) & 0x0FF);
      rqts->np_rqts.timestamp.format = SCPS32;
    }
  else
    {
      memcpy ((char *) (rqts->np_rqts.timestamp.ts_val), (char *)
	      (ts->ts_val), 4);
      rqts->np_rqts.timestamp.format = ts->format;
    }
#endif /* NOT_DEFINED */

/* Retrieve the security association values from the SADB                   */
  if ((get_SAinfo (&(rqts->np_rqts), &SAinfo)) == -1)
    {
#ifdef SECURE_GATEWAY
  if (rqts->secure_gateway_rqts == SECURE_GATEWAY_ON_DEMAND) {
    s->np_rqts.tpid = SCPSTP;
    s->sp_rqts.tpid = SCPSTP;
    s->sp_rqts.np_rqts.tpid = SCPSTP;
   
    switch (s->np_rqts.nl_protocol) {
        case NL_PROTOCOL_IP:
                s->np_size = ip_get_template (&(s->np_rqts), &(s->ip_templ));
                cc = ip_trequest (s, m, (uint32_t *) bytes_sent);
                break;
        case NL_PROTOCOL_NP: 
                s->np_size = scps_np_get_template (&(s->np_rqts), &(s->np_templ));              
                cc = scps_np_trequest (s, NULL, NULL, *bytes_sent, m, s->th_off);            
                break;
    }           

  } else {

#ifdef SECURE_GATEWAY_DEBUG
  int i;

      for (i = 0; i < len; i++)
        { 
        printf ("%x ", (unsigned char) (0x0ff & (lin_buff[i])));
        if (i % 32 == 31)
          printf ("\n");
        }
      printf ("\n");
#endif /* SECURE_GATEWAY_DEBUG */

printf ("PDF no entry in sadb %lx %lx %s %d\n",rqts->np_rqts.src_addr, rqts->np_rqts.src_addr,__FILE__, __LINE__); 
  return (0);
  }
#else /* SECURE_GATEWAY */
      exit (0);
#endif /* SECURE_GATEWAY */

    }

/*  Initialize the clear header         */
  Clear_Header = (char) (rqts->tpid);

/*  Initialize the protected header     */
  Protected_Header = (char) 0;

  data_len = 2;

/*   --------------
 *   SECURITY LABEL - add a security label to the protected header ?
 *   --------------
 */
  if ((rqts->sprqts & SECURITY_LABEL) || (SAinfo.QOS & SECURITY_LABEL))
    {
      Protected_Header |= SEC_LABEL;	/* Set security label bitflag in
					   the protected header flags */
      ws[data_len++] = SAinfo.sec_label_len;
      memcpy ((char *) &(ws[data_len]), (char *) (SAinfo.sec_label), SAinfo.sec_label_len);
      data_len += SAinfo.sec_label_len;
    }

/*   --------------
 *   AUTHENTICATION - copy the PATH addresses to protected header
 *   --------------
 *
 *    size of addresses are assumed to be 4 bytes for now (CCSDS path)
 */
  if ((rqts->sprqts & AUTHENTICATION) || (SAinfo.QOS & AUTHENTICATION))
    {
      uint32_t flipped_addr;
      Protected_Header |= ENCAPS_NP_ADDR;	/* Set authentication bitflag in
						   the protected header flags    */

      /*  Copy the source NP address into protected header  */
      flipped_addr = ntohl (rqts->np_rqts.src_addr);
      memcpy ((char *) &ws[data_len], (char *) &(flipped_addr),
	      4);
      /*     ADDR_LEN(rqts->np_rqts.src_addr.type) ); */
      data_len += 4;		/* ADDR_LEN(rqts->np_rqts.src_addr.type) ; */

      /*  Copy the destination NP address into protected header  */
      flipped_addr = ntohl (rqts->np_rqts.dst_addr);
      memcpy ((char *) &ws[data_len], (char *) &(flipped_addr),
	      4);
      /*     ADDR_LEN(rqts->np_rqts.dst_addr.type) ); */
      data_len += 4;		/* ADDR_LEN(rqts->np_rqts.dst_addr.type) ; */

    }

/*   -------
 *   PADDING  - Add any necessary padding to the protected header
 *   -------
 */
  if ((rqts->sprqts & CONFIDENTIALITY) || (SAinfo.QOS & CONFIDENTIALITY))
    {
      int plainlen;
      char padvalue;

      plainlen = data_len - 1;	/* Don't include the clear header */
      plainlen += len;

      /*  If integrity is being applied, include the size of the ICV as well.
       */
      if ((rqts->sprqts & INTEGRITY) || (SAinfo.QOS & INTEGRITY))
	plainlen += SAinfo.ICVsize;

      /*  Apply padding as necessary for encryption.
       */
      if (plainlen % SAinfo.crypt_blksize)
	{
	  Protected_Header |= PADDING;
	  padvalue = SAinfo.crypt_blksize - (plainlen % SAinfo.crypt_blksize);
	  do
	    ws[data_len++] = padvalue;
	  while (++plainlen % SAinfo.crypt_blksize);
	}
    }

/* --------------------
**  Copy the TP packet
** --------------------
*/

  memcpy ((char *) &ws[data_len], lin_buff + 0, len);
  sp_hdr_len = data_len;
  data_len += len;


/*   ---------------------
 *   INTEGRITY CHECK VALUE - compute an integrity check value over the SP-PDU
 *   ---------------------
 */
  if (rqts->sprqts & INTEGRITY)
    {
      /*
         **  Compute an ICV over the TP-PDU and append to workspace buffer
       */
      Protected_Header |= ICV_APPEND;
      compute_ICV (&SAinfo, Protected_Data, data_len - 1, &ws[data_len]);
      data_len += SAinfo.ICVsize;
    }


/*   ---------------
 *   CONFIDENTIALITY - secure the header and data being protected (in place)
 *   ---------------
 */
  if (SAinfo.QOS & CONFIDENTIALITY)
    {
      IV MI;
/* 
** Encrypt the newly constructed packet.
** The algorithm employed, as well as the key(s), will be directed by the SADB
*/
      generate_IV (&(rqts->np_rqts), MI);
      encrypt_data (&SAinfo, MI, Protected_Data, data_len - 1);
    }


/* SP packet built, pass down to NP (path) */



#ifdef SP_STANDALONE
  while (!(ll_ready ()));
  /* I ain't got no body ... */
#endif /* SP_STANDALONE */

  {
    struct mbuff *m_tmp;

/* All tp_header and SP header is combined in the external buffer
   for a new mbuff  */
    m_tmp = mb_attach (NULL, ws, data_len);

    *bytes_sent = data_len;

    switch (s->np_rqts.nl_protocol) {
        case NL_PROTOCOL_IP:
                cc = ip_trequest (s, m_tmp, (uint32_t *) bytes_sent);
                break;
        case NL_PROTOCOL_NP: 
                cc = scps_np_trequest (s, NULL, NULL, data_len, m_tmp, s->sh_off);  
                break;
    } 

    free_mbuff (m_tmp);
    return (cc);
  }

}



/*================================ sp_ind ==================================*/
/*                                                                          */
/*                The fully connectionless API to scps_sp                   */
/*                                                                          */
/*==========================================================================*/
#ifdef ANSI
int
sp_ind (scps_sp_rqts * sp_rqts,
	short length,
	int *offset)
#else /* ANSI */
int
sp_ind (sp_rqts, length, offset)
     scps_sp_rqts *sp_rqts;
     short length;
     int *offset;
#endif /* ANSI */
{
  int track, final_length;
  int pktlen;
  SA_data SAinfo;
  scps_sp_rqts *rqts = sp_rqts;
  unsigned char *sp_data;
#ifdef SECURE_GATEWAY
  int gateway_secure_mode = SECURE_GATEWAY_NO_SECURITY;
#endif /* SECURE_GATEWAY */

/* Retrieve data packet from PATH */

#ifdef PATH
  pktlen = path_ind (&(rqts->np_rqts), length, offset);
#else /* PATH */
  pktlen = nl_ind (&(rqts->np_rqts), length, offset);
#endif /* PATH */

  if (pktlen == 0)
    return (0);
  if (pktlen == -1)
    return (0);

  (int32_t) received++;

/*sp_data = (char *) (in_data->data + in_data -> offset); */
  sp_data = (char *) (in_data->data + *offset);

#ifdef SECURE_GATEWAY
  if (in_data->divert_port_number == gw_ifs.aif_divport) {
    gateway_secure_mode = gw_ifs.aif_scps_security;
  }

  if (in_data->divert_port_number == gw_ifs.bif_divport) {
    gateway_secure_mode = gw_ifs.bif_scps_security;
  }

  rqts->secure_gateway_rqts = gateway_secure_mode;

  if ((gateway_secure_mode != SECURE_GATEWAY_STRICT_SECURITY) &&
      ( (rqts->np_rqts.tpid == SCPSTP) ||
        (rqts->np_rqts.tpid == SCPSUDP) ||
        (rqts->np_rqts.tpid == ICMP))) {
      return (pktlen);
  }
#else /* SECURE_GATEWAY */

  if (rqts->np_rqts.tpid != SP) {
    return (0);
  }

#endif /* SECURE_GATEWAY */
/* if( sp_data [0] & 0x0F0 ) return( -1 ); */

  rqts->tpid = sp_data[0];

/* Obtain the security association values for this association (address pair).
*/
  if ((get_SAinfo (&(rqts->np_rqts), &SAinfo)) == -1)
    {
#ifdef SECURE_GATEWAY
      return (0);
#else /* SECURE_GATEWAY */
      exit (0);
#endif /* SECURE_GATEWAY */
    }

  memcpy ((char *) ws, (char *) sp_data, pktlen);

/*   ---------------
 *   CONFIDENTIALITY - Decipher encrypted data first 
 *   ---------------
 */

  if ((rqts->sprqts & CONFIDENTIALITY) || (SAinfo.QOS & CONFIDENTIALITY))
    {
      IV MI;

      generate_IV (&rqts->np_rqts, MI);
      decrypt_data (&SAinfo, MI, Protected_Data, pktlen - 1);

      /*  Test for possible timestamp rollover:
         **    4 bits within the protected header will always be zero...
         **    if there is any padding, it can be checked as well.
       */
      if (test_decrypt ((unsigned char *) (Protected_Data), &SAinfo) != 0)
	{
	  /* Decryption must be incorrect!  Try a rollback of the course time 
	     ** component of the MI...
	   */
	  uint32_t t;
	  t = 0;
	  t = (int32_t) MI[2] << 24;
	  t |= (int32_t) MI[3] << 16;
	  t |= (int32_t) MI[4] << 8;
	  t -= 1;
	  MI[4] = (t >> 8) & 0xFF;
	  MI[3] = (t >> 16) & 0xFF;
	  MI[2] = (t >> 24) & 0xFF;

	  /* Recopy the incoming SP-PDU to the work space */
	  memcpy ((char *) ws, (char *) sp_data, pktlen);

	  decrypt_data (&SAinfo, MI, Protected_Data, pktlen - 1);
	  if (test_decrypt (Protected_Data, &SAinfo) != 0)
	    {
	      log_sp_error (CORRUPTED_SP_PDU);
	      return (0);
	    }
	}
    }



/*   ---------------------
 *   INTEGRITY CHECK VALUE - verify the integrity check value for the SP-PDU
 *   ---------------------
 */
  if (Protected_Header & ICV_APPEND)
    {
      char ICVtest[MAX_ICV_LEN];
      compute_ICV (&SAinfo, Protected_Data, (int) pktlen - 1 - SAinfo.ICVsize,
		   ICVtest);
      if (memcmp ((char *) &ws[pktlen - SAinfo.ICVsize],
		  (char *) ICVtest, SAinfo.ICVsize) != 0)
	{
	  log_sp_error (INTEGRITY_CHECK_FAILED);
	  return (-1);
	}
    }

  track = 2;			/* Track is used to parse out the optional fields */


/*   --------------
 *   SECURITY LABEL - check the security label if present
 *   --------------
 */
  if (Protected_Header & SEC_LABEL)
    {
      track++;			/* Walk past the length field before the compare */
      if (memcmp ((char *) &ws[track], (char *) (SAinfo.sec_label),
		  SAinfo.sec_label_len) != 0)
	{
	  log_sp_error (SECURITY_LABEL_BAD);
	  return (-1);
	}
      track += SAinfo.sec_label_len;
    }


/*   --------------
 *   AUTHENTICATION - verify the encapsulated NP addresses match those in
 *   --------------   the scps_np_rqts structure
 */
  if (Protected_Header & ENCAPS_NP_ADDR)
    {
      uint32_t tmp_addr;
      uint32_t flipped_addr;

      memcpy (&tmp_addr, &ws[track], 4);
      flipped_addr = ntohl (tmp_addr);
      if (memcmp ((char *) &flipped_addr, (char *)
		  &(rqts->np_rqts.src_addr), 4) != 0)
	{
/*            ADDR_LEN(rqts->np_rqts.src_addr.type) )     != 0 ) { */
	  log_sp_error (AUTHENTICATION_FAILED);
	  return (-1);
	}
      track += 4;		/* ADDR_LEN(rqts->np_rqts.src_addr.type) ; */

      memcpy (&tmp_addr, &ws[track], 4);
      flipped_addr = ntohl (tmp_addr);
      if (memcmp ((char *) &flipped_addr, (char *)
		  &(rqts->np_rqts.dst_addr), 4) != 0)
	{
/* ADDR_LEN(rqts->np_rqts.dst_addr.type) )     != 0 ) { */
	  log_sp_error (AUTHENTICATION_FAILED);
	  return (-1);
	}
      track += 4;		/*ADDR_LEN(rqts->np_rqts.dst_addr.type) ; */
    }


/*    At this point, everything has checked out, so locate the TP-PDU between
 *    the protected header and the optional ICV and pass on to scps_tp_ind.
 */

  if (Protected_Header & PADDING)
    track += ws[track];

  final_length = pktlen;
  if (Protected_Header & ICV_APPEND)
    final_length -= SAinfo.ICVsize;
  final_length -= track;

/*memcpy( (char *)(in_data->data + in_data -> offset), (char *)&ws[track] , final_length ); */
  memcpy ((char *) (in_data->data + *offset), (char *) &ws[track], final_length);
  (int32_t) processed++;
  return (final_length);
}


/*
 *   test_decrypt attempts to determine if a decrypted SP-PDU is valid or not.
 *   Returns:  0 -> the data unit is valid
 *            -1 -> the data unit is invalid
 */
#ifdef ANSI
int
test_decrypt (char *prot_data, SA_data * SAinfo)
#else /* ANSI */
int
test_decrypt (prot_data, SAinfo)
     char *prot_data;
     SA_data *SAinfo;
#endif /* ANSI */
{
  int pad_off;

  /*  Test the header: the protected header has 4 bits that should always
     **  be zero...
   */
/*  if( prot_data[0] & 0x0F ) return(-1); */

  /* Check padding and make sure it is valid */
  if (prot_data[0] & PADDING)
    {
      int count;
      char padvalue;
      pad_off = 1;
      if (prot_data[0] & SEC_LABEL) {
	pad_off += (int) SAinfo->sec_label_len + 1;
}
      if (prot_data[0] & ENCAPS_NP_ADDR)
	{
	  pad_off += 4;		/*ADDR_LEN( SAinfo->src.type ); */
	  pad_off += 4;		/*ADDR_LEN( SAinfo->dst.type ); */
	}
      padvalue = prot_data[pad_off];
       
      if ((padvalue - 1) >= MAX_CRYPT_PAD) {
	return (-1);
      }

      for (count = 1; count < padvalue; count++)  {
	if (prot_data[count + pad_off] != padvalue) {
	  return (-1);
        }
      }
    }
  return (0);
}



/* ---------------------------------------------------------------------- */
/*                    log_sp_error: SCPS_SP Error handler                 */
/* ---------------------------------------------------------------------- */
#ifdef ANSI
void
log_sp_error (enum ERRORS error)
#else /* ANSI */
void
log_sp_error (error)
     enum ERRORS error;
#endif /* ANSI */
{

#ifdef LASHAM
  switch (error)
    {
    case MEM_ALLOC_FAILED:
      printf (" Memory allocation failed. \n");
      break;
    case DATA_OVERFLOW:
      printf ("Data overflow. \n");
      break;
    case INTEGRITY_CHECK_FAILED:
      printf ("Data integrity check failed. \n");
      break;
    case AUTHENTICATION_FAILED:
      printf ("Authentication check failed.\n");
      break;
    case ERROR_ACCESSING_SA_FILE:
      printf ("Error opening/accessing security associations file.\n");
      break;
    case SA_NOT_FOUND:
      printf ("Security association not found in database.\n");
      break;
    case CORRUPTED_SP_PDU:
      printf ("Corrupt data unit encountered.\n");
      break;
    case SECURITY_LABEL_BAD:
      printf ("Bad security label.\n");
      break;
    }
#endif /* LASHAM */

  (int32_t) failures++;

}



#ifdef NOT_DEFINED
/*=============================== generate_IV ==============================*/
/*                                                                          */
/*  For now this simply uses network addresses as the MI. Clock values will */
/*  be implemented later. STRV clock has too much drift, and only 100ms     */
/*  accuracy.                                                               */
/*==========================================================================*/
#ifdef ANSI
void
generate_IV (scps_np_rqts * rqts, IV * MI)
#else /* ANSI */
void
generate_IV (rqts, MI)
     scps_sp_rqts *rqts;
     IV *MI;
#endif /* ANSI */
{
  memcpy ((char *) MI, (char *) &(rqts->src_addr), 4);
  memcpy ((char *) MI + 4, (char *) &(rqts->dst_addr), 4);
}

#endif /* NOT_DEFINED */
#undef ANSI
#endif /*SCPSSP */
