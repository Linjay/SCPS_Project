#ifdef SCPSSP
#define ANSI
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

/*     SCPS_SP cryptographic functions
*/

#include "scps.h"
#include "scpstp.h"
#include "scpsnp_protos.h"
#include "scps_sp.h"
#include "scps_sadb.h"
#include "md5.h"

#ifdef DES
#include "des/des.h"
#endif /* DES */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: scps_spc.c,v $ -- $Revision: 1.10 $\n";
#endif

int MD5Init (MD5_CTX * context);
int MD5Final (unsigned char *digest, MD5_CTX * context);
int MD5Update (MD5_CTX * context, unsigned char *input, unsigned int inputLen);
void kxor (char *data, int length, char *key);

/*
**  Compute a keyed integrity check value for a given packet of data.
**  Select the algorithm and key employed based on the security association.
**
*/
#ifdef ANSI
void
compute_ICV (SA_data * SAinfo, char *data, int length, char *ICV)
#else /* ANSI */
void
compute_ICV (SAinfo, data, length, ICV)
     SA_data *SAinfo;
     char *data;
     int length;
     char *ICV;
#endif /* ANSI */
{
  MD5_CTX context;

/*   Add integrity algorithms here... for now there's only MD5.
**   The types are enumerated in scps_sadb.h and the maximum integrity
**   check value's size is specified in scps_sadb.h
*/
  switch (SAinfo->ICV_algo)
    {

    case MD5:
      MD5Init (&context);
      MD5Update (&context, SAinfo->ICVkey, MAX_ICV_KEY);
      MD5Update (&context, data, length);
      MD5Final (ICV, &context);
      break;

    }
}


/* Generate a 64 bit initialization vector for the encryption and decryption 
** as follows:
**   16 bits of fine time taken from the low order bits of 
**      scps_np_rqts.timestamp.ts_val
**   24 bits of course time from system clock (take the 24 most sig. bits)
**      in seconds since GMT 00:00, Jan 1, 1970
**   24 bits of source and destination addresses:
**       ( (source & 0xFFFF) << 8 )  |  (destination & 0xFFFF)
*/
#ifdef ANSI
void
generate_IV (scps_np_rqts * np_rqts, char *MI)
#else /* ANSI */
void
generate_IV (np_rqts, MI)
     scps_np_rqts *np_rqts;
     char *MI;
#endif /* ANSI */
{

#undef NOT_DEFINED
#ifdef NOT_DEFINED

  struct timeval t1;

  MI[0] = np_rqts->timestamp.ts_val[2];
  MI[1] = np_rqts->timestamp.ts_val[3];

/* Copy the 2 least significant bytes into MI */
  MI[5] = (char) (np_rqts->src_addr[0] & 0x0FF);
  MI[6] = (char) np_rqts->src_addr[1];

  MI[6] ^= np_rqts->dst_addr.addr[ADDR_LEN (np_rqts->dst_addr.type) - 2];
  MI[7] = np_rqts->dst_addr.addr[ADDR_LEN (np_rqts->dst_addr.type) - 1];

/* Finally, add the course time clock */
  gettimeofday (&t1, NULL);

  MI[2] = (unsigned char) ((t1.tv_sec >> 24) & 0xFF);
  MI[3] = (unsigned char) ((t1.tv_sec >> 16) & 0xFF);
  MI[4] = (unsigned char) ((t1.tv_sec >> 8) & 0xFF);
#endif /* NOT_DEFINED */

  memcpy ((char *) MI, (char *) "IVIVIVIV", 8);

  return;
}



/* Encrypt data takes a pointer to a data buffer and encrypts that data in place. */
#ifdef ANSI
void
encrypt_data (SA_data * SAinfo, IV MI, char *data, int length)
#else /* ANSI */
void
encrypt_data (SAinfo, MI, data, length)
     SA_data *SAinfo;
     IV MI;
     char *data;
     int length;
#endif /* ANSI */
{
  switch (SAinfo->crypt_algo)
    {
      /*  For now, just use a simple xor 'cipher' 
       */

#ifdef DES
    case DES:
      {
	des_key_schedule ks;
	des_set_key ((des_cblock *) SAinfo->crypt_key, ks);
	des_cbc_encrypt ((des_cblock *) data, (des_cblock *) data, length,
			 ks, (des_cblock *) MI, 1);
	break;
      }
#endif /* DES */
    default:
    case XOR:
      kxor (data, length, SAinfo->crypt_key);
      break;
    }

  return;
}


/* Decrypt data takes a pointer to a data buffer and decrypts that data in place. */
#ifdef ANSI
void
decrypt_data (SA_data * SAinfo, IV MI, char *data, int length)
#else /* ANSI */
void
decrypt_data (SAinfo, MI, data, length)
     SA_data *SAinfo;
     IV MI;
     char *data;
     int length;
#endif /* ANSI */
{
  switch (SAinfo->crypt_algo)
    {
      /*  For now, just use a simple xor 'cipher' 
       */

#ifdef DES
    case DES:
      {
	des_key_schedule ks;
	des_set_key ((des_cblock *) SAinfo->crypt_key, ks);
	des_cbc_encrypt ((des_cblock *) data, (des_cblock *) data, length,
			 ks, (des_cblock *) MI, 0);
	break;
      }
#endif /* DES */

    default:
    case XOR:
      kxor (data, length, SAinfo->crypt_key); 
      break;
    }

  return;
}



/* XOR is a simple vigenere cipher which uses a repeating 8 char key */
/* Encryption is the same as decryption (obviously)                  */
#ifdef ANSI
void
kxor (char *data, int length, char *key)
#else /* ANSI */
void
kxor (data, length, key)
     char *data;
     int length;
     char *key;
#endif /* ANSI */
{
  char *track;
  int step, delay[4];

  track = data;
  for (step = 0; step < length; step++)
    {
      *track ^= key[step % 8];
      track++;
    }

/* Add in a delay which approximates the time taken by a real cipher such
** as DES
*/
  for (step = 0; step < 16 * 4; step++)
    {
      delay[0] ^= delay[1];
      delay[2] >>= 2;
    }

  return;
}
#undef ANSI
#endif /* SCPSSP */
