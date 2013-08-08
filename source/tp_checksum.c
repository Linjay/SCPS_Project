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

#include "scps.h"
#include "scpstp.h"
#include "scpsudp.h"

#define ADDCARRY(x)  (x > 65535 ? x -= 65535 :x)
#define REDUCE {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);}

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: tp_checksum.c,v $ -- $Revision: 1.9 $\n";
#endif

/*
 * Do a one's complement checksum
 */

uint32_t
checksum (word * dp, int length)
{
  int len;
  int byte_swapped = 0;
  uint32_t sum;

  union
    {
      char c[2];
      word s;
    }
  s_util;

  union
    {
      word s[2];
      int32_t l;
    }
  l_util;

  len = length >> 1;

  sum = 0;

  /* 
   * If we are starting on an odd-byte boundary, store 
   * the first (odd) byte and make a note; All other 
   * processing on this chunk can be done via even/aligned
   * memory accesses. We will add this byte back into the
   * appropriate column at the end.
   */

  if ((int) dp & 1)
    {

      /* 
       * Set the byte_swapped flag, save the first byte
       * and then push dp to an even boundary.
       */

      byte_swapped = 1;
      s_util.c[0] = *(char *) dp;
      s_util.c[1] = 0;
      dp = (word *) ((char *) dp + 1);

      /* 
       * We need to decrement the total length of bytes 
       * to be checksummed by one (the odd byte);
       * If this leaves us with an odd number, we knock off
       * the last word from the process, and we will catch
       * the remaining word at the end.
       */

      if (!(length-- & 1))
	len--;
    }

  while (len >= 16)
    {
      sum += (dp[0]);
      sum += (dp[1]);
      sum += (dp[2]);
      sum += (dp[3]);
      sum += (dp[4]);
      sum += (dp[5]);
      sum += (dp[6]);
      sum += (dp[7]);
      sum += (dp[8]);
      sum += (dp[9]);
      sum += (dp[10]);
      sum += (dp[11]);
      sum += (dp[12]);
      sum += (dp[13]);
      sum += (dp[14]);
      sum += (dp[15]);
      dp += 16;
      len -= 16;
    }

  while (len >= 8)
    {
      sum += (dp[0]);
      sum += (dp[1]);
      sum += (dp[2]);
      sum += (dp[3]);
      sum += (dp[4]);
      sum += (dp[5]);
      sum += (dp[6]);
      sum += (dp[7]);
      dp += 8;
      len -= 8;
    }

  while (len >= 4)
    {
      sum += (dp[0]);
      sum += (dp[1]);
      sum += (dp[2]);
      sum += (dp[3]);
      dp += 4;
      len -= 4;
    }

  while (len-- > 0)
    sum += (*dp++);

  /*
   * It's cleanup time.
   *
   * If we are byte_swapped (started on an odd boundary)
   * we need to realign the bytes of our checksum and add
   * in the initial odd-byte
   */

  if (byte_swapped)
    {
      REDUCE;
      sum <<= 8;
      byte_swapped = 0;

      /* 
       * If we've got one byte left to add-in (an odd length)
       * we handle it with the first odd byte. The leading byte
       * s_util.c[0] is the initial odd-boundary byte. The trailing
       * byte is placed into s_util.c[1]. These are then added in
       * by treating the combination as a single word. This allows
       * both bytes to be added into their proper columns.
       */

      if (length & 1)
	{
	  s_util.c[1] = *(char *) dp;
	  sum += s_util.s;
	}

      /*
       * This prevents us from trying to processes a
       * trailing byte again below.
       */

      length--;
    }

  /* 
   * Handle the last byte in an odd length if we didn't
   * account for it above.
   */

  else if (length & 1)
    s_util.c[0] = *(char *) dp;

  if (length & 1)
    {
      s_util.c[1] = 0;
      sum += s_util.s;
    }

  REDUCE;

  sum = (sum & 0xFFFF) + ((sum >> 16) & 0xFFFF);

  sum = (sum & 0xFFFF) + ((sum >> 16) & 0xFFFF);

  return ((sum));
}

/*
 * This checksum routine checks for spanning of clusters, and hopefully
 * handles them properly.
 */

uint32_t
data_checksum (struct mbcluster * cluster, int length, int offset)
{
  int len;
  int chunk = 0;
  int byte_swapped = 0;
  uint32_t sum;
  word *dp;
  word *orig_dp;
  int orig_len, orig_length, orig_offset;
  struct mbcluster *orig_cluster;

  union
    {
      char c[2];
      word s;
    }
  s_util;

  union
    {
      word s[2];
      int32_t l;
    }
  l_util;

  len = length >> 1;
  orig_length = length;
  orig_len = len;
  orig_offset = offset;
  orig_cluster = cluster;

  sum = 0;

  dp = (word *) (cluster->c_data + offset);
  orig_dp = dp;
  /*
   * If we are starting on an odd-byte boundary, store
   * the first (odd) byte and make a note; All other
   * processing on this chunk can be done via even/aligned
   * memory accesses. We will add this byte back into the
   * appropriate column at the end.
   */

  if ((int) dp & 1)
    {

      /*
       * Set the byte_swapped flag, save the first byte
       * and then push dp to an even boundary. 
       */

      byte_swapped = 1;
      s_util.c[0] = *(char *) dp;
      s_util.c[1] = 0;
      dp = (word *) ((char *) dp + 1);

      /*
       * We need to decrement the total length of bytes
       * to be checksummed by one (the odd byte);
       * If this leaves us with an odd number, we knock off
       * the last word from the process, and we will catch
       * the remaining word at the end.
       */

      if (!(length-- & 1))
	len--;
    }

  while (len > 0)
    {

      /* Optimization goof here!! */
      chunk = (SMCLBYTES - offset);
      if (chunk > (len << 1))
	chunk = (len << 1);

      offset += chunk;
      len -= (chunk >> 1);

      while (chunk >= 64)
	{
	  sum += (dp[0]);
	  sum += (dp[1]);
	  sum += (dp[2]);
	  sum += (dp[3]);
	  sum += (dp[4]);
	  sum += (dp[5]);
	  sum += (dp[6]);
	  sum += (dp[7]);
	  sum += (dp[8]);
	  sum += (dp[9]);
	  sum += (dp[10]);
	  sum += (dp[11]);
	  sum += (dp[12]);
	  sum += (dp[13]);
	  sum += (dp[14]);
	  sum += (dp[15]);
	  sum += (dp[16]);
	  sum += (dp[17]);
	  sum += (dp[18]);
	  sum += (dp[19]);
	  sum += (dp[20]);
	  sum += (dp[21]);
	  sum += (dp[22]);
	  sum += (dp[23]);
	  sum += (dp[24]);
	  sum += (dp[25]);
	  sum += (dp[26]);
	  sum += (dp[27]);
	  sum += (dp[28]);
	  sum += (dp[29]);
	  sum += (dp[30]);
	  sum += (dp[31]);
	  chunk -= 64;
	  dp += 32;
	}

      while (chunk >= 32)
	{
	  sum += (dp[0]);
	  sum += (dp[1]);
	  sum += (dp[2]);
	  sum += (dp[3]);
	  sum += (dp[4]);
	  sum += (dp[5]);
	  sum += (dp[6]);
	  sum += (dp[7]);
	  sum += (dp[8]);
	  sum += (dp[9]);
	  sum += (dp[10]);
	  sum += (dp[11]);
	  sum += (dp[12]);
	  sum += (dp[13]);
	  sum += (dp[14]);
	  sum += (dp[15]);
	  chunk -= 32;
	  dp += 16;
	}

      while (chunk >= 16)
	{
	  sum += (dp[0]);
	  sum += (dp[1]);
	  sum += (dp[2]);
	  sum += (dp[3]);
	  sum += (dp[4]);
	  sum += (dp[5]);
	  sum += (dp[6]);
	  sum += (dp[7]);
	  chunk -= 16;
	  dp += 8;
	}

      while (chunk >= 8)
	{
	  sum += (dp[0]);
	  sum += (dp[1]);
	  sum += (dp[2]);
	  sum += (dp[3]);
	  chunk -= 8;
	  dp += 4;
	}

      while (chunk > 0)
	{
	  sum += (dp[0]);
	  dp++;
	  chunk -= 2;
	}

      if (chunk < 0)
	{
	  unsigned char lin_buff[1500];

	  dp = (word *) (cluster->c_data + orig_offset);
	  clust_copy (orig_cluster, lin_buff, orig_length, orig_offset);
	  sum = checksum ((word *) & lin_buff, orig_length);
	  return (sum);
	}


      if (offset >= SMCLBYTES)
	{
	  offset = 0;
	  cluster = cluster->c_next;
	  dp = (word *) (cluster->c_data);
	}

    }

  if (byte_swapped)
    {
      REDUCE;
      sum <<= 8;
      byte_swapped = 0;

      /*  
       * If we've got one byte left to add-in (an odd length)
       * we handle it with the first odd byte. The leading byte
       * s_util.c[0] is the initial odd-boundary byte. The trailing
       * byte is placed into s_util.c[1]. These are then added in
       * by treating the combination as a single word. This allows
       * both bytes to be added into their proper columns.
       */

      if (length & 1)
	{
	  s_util.c[1] = *(char *) dp;
	  sum += s_util.s;
	}

      /*
       * This prevents us from trying to processes a
       * trailing byte again below.
       */

      length--;
    }

  /*    
   * Handle the last byte in an odd length if we didn't
   * account for it above.
   */

  else if (length & 1)
    s_util.c[0] = *(char *) dp;

  if (length & 1)
    {
      s_util.c[1] = 0;
      sum += s_util.s;
    }

  REDUCE;

  sum = (sum & 0xFFFF) + ((sum >> 16) & 0xFFFF);

  sum = (sum & 0xFFFF) + ((sum >> 16) & 0xFFFF);

  return ((sum));
}

void
tp_FinalCksum (tp_Socket * s, struct mbuff *m, tp_Header * th, uint32_t thl)
{

  uint32_t long_temp;

  switch (s->nl_protocol_id) {
        case NL_PROTOCOL_IPV4:
        case NL_PROTOCOL_NP:
                s->ph.nl_head.ipv4.length = htons (thl + m->m_ext.len);
                th->checksum = 0;

                long_temp = checksum ((word *) th, thl) + m->m_ext.checksum;
                long_temp = ((long_temp >> 16) & 0xffff) + (long_temp & 0xffff);
                s->ph.nl_head.ipv4.checksum = ((long_temp >> 16) & 0xffff) + (long_temp & 0xffff);
                th->checksum = ~checksum ((word *) & (s->ph), 14);
                break;

        case NL_PROTOCOL_IPV6:
                s->ph.nl_head.ipv6.length = htonl (thl + m->m_ext.len);
                th->checksum = 0;

                long_temp = checksum ((word *) th, thl) + m->m_ext.checksum;
                long_temp = ((long_temp >> 16) & 0xffff) + (long_temp & 0xffff);
                s->ph.nl_head.ipv6.checksum = ((long_temp >> 16) & 0xffff) + (long_temp & 0xffff);
                th->checksum = ~checksum ((word *) & (s->ph), 42);
                break;
  }

}

void
udp_FinalCksum (udp_Socket * s, struct mbuff *m, udp_Header * uh)
{

  longword long_temp;

  s->ph.nl_head.ipv4.length = htons (UDP_HDR_LEN + m->m_ext.len);
  uh->checksum = 0;

  long_temp = checksum ((word *) uh, UDP_HDR_LEN) + m->m_ext.checksum;
  long_temp = ((long_temp >> 16) & 0xffff) + (long_temp & 0xffff);
  s->ph.nl_head.ipv4.checksum = ((long_temp >> 16) & 0xffff) + (long_temp & 0xffff);
  uh->checksum = ~checksum ((word *) & (s->ph), 14);
}
