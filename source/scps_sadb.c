#ifdef SCPSSP
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

/*

                     SECURITY ASSOCIATION DATABASE
                     ======== =========== ========

    The security attributes to be used between a pair of network protocol
    addresses are stored in an array, sorted by source address.

    For STRV, only two entries exist...


*/

/*
#include <search.h>
*/

#include "scps.h"
#include "scpstp.h"
#include "scpsnp_protos.h"
#include "scps_sp.h"
#include "scps_sadb.h"
#include <stdio.h>

/* XXX PDF These are hardcoded */

#define ZUL_IP_ADDRESS          (0xc0307280L)	/* strv.scps.org */
#define ASTEROID_IP_ADDRESS     (0xc0307283L)	/* phony */
#define DUMPLINGMAN_IP_ADDRESS  (0xc0307299L)	/* phony */

#define SADB_FILE "SA_table"

/*  Maximum number of entries in the security association table  */
#define MAX_TABLE_SIZE 100

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: scps_sadb.c,v $ -- $Revision: 1.9 $\n";
#endif

SA_data SA_table[MAX_TABLE_SIZE];
int SA_entries;

/*-----------------------------------------------------------------------
**            Initialize the security association table.
**-----------------------------------------------------------------------
*/
#ifdef ANSI
int
SADB_init (void)
#else /* ANSI */
int
SADB_init ()
#endif				/* ANSI */
{
  int notdone = 1;
  FILE *datafile;
  int rc;
  uint32_t a;

  /*Load the security association entries from a file... */
  datafile = fopen (SADB_FILE, "r");
  if (datafile == NULL)
    {
      log_sp_error (ERROR_ACCESSING_SA_FILE);
      return (-1);
    }

  SA_entries = 0;
  while (notdone)
    {
      rc = fscanf (datafile, "%lx %lx %s %d %d %s %d %d %d %s %lx\n",
		   &(SA_table[SA_entries].src),
		   &(SA_table[SA_entries].dst),
		   (char *) &(SA_table[SA_entries].crypt_key),
		   &(SA_table[SA_entries].crypt_blksize),
		   (int *) &(SA_table[SA_entries].crypt_algo),
		   (char *) &(SA_table[SA_entries].ICVkey),
		   &(SA_table[SA_entries].ICVsize),
		   (int *) &(SA_table[SA_entries].ICV_algo),
		   (int *) &(SA_table[SA_entries].sec_label_len),
		   (char *) &(SA_table[SA_entries].sec_label),
		   &a);

/*	SA_table [SA_entries].QOS = (unsigned char *) a; */
      SA_table[SA_entries].QOS = (unsigned char) a;	/* Changed by Durst 11/13/97 from above */
      if (SA_table[SA_entries].sec_label_len == 0)
	SA_table[SA_entries].sec_label[0] = (char )NULL;

      if (rc == EOF)
	notdone = 0;
      else if (rc == 11)
	SA_entries++;
      else
	{
	  exit (1);
	}
    }

/*
sort_SADB();

*/
  return (0);
}


#ifdef STRV_ONLY
/* For STRV specific application */
SADB_init ()
{
  SA_entries = 4;
  SA_table[0].src = (ZUL_IP_ADDRESS);
  SA_table[0].dst = (ASTEROID_IP_ADDRESS);
  SA_table[1].src = (ASTEROID_IP_ADDRESS);
  SA_table[1].dst = (ZUL_IP_ADDRESS);
  memcpy ((char *) (SA_table[0].crypt_key), (char *) "KEYKEYKE", 8);
  memcpy ((char *) (SA_table[1].crypt_key), (char *) "KEYKEYKE", 8);
  SA_table[0].crypt_blksize = SA_table[1].crypt_blksize = 8;
  SA_table[0].crypt_algo = SA_table[1].crypt_algo = XOR;
  memcpy ((char *) (SA_table[0].ICVkey), (char *) "MD5PKEY!", 8);
  memcpy ((char *) (SA_table[1].ICVkey), (char *) "MD5PKEY!", 8);
  SA_table[0].ICV_algo = SA_table[1].ICV_algo = MD5;
  SA_table[0].ICVsize = SA_table[1].ICVsize = 16;
  SA_table[0].sec_label_len = SA_table[1].sec_label_len = 0;
  SA_table[0].QOS = (0xFF &
		     (		/* CONFIDENTIALITY | */
		       AUTHENTICATION | SECURITY_LABEL | INTEGRITY));
  SA_table[1].QOS = (0xFF &
		     (		/* CONFIDENTIALITY | */
		       AUTHENTICATION | SECURITY_LABEL | INTEGRITY));

  SA_table[2].src = (ZUL_IP_ADDRESS);
  SA_table[2].dst = (DUMPLINGMAN_IP_ADDRESS);
  SA_table[3].src = (DUMPLINGMAN_IP_ADDRESS);
  SA_table[3].dst = (ZUL_IP_ADDRESS);
  memcpy ((char *) (SA_table[2].crypt_key), (char *) "KEYKEYKE", 8);
  memcpy ((char *) (SA_table[3].crypt_key), (char *) "KEYKEYKE", 8);
  SA_table[2].crypt_blksize = SA_table[3].crypt_blksize = 8;
  SA_table[2].crypt_algo = SA_table[3].crypt_algo = XOR;
  memcpy ((char *) (SA_table[2].ICVkey), (char *) "MD5PKEY!", 8);
  memcpy ((char *) (SA_table[3].ICVkey), (char *) "MD5PKEY!", 8);
  SA_table[2].ICV_algo = SA_table[3].ICV_algo = MD5;
  SA_table[2].ICVsize = SA_table[3].ICVsize = 16;
  SA_table[2].sec_label_len = SA_table[3].sec_label_len = 0;
  SA_table[2].QOS = (0xFF &
		     (		/* CONFIDENTIALITY | */
		       AUTHENTICATION | SECURITY_LABEL | INTEGRITY));
  SA_table[3].QOS = (0xFF &
		     (		/* CONFIDENTIALITY | */
		       AUTHENTICATION | SECURITY_LABEL | INTEGRITY));

  return (0);
}
#endif /* STRV_ONLY */



/*  The comparison function for sorting and searching SA entries: */
#ifdef ANSI
int
compare_SAent (const void *ent1, const void *ent2)
#else /* ANSI */
int
compare_SAent (ent1, ent2)
     void *ent1;
     void *ent2;
#endif /* ANSI */
{
  int rtn_value;
  rtn_value = memcmp ((char *) (((SA_data *) ent1)->src),
		      (char *) (((SA_data *) ent2)->src), 4);
  if (rtn_value != 0)
    return (rtn_value);
  else
    return (memcmp ((char *) (((SA_data *) ent1)->dst),
		    (char *) (((SA_data *) ent2)->dst), 4));
}


/*-----------------------------------------------------------------------
**   get_SAinfo searches the SA_table for an entry that corresponds to
**   the scps_np addresses found in scps_np_rqts. It fills the SA_data
**   structure with the proper attributes, or else can log the fact that
**   no matching SA_data entry was found.
**-----------------------------------------------------------------------
*/
#ifdef ANSI
int
get_SAinfo (scps_np_rqts * np_rqts, SA_data * SAinfo)
#else /* ANSI */
int
get_SAinfo (np_rqts, SAinfo)
     scps_np_rqts *np_rqts;
     SA_data *SAinfo;
#endif /* ANSI */
{
  SA_data key;
  int lookup;

/* Query the database to retrieve the security association attributes
** for the given pair of addresses in the network protocol requirements.
*/
  memcpy ((char *) &key.src, (char *) &(np_rqts->src_addr), 4);
  memcpy ((char *) &key.dst, (char *) &(np_rqts->dst_addr), 4);

/* Commented out for cc50 compiler...
lookup = (SA_data *)bsearch( (char *)(&key) , (char *)SA_table ,
			    SA_entries , sizeof( SA_data ) , 
			    compare_SAent );
*/

/* For STRV (CC50) application */
  for (lookup = 0; lookup < SA_entries; lookup++)
    {
      if (memcmp ((char *) &(SA_table[lookup].src),
		  (char *) &(key.src), 4) == 0)
	if (memcmp ((char *) &(SA_table[lookup].dst),
		    (char *) &(key.dst), 4) == 0)
	  goto end;
    }

end:

  if (lookup >= SA_entries)
    return (-1);
  memcpy ((char *) SAinfo, (char *) &SA_table[lookup], sizeof (SA_data));

  return (0);
}


/*  Sort the entries in the SA table
*/
void
sort_SADB ()
{

/* Don't sort for STRV application
qsort( SA_table , SA_entries , sizeof( SA_data ) , compare_SAent );
*/

  return;
}



int
get_SAent (x, SAent)
     int x;
     SA_data *SAent;
{
  memcpy ((char *) SAent, (char *) &SA_table[x], sizeof (SA_data));
  return (0);
}


#endif /* SCPSSP */
