#ifdef SCPSSP
#ifndef scps_sadb
#define scps_sadb
#include "scpsnp_protos.h"


/*  The following size definitions are in bytes. By declaring a fixed (maximum) size
**  for each item in a SADB entry, no extensive memory allocations/deallocations
**  are required.
*/

#define MAX_NP_ADDR_LEN   (4)	/* Maximum length for a NP address         */

#define MAX_CRYPT_KEY     (8)	/* Largest cryptographic key to be used    */
#define MAX_CRYPT_PAD     (8)	/* Maximum padding possible for any cipher */

#define MAX_SEC_LABEL_LEN (32)	/* The optional security label field       */

#define MAX_ICV_KEY       (8)	/* Largest key to be used for integrity    */
#define MAX_ICV_LEN       (16)	/* Maximum integrity check value length    */


/*   Cryptologic algorithms   */
enum CRYPTO_TYPE
  {
    DES,
    XOR
  };


/*   Integrity algorithms     */
enum INTEGRITY_ALGO
  {
    MD5
  };


/*
**  The following structure is used to retrieve the security association
**  values for each pair of NP addresses.
**
*/
typedef struct SADB_entry
  {

    /* Address Pair that this SA is defined for
       ------------------------------------------- */
    uint32_t src, dst;

    /* Cryptographic attributes
       --------------------------- */
    char crypt_key[MAX_CRYPT_KEY];
    int crypt_blksize;
    enum CRYPTO_TYPE crypt_algo;	/* Implies key and block size */

    /* Integrity attributes
       ----------------------- */
    char ICVkey[MAX_ICV_KEY];
    int ICVsize;
    enum INTEGRITY_ALGO ICV_algo;

    /* Security label attributes
       ---------------------------- */
    char sec_label_len;
    char sec_label[MAX_SEC_LABEL_LEN];

    unsigned char QOS;
  }
SA_data;


/* Assume ciphers will use an 8 octet block size */
typedef unsigned char IV[8];

#ifdef ANSI
void generate_IV (scps_np_rqts * np_rqts, char *MI);
#else /* ANSI */
void generate_IV ();
#endif /* ANSI */

#ifdef ANSI
void encrypt_data (SA_data * SAinfo, IV MI, char *data, int length);
#else /* ANSI */
void encrypt_data ();
#endif /* ANSI */

#ifdef ANSI
void decrypt_data (SA_data * SAinfo, IV MI, char *data, int length);
#else /* ANSI */
void decrypt_data ();
#endif /* ANSI */

#ifdef ANSI
void compute_ICV (SA_data * SAinfo, char *data, int length, char *ICV);
#else /* ANSI */
void compute_ICV ();
#endif /* ANSI */

/* XOR is a simple vigenere cipher which uses a repeating 8 char key */
/* Encryption is the same as decryption (obviously)                  */
#ifdef ANSI
int xor (char *data, int length, char *key);
#else /* ANSI */
int xor ();
#endif /* ANSI */
#endif /* scps_sadb */
#endif /* SCPSSP */
