#ifdef SCPSSP
#define ANSI
/* MD5.C

   Revised for SCPS-SP 1750 compatibility. 
   Final version 4/15/96
   Ken Corson  Sparta, Inc.

*/
/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#include "md5.h"
void MD5Transform (uint32_t *state, unsigned char *block);
void Encode (unsigned char *output, uint32_t *input, unsigned int len);

/* Constants for MD5Transform routine. */

#ifndef NO_CVS_IDENTIFY
static char CVSID[] = "$RCSfile: md5.c,v $ -- $Revision: 1.7 $\n";
#endif

uint32_t MD5SN[64] =
{
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
  0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
  0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
  0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
  0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
  0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
  0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039,
  0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
  0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
  0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

int MD5xlut[64] =
{
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
  5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
  0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9};

int MD5SCnts[16] =
{7, 12, 17, 22, 5, 9, 14, 20,
 4, 11, 16, 23, 6, 10, 15, 21};


/* Unsigned int32_t integer (32 bit) addition */
#ifdef ANSI
void
Ladd (uint32_t *uli1, uint32_t uli2)
#else /* ANSI */
void
Ladd (uli1, uli2)
     uint32_t *uli1;
     uint32_t uli2;
#endif /* ANSI */
{
  int32_t acc1, acc2, acc3;
  acc1 = (uint32_t) (*uli1);
  acc1 &= (uint32_t) 0x0000FFFF;
  acc2 = (uint32_t) uli2;
  acc2 &= (uint32_t) 0x0000FFFF;
  acc2 += (uint32_t) acc1;
/* Lower 16 bits of result */
  acc3 = acc2;
  acc3 &= (uint32_t) 0x0000FFFF;
/* Add low 16-bit carry into high 16 bit add */
  acc2 >>= 16;
  acc1 = (uint32_t) (*uli1);
  acc1 >>= 16;
  acc2 += acc1;
  acc1 = (uint32_t) uli2;
  acc1 >>= 16;
  acc2 += acc1;
/* Hi 16bit result */
  acc2 <<= 16;
/* Or in the low 16 bit result */
  acc2 |= acc3;
  *uli1 = acc2;
  return;
}

#ifdef ANSI
int
mdmemcpy (unsigned char *a, unsigned char *b, int len)
#else /* ANSI */
int
mdmemcpy (a, b, len)
     unsigned char *a;
     unsigned char *b;
     int len;
#endif /* ANSI */
{
  int i;
  for (i = 0; i < len; i++)
    a[i] = b[i];
  return (len);
}

#ifdef ANSI
int
mdmemset (char *a, char b, int len)
#else /* ANSI */
int
mdmemset (a, b, len)
     char *a;
     char b;
     int len;
#endif /* ANSI */
{
  int i;
  for (i = 0; i < len; i++)
    a[i] = b;
  return (len);
}

unsigned char PADDING[64] =
{
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};


/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((uint32_t)(x) << (n)) | ((uint32_t)(x) >> (32-(n))))

 /* F, G, H and I are basic MD5 functions. */
#define F(x, y, z) (((uint32_t)(x) & (uint32_t)(y)) | ((uint32_t)(~x) & (uint32_t)(z)))
#define G(x, y, z) (((uint32_t)(x) & (uint32_t)(z)) | ((uint32_t)(y) & (uint32_t)(~z)))
#define H(x, y, z) ((uint32_t)(x) ^ (uint32_t)(y) ^ (uint32_t)(z))
#define I(x, y, z) ((uint32_t)(y) ^ ((uint32_t)(x) | (uint32_t)(~z)))

/* MD5 initialization. Begins an MD5 operation, writing a new context. */
#ifdef ANSI
void
MD5Init (MD5_CTX * context)
#else /* ANSI */
void
MD5Init (context)
     MD5_CTX *context;		/* context */
#endif /* ANSI */
{
  context->count[0] = context->count[1] = 0;
  /* Load magic initialization constants. */
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context. */
#ifdef ANSI
void
MD5Update (MD5_CTX * context, unsigned char *input, unsigned int inputLen)
#else /* ANSI */
int
MD5Update (context, input, inputLen)
     MD5_CTX *context;		/* context */
     unsigned char *input;	/* input block */
     unsigned int inputLen;	/* length of input block */
#endif /* ANSI */
{
  unsigned int i, index, partLen;

  /* Compute number of bytes mod 64 */
  index = (unsigned int) ((context->count[0] >> 3) & 0x3F);

  /* Update number of bits */
  if ((context->count[0] += ((uint32_t) inputLen << 3))
      < ((uint32_t) inputLen << 3))
    context->count[1]++;
  context->count[1] += ((uint32_t) inputLen >> 29);

  partLen = 64 - index;

  /* Transform as many times as possible. */
  if (inputLen >= partLen)
    {
      mdmemcpy (&context->buffer[index], input, partLen);
      MD5Transform (context->state, context->buffer);

      for (i = partLen; i + 63 < inputLen; i += 64)
	MD5Transform (context->state, &input[i]);

      index = 0;
    }
  else
    i = 0;

  /* Buffer remaining input */
  mdmemcpy
    (&context->buffer[index], &input[i],
     inputLen - i);
}


unsigned char bits[8];

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
#ifdef ANSI
void
MD5Final (unsigned char *digest, MD5_CTX * context)
#else /* ANSI */
void
MD5Final (digest, context)
     unsigned char *digest;	/* message digest */
     MD5_CTX *context;		/* context        */
#endif /* ANSI */
{
  unsigned int index, padLen;

  /* Save number of bits */
  Encode (bits, context->count, 8);

  /* Pad out to 56 mod 64. */
  index = (unsigned int) ((context->count[0] >> 3) & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);
  MD5Update (context, PADDING, padLen);
  /* Append length (before padding) */
  MD5Update (context, bits, 8);

  /* Store state in digest */
  Encode (digest, context->state, 16);

  /* Zeroize sensitive information. */
  (void) mdmemset ((char *) context, 0, sizeof (*context));
}

/* MD5 basic transformation. Transforms state based on block. */
#ifdef ANSI
void
MD5Transform (uint32_t *state, unsigned char *block)
#else /* ANSI */
void
MD5Transform (state, block)
     uint32_t *state;
     unsigned char *block;
#endif /* ANSI */
{
  uint32_t a, b, c, d, rotator, x[16];
  int w, z;

  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];

  /* Decode the block of chars to int32_t ints */
  /* This is written specifically for 1750  */
  for (z = 0; z < 16; z++)
    {
      uint32_t reg;
      w = z << 2;

      reg = (char) block[w + 3];
      reg &= 0x000000ff;
      x[z] = reg;
      x[z] <<= 8;

      reg = (char) block[w + 2];
      reg &= 0x000000ff;
      x[z] |= reg;
      x[z] <<= 8;

      reg = (char) block[w + 1];
      reg &= 0x000000ff;
      x[z] |= reg;
      x[z] <<= 8;

      reg = (char) block[w + 0];
      reg &= 0x000000ff;
      x[z] |= reg;
    }

  for (z = 0; z < 64; z++)
    {

      switch (z >> 4)
	{
	case 0:
	  Ladd (&a, F ((b), (c), (d)));
	  break;
	case 1:
	  Ladd (&a, G ((b), (c), (d)));
	  break;
	case 2:
	  Ladd (&a, H ((b), (c), (d)));
	  break;
	case 3:
	  Ladd (&a, I ((b), (c), (d)));
	  break;
	}
      Ladd (&a, (uint32_t) x[MD5xlut[z]]);
      Ladd (&a, (uint32_t) MD5SN[z]);
      a = ROTATE_LEFT (a, MD5SCnts[((z >> 4) << 2) | (z & 3)]);
      Ladd (&a, b);

      rotator = d;
      d = c;
      c = b;
      b = a;
      a = rotator;

    }

  Ladd (&state[0], a);
  Ladd (&state[1], b);
  Ladd (&state[2], c);
  Ladd (&state[3], d);

  /* Zeroize sensitive information. */
  mdmemset ((char *) x, 0, sizeof (x));
}

/* Encodes input (uint32_t) into output (unsigned char). Assumes len is
  a multiple of 4. */
#ifdef ANSI
void
Encode (unsigned char *output, uint32_t *input, unsigned int len)
#else /* ANSI */
void
Encode (output, input, len)
     unsigned char *output;
     uint32_t *input;
     unsigned int len;
#endif /* ANSI */
{
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
    {
      output[j] = (unsigned char) (input[i] & 0xff);
      output[j + 1] = (unsigned char) ((input[i] >> 8) & 0xff);
      output[j + 2] = (unsigned char) ((input[i] >> 16) & 0xff);
      output[j + 3] = (unsigned char) ((input[i] >> 24) & 0xff);
    }
}


/* For testing:

main() {
int x;
MD5_CTX md5context;
char hashval[16];
char teststr[20];
char hexchars[16];
for(x=0;x<16;x++) 
  if(x<10) hexchars[x]='0'+x;
  else     hexchars[x]='A'+x-10;
MD5Init( &md5context );
for(x=0;x<35;x++)
  MD5Update( &md5context , teststr , 10 );
MD5Final( hashval , &md5context );
if( (char)hashval[0] == (char)0x90 ) x=0;
else x=1;
if( (char)hashval[1] == (char)0x01 ) x=0;
else x=1;
exit(0);
}

*/
#endif /*SCPSSP */
