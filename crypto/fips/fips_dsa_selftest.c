/* crypto/dsa/dsatest.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/dsa.h>
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#ifdef OPENSSL_FIPS

static unsigned char seed[20] = {
	0x02,0x47,0x11,0x92,0x11,0x88,0xC8,0xFB,0xAF,0x48,0x4C,0x62,
	0xDF,0xA5,0xBE,0xA0,0xA4,0x3C,0x56,0xE3,
	};

static unsigned char out_p[] = {
	0xAC,0xCB,0x1E,0x63,0x60,0x69,0x0C,0xFB,0x06,0x19,0x68,0x3E,
	0xA5,0x01,0x5A,0xA2,0x15,0x5C,0xE2,0x99,0x2D,0xD5,0x30,0x99,
	0x7E,0x5F,0x8D,0xE2,0xF7,0xC6,0x2E,0x8D,0xA3,0x9F,0x58,0xAD,
	0xD6,0xA9,0x7D,0x0E,0x0D,0x95,0x53,0xA6,0x71,0x3A,0xDE,0xAB,
	0xAC,0xE9,0xF4,0x36,0x55,0x9E,0xB9,0xD6,0x93,0xBF,0xF3,0x18,
	0x1C,0x14,0x7B,0xA5,0x42,0x2E,0xCD,0x00,0xEB,0x35,0x3B,0x1B,
	0xA8,0x51,0xBB,0xE1,0x58,0x42,0x85,0x84,0x22,0xA7,0x97,0x5E,
	0x99,0x6F,0x38,0x20,0xBD,0x9D,0xB6,0xD9,0x33,0x37,0x2A,0xFD,
	0xBB,0xD4,0xBC,0x0C,0x2A,0x67,0xCB,0x9F,0xBB,0xDF,0xF9,0x93,
	0xAA,0xD6,0xF0,0xD6,0x95,0x0B,0x5D,0x65,0x14,0xD0,0x18,0x9D,
	0xC6,0xAF,0xF0,0xC6,0x37,0x7C,0xF3,0x5F,
	};

static unsigned char out_q[] = {
	0xE3,0x8E,0x5E,0x6D,0xBF,0x2B,0x79,0xF8,0xC5,0x4B,0x89,0x8B,
	0xBA,0x2D,0x91,0xC3,0x6C,0x80,0xAC,0x87,
	};

static unsigned char out_g[] = {
	0x42,0x4A,0x04,0x4E,0x79,0xB4,0x99,0x7F,0xFD,0x58,0x36,0x2C,
	0x1B,0x5F,0x18,0x7E,0x0D,0xCC,0xAB,0x81,0xC9,0x5D,0x10,0xCE,
	0x4E,0x80,0x7E,0x58,0xB4,0x34,0x3F,0xA7,0x45,0xC7,0xAA,0x36,
	0x24,0x42,0xA9,0x3B,0xE8,0x0E,0x04,0x02,0x2D,0xFB,0xA6,0x13,
	0xB9,0xB5,0x15,0xA5,0x56,0x07,0x35,0xE4,0x03,0xB6,0x79,0x7C,
	0x62,0xDD,0xDF,0x3F,0x71,0x3A,0x9D,0x8B,0xC4,0xF6,0xE7,0x1D,
	0x52,0xA8,0xA9,0x43,0x1D,0x33,0x51,0x88,0x39,0xBD,0x73,0xE9,
	0x5F,0xBE,0x82,0x49,0x27,0xE6,0xB5,0x53,0xC1,0x38,0xAC,0x2F,
	0x6D,0x97,0x6C,0xEB,0x67,0xC1,0x5F,0x67,0xF8,0x35,0x05,0x5E,
	0xD5,0x68,0x80,0xAA,0x96,0xCA,0x0B,0x8A,0xE6,0xF1,0xB1,0x41,
	0xC6,0x75,0x94,0x0A,0x0A,0x2A,0xFA,0x29,
	};

static const unsigned char str1[]="12345678901234567890";

void FIPS_corrupt_dsa()
    {
    ++seed[0];
    }

int FIPS_selftest_dsa()
    {
    DSA *dsa;
    int counter,i,j, ret = 0;
    unsigned int slen;
    unsigned char buf[256];
    unsigned long h;
    EVP_MD_CTX mctx;
    EVP_PKEY *pk = NULL;

    EVP_MD_CTX_init(&mctx);

    dsa = DSA_new();

    if(dsa == NULL)
	goto err;
    if(!DSA_generate_parameters_ex(dsa, 1024,seed,20,&counter,&h,NULL))
	goto err;
    if (counter != 239) 
	goto err;
    if (h != 2)
	goto err;
    i=BN_bn2bin(dsa->q,buf);
    j=sizeof(out_q);
    if (i != j || memcmp(buf,out_q,i) != 0)
	goto err;

    i=BN_bn2bin(dsa->p,buf);
    j=sizeof(out_p);
    if (i != j || memcmp(buf,out_p,i) != 0)
	goto err;

    i=BN_bn2bin(dsa->g,buf);
    j=sizeof(out_g);
    if (i != j || memcmp(buf,out_g,i) != 0)
	goto err;
    DSA_generate_key(dsa);

    if ((pk=EVP_PKEY_new()) == NULL)
	goto err;
    EVP_PKEY_assign_DSA(pk, dsa);

    if (!EVP_SignInit_ex(&mctx, EVP_dss1(), NULL))
	goto err;
    if (!EVP_SignUpdate(&mctx, str1, 20))
	goto err;
    if (!EVP_SignFinal(&mctx, buf, &slen, pk))
	goto err;

    if (!EVP_VerifyInit_ex(&mctx, EVP_dss1(), NULL))
	goto err;
    if (!EVP_VerifyUpdate(&mctx, str1, 20))
	goto err;
    if (EVP_VerifyFinal(&mctx, buf, slen, pk) != 1)
	goto err;

    ret = 1;

    err:
    EVP_MD_CTX_cleanup(&mctx);
    if (pk)
	EVP_PKEY_free(pk);
    else if (dsa)
	DSA_free(dsa);
    if (ret == 0)
	    FIPSerr(FIPS_F_FIPS_SELFTEST_DSA,FIPS_R_SELFTEST_FAILED);
    return ret;
    }
#endif
