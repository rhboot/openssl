/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/dsa.h>
#include <openssl/fips.h>
#include "internal/fips_int.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include "fips_locl.h"

#ifdef OPENSSL_FIPS

static const unsigned char dsa_test_2048_p[] = {
    0xa8, 0x53, 0x78, 0xd8, 0xfd, 0x3f, 0x8d, 0x72, 0xec, 0x74, 0x18, 0x08,
    0x0d, 0xa2, 0x13, 0x17, 0xe4, 0x3e, 0xc4, 0xb6, 0x2b, 0xa8, 0xc8, 0x62,
    0x3b, 0x7e, 0x4d, 0x04, 0x44, 0x1d, 0xd1, 0xa0, 0x65, 0x86, 0x62, 0x59,
    0x64, 0x93, 0xca, 0x8e, 0x9e, 0x8f, 0xbb, 0x7e, 0x34, 0xaa, 0xdd, 0xb6,
    0x2e, 0x5d, 0x67, 0xb6, 0xd0, 0x9a, 0x6e, 0x61, 0xb7, 0x69, 0xe7, 0xc3,
    0x52, 0xaa, 0x2b, 0x10, 0xe2, 0x0c, 0xa0, 0x63, 0x69, 0x63, 0xb5, 0x52,
    0x3e, 0x86, 0x47, 0x0d, 0xec, 0xbb, 0xed, 0xa0, 0x27, 0xe7, 0x97, 0xe7,
    0xb6, 0x76, 0x35, 0xd4, 0xd4, 0x9c, 0x30, 0x70, 0x0e, 0x74, 0xaf, 0x8a,
    0x0f, 0xf1, 0x56, 0xa8, 0x01, 0xaf, 0x57, 0xa2, 0x6e, 0x70, 0x78, 0xf1,
    0xd8, 0x2f, 0x74, 0x90, 0x8e, 0xcb, 0x6d, 0x07, 0xe7, 0x0b, 0x35, 0x03,
    0xee, 0xd9, 0x4f, 0xa3, 0x2c, 0xf1, 0x7a, 0x7f, 0xc3, 0xd6, 0xcf, 0x40,
    0xdc, 0x7b, 0x00, 0x83, 0x0e, 0x6a, 0x25, 0x66, 0xdc, 0x07, 0x3e, 0x34,
    0x33, 0x12, 0x51, 0x7c, 0x6a, 0xa5, 0x15, 0x2b, 0x4b, 0xfe, 0xcd, 0x2e,
    0x55, 0x1f, 0xee, 0x34, 0x63, 0x18, 0xa1, 0x53, 0x42, 0x3c, 0x99, 0x6b,
    0x0d, 0x5d, 0xcb, 0x91, 0x02, 0xae, 0xdd, 0x38, 0x79, 0x86, 0x16, 0xf1,
    0xf1, 0xe0, 0xd6, 0xc4, 0x03, 0x52, 0x5b, 0x1f, 0x9b, 0x3d, 0x4d, 0xc7,
    0x66, 0xde, 0x2d, 0xfc, 0x4a, 0x56, 0xd7, 0xb8, 0xba, 0x59, 0x63, 0xd6,
    0x0f, 0x3e, 0x16, 0x31, 0x88, 0x70, 0xad, 0x43, 0x69, 0x52, 0xe5, 0x57,
    0x65, 0x37, 0x4e, 0xab, 0x85, 0xe8, 0xec, 0x17, 0xd6, 0xb9, 0xa4, 0x54,
    0x7b, 0x9b, 0x5f, 0x27, 0x52, 0xf3, 0x10, 0x5b, 0xe8, 0x09, 0xb2, 0x3a,
    0x2c, 0x8d, 0x74, 0x69, 0xdb, 0x02, 0xe2, 0x4d, 0x59, 0x23, 0x94, 0xa7,
    0xdb, 0xa0, 0x69, 0xe9
};

static const unsigned char dsa_test_2048_q[] = {
    0xd2, 0x77, 0x04, 0x4e, 0x50, 0xf5, 0xa4, 0xe3, 0xf5, 0x10, 0xa5, 0x0a,
    0x0b, 0x84, 0xfd, 0xff, 0xbc, 0xa0, 0x47, 0xed, 0x27, 0x60, 0x20, 0x56,
    0x74, 0x41, 0xa0, 0xa5
};

static const unsigned char dsa_test_2048_g[] = {
    0x13, 0xd7, 0x54, 0xe2, 0x1f, 0xd2, 0x41, 0x65, 0x5d, 0xa8, 0x91, 0xc5,
    0x22, 0xa6, 0x5a, 0x72, 0xa8, 0x9b, 0xdc, 0x64, 0xec, 0x9b, 0x54, 0xa8,
    0x21, 0xed, 0x4a, 0x89, 0x8b, 0x49, 0x0e, 0x0c, 0x4f, 0xcb, 0x72, 0x19,
    0x2a, 0x4a, 0x20, 0xf5, 0x41, 0xf3, 0xf2, 0x92, 0x53, 0x99, 0xf0, 0xba,
    0xec, 0xf9, 0x29, 0xaa, 0xfb, 0xf7, 0x9d, 0xfe, 0x43, 0x32, 0x39, 0x3b,
    0x32, 0xcd, 0x2e, 0x2f, 0xcf, 0x27, 0x2f, 0x32, 0xa6, 0x27, 0x43, 0x4a,
    0x0d, 0xf2, 0x42, 0xb7, 0x5b, 0x41, 0x4d, 0xf3, 0x72, 0x12, 0x1e, 0x53,
    0xa5, 0x53, 0xf2, 0x22, 0xf8, 0x36, 0xb0, 0x00, 0xf0, 0x16, 0x48, 0x5b,
    0x6b, 0xd0, 0x89, 0x84, 0x51, 0x80, 0x1d, 0xcd, 0x8d, 0xe6, 0x4c, 0xd5,
    0x36, 0x56, 0x96, 0xff, 0xc5, 0x32, 0xd5, 0x28, 0xc5, 0x06, 0x62, 0x0a,
    0x94, 0x2a, 0x03, 0x05, 0x04, 0x6d, 0x8f, 0x18, 0x76, 0x34, 0x1f, 0x1e,
    0x57, 0x0b, 0xc3, 0x97, 0x4b, 0xa6, 0xb9, 0xa4, 0x38, 0xe9, 0x70, 0x23,
    0x02, 0xa2, 0xe6, 0xe6, 0x7b, 0xfd, 0x06, 0xd3, 0x2b, 0xc6, 0x79, 0x96,
    0x22, 0x71, 0xd7, 0xb4, 0x0c, 0xd7, 0x2f, 0x38, 0x6e, 0x64, 0xe0, 0xd7,
    0xef, 0x86, 0xca, 0x8c, 0xa5, 0xd1, 0x42, 0x28, 0xdc, 0x2a, 0x4f, 0x16,
    0xe3, 0x18, 0x98, 0x86, 0xb5, 0x99, 0x06, 0x74, 0xf4, 0x20, 0x0f, 0x3a,
    0x4c, 0xf6, 0x5a, 0x3f, 0x0d, 0xdb, 0xa1, 0xfa, 0x67, 0x2d, 0xff, 0x2f,
    0x5e, 0x14, 0x3d, 0x10, 0xe4, 0xe9, 0x7a, 0xe8, 0x4f, 0x6d, 0xa0, 0x95,
    0x35, 0xd5, 0xb9, 0xdf, 0x25, 0x91, 0x81, 0xa7, 0x9b, 0x63, 0xb0, 0x69,
    0xe9, 0x49, 0x97, 0x2b, 0x02, 0xba, 0x36, 0xb3, 0x58, 0x6a, 0xab, 0x7e,
    0x45, 0xf3, 0x22, 0xf8, 0x2e, 0x4e, 0x85, 0xca, 0x3a, 0xb8, 0x55, 0x91,
    0xb3, 0xc2, 0xa9, 0x66
};

static const unsigned char dsa_test_2048_pub_key[] = {
    0x24, 0x52, 0xf3, 0xcc, 0xbe, 0x9e, 0xd5, 0xca, 0x7d, 0xc7, 0x4c, 0x60,
    0x2b, 0x99, 0x22, 0x6e, 0x8f, 0x2f, 0xab, 0x38, 0xe7, 0xd7, 0xdd, 0xfb,
    0x75, 0x53, 0x9b, 0x17, 0x15, 0x5e, 0x9f, 0xcf, 0xd1, 0xab, 0xa5, 0x64,
    0xeb, 0x85, 0x35, 0xd8, 0x12, 0xc9, 0xc2, 0xdc, 0xf9, 0x72, 0x84, 0x44,
    0x1b, 0xc4, 0x82, 0x24, 0x36, 0x24, 0xc7, 0xf4, 0x57, 0x58, 0x0c, 0x1c,
    0x38, 0xa5, 0x7c, 0x46, 0xc4, 0x57, 0x39, 0x24, 0x70, 0xed, 0xb5, 0x2c,
    0xb5, 0xa6, 0xe0, 0x3f, 0xe6, 0x28, 0x7b, 0xb6, 0xf4, 0x9a, 0x42, 0xa2,
    0x06, 0x5a, 0x05, 0x4f, 0x03, 0x08, 0x39, 0xdf, 0x1f, 0xd3, 0x14, 0x9c,
    0x4c, 0xa0, 0x53, 0x1d, 0xd8, 0xca, 0x8a, 0xaa, 0x9c, 0xc7, 0x33, 0x71,
    0x93, 0x38, 0x73, 0x48, 0x33, 0x61, 0x18, 0x22, 0x45, 0x45, 0xe8, 0x8c,
    0x80, 0xff, 0xd8, 0x76, 0x5d, 0x74, 0x36, 0x03, 0x33, 0xcc, 0xab, 0x99,
    0x72, 0x77, 0x9b, 0x65, 0x25, 0xa6, 0x5b, 0xdd, 0x0d, 0x10, 0xc6, 0x75,
    0xc1, 0x09, 0xbb, 0xd3, 0xe5, 0xbe, 0x4d, 0x72, 0xef, 0x6e, 0xba, 0x6e,
    0x43, 0x8d, 0x52, 0x26, 0x23, 0x7d, 0xb8, 0x88, 0x37, 0x9c, 0x5f, 0xcc,
    0x47, 0xa3, 0x84, 0x7f, 0xf6, 0x37, 0x11, 0xba, 0xed, 0x6d, 0x03, 0xaf,
    0xe8, 0x1e, 0x69, 0x4a, 0x41, 0x3b, 0x68, 0x0b, 0xd3, 0x8a, 0xb4, 0x90,
    0x3f, 0x83, 0x70, 0xa7, 0x07, 0xef, 0x55, 0x1d, 0x49, 0x41, 0x02, 0x6d,
    0x95, 0x79, 0xd6, 0x91, 0xde, 0x8e, 0xda, 0xa1, 0x61, 0x05, 0xeb, 0x9d,
    0xba, 0x3c, 0x2f, 0x4c, 0x1b, 0xec, 0x50, 0x82, 0x75, 0xaa, 0x02, 0x07,
    0xe2, 0x51, 0xb5, 0xec, 0xcb, 0x28, 0x6a, 0x4b, 0x01, 0xd4, 0x49, 0xd3,
    0x0a, 0xcb, 0x67, 0x37, 0x17, 0xa0, 0xd2, 0xfb, 0x3b, 0x50, 0xc8, 0x93,
    0xf7, 0xda, 0xb1, 0x4f
};

static const unsigned char dsa_test_2048_priv_key[] = {
    0x0c, 0x4b, 0x30, 0x89, 0xd1, 0xb8, 0x62, 0xcb, 0x3c, 0x43, 0x64, 0x91,
    0xf0, 0x91, 0x54, 0x70, 0xc5, 0x27, 0x96, 0xe3, 0xac, 0xbe, 0xe8, 0x00,
    0xec, 0x55, 0xf6, 0xcc
};

int FIPS_selftest_dsa()
{
    DSA *dsa = NULL;
    EVP_PKEY *pk = NULL;
    int ret = -1;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *pub_key = NULL, *priv_key = NULL;

    fips_load_key_component(p, dsa_test_2048);
    fips_load_key_component(q, dsa_test_2048);
    fips_load_key_component(g, dsa_test_2048);
    fips_load_key_component(pub_key, dsa_test_2048);
    fips_load_key_component(priv_key, dsa_test_2048);

    dsa = DSA_new();

    if (dsa == NULL)
        goto err;

    DSA_set0_pqg(dsa, p, q, g);

    DSA_set0_key(dsa, pub_key, priv_key);

    if ((pk = EVP_PKEY_new()) == NULL)
        goto err;

    EVP_PKEY_assign_DSA(pk, dsa);

    if (!fips_pkey_signature_test(pk, NULL, 0,
                                  NULL, 0, EVP_sha256(), 0, "DSA SHA256"))
        goto err;
    ret = 1;

 err:
    if (pk)
        EVP_PKEY_free(pk);
    else if (dsa)
        DSA_free(dsa);
    else {
        BN_free(p);
        BN_free(q);
        BN_free(g);
        BN_free(pub_key);
        BN_free(priv_key);
    }
    return ret;
}
#endif
