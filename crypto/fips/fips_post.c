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

#define OPENSSL_FIPSAPI

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <string.h>
#include <limits.h>

#ifdef OPENSSL_FIPS

/* Power on self test (POST) support functions */

# include <openssl/fips.h>
# include "fips_locl.h"

/* Run all selftests */
int FIPS_selftest(void)
{
    int rv = 1;
    if (!FIPS_selftest_drbg())
        rv = 0;
    if (!FIPS_selftest_x931())
        rv = 0;
    if (!FIPS_selftest_sha1())
        rv = 0;
    if (!FIPS_selftest_sha2())
        rv = 0;
    if (!FIPS_selftest_hmac())
        rv = 0;
    if (!FIPS_selftest_cmac())
        rv = 0;
    if (!FIPS_selftest_aes())
        rv = 0;
    if (!FIPS_selftest_aes_ccm())
        rv = 0;
    if (!FIPS_selftest_aes_gcm())
        rv = 0;
    if (!FIPS_selftest_aes_xts())
        rv = 0;
    if (!FIPS_selftest_des())
        rv = 0;
    if (!FIPS_selftest_rsa())
        rv = 0;
    if (!FIPS_selftest_dsa())
        rv = 0;
    return rv;
}

/* Generalized public key test routine. Signs and verifies the data
 * supplied in tbs using mesage digest md and setting option digest
 * flags md_flags. If the 'kat' parameter is not NULL it will
 * additionally check the signature matches it: a known answer test
 * The string "fail_str" is used for identification purposes in case
 * of failure. If "pkey" is NULL just perform a message digest check.
 */

int fips_pkey_signature_test(EVP_PKEY *pkey,
                             const unsigned char *tbs, int tbslen,
                             const unsigned char *kat, unsigned int katlen,
                             const EVP_MD *digest, unsigned int md_flags,
                             const char *fail_str)
{
    int ret = 0;
    unsigned char sigtmp[256], *sig = sigtmp;
    unsigned int siglen;
    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);

    if (digest == NULL)
        digest = EVP_sha256();

    if ((pkey->type == EVP_PKEY_RSA)
        && (RSA_size(pkey->pkey.rsa) > sizeof(sigtmp))) {
        sig = OPENSSL_malloc(RSA_size(pkey->pkey.rsa));
        if (!sig) {
            FIPSerr(FIPS_F_FIPS_PKEY_SIGNATURE_TEST, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    if (tbslen == -1)
        tbslen = strlen((char *)tbs);

    if (md_flags)
        EVP_MD_CTX_set_flags(&mctx, md_flags);

    if (!EVP_SignInit_ex(&mctx, digest, NULL))
        goto error;
    if (!EVP_SignUpdate(&mctx, tbs, tbslen))
        goto error;
    if (!EVP_SignFinal(&mctx, sig, &siglen, pkey))
        goto error;

    if (kat && ((siglen != katlen) || memcmp(kat, sig, katlen)))
        goto error;

    if (!EVP_VerifyInit_ex(&mctx, digest, NULL))
        goto error;
    if (!EVP_VerifyUpdate(&mctx, tbs, tbslen))
        goto error;
    ret = EVP_VerifyFinal(&mctx, sig, siglen, pkey);

 error:
    if (sig != sigtmp)
        OPENSSL_free(sig);
    EVP_MD_CTX_cleanup(&mctx);
    if (ret != 1) {
        FIPSerr(FIPS_F_FIPS_PKEY_SIGNATURE_TEST, FIPS_R_TEST_FAILURE);
        if (fail_str)
            ERR_add_error_data(2, "Type=", fail_str);
        return 0;
    }
    return 1;
}

/* Generalized symmetric cipher test routine. Encrypt data, verify result
 * against known answer, decrypt and compare with original plaintext.
 */

int fips_cipher_test(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                     const unsigned char *key,
                     const unsigned char *iv,
                     const unsigned char *plaintext,
                     const unsigned char *ciphertext, int len)
{
    unsigned char pltmp[FIPS_MAX_CIPHER_TEST_SIZE];
    unsigned char citmp[FIPS_MAX_CIPHER_TEST_SIZE];

    OPENSSL_assert(len <= FIPS_MAX_CIPHER_TEST_SIZE);
    memset(pltmp, 0, FIPS_MAX_CIPHER_TEST_SIZE);
    memset(citmp, 0, FIPS_MAX_CIPHER_TEST_SIZE);

    if (EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1) <= 0)
        return 0;
    if (EVP_Cipher(ctx, citmp, plaintext, len) <= 0)
        return 0;
    if (memcmp(citmp, ciphertext, len))
        return 0;
    if (EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0) <= 0)
        return 0;
    if (EVP_Cipher(ctx, pltmp, citmp, len) <= 0)
        return 0;
    if (memcmp(pltmp, plaintext, len))
        return 0;
    return 1;
}
#endif
