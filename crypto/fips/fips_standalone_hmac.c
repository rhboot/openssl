/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#ifndef FIPSCANISTER_O
int FIPS_selftest_failed()
{
    return 0;
}

void FIPS_selftest_check()
{
}
#endif

#ifdef OPENSSL_FIPS
int bn_mul_mont_fpu64(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                      const BN_ULONG *np, const BN_ULONG *n0, int num)
{
    return 0;
};

int bn_mul_mont_int(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                    const BN_ULONG *np, const BN_ULONG *n0, int num)
{
    return 0;
};

# if     defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
        defined(__INTEL__) || \
        defined(__x86_64) || defined(__x86_64__) || \
        defined(_M_AMD64) || defined(_M_X64)

unsigned int OPENSSL_ia32cap_P[4];
unsigned long *OPENSSL_ia32cap_loc(void)
{
    if (sizeof(long) == 4)
        /*
         * If 32-bit application pulls address of OPENSSL_ia32cap_P[0]
         * clear second element to maintain the illusion that vector
         * is 32-bit.
         */
        OPENSSL_ia32cap_P[1] = 0;

    OPENSSL_ia32cap_P[2] = 0;

    return (unsigned long *)OPENSSL_ia32cap_P;
}

#  if defined(OPENSSL_CPUID_OBJ) && !defined(OPENSSL_NO_ASM) && !defined(I386_ONLY)
#   define OPENSSL_CPUID_SETUP
#   if defined(_WIN32)
typedef unsigned __int64 IA32CAP;
#   else
typedef unsigned long long IA32CAP;
#   endif
void OPENSSL_cpuid_setup(void)
{
    static int trigger = 0;
    IA32CAP OPENSSL_ia32_cpuid(unsigned int *);
    IA32CAP vec;
    char *env;

    if (trigger)
        return;

    trigger = 1;
    if ((env = getenv("OPENSSL_ia32cap"))) {
        int off = (env[0] == '~') ? 1 : 0;
#   if defined(_WIN32)
        if (!sscanf(env + off, "%I64i", &vec))
            vec = strtoul(env + off, NULL, 0);
#   else
        if (!sscanf(env + off, "%lli", (long long *)&vec))
            vec = strtoul(env + off, NULL, 0);
#   endif
        if (off)
            vec = OPENSSL_ia32_cpuid(OPENSSL_ia32cap_P) & ~vec;
        else if (env[0] == ':')
            vec = OPENSSL_ia32_cpuid(OPENSSL_ia32cap_P);

        OPENSSL_ia32cap_P[2] = 0;
        if ((env = strchr(env, ':'))) {
            unsigned int vecx;
            env++;
            off = (env[0] == '~') ? 1 : 0;
            vecx = strtoul(env + off, NULL, 0);
            if (off)
                OPENSSL_ia32cap_P[2] &= ~vecx;
            else
                OPENSSL_ia32cap_P[2] = vecx;
        }
    } else
        vec = OPENSSL_ia32_cpuid(OPENSSL_ia32cap_P);

    /*
     * |(1<<10) sets a reserved bit to signal that variable
     * was initialized already... This is to avoid interference
     * with cpuid snippets in ELF .init segment.
     */
    OPENSSL_ia32cap_P[0] = (unsigned int)vec | (1 << 10);
    OPENSSL_ia32cap_P[1] = (unsigned int)(vec >> 32);
}
#  else
unsigned int OPENSSL_ia32cap_P[4];
#  endif

# else
unsigned long *OPENSSL_ia32cap_loc(void)
{
    return NULL;
}
# endif
int OPENSSL_NONPIC_relocated = 0;
# if !defined(OPENSSL_CPUID_SETUP) && !defined(OPENSSL_CPUID_OBJ)
void OPENSSL_cpuid_setup(void)
{
}
# endif

static void hmac_init(SHA256_CTX *md_ctx, SHA256_CTX *o_ctx, const char *key)
{
    size_t len = strlen(key);
    int i;
    unsigned char keymd[HMAC_MAX_MD_CBLOCK];
    unsigned char pad[HMAC_MAX_MD_CBLOCK];

    if (len > SHA_CBLOCK) {
        SHA256_Init(md_ctx);
        SHA256_Update(md_ctx, key, len);
        SHA256_Final(keymd, md_ctx);
        len = SHA256_DIGEST_LENGTH;
    } else
        memcpy(keymd, key, len);
    memset(&keymd[len], '\0', HMAC_MAX_MD_CBLOCK - len);

    for (i = 0; i < HMAC_MAX_MD_CBLOCK; i++)
        pad[i] = 0x36 ^ keymd[i];
    SHA256_Init(md_ctx);
    SHA256_Update(md_ctx, pad, SHA256_CBLOCK);

    for (i = 0; i < HMAC_MAX_MD_CBLOCK; i++)
        pad[i] = 0x5c ^ keymd[i];
    SHA256_Init(o_ctx);
    SHA256_Update(o_ctx, pad, SHA256_CBLOCK);
}

static void hmac_final(unsigned char *md, SHA256_CTX *md_ctx,
                       SHA256_CTX *o_ctx)
{
    unsigned char buf[SHA256_DIGEST_LENGTH];

    SHA256_Final(buf, md_ctx);
    SHA256_Update(o_ctx, buf, sizeof buf);
    SHA256_Final(md, o_ctx);
}

#endif

int main(int argc, char **argv)
{
#ifdef OPENSSL_FIPS
    static char key[] = "orboDeJITITejsirpADONivirpUkvarP";
    int n, binary = 0;

    if (argc < 2) {
        fprintf(stderr, "%s [<file>]+\n", argv[0]);
        exit(1);
    }

    n = 1;
    if (!strcmp(argv[n], "-binary")) {
        n++;
        binary = 1;             /* emit binary fingerprint... */
    }

    for (; n < argc; ++n) {
        FILE *f = fopen(argv[n], "rb");
        SHA256_CTX md_ctx, o_ctx;
        unsigned char md[SHA256_DIGEST_LENGTH];
        int i;

        if (!f) {
            perror(argv[n]);
            exit(2);
        }

        hmac_init(&md_ctx, &o_ctx, key);
        for (;;) {
            char buf[1024];
            size_t l = fread(buf, 1, sizeof buf, f);

            if (l == 0) {
                if (ferror(f)) {
                    perror(argv[n]);
                    exit(3);
                } else
                    break;
            }
            SHA256_Update(&md_ctx, buf, l);
        }
        hmac_final(md, &md_ctx, &o_ctx);

        if (binary) {
            fwrite(md, SHA256_DIGEST_LENGTH, 1, stdout);
            break;              /* ... for single(!) file */
        }

/*      printf("HMAC-SHA1(%s)= ",argv[n]); */
        for (i = 0; i < SHA256_DIGEST_LENGTH; ++i)
            printf("%02x", md[i]);
        printf("\n");
    }
#endif
    return 0;
}
