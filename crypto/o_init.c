/* o_init.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
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
 * ====================================================================
 *
 */

#include <e_os.h>
#include <openssl/err.h>
#ifdef OPENSSL_FIPS
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <openssl/fips.h>
#include <openssl/rand.h>

#define FIPS_MODE_SWITCH_FILE "/proc/sys/crypto/fips_enabled"

static void init_fips_mode(void)
	{
	char buf[2] = "0";
	int fd;
	
	if (getenv("OPENSSL_FORCE_FIPS_MODE") != NULL)
		{
		buf[0] = '1';
		}
	else if ((fd = open(FIPS_MODE_SWITCH_FILE, O_RDONLY)) >= 0)
		{
		while (read(fd, buf, sizeof(buf)) < 0 && errno == EINTR);
		close(fd);
		}
	/* Failure reading the fips mode switch file means just not
	 * switching into FIPS mode. We would break too many things
	 * otherwise. 
	 */
	
	if (buf[0] == '1')
		{
		FIPS_mode_set(1);
		}
	}
#endif

/* Perform any essential OpenSSL initialization operations.
 * Currently only sets FIPS callbacks
 */

void OPENSSL_init_library(void)
	{
	static int done = 0;
	if (done)
		return;
	done = 1;
#ifdef OPENSSL_FIPS
	RAND_init_fips();
	init_fips_mode();
	if (!FIPS_mode())
		{
		/* Clean up prematurely set default rand method */
		RAND_set_rand_method(NULL);
		}
#endif
#if 0
	fprintf(stderr, "Called OPENSSL_init\n");
#endif
	}

void OPENSSL_init(void)
	{
	OPENSSL_init_library();
	}
