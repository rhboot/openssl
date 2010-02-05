/* ssl/t1_lib.c */
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

#include <stdio.h>
#include <openssl/objects.h>
#include "ssl_locl.h"

const char tls1_version_str[]="TLSv1" OPENSSL_VERSION_PTEXT;

SSL3_ENC_METHOD TLSv1_enc_data={
	tls1_enc,
	tls1_mac,
	tls1_setup_key_block,
	tls1_generate_master_secret,
	tls1_change_cipher_state,
	tls1_final_finish_mac,
	TLS1_FINISH_MAC_LENGTH,
	tls1_cert_verify_mac,
	TLS_MD_CLIENT_FINISH_CONST,TLS_MD_CLIENT_FINISH_CONST_SIZE,
	TLS_MD_SERVER_FINISH_CONST,TLS_MD_SERVER_FINISH_CONST_SIZE,
	tls1_alert_code,
	};

long tls1_default_timeout(void)
	{
	/* 2 hours, the 24 hours mentioned in the TLSv1 spec
	 * is way too long for http, the cache would over fill */
	return(60*60*2);
	}

IMPLEMENT_tls1_meth_func(tlsv1_base_method,
			ssl_undefined_function,
			ssl_undefined_function,
			ssl_bad_method)

int tls1_new(SSL *s)
	{
	if (!ssl3_new(s)) return(0);
	s->method->ssl_clear(s);
	return(1);
	}

void tls1_free(SSL *s)
	{
	ssl3_free(s);
	}

void tls1_clear(SSL *s)
	{
	ssl3_clear(s);
	s->version=TLS1_VERSION;
	}

#if 0
long tls1_ctrl(SSL *s, int cmd, long larg, char *parg)
	{
	return(0);
	}

long tls1_callback_ctrl(SSL *s, int cmd, void *(*fp)())
	{
	return(0);
	}
#endif

unsigned char *ssl_add_clienthello_tlsext(SSL *s, unsigned char *p, unsigned char *limit)
	{
	int extdatalen=0;
	unsigned char *ret = p;

	/* don't add extensions for SSLv3 unless doing secure renegotiation */
	if (s->client_version == SSL3_VERSION
					&& !s->s3->send_connection_binding)
		return p;

	ret+=2;

	if (ret>=limit) return NULL; /* this really never occurs, but ... */
 
        /* Add RI if renegotiating */
        if (s->new_session)
          {
          int el;
          
          if(!ssl_add_clienthello_renegotiate_ext(s, 0, &el, 0))
              {
              SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
              return NULL;
              }

          if((limit - p - 4 - el) < 0) return NULL;
          
          s2n(TLSEXT_TYPE_renegotiate,ret);
          s2n(el,ret);

          if(!ssl_add_clienthello_renegotiate_ext(s, ret, &el, el))
              {
              SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
              return NULL;
              }

          ret += el;
        }

	if ((extdatalen = ret-p-2)== 0) 
		return p;

	s2n(extdatalen,p);
	return ret;
	}

unsigned char *ssl_add_serverhello_tlsext(SSL *s, unsigned char *p, unsigned char *limit)
	{
	int extdatalen=0;
	unsigned char *ret = p;

	/* don't add extensions for SSLv3, unless doing secure renegotiation */
	if (s->version == SSL3_VERSION && !s->s3->send_connection_binding)
		return p;
	
	ret+=2;
	if (ret>=limit) return NULL; /* this really never occurs, but ... */

	if(s->s3->send_connection_binding)
        {
          int el;
          
          if(!ssl_add_serverhello_renegotiate_ext(s, 0, &el, 0))
              {
              SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
              return NULL;
              }

          if((limit - p - 4 - el) < 0) return NULL;
          
          s2n(TLSEXT_TYPE_renegotiate,ret);
          s2n(el,ret);

          if(!ssl_add_serverhello_renegotiate_ext(s, ret, &el, el))
              {
              SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
              return NULL;
              }

          ret += el;
        }

	if ((extdatalen = ret-p-2)== 0) 
		return p;

	s2n(extdatalen,p);
	return ret;
	}

int ssl_parse_clienthello_tlsext(SSL *s, unsigned char **p, unsigned char *d, int n, int *al)
	{
	unsigned short type;
	unsigned short size;
	unsigned short len;
	unsigned char *data = *p;
	int renegotiate_seen = 0;

	if (data >= (d+n-2))
		goto ri_check;

	n2s(data,len);

	if (data > (d+n-len)) 
		goto ri_check;

	while (data <= (d+n-4))
		{
		n2s(data,type);
		n2s(data,size);

		if (data+size > (d+n))
	   		goto ri_check;

		if (type == TLSEXT_TYPE_renegotiate)
			{
			if(!ssl_parse_clienthello_renegotiate_ext(s, data, size, al))
				return 0;
			renegotiate_seen = 1;
			}

		data+=size;		
		}
	*p = data;

	ri_check:

	/* Need RI if renegotiating */

	if (!renegotiate_seen && s->new_session &&
		!(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION))
		{
		*al = SSL_AD_HANDSHAKE_FAILURE;
	 	SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT,
				SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
		return 0;
		}

	return 1;
	}

int ssl_parse_serverhello_tlsext(SSL *s, unsigned char **p, unsigned char *d, int n, int *al)
	{
	unsigned short type;
	unsigned short size;
	unsigned short len;  
	unsigned char *data = *p;
	int renegotiate_seen = 0;

	if (data >= (d+n-2))
		goto ri_check;

	n2s(data,len);

	while(data <= (d+n-4))
		{
		n2s(data,type);
		n2s(data,size);

		if (data+size > (d+n))
	   		goto ri_check;
		if (type == TLSEXT_TYPE_renegotiate)
			{
			if(!ssl_parse_serverhello_renegotiate_ext(s, data, size, al))
				return 0;
			renegotiate_seen = 1;
			}
		data+=size;		
		}

	if (data != d+n)
		{
		*al = SSL_AD_DECODE_ERROR;
		return 0;
		}

	*p = data;

	ri_check:

	/* Determine if we need to see RI. Strictly speaking if we want to
	 * avoid an attack we should *always* see RI even on initial server
	 * hello because the client doesn't see any renegotiation during an
	 * attack. However this would mean we could not connect to any server
	 * which doesn't support RI so for the immediate future tolerate RI
	 * absence on initial connect only.
	 */
	if (!renegotiate_seen
		&& !(s->options & SSL_OP_LEGACY_SERVER_CONNECT)
		&& !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION))
		{
		*al = SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT,
				SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
		return 0;
		}

	return 1;
	}
