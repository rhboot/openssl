/* crypto/ec/ec_curve.c */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2010 The OpenSSL Project.  All rights reserved.
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
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by 
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by 
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#include "ec_lcl.h"
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslconf.h>

typedef struct {
	int	field_type,	/* either NID_X9_62_prime_field or
				 * NID_X9_62_characteristic_two_field */
		seed_len,
		param_len;
	unsigned int cofactor;	/* promoted to BN_ULONG */
} EC_CURVE_DATA;

static const struct { EC_CURVE_DATA h; unsigned char data[20+48*6]; }
	_EC_NIST_PRIME_384 = {
	{ NID_X9_62_prime_field,20,48,1 },
	{ 0xA3,0x35,0x92,0x6A,0xA3,0x19,0xA2,0x7A,0x1D,0x00,	/* seed */
	  0x89,0x6A,0x67,0x73,0xA4,0x82,0x7A,0xCD,0xAC,0x73,

	  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* p */
	  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	  0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
	  0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,
	  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* a */
	  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	  0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
	  0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFC,
	  0xB3,0x31,0x2F,0xA7,0xE2,0x3E,0xE7,0xE4,0x98,0x8E,	/* b */
	  0x05,0x6B,0xE3,0xF8,0x2D,0x19,0x18,0x1D,0x9C,0x6E,
	  0xFE,0x81,0x41,0x12,0x03,0x14,0x08,0x8F,0x50,0x13,
	  0x87,0x5A,0xC6,0x56,0x39,0x8D,0x8A,0x2E,0xD1,0x9D,
	  0x2A,0x85,0xC8,0xED,0xD3,0xEC,0x2A,0xEF,
	  0xAA,0x87,0xCA,0x22,0xBE,0x8B,0x05,0x37,0x8E,0xB1,	/* x */
	  0xC7,0x1E,0xF3,0x20,0xAD,0x74,0x6E,0x1D,0x3B,0x62,
	  0x8B,0xA7,0x9B,0x98,0x59,0xF7,0x41,0xE0,0x82,0x54,
	  0x2A,0x38,0x55,0x02,0xF2,0x5D,0xBF,0x55,0x29,0x6C,
	  0x3A,0x54,0x5E,0x38,0x72,0x76,0x0A,0xB7,
	  0x36,0x17,0xde,0x4a,0x96,0x26,0x2c,0x6f,0x5d,0x9e,	/* y */
	  0x98,0xbf,0x92,0x92,0xdc,0x29,0xf8,0xf4,0x1d,0xbd,
	  0x28,0x9a,0x14,0x7c,0xe9,0xda,0x31,0x13,0xb5,0xf0,
	  0xb8,0xc0,0x0a,0x60,0xb1,0xce,0x1d,0x7e,0x81,0x9d,
	  0x7a,0x43,0x1d,0x7c,0x90,0xea,0x0e,0x5f,
	  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,	/* order */
	  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	  0xFF,0xFF,0xFF,0xFF,0xC7,0x63,0x4D,0x81,0xF4,0x37,
	  0x2D,0xDF,0x58,0x1A,0x0D,0xB2,0x48,0xB0,0xA7,0x7A,
	  0xEC,0xEC,0x19,0x6A,0xCC,0xC5,0x29,0x73 }
	};

static const struct { EC_CURVE_DATA h; unsigned char data[20+32*6]; }
	_EC_X9_62_PRIME_256V1 = {
	{ NID_X9_62_prime_field,20,32,1 },
	{ 0xC4,0x9D,0x36,0x08,0x86,0xE7,0x04,0x93,0x6A,0x66,	/* seed */
	  0x78,0xE1,0x13,0x9D,0x26,0xB7,0x81,0x9F,0x7E,0x90,

	  0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0x00,0x00,	/* p */
	  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	  0xFF,0xFF,
	  0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x01,0x00,0x00,	/* a */
	  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	  0xFF,0xFC,
	  0x5A,0xC6,0x35,0xD8,0xAA,0x3A,0x93,0xE7,0xB3,0xEB,	/* b */
	  0xBD,0x55,0x76,0x98,0x86,0xBC,0x65,0x1D,0x06,0xB0,
	  0xCC,0x53,0xB0,0xF6,0x3B,0xCE,0x3C,0x3E,0x27,0xD2,
	  0x60,0x4B,
	  0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,0xF8,0xBC,	/* x */
	  0xE6,0xE5,0x63,0xA4,0x40,0xF2,0x77,0x03,0x7D,0x81,
	  0x2D,0xEB,0x33,0xA0,0xF4,0xA1,0x39,0x45,0xD8,0x98,
	  0xC2,0x96,
	  0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,0x8e,0xe7,	/* y */
	  0xeb,0x4a,0x7c,0x0f,0x9e,0x16,0x2b,0xce,0x33,0x57,
	  0x6b,0x31,0x5e,0xce,0xcb,0xb6,0x40,0x68,0x37,0xbf,
	  0x51,0xf5,
	  0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,	/* order */
	  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xBC,0xE6,0xFA,0xAD,
	  0xA7,0x17,0x9E,0x84,0xF3,0xB9,0xCA,0xC2,0xFC,0x63,
	  0x25,0x51 }
	};

typedef struct _ec_list_element_st {
	int	nid;
	const EC_CURVE_DATA *data;
	const EC_METHOD *(*meth)(void);
	const char *comment;
	} ec_list_element;

static const ec_list_element curve_list[] = {
	/* prime field curves */
	/* secg curves */
	/* SECG secp256r1 is the same as X9.62 prime256v1 and hence omitted */
	{ NID_secp384r1, &_EC_NIST_PRIME_384.h, 0, "NIST/SECG curve over a 384 bit prime field" },
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
	{ NID_X9_62_prime256v1, &_EC_X9_62_PRIME_256V1.h, EC_GFp_nistp256_method, "X9.62/SECG curve over a 256 bit prime field" },
#else
	{ NID_X9_62_prime256v1, &_EC_X9_62_PRIME_256V1.h, 0, "X9.62/SECG curve over a 256 bit prime field" },
#endif
};

#define curve_list_length (sizeof(curve_list)/sizeof(ec_list_element))

static EC_GROUP *ec_group_new_from_data(const ec_list_element curve)
	{
	EC_GROUP *group=NULL;
	EC_POINT *P=NULL;
	BN_CTX	 *ctx=NULL;
	BIGNUM	 *p=NULL, *a=NULL, *b=NULL, *x=NULL, *y=NULL, *order=NULL;
	int	 ok=0;
	int	 seed_len,param_len;
	const EC_METHOD *meth;
	const EC_CURVE_DATA *data;
	const unsigned char *params;

	if ((ctx = BN_CTX_new()) == NULL)
		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	data = curve.data;
	seed_len  = data->seed_len;
	param_len = data->param_len;
	params	  = (const unsigned char *)(data+1);	/* skip header */
	params	 += seed_len;				/* skip seed   */

	if (!(p = BN_bin2bn(params+0*param_len, param_len, NULL))
		|| !(a = BN_bin2bn(params+1*param_len, param_len, NULL))
		|| !(b = BN_bin2bn(params+2*param_len, param_len, NULL)))
		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
		goto err;
		}

	if (curve.meth != 0)
		{
		meth = curve.meth();
		if (((group = EC_GROUP_new(meth)) == NULL) ||
			(!(group->meth->group_set_curve(group, p, a, b, ctx))))
			{
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
			goto err;
			}
		}
	else if (data->field_type == NID_X9_62_prime_field)
		{
		if ((group = EC_GROUP_new_curve_GFp(p, a, b, ctx)) == NULL)
			{
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
			goto err;
			}
		}
#ifndef OPENSSL_NO_EC2M
	else	/* field_type == NID_X9_62_characteristic_two_field */
		{
		if ((group = EC_GROUP_new_curve_GF2m(p, a, b, ctx)) == NULL)
			{
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
			goto err;
			}
		}
#endif

	if ((P = EC_POINT_new(group)) == NULL)
		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
		goto err;
		}

	if (!(x = BN_bin2bn(params+3*param_len, param_len, NULL))
		|| !(y = BN_bin2bn(params+4*param_len, param_len, NULL)))
		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
		goto err;
		}
	if (!EC_POINT_set_affine_coordinates_GFp(group, P, x, y, ctx))
		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
		goto err;
		}
	if (!(order = BN_bin2bn(params+5*param_len, param_len, NULL))
		|| !BN_set_word(x, (BN_ULONG)data->cofactor))
		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
		goto err;
		}
	if (!EC_GROUP_set_generator(group, P, order, x))
		{
		ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
		goto err;
		}
	if (seed_len)
		{
		if (!EC_GROUP_set_seed(group, params-seed_len, seed_len))
			{
			ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
			goto err;
			}
		}
	ok=1;
err:
	if (!ok)
		{
		EC_GROUP_free(group);
		group = NULL;
		}
	if (P)
		EC_POINT_free(P);
	if (ctx)
		BN_CTX_free(ctx);
	if (p)
		BN_free(p);
	if (a)
		BN_free(a);
	if (b)
		BN_free(b);
	if (order)
		BN_free(order);
	if (x)
		BN_free(x);
	if (y)
		BN_free(y);
	return group;
	}

EC_GROUP *EC_GROUP_new_by_curve_name(int nid)
	{
	size_t i;
	EC_GROUP *ret = NULL;

	if (nid <= 0)
		return NULL;

	for (i=0; i<curve_list_length; i++)
		if (curve_list[i].nid == nid)
			{
			ret = ec_group_new_from_data(curve_list[i]);
			break;
			}

	if (ret == NULL)
		{
		ECerr(EC_F_EC_GROUP_NEW_BY_CURVE_NAME, EC_R_UNKNOWN_GROUP);
		return NULL;
		}

	EC_GROUP_set_curve_name(ret, nid);

	return ret;
	}

size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems)
	{
	size_t	i, min;

	if (r == NULL || nitems == 0)
		return curve_list_length;

	min = nitems < curve_list_length ? nitems : curve_list_length;

	for (i = 0; i < min; i++)
		{
		r[i].nid = curve_list[i].nid;
		r[i].comment = curve_list[i].comment;
		}

	return curve_list_length;
	}
