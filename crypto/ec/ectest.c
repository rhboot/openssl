/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/nelem.h"
#include "testutil.h"

#ifndef OPENSSL_NO_EC
# include <openssl/ec.h>
# ifndef OPENSSL_NO_ENGINE
#  include <openssl/engine.h>
# endif
# include <openssl/err.h>
# include <openssl/obj_mac.h>
# include <openssl/objects.h>
# include <openssl/rand.h>
# include <openssl/bn.h>
# include <openssl/opensslconf.h>

static size_t crv_len = 0;
static EC_builtin_curve *curves = NULL;

/* test multiplication with group order, long and negative scalars */
static int group_order_tests(EC_GROUP *group)
{
    BIGNUM *n1 = NULL, *n2 = NULL, *order = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL, *S = NULL;
    const EC_POINT *G = NULL;
    BN_CTX *ctx = NULL;
    int i = 0, r = 0;

    if (!TEST_ptr(n1 = BN_new())
        || !TEST_ptr(n2 = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(G = EC_GROUP_get0_generator(group))
        || !TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_ptr(S = EC_POINT_new(group)))
        goto err;

    if (!TEST_true(EC_GROUP_get_order(group, order, ctx))
        || !TEST_true(EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, Q))
        || !TEST_true(EC_GROUP_precompute_mult(group, ctx))
        || !TEST_true(EC_POINT_mul(group, Q, order, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, Q))
        || !TEST_true(EC_POINT_copy(P, G))
        || !TEST_true(BN_one(n1))
        || !TEST_true(EC_POINT_mul(group, Q, n1, NULL, NULL, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx))
        || !TEST_true(BN_sub(n1, order, n1))
        || !TEST_true(EC_POINT_mul(group, Q, n1, NULL, NULL, ctx))
        || !TEST_true(EC_POINT_invert(group, Q, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx)))
        goto err;

    for (i = 1; i <= 2; i++) {
        const BIGNUM *scalars[6];
        const EC_POINT *points[6];

        if (!TEST_true(BN_set_word(n1, i))
            /*
             * If i == 1, P will be the predefined generator for which
             * EC_GROUP_precompute_mult has set up precomputation.
             */
            || !TEST_true(EC_POINT_mul(group, P, n1, NULL, NULL, ctx))
            || (i == 1 && !TEST_int_eq(0, EC_POINT_cmp(group, P, G, ctx)))
            || !TEST_true(BN_one(n1))
            /* n1 = 1 - order */
            || !TEST_true(BN_sub(n1, n1, order))
            || !TEST_true(EC_POINT_mul(group, Q, NULL, P, n1, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx))

            /* n2 = 1 + order */
            || !TEST_true(BN_add(n2, order, BN_value_one()))
            || !TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx))

            /* n2 = (1 - order) * (1 + order) = 1 - order^2 */
            || !TEST_true(BN_mul(n2, n1, n2, ctx))
            || !TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, Q, P, ctx)))
            goto err;

        /* n2 = order^2 - 1 */
        BN_set_negative(n2, 0);
        if (!TEST_true(EC_POINT_mul(group, Q, NULL, P, n2, ctx))
            /* Add P to verify the result. */
            || !TEST_true(EC_POINT_add(group, Q, Q, P, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, Q))

            /* Exercise EC_POINTs_mul, including corner cases. */
            || !TEST_false(EC_POINT_is_at_infinity(group, P)))
            goto err;

        scalars[0] = scalars[1] = BN_value_one();
        points[0]  = points[1]  = P;

        if (!TEST_true(EC_POINTs_mul(group, R, NULL, 2, points, scalars, ctx))
            || !TEST_true(EC_POINT_dbl(group, S, points[0], ctx))
            || !TEST_int_eq(0, EC_POINT_cmp(group, R, S, ctx)))
            goto err;

        scalars[0] = n1;
        points[0] = Q;          /* => infinity */
        scalars[1] = n2;
        points[1] = P;          /* => -P */
        scalars[2] = n1;
        points[2] = Q;          /* => infinity */
        scalars[3] = n2;
        points[3] = Q;          /* => infinity */
        scalars[4] = n1;
        points[4] = P;          /* => P */
        scalars[5] = n2;
        points[5] = Q;          /* => infinity */
        if (!TEST_true(EC_POINTs_mul(group, P, NULL, 6, points, scalars, ctx))
            || !TEST_true(EC_POINT_is_at_infinity(group, P)))
            goto err;
    }

    r = 1;
err:
    if (r == 0 && i != 0)
        TEST_info(i == 1 ? "allowing precomputation" :
                           "without precomputation");
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    EC_POINT_free(S);
    BN_free(n1);
    BN_free(n2);
    BN_free(order);
    BN_CTX_free(ctx);
    return r;
}

static int prime_field_tests(void)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *scalar3 = NULL;
    EC_GROUP *group = NULL, *tmp = NULL;
    EC_GROUP *P_160 = NULL, *P_192 = NULL, *P_224 = NULL,
             *P_256 = NULL, *P_384 = NULL, *P_521 = NULL;
    EC_POINT *P = NULL, *Q = NULL, *R = NULL;
    BIGNUM *x = NULL, *y = NULL, *z = NULL, *yplusone = NULL;
    const EC_POINT *points[4];
    const BIGNUM *scalars[4];
    unsigned char buf[100];
    size_t len, r = 0;
    int k;

    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        /*
         * applications should use EC_GROUP_new_curve_GFp so
         * that the library gets to choose the EC_METHOD
         */
        || !TEST_ptr(group = EC_GROUP_new(EC_GFp_mont_method()))
        || !TEST_ptr(tmp = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(tmp, group)))
        goto err;
    EC_GROUP_free(group);
    group = tmp;
    tmp = NULL;

    buf[0] = 0;
    if (!TEST_ptr(P = EC_POINT_new(group))
        || !TEST_ptr(Q = EC_POINT_new(group))
        || !TEST_ptr(R = EC_POINT_new(group))
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(z = BN_new())
        || !TEST_ptr(yplusone = BN_new()))
        goto err;

    /* Curve P-224 (FIPS PUB 186-2, App. 6) */

    if (!TEST_true(BN_hex2bn(&p,         "FFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFF000000000000000000000001"))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a,         "FFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE"))
        || !TEST_true(BN_hex2bn(&b,         "B4050A850C04B3ABF5413256"
                                    "5044B0B7D7BFD8BA270B39432355FFB4"))
        || !TEST_true(EC_GROUP_set_curve(group, p, a, b, ctx))
        || !TEST_true(BN_hex2bn(&x,         "B70E0CBD6BB4BF7F321390B9"
                                    "4A03C1D356C21122343280D6115C1D21"))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, P, x, 0, ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z,         "FFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFF16A2E0B8F03E13DD29455C5C2A3D"))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, BN_value_one()))
        || !TEST_true(EC_POINT_get_affine_coordinates(group, P, x, y, ctx)))
        goto err;

    TEST_info("NIST curve P-224 -- Generator");
    test_output_bignum("x", x);
    test_output_bignum("y", y);
    /* G_y value taken from the standard: */
    if (!TEST_true(BN_hex2bn(&z,         "BD376388B5F723FB4C22DFE6"
                                 "CD4375A05A07476444D5819985007E34"))
        || !TEST_BN_eq(y, z)
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates(group, P, x, yplusone,
                                                       ctx))
        || !TEST_int_eq(EC_GROUP_get_degree(group), 224)
        || !group_order_tests(group)
        || !TEST_ptr(P_224 = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(P_224, group))

    /* Curve P-256 (FIPS PUB 186-2, App. 6) */

        || !TEST_true(BN_hex2bn(&p, "FFFFFFFF000000010000000000000000"
                                    "00000000FFFFFFFFFFFFFFFFFFFFFFFF"))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, "FFFFFFFF000000010000000000000000"
                                    "00000000FFFFFFFFFFFFFFFFFFFFFFFC"))
        || !TEST_true(BN_hex2bn(&b, "5AC635D8AA3A93E7B3EBBD55769886BC"
                                    "651D06B0CC53B0F63BCE3C3E27D2604B"))
        || !TEST_true(EC_GROUP_set_curve(group, p, a, b, ctx))

        || !TEST_true(BN_hex2bn(&x, "6B17D1F2E12C4247F8BCE6E563A440F2"
                                    "77037D812DEB33A0F4A13945D898C296"))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, P, x, 1, ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z, "FFFFFFFF00000000FFFFFFFFFFFFFFFF"
                                    "BCE6FAADA7179E84F3B9CAC2FC632551"))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, BN_value_one()))
        || !TEST_true(EC_POINT_get_affine_coordinates(group, P, x, y, ctx)))
        goto err;

    TEST_info("NIST curve P-256 -- Generator");
    test_output_bignum("x", x);
    test_output_bignum("y", y);
    /* G_y value taken from the standard: */
    if (!TEST_true(BN_hex2bn(&z, "4FE342E2FE1A7F9B8EE7EB4A7C0F9E16"
                                 "2BCE33576B315ECECBB6406837BF51F5"))
        || !TEST_BN_eq(y, z)
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates(group, P, x, yplusone,
                                                       ctx))
        || !TEST_int_eq(EC_GROUP_get_degree(group), 256)
        || !group_order_tests(group)
        || !TEST_ptr(P_256 = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(P_256, group))

    /* Curve P-384 (FIPS PUB 186-2, App. 6) */

        || !TEST_true(BN_hex2bn(&p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
                                    "FFFFFFFF0000000000000000FFFFFFFF"))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
                                    "FFFFFFFF0000000000000000FFFFFFFC"))
        || !TEST_true(BN_hex2bn(&b, "B3312FA7E23EE7E4988E056BE3F82D19"
                                    "181D9C6EFE8141120314088F5013875A"
                                    "C656398D8A2ED19D2A85C8EDD3EC2AEF"))
        || !TEST_true(EC_GROUP_set_curve(group, p, a, b, ctx))

        || !TEST_true(BN_hex2bn(&x, "AA87CA22BE8B05378EB1C71EF320AD74"
                                    "6E1D3B628BA79B9859F741E082542A38"
                                    "5502F25DBF55296C3A545E3872760AB7"))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, P, x, 1, ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFC7634D81F4372DDF"
                                    "581A0DB248B0A77AECEC196ACCC52973"))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, BN_value_one()))
        || !TEST_true(EC_POINT_get_affine_coordinates(group, P, x, y, ctx)))
        goto err;

    TEST_info("NIST curve P-384 -- Generator");
    test_output_bignum("x", x);
    test_output_bignum("y", y);
    /* G_y value taken from the standard: */
    if (!TEST_true(BN_hex2bn(&z, "3617DE4A96262C6F5D9E98BF9292DC29"
                                 "F8F41DBD289A147CE9DA3113B5F0B8C0"
                                 "0A60B1CE1D7E819D7A431D7C90EA0E5F"))
        || !TEST_BN_eq(y, z)
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates(group, P, x, yplusone,
                                                       ctx))
        || !TEST_int_eq(EC_GROUP_get_degree(group), 384)
        || !group_order_tests(group)
        || !TEST_ptr(P_384 = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(P_384, group))

    /* Curve P-521 (FIPS PUB 186-2, App. 6) */
        || !TEST_true(BN_hex2bn(&p,                              "1FF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a,                              "1FF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"))
        || !TEST_true(BN_hex2bn(&b,                              "051"
                                    "953EB9618E1C9A1F929A21A0B68540EE"
                                    "A2DA725B99B315F3B8B489918EF109E1"
                                    "56193951EC7E937B1652C0BD3BB1BF07"
                                    "3573DF883D2C34F1EF451FD46B503F00"))
        || !TEST_true(EC_GROUP_set_curve(group, p, a, b, ctx))
        || !TEST_true(BN_hex2bn(&x,                               "C6"
                                    "858E06B70404E9CD9E3ECB662395B442"
                                    "9C648139053FB521F828AF606B4D3DBA"
                                    "A14B5E77EFE75928FE1DC127A2FFA8DE"
                                    "3348B3C1856A429BF97E7E31C2E5BD66"))
        || !TEST_true(EC_POINT_set_compressed_coordinates(group, P, x, 0, ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(BN_hex2bn(&z,                              "1FF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA"
                                    "51868783BF2F966B7FCC0148F709A5D0"
                                    "3BB5C9B8899C47AEBB6FB71E91386409"))
        || !TEST_true(EC_GROUP_set_generator(group, P, z, BN_value_one()))
        || !TEST_true(EC_POINT_get_affine_coordinates(group, P, x, y, ctx)))
        goto err;

    TEST_info("NIST curve P-521 -- Generator");
    test_output_bignum("x", x);
    test_output_bignum("y", y);
    /* G_y value taken from the standard: */
    if (!TEST_true(BN_hex2bn(&z,                              "118"
                                 "39296A789A3BC0045C8A5FB42C7D1BD9"
                                 "98F54449579B446817AFBD17273E662C"
                                 "97EE72995EF42640C550B9013FAD0761"
                                 "353C7086A272C24088BE94769FD16650"))
        || !TEST_BN_eq(y, z)
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates(group, P, x, yplusone,
                                                       ctx))
        || !TEST_int_eq(EC_GROUP_get_degree(group), 521)
        || !group_order_tests(group)
        || !TEST_ptr(P_521 = EC_GROUP_new(EC_GROUP_method_of(group)))
        || !TEST_true(EC_GROUP_copy(P_521, group))

    /* more tests using the last curve */

    /* Restore the point that got mangled in the (x, y + 1) test. */
        || !TEST_true(EC_POINT_set_affine_coordinates(group, P, x, y, ctx))
        || !TEST_true(EC_POINT_copy(Q, P))
        || !TEST_false(EC_POINT_is_at_infinity(group, Q))
        || !TEST_true(EC_POINT_dbl(group, P, P, ctx))
        || !TEST_int_gt(EC_POINT_is_on_curve(group, P, ctx), 0)
        || !TEST_true(EC_POINT_invert(group, Q, ctx))       /* P = -2Q */
        || !TEST_true(EC_POINT_add(group, R, P, Q, ctx))
        || !TEST_true(EC_POINT_add(group, R, R, Q, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, R))    /* R = P + 2Q */
        || !TEST_false(EC_POINT_is_at_infinity(group, Q)))
        goto err;
    points[0] = Q;
    points[1] = Q;
    points[2] = Q;
    points[3] = Q;

    if (!TEST_true(EC_GROUP_get_order(group, z, ctx))
        || !TEST_true(BN_add(y, z, BN_value_one()))
        || !TEST_BN_even(y)
        || !TEST_true(BN_rshift1(y, y)))
        goto err;
    scalars[0] = y;         /* (group order + 1)/2, so y*Q + y*Q = Q */
    scalars[1] = y;

    TEST_note("combined multiplication ...");

    /* z is still the group order */
    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
        || !TEST_true(EC_POINTs_mul(group, R, z, 2, points, scalars, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, P, R, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(group, R, Q, ctx))
        || !TEST_true(BN_rand(y, BN_num_bits(y), 0, 0))
        || !TEST_true(BN_add(z, z, y)))
        goto err;
    BN_set_negative(z, 1);
    scalars[0] = y;
    scalars[1] = z;         /* z = -(order + y) */

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 2, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P))
        || !TEST_true(BN_rand(x, BN_num_bits(y) - 1, 0, 0))
        || !TEST_true(BN_add(z, x, y)))
        goto err;
    BN_set_negative(z, 1);
    scalars[0] = x;
    scalars[1] = y;
    scalars[2] = z;         /* z = -(x+y) */

    if (!TEST_ptr(scalar3 = BN_new()))
        goto err;
    BN_zero(scalar3);
    scalars[3] = scalar3;

    if (!TEST_true(EC_POINTs_mul(group, P, NULL, 4, points, scalars, ctx))
        || !TEST_true(EC_POINT_is_at_infinity(group, P)))
        goto err;

    TEST_note(" ok\n");


    r = 1;
err:
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    EC_GROUP_free(group);
    EC_GROUP_free(tmp);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(R);
    BN_free(x);
    BN_free(y);
    BN_free(z);
    BN_free(yplusone);
    BN_free(scalar3);

    EC_GROUP_free(P_224);
    EC_GROUP_free(P_256);
    EC_GROUP_free(P_384);
    EC_GROUP_free(P_521);
    return r;
}

static int internal_curve_test(int n)
{
    EC_GROUP *group = NULL;
    int nid = curves[n].nid;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(nid))) {
        TEST_info("EC_GROUP_new_curve_name() failed with curve %s\n",
                  OBJ_nid2sn(nid));
        return 0;
    }
    if (!TEST_true(EC_GROUP_check(group, NULL))) {
        TEST_info("EC_GROUP_check() failed with curve %s\n", OBJ_nid2sn(nid));
        EC_GROUP_free(group);
        return 0;
    }
    EC_GROUP_free(group);
    return 1;
}

static int internal_curve_test_method(int n)
{
    int r, nid = curves[n].nid;
    EC_GROUP *group;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(nid))) {
        TEST_info("Curve %s failed\n", OBJ_nid2sn(nid));
        return 0;
    }
    r = group_order_tests(group);
    EC_GROUP_free(group);
    return r;
}

# ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
/*
 * nistp_test_params contains magic numbers for testing our optimized
 * implementations of several NIST curves with characteristic > 3.
 */
struct nistp_test_params {
    const EC_METHOD *(*meth) (void);
    int degree;
    /*
     * Qx, Qy and D are taken from
     * http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/ECDSA_Prime.pdf
     * Otherwise, values are standard curve parameters from FIPS 180-3
     */
    const char *p, *a, *b, *Qx, *Qy, *Gx, *Gy, *order, *d;
};

static const struct nistp_test_params nistp_tests_params[] = {
    {
     /* P-224 */
     EC_GFp_nistp224_method,
     224,
     /* p */
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
     /* a */
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
     /* b */
     "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
     /* Qx */
     "E84FB0B8E7000CB657D7973CF6B42ED78B301674276DF744AF130B3E",
     /* Qy */
     "4376675C6FC5612C21A0FF2D2A89D2987DF7A2BC52183B5982298555",
     /* Gx */
     "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
     /* Gy */
     "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
     /* order */
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
     /* d */
     "3F0C488E987C80BE0FEE521F8D90BE6034EC69AE11CA72AA777481E8",
     },
    {
     /* P-256 */
     EC_GFp_nistp256_method,
     256,
     /* p */
     "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
     /* a */
     "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
     /* b */
     "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
     /* Qx */
     "b7e08afdfe94bad3f1dc8c734798ba1c62b3a0ad1e9ea2a38201cd0889bc7a19",
     /* Qy */
     "3603f747959dbf7a4bb226e41928729063adc7ae43529e61b563bbc606cc5e09",
     /* Gx */
     "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
     /* Gy */
     "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
     /* order */
     "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
     /* d */
     "c477f9f65c22cce20657faa5b2d1d8122336f851a508a1ed04e479c34985bf96",
     },
    {
     /* P-521 */
     EC_GFp_nistp521_method,
     521,
     /* p */
                                                                  "1ff"
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     /* a */
                                                                  "1ff"
     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
     "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
     /* b */
                                                                  "051"
     "953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e1"
     "56193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
     /* Qx */
                                                                 "0098"
     "e91eef9a68452822309c52fab453f5f117c1da8ed796b255e9ab8f6410cca16e"
     "59df403a6bdc6ca467a37056b1e54b3005d8ac030decfeb68df18b171885d5c4",
     /* Qy */
                                                                 "0164"
     "350c321aecfc1cca1ba4364c9b15656150b4b78d6a48d7d28e7f31985ef17be8"
     "554376b72900712c4b83ad668327231526e313f5f092999a4632fd50d946bc2e",
     /* Gx */
                                                                   "c6"
     "858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dba"
     "a14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
     /* Gy */
                                                                  "118"
     "39296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c"
     "97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
     /* order */
                                                                  "1ff"
     "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa"
     "51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
     /* d */
                                                                 "0100"
     "085f47b8e1b8b11b7eb33028c0b2888e304bfc98501955b45bba1478dc184eee"
     "df09b86a5f7c21994406072787205e69a63709fe35aa93ba333514b24f961722",
     },
};

static int nistp_single_test(int idx)
{
    const struct nistp_test_params *test = nistp_tests_params + idx;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *x = NULL, *y = NULL;
    BIGNUM *n = NULL, *m = NULL, *order = NULL, *yplusone = NULL;
    EC_GROUP *NISTP = NULL;
    EC_POINT *G = NULL, *P = NULL, *Q = NULL, *Q_CHECK = NULL;
    int r = 0;

    TEST_note("NIST curve P-%d (optimised implementation):",
              test->degree);
    if (!TEST_ptr(ctx = BN_CTX_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(x = BN_new())
        || !TEST_ptr(y = BN_new())
        || !TEST_ptr(m = BN_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(order = BN_new())
        || !TEST_ptr(yplusone = BN_new())

        || !TEST_ptr(NISTP = EC_GROUP_new(test->meth()))
        || !TEST_true(BN_hex2bn(&p, test->p))
        || !TEST_int_eq(1, BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
        || !TEST_true(BN_hex2bn(&a, test->a))
        || !TEST_true(BN_hex2bn(&b, test->b))
        || !TEST_true(EC_GROUP_set_curve(NISTP, p, a, b, ctx))
        || !TEST_ptr(G = EC_POINT_new(NISTP))
        || !TEST_ptr(P = EC_POINT_new(NISTP))
        || !TEST_ptr(Q = EC_POINT_new(NISTP))
        || !TEST_ptr(Q_CHECK = EC_POINT_new(NISTP))
        || !TEST_true(BN_hex2bn(&x, test->Qx))
        || !TEST_true(BN_hex2bn(&y, test->Qy))
        || !TEST_true(BN_add(yplusone, y, BN_value_one()))
    /*
     * When (x, y) is on the curve, (x, y + 1) is, as it happens, not,
     * and therefore setting the coordinates should fail.
     */
        || !TEST_false(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x,
                                                       yplusone, ctx))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, Q_CHECK, x, y,
                                                      ctx))
        || !TEST_true(BN_hex2bn(&x, test->Gx))
        || !TEST_true(BN_hex2bn(&y, test->Gy))
        || !TEST_true(EC_POINT_set_affine_coordinates(NISTP, G, x, y, ctx))
        || !TEST_true(BN_hex2bn(&order, test->order))
        || !TEST_true(EC_GROUP_set_generator(NISTP, G, order, BN_value_one()))
        || !TEST_int_eq(EC_GROUP_get_degree(NISTP), test->degree))
        goto err;

    TEST_note("NIST test vectors ... ");
    if (!TEST_true(BN_hex2bn(&n, test->d)))
        goto err;
    /* fixed point multiplication */
    EC_POINT_mul(NISTP, Q, n, NULL, NULL, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;
    /* random point multiplication */
    EC_POINT_mul(NISTP, Q, NULL, G, n, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx))

        /* set generator to P = 2*G, where G is the standard generator */
        || !TEST_true(EC_POINT_dbl(NISTP, P, G, ctx))
        || !TEST_true(EC_GROUP_set_generator(NISTP, P, order, BN_value_one()))
        /* set the scalar to m=n/2, where n is the NIST test scalar */
        || !TEST_true(BN_rshift(m, n, 1)))
        goto err;

    /* test the non-standard generator */
    /* fixed point multiplication */
    EC_POINT_mul(NISTP, Q, m, NULL, NULL, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;
    /* random point multiplication */
    EC_POINT_mul(NISTP, Q, NULL, P, m, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx))

    /*
     * We have not performed precomputation so have_precompute mult should be
     * false
     */
        || !TEST_false(EC_GROUP_have_precompute_mult(NISTP))

    /* now repeat all tests with precomputation */
        || !TEST_true(EC_GROUP_precompute_mult(NISTP, ctx))
        || !TEST_true(EC_GROUP_have_precompute_mult(NISTP)))
        goto err;

    /* fixed point multiplication */
    EC_POINT_mul(NISTP, Q, m, NULL, NULL, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;
    /* random point multiplication */
    EC_POINT_mul(NISTP, Q, NULL, P, m, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx))

    /* reset generator */
        || !TEST_true(EC_GROUP_set_generator(NISTP, G, order, BN_value_one())))
        goto err;
    /* fixed point multiplication */
    EC_POINT_mul(NISTP, Q, n, NULL, NULL, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;
    /* random point multiplication */
    EC_POINT_mul(NISTP, Q, NULL, G, n, ctx);
    if (!TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, Q_CHECK, ctx)))
        goto err;

    /* regression test for felem_neg bug */
    if (!TEST_true(BN_set_word(m, 32))
        || !TEST_true(BN_set_word(n, 31))
        || !TEST_true(EC_POINT_copy(P, G))
        || !TEST_true(EC_POINT_invert(NISTP, P, ctx))
        || !TEST_true(EC_POINT_mul(NISTP, Q, m, P, n, ctx))
        || !TEST_int_eq(0, EC_POINT_cmp(NISTP, Q, G, ctx)))
      goto err;

    r = group_order_tests(NISTP);
err:
    EC_GROUP_free(NISTP);
    EC_POINT_free(G);
    EC_POINT_free(P);
    EC_POINT_free(Q);
    EC_POINT_free(Q_CHECK);
    BN_free(n);
    BN_free(m);
    BN_free(p);
    BN_free(a);
    BN_free(b);
    BN_free(x);
    BN_free(y);
    BN_free(order);
    BN_free(yplusone);
    BN_CTX_free(ctx);
    return r;
}
# endif

static const unsigned char p521_named[] = {
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
};

static const unsigned char p521_explicit[] = {
    0x30, 0x82, 0x01, 0xc3, 0x02, 0x01, 0x01, 0x30, 0x4d, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x01, 0x01, 0x02, 0x42, 0x01, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0x30, 0x81, 0x9f, 0x04, 0x42, 0x01, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfc, 0x04, 0x42, 0x00, 0x51, 0x95, 0x3e, 0xb9, 0x61, 0x8e, 0x1c, 0x9a,
    0x1f, 0x92, 0x9a, 0x21, 0xa0, 0xb6, 0x85, 0x40, 0xee, 0xa2, 0xda, 0x72,
    0x5b, 0x99, 0xb3, 0x15, 0xf3, 0xb8, 0xb4, 0x89, 0x91, 0x8e, 0xf1, 0x09,
    0xe1, 0x56, 0x19, 0x39, 0x51, 0xec, 0x7e, 0x93, 0x7b, 0x16, 0x52, 0xc0,
    0xbd, 0x3b, 0xb1, 0xbf, 0x07, 0x35, 0x73, 0xdf, 0x88, 0x3d, 0x2c, 0x34,
    0xf1, 0xef, 0x45, 0x1f, 0xd4, 0x6b, 0x50, 0x3f, 0x00, 0x03, 0x15, 0x00,
    0xd0, 0x9e, 0x88, 0x00, 0x29, 0x1c, 0xb8, 0x53, 0x96, 0xcc, 0x67, 0x17,
    0x39, 0x32, 0x84, 0xaa, 0xa0, 0xda, 0x64, 0xba, 0x04, 0x81, 0x85, 0x04,
    0x00, 0xc6, 0x85, 0x8e, 0x06, 0xb7, 0x04, 0x04, 0xe9, 0xcd, 0x9e, 0x3e,
    0xcb, 0x66, 0x23, 0x95, 0xb4, 0x42, 0x9c, 0x64, 0x81, 0x39, 0x05, 0x3f,
    0xb5, 0x21, 0xf8, 0x28, 0xaf, 0x60, 0x6b, 0x4d, 0x3d, 0xba, 0xa1, 0x4b,
    0x5e, 0x77, 0xef, 0xe7, 0x59, 0x28, 0xfe, 0x1d, 0xc1, 0x27, 0xa2, 0xff,
    0xa8, 0xde, 0x33, 0x48, 0xb3, 0xc1, 0x85, 0x6a, 0x42, 0x9b, 0xf9, 0x7e,
    0x7e, 0x31, 0xc2, 0xe5, 0xbd, 0x66, 0x01, 0x18, 0x39, 0x29, 0x6a, 0x78,
    0x9a, 0x3b, 0xc0, 0x04, 0x5c, 0x8a, 0x5f, 0xb4, 0x2c, 0x7d, 0x1b, 0xd9,
    0x98, 0xf5, 0x44, 0x49, 0x57, 0x9b, 0x44, 0x68, 0x17, 0xaf, 0xbd, 0x17,
    0x27, 0x3e, 0x66, 0x2c, 0x97, 0xee, 0x72, 0x99, 0x5e, 0xf4, 0x26, 0x40,
    0xc5, 0x50, 0xb9, 0x01, 0x3f, 0xad, 0x07, 0x61, 0x35, 0x3c, 0x70, 0x86,
    0xa2, 0x72, 0xc2, 0x40, 0x88, 0xbe, 0x94, 0x76, 0x9f, 0xd1, 0x66, 0x50,
    0x02, 0x42, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfa,
    0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48,
    0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae,
    0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09, 0x02, 0x01, 0x01,
};

static int parameter_test(void)
{
    EC_GROUP *group = NULL, *group2 = NULL;
    ECPARAMETERS *ecparameters = NULL;
    unsigned char *buf = NULL;
    int r = 0, len;

    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_secp384r1))
        || !TEST_ptr(ecparameters = EC_GROUP_get_ecparameters(group, NULL))
        || !TEST_ptr(group2 = EC_GROUP_new_from_ecparameters(ecparameters))
        || !TEST_int_eq(EC_GROUP_cmp(group, group2, NULL), 0))
        goto err;

    EC_GROUP_free(group);
    group = NULL;

    /* Test the named curve encoding, which should be default. */
    if (!TEST_ptr(group = EC_GROUP_new_by_curve_name(NID_secp521r1))
        || !TEST_true((len = i2d_ECPKParameters(group, &buf)) >= 0)
        || !TEST_mem_eq(buf, len, p521_named, sizeof(p521_named)))
        goto err;

    OPENSSL_free(buf);
    buf = NULL;

    /*
     * Test the explicit encoding. P-521 requires correctly zero-padding the
     * curve coefficients.
     */
    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE);
    if (!TEST_true((len = i2d_ECPKParameters(group, &buf)) >= 0)
        || !TEST_mem_eq(buf, len, p521_explicit, sizeof(p521_explicit)))
        goto err;

    r = 1;
err:
    EC_GROUP_free(group);
    EC_GROUP_free(group2);
    ECPARAMETERS_free(ecparameters);
    OPENSSL_free(buf);
    return r;
}
#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_EC
    crv_len = EC_get_builtin_curves(NULL, 0);
    if (!TEST_ptr(curves = OPENSSL_malloc(sizeof(*curves) * crv_len))
        || !TEST_true(EC_get_builtin_curves(curves, crv_len)))
        return 0;

    ADD_TEST(parameter_test);
    ADD_TEST(prime_field_tests);
# ifndef OPENSSL_NO_EC2M
    ADD_TEST(char2_field_tests);
    ADD_ALL_TESTS(char2_curve_test, OSSL_NELEM(char2_curve_tests));
# endif
# ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
    ADD_ALL_TESTS(nistp_single_test, OSSL_NELEM(nistp_tests_params));
# endif
    ADD_ALL_TESTS(internal_curve_test, crv_len);
    ADD_ALL_TESTS(internal_curve_test_method, crv_len);
#endif
    return 1;
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_EC
    OPENSSL_free(curves);
#endif
}
