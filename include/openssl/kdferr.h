/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_KDFERR_H
# define HEADER_KDFERR_H

# ifdef  __cplusplus
extern "C"
# endif
int ERR_load_KDF_strings(void);

/*
 * KDF function codes.
 */
# define KDF_F_HKDF_EXTRACT                               112
# define KDF_F_KDF_HKDF_DERIVE                            113
# define KDF_F_KDF_HKDF_NEW                               114
# define KDF_F_KDF_HKDF_SIZE                              115
# define KDF_F_KDF_MD2CTRL                                116
# define KDF_F_KDF_PBKDF2_CTRL_STR                        117
# define KDF_F_KDF_PBKDF2_DERIVE                          118
# define KDF_F_KDF_PBKDF2_NEW                             119
# define KDF_F_KDF_SCRYPT_CTRL_STR                        120
# define KDF_F_KDF_SCRYPT_CTRL_UINT32                     121
# define KDF_F_KDF_SCRYPT_CTRL_UINT64                     122
# define KDF_F_KDF_SCRYPT_DERIVE                          123
# define KDF_F_KDF_SCRYPT_NEW                             124
# define KDF_F_KDF_TLS1_PRF_CTRL_STR                      125
# define KDF_F_KDF_TLS1_PRF_DERIVE                        126
# define KDF_F_KDF_TLS1_PRF_NEW                           127
# define KDF_F_PBKDF2_SET_MEMBUF                          128
# define KDF_F_PKEY_HKDF_CTRL_STR                         103
# define KDF_F_PKEY_HKDF_DERIVE                           102
# define KDF_F_PKEY_HKDF_INIT                             108
# define KDF_F_PKEY_SCRYPT_CTRL_STR                       104
# define KDF_F_PKEY_SCRYPT_CTRL_UINT64                    105
# define KDF_F_PKEY_SCRYPT_DERIVE                         109
# define KDF_F_PKEY_SCRYPT_INIT                           106
# define KDF_F_PKEY_SCRYPT_SET_MEMBUF                     107
# define KDF_F_PKEY_TLS1_PRF_CTRL_STR                     100
# define KDF_F_PKEY_TLS1_PRF_DERIVE                       101
# define KDF_F_PKEY_TLS1_PRF_INIT                         110
# define KDF_F_SCRYPT_SET_MEMBUF                          129
# define KDF_F_TLS1_PRF_ALG                               111

/*
 * KDF reason codes.
 */
# define KDF_R_INVALID_DIGEST                             100
# define KDF_R_MISSING_ITERATION_COUNT                    109
# define KDF_R_MISSING_KEY                                104
# define KDF_R_MISSING_MESSAGE_DIGEST                     105
# define KDF_R_MISSING_PARAMETER                          101
# define KDF_R_MISSING_PASS                               110
# define KDF_R_MISSING_SALT                               111
# define KDF_R_MISSING_SECRET                             107
# define KDF_R_MISSING_SEED                               106
# define KDF_R_UNKNOWN_PARAMETER_TYPE                     103
# define KDF_R_VALUE_ERROR                                108
# define KDF_R_VALUE_MISSING                              102
# define KDF_R_WRONG_OUTPUT_BUFFER_SIZE                   112

#endif
