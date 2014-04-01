/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/openssl/enc_provider/aes.c */
/*
 * Copyright (C) 2003, 2007, 2008, 2009 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "crypto_int.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

/* proto's */
static krb5_error_code
cbc_enc(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
        size_t num_data);
static krb5_error_code
cbc_decr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data);
static krb5_error_code
cts_encr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data, size_t dlen);
static krb5_error_code
cts_decr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data, size_t dlen);
static krb5_error_code
gcm_encr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data);
static krb5_error_code
gcm_decr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data);

#define BLOCK_SIZE 16
#define NUM_BITS 8
#define IV_CTS_BUF_SIZE 16 /* 16 - hardcoded in CRYPTO_cts128_en/decrypt */
#define TAG_SIZE 16

/**
 * When we don't want an IV, we just use an array of null bytes.
 * The IV size for GCM is 96 bits (12 bytes).
 */
static const unsigned char gcm_no_iv[12] = { 0x00 };

static const EVP_CIPHER *
map_mode(unsigned int len)
{
    if (len==16)
        return EVP_aes_128_cbc();
    if (len==32)
        return EVP_aes_256_cbc();
    else
        return NULL;
}

/* Encrypt one block using CBC. */
static krb5_error_code
cbc_enc(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
        size_t num_data)
{
    int             ret, olen = BLOCK_SIZE;
    unsigned char   iblock[BLOCK_SIZE], oblock[BLOCK_SIZE];
    EVP_CIPHER_CTX  ciph_ctx;
    struct iov_cursor cursor;

    EVP_CIPHER_CTX_init(&ciph_ctx);
    ret = EVP_EncryptInit_ex(&ciph_ctx, map_mode(key->keyblock.length),
                             NULL, key->keyblock.contents, (ivec) ? (unsigned char*)ivec->data : NULL);
    if (ret == 0)
        return KRB5_CRYPTO_INTERNAL;

    k5_iov_cursor_init(&cursor, data, num_data, BLOCK_SIZE, FALSE);
    k5_iov_cursor_get(&cursor, iblock);
    EVP_CIPHER_CTX_set_padding(&ciph_ctx,0);
    ret = EVP_EncryptUpdate(&ciph_ctx, oblock, &olen, iblock, BLOCK_SIZE);
    if (ret == 1)
        k5_iov_cursor_put(&cursor, oblock);
    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    zap(iblock, BLOCK_SIZE);
    zap(oblock, BLOCK_SIZE);
    return (ret == 1) ? 0 : KRB5_CRYPTO_INTERNAL;
}

/* Decrypt one block using CBC. */
static krb5_error_code
cbc_decr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data)
{
    int              ret = 0, olen = BLOCK_SIZE;
    unsigned char    iblock[BLOCK_SIZE], oblock[BLOCK_SIZE];
    EVP_CIPHER_CTX   ciph_ctx;
    struct iov_cursor cursor;

    EVP_CIPHER_CTX_init(&ciph_ctx);
    ret = EVP_DecryptInit_ex(&ciph_ctx, map_mode(key->keyblock.length),
                             NULL, key->keyblock.contents, (ivec) ? (unsigned char*)ivec->data : NULL);
    if (ret == 0)
        return KRB5_CRYPTO_INTERNAL;

    k5_iov_cursor_init(&cursor, data, num_data, BLOCK_SIZE, FALSE);
    k5_iov_cursor_get(&cursor, iblock);
    EVP_CIPHER_CTX_set_padding(&ciph_ctx,0);
    ret = EVP_DecryptUpdate(&ciph_ctx, oblock, &olen, iblock, BLOCK_SIZE);
    if (ret == 1)
        k5_iov_cursor_put(&cursor, oblock);
    EVP_CIPHER_CTX_cleanup(&ciph_ctx);

    zap(iblock, BLOCK_SIZE);
    zap(oblock, BLOCK_SIZE);
    return (ret == 1) ? 0 : KRB5_CRYPTO_INTERNAL;
}

static krb5_error_code
cts_encr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data, size_t dlen)
{
    int                    ret = 0;
    size_t                 size = 0;
    unsigned char         *oblock = NULL, *dbuf = NULL;
    unsigned char          iv_cts[IV_CTS_BUF_SIZE];
    struct iov_cursor      cursor;
    AES_KEY                enck;

    memset(iv_cts,0,sizeof(iv_cts));
    if (ivec && ivec->data){
        if (ivec->length != sizeof(iv_cts))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv_cts, ivec->data,ivec->length);
    }

    oblock = OPENSSL_malloc(dlen);
    if (!oblock){
        return ENOMEM;
    }
    dbuf = OPENSSL_malloc(dlen);
    if (!dbuf){
        OPENSSL_free(oblock);
        return ENOMEM;
    }

    k5_iov_cursor_init(&cursor, data, num_data, dlen, FALSE);
    k5_iov_cursor_get(&cursor, dbuf);

    AES_set_encrypt_key(key->keyblock.contents,
                        NUM_BITS * key->keyblock.length, &enck);

    size = CRYPTO_cts128_encrypt((unsigned char *)dbuf, oblock, dlen, &enck,
                                 iv_cts, (cbc128_f)AES_cbc_encrypt);
    if (size <= 0)
        ret = KRB5_CRYPTO_INTERNAL;
    else
        k5_iov_cursor_put(&cursor, oblock);

    if (!ret && ivec && ivec->data)
        memcpy(ivec->data, iv_cts, sizeof(iv_cts));

    zap(oblock, dlen);
    zap(dbuf, dlen);
    OPENSSL_free(oblock);
    OPENSSL_free(dbuf);

    return ret;
}

static krb5_error_code
cts_decr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data, size_t dlen)
{
    int                    ret = 0;
    size_t                 size = 0;
    unsigned char         *oblock = NULL;
    unsigned char         *dbuf = NULL;
    unsigned char          iv_cts[IV_CTS_BUF_SIZE];
    struct iov_cursor      cursor;
    AES_KEY                deck;

    memset(iv_cts,0,sizeof(iv_cts));
    if (ivec && ivec->data){
        if (ivec->length != sizeof(iv_cts))
            return KRB5_CRYPTO_INTERNAL;
        memcpy(iv_cts, ivec->data,ivec->length);
    }

    oblock = OPENSSL_malloc(dlen);
    if (!oblock)
        return ENOMEM;
    dbuf = OPENSSL_malloc(dlen);
    if (!dbuf){
        OPENSSL_free(oblock);
        return ENOMEM;
    }

    AES_set_decrypt_key(key->keyblock.contents,
                        NUM_BITS * key->keyblock.length, &deck);

    k5_iov_cursor_init(&cursor, data, num_data, dlen, FALSE);
    k5_iov_cursor_get(&cursor, dbuf);

    size = CRYPTO_cts128_decrypt((unsigned char *)dbuf, oblock,
                                 dlen, &deck,
                                 iv_cts, (cbc128_f)AES_cbc_encrypt);
    if (size <= 0)
        ret = KRB5_CRYPTO_INTERNAL;
    else
        k5_iov_cursor_put(&cursor, oblock);

    if (!ret && ivec && ivec->data)
        memcpy(ivec->data, iv_cts, sizeof(iv_cts));

    zap(oblock, dlen);
    zap(dbuf, dlen);
    OPENSSL_free(oblock);
    OPENSSL_free(dbuf);

    return ret;
}

/* Encrypt using GCM */
static krb5_error_code
gcm_encr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data)
{
    int             ret = 0, t = 0;
    size_t          i = 0;
    EVP_CIPHER_CTX  ciph_ctx;
    krb5_crypto_iov *tag_data;
    struct iov_cursor cursor;

    // Create cipher context
    EVP_CIPHER_CTX_init(&ciph_ctx);
    ret = EVP_EncryptInit_ex(&ciph_ctx, EVP_aes_256_gcm(), NULL, key->keyblock.contents, NULL);
    if (ret == 0) {
        EVP_CIPHER_CTX_cleanup(&ciph_ctx);
        return KRB5_CRYPTO_INTERNAL;
    }

    if (ivec) {
        /* Initialise IV with ivec */
        ret = EVP_CIPHER_CTX_ctrl(&ciph_ctx, EVP_CTRL_GCM_SET_IVLEN, ivec->length, NULL);
        if (ret == 0) {
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);
            return KRB5_CRYPTO_INTERNAL;
        }
        ret = EVP_EncryptInit_ex(&ciph_ctx, NULL, NULL, NULL, (unsigned char *)ivec->data);
        if (ret == 0) {
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);
            return KRB5_CRYPTO_INTERNAL;
        }
    } else {
        /* Initialise IV to zero */
        // TODO: maybe we don't need to call EVP_CTRL_GCM_SET_IVLEN in this case?
        ret = EVP_CIPHER_CTX_ctrl(&ciph_ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_no_iv), NULL);
        if (ret == 0) {
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);
            return KRB5_CRYPTO_INTERNAL;
        }
        ret = EVP_EncryptInit_ex(&ciph_ctx, NULL, NULL, NULL, gcm_no_iv);
        if (ret == 0) {
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);
            return KRB5_CRYPTO_INTERNAL;
        }
    }

    // Encrypt the data in-place
    for (i=0; i<num_data; i++) {
        krb5_crypto_iov *iov = &data[i];
        if (!ENCRYPT_IOV(iov)) {
            continue;
        }
        // Encrypt the data
        ret = EVP_EncryptUpdate(&ciph_ctx, (unsigned char*)iov->data.data, &t, (unsigned char*)iov->data.data, iov->data.length);
        if (ret == 0) {
            // TODO: do we want to use goto statements instead?
            // TODO: should we zap the iov?
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);
            return KRB5_CRYPTO_INTERNAL;
        }
        assert(t == (int)iov->data.length);
    }

    // Finalize, does not actually encrypt anything
    // TODO: is it ok to pass NULL here?
    ret = EVP_EncryptFinal_ex(&ciph_ctx, NULL, &t);
    if (ret == 0) {
        EVP_CIPHER_CTX_cleanup(&ciph_ctx);
        return KRB5_CRYPTO_INTERNAL;
    }

    // Write the TAG
    // TODO: micro-optimization, save the position of the TRAILER in the loop above
    tag_data = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (tag_data == NULL) {
        EVP_CIPHER_CTX_cleanup(&ciph_ctx);
        return KRB5_CRYPTO_INTERNAL;
    }
    assert(tag_data->data.length == TAG_SIZE);

    EVP_CIPHER_CTX_ctrl(&ciph_ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag_data->data.data);
    if (ret == 0) {
        EVP_CIPHER_CTX_cleanup(&ciph_ctx);
        return KRB5_CRYPTO_INTERNAL;
    }
    
    // We are done!
    EVP_CIPHER_CTX_cleanup(&ciph_ctx);
    return 0;
}

/* Decrypt using GCM */
static krb5_error_code
gcm_decr(krb5_key key, const krb5_data *ivec, krb5_crypto_iov *data,
         size_t num_data)
{
    int               ret = 0, t = 0;
    size_t            i = 0;
    EVP_CIPHER_CTX    ciph_ctx;
    krb5_crypto_iov   *tag_data;

    EVP_CIPHER_CTX_init(&ciph_ctx);
    ret = EVP_DecryptInit_ex(&ciph_ctx, EVP_aes_256_gcm(), NULL, key->keyblock.contents, NULL);
    if (ret == 0) {
        EVP_CIPHER_CTX_cleanup(&ciph_ctx);
        return KRB5_CRYPTO_INTERNAL;
    }

    if (ivec) {
        /* Initialise IV with ivec */
        ret = EVP_CIPHER_CTX_ctrl(&ciph_ctx, EVP_CTRL_GCM_SET_IVLEN, ivec->length, NULL);
        if (ret == 0) {
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);
            return KRB5_CRYPTO_INTERNAL;
        }
        ret = EVP_DecryptInit_ex(&ciph_ctx, NULL, NULL, NULL, (unsigned char *)ivec->data);
        if (ret == 0) {
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);
            return KRB5_CRYPTO_INTERNAL;
        }
    } else {
        /* Initialise IV to zero */
        // TODO: maybe we don't need to call EVP_CTRL_GCM_SET_IVLEN in this case?
        ret = EVP_CIPHER_CTX_ctrl(&ciph_ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(gcm_no_iv), NULL);
        if (ret == 0) {
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);
            return KRB5_CRYPTO_INTERNAL;
        }
        ret = EVP_DecryptInit_ex(&ciph_ctx, NULL, NULL, NULL, gcm_no_iv);
        if (ret == 0) {
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);
            return KRB5_CRYPTO_INTERNAL;
        }
    }

    // Setup the TAG
    tag_data = krb5int_c_locate_iov(data, num_data, KRB5_CRYPTO_TYPE_TRAILER);
    if (tag_data == NULL) {
        EVP_CIPHER_CTX_cleanup(&ciph_ctx);
        return KRB5_CRYPTO_INTERNAL;
    }
    assert(tag_data->data.length == TAG_SIZE);
    EVP_CIPHER_CTX_ctrl(&ciph_ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag_data->data.data);

    for (i=0; i<num_data; i++) {
        krb5_crypto_iov *iov = &data[i];
        if (iov->data.length == 0) {
            // krb5_k_decrypt adds empty PADDING, so skip it. Also skip anything which has zero length.
            continue;
        }
        if (!ENCRYPT_IOV(iov)) {
            continue;
        }
        // Decrypt the data
        ret = EVP_DecryptUpdate(&ciph_ctx, (unsigned char*)iov->data.data, &t, (unsigned char*)iov->data.data, iov->data.length);
        if (ret == 0) {
            EVP_CIPHER_CTX_cleanup(&ciph_ctx);
            return KRB5_CRYPTO_INTERNAL;
        }
        assert(t == (int)iov->data.length);
    }

    // Finalize, does not actually do anything besides check the TAG
    ret = EVP_DecryptFinal_ex(&ciph_ctx, NULL, &t);
    if (ret == 0) {
        EVP_CIPHER_CTX_cleanup(&ciph_ctx);
        return KRB5_CRYPTO_INTERNAL;
    }

    // We are done!
    EVP_CIPHER_CTX_cleanup(&ciph_ctx);
    return 0;
}

krb5_error_code
krb5int_aes_encrypt(krb5_key key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data)
{
    int    ret = 0;
    size_t input_length, nblocks;

    input_length = iov_total_length(data, num_data, FALSE);
    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (nblocks == 1) {
        if (input_length != BLOCK_SIZE)
            return KRB5_BAD_MSIZE;
        ret = cbc_enc(key, ivec, data, num_data);
    } else if (nblocks > 1) {
        ret = cts_encr(key, ivec, data, num_data, input_length);
    }

    return ret;
}

krb5_error_code
krb5int_aes_decrypt(krb5_key key, const krb5_data *ivec,
                    krb5_crypto_iov *data, size_t num_data)
{
    int    ret = 0;
    size_t input_length, nblocks;

    input_length = iov_total_length(data, num_data, FALSE);
    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (nblocks == 1) {
        if (input_length != BLOCK_SIZE)
            return KRB5_BAD_MSIZE;
        ret = cbc_decr(key, ivec, data, num_data);
    } else if (nblocks > 1) {
        ret = cts_decr(key, ivec, data, num_data, input_length);
    }

    return ret;
}

krb5_error_code
krb5int_aes_gcm_encrypt(krb5_key key, const krb5_data *ivec,
                        krb5_crypto_iov *data, size_t num_data)
{
    int    ret = 0;
    size_t input_length, nblocks;

    input_length = iov_total_length(data, num_data, FALSE);
    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (nblocks == 1) {
        if (input_length != BLOCK_SIZE)
            return KRB5_BAD_MSIZE;
        ret = cbc_enc(key, ivec, data, num_data);
    } else if (nblocks > 1) {
        ret = gcm_encr(key, ivec, data, num_data);
    }

    return ret;
}

krb5_error_code
krb5int_aes_gcm_decrypt(krb5_key key, const krb5_data *ivec,
                        krb5_crypto_iov *data, size_t num_data)
{
    int    ret = 0;
    size_t input_length, nblocks;

    input_length = iov_total_length(data, num_data, FALSE);
    nblocks = (input_length + BLOCK_SIZE - 1) / BLOCK_SIZE;
    if (nblocks == 1) {
        if (input_length != BLOCK_SIZE)
            return KRB5_BAD_MSIZE;
        ret = cbc_decr(key, ivec, data, num_data);
    } else if (nblocks > 1) {
        ret = gcm_decr(key, ivec, data, num_data);
    }

    return ret;
}

static krb5_error_code
krb5int_aes_init_state (const krb5_keyblock *key, krb5_keyusage usage,
                        krb5_data *state)
{
    state->length = 16;
    state->data = (void *) malloc(16);
    if (state->data == NULL)
        return ENOMEM;
    memset(state->data, 0, state->length);
    return 0;
}
const struct krb5_enc_provider krb5int_enc_aes128 = {
    16,
    16, 16,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    NULL,
    krb5int_aes_init_state,
    krb5int_default_free_state,
    NULL
};

const struct krb5_enc_provider krb5int_enc_aes256 = {
    16,
    32, 32,
    krb5int_aes_encrypt,
    krb5int_aes_decrypt,
    NULL,
    krb5int_aes_init_state,
    krb5int_default_free_state,
    NULL
};

const struct krb5_enc_provider krb5int_enc_aes256_gcm = {
    16,
    32, 32,
    krb5int_aes_gcm_encrypt,
    krb5int_aes_gcm_decrypt,
    NULL,
    krb5int_aes_init_state,
    krb5int_default_free_state,
    NULL
};
