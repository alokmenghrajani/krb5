/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/crypto_tests/aes_gcm-test.c */

#include "crypto_int.h"

/**
 * From NIST test vector:
 *
 * [Keylen = 256]
 * [IVlen = 96]
 * [PTlen = 256]
 * [AADlen = 0]
 * [Taglen = 128]
 *
 * Count = 0
 * Key = 268ed1b5d7c9c7304f9cae5fc437b4cd3aebe2ec65f0d85c3918d3d3b5bba89b
 * IV = 9ed9d8180564e0e945f5e5d4
 * PT = fe29a40d8ebf57262bdb87191d01843f4ca4b2de97d88273154a0b7d9e2fdb80
 * AAD =
 * CT = 791a4a026f16f3a5ea06274bf02baab469860abde5e645f3dd473a5acddeecfc
 * Tag = 05b2b74db0662550435ef1900e136b15
 */

static unsigned char keybytes[] = {
    0x26, 0x8e, 0xd1, 0xb5, 0xd7, 0xc9, 0xc7, 0x30,
    0x4f, 0x9c, 0xae, 0x5f, 0xc4, 0x37, 0xb4, 0xcd,
    0x3a, 0xeb, 0xe2, 0xec, 0x65, 0xf0, 0xd8, 0x5c,
    0x39, 0x18, 0xd3, 0xd3, 0xb5, 0xbb, 0xa8, 0x9b
};

static char iv[] = {
    0x9e, 0xd9, 0xd8, 0x18, 0x05, 0x64, 0xe0, 0xe9, 0x45, 0xf5, 0xe5, 0xd4
};

static unsigned char pt[] = {
    0xfe, 0x29, 0xa4, 0x0d, 0x8e, 0xbf, 0x57, 0x26,
    0x2b, 0xdb, 0x87, 0x19, 0x1d, 0x01, 0x84, 0x3f,
    0x4c, 0xa4, 0xb2, 0xde, 0x97, 0xd8, 0x82, 0x73,
    0x15, 0x4a, 0x0b, 0x7d, 0x9e, 0x2f, 0xdb, 0x80
};

/* Expected cipher text and tag */

static char expected_ct[] = {
    0x79, 0x1a, 0x4a, 0x02, 0x6f, 0x16, 0xf3, 0xa5,
    0xea, 0x06, 0x27, 0x4b, 0xf0, 0x2b, 0xaa, 0xb4,
    0x69, 0x86, 0x0a, 0xbd, 0xe5, 0xe6, 0x45, 0xf3,
    0xdd, 0x47, 0x3a, 0x5a, 0xcd, 0xde, 0xec, 0xfc
};
static char expected_tag[] = {
    0x05, 0xb2, 0xb7, 0x4d, 0xb0, 0x66, 0x25, 0x50,
    0x43, 0x5e, 0xf1, 0x90, 0x0e, 0x13, 0x6b, 0x15
};

static void
check_result(const char *name, const char *result, const char *expected, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (result[i] != expected[i]) {
            fprintf(stderr, "AES-GCM test vector failure: %s\n", name);
            exit(1);
        }
    }
}

int
main(int argc, char **argv)
{
    krb5_context context = NULL;
    krb5_keyblock keyblock;
    krb5_key key;
    krb5_data ivec;
    krb5_crypto_iov iov[2];
    unsigned char resultbuf[sizeof(pt) + 100];
    krb5_data result = make_data(resultbuf, sizeof(pt));
    unsigned char tag[sizeof(expected_tag)];

    /* Create the example key. */
    keyblock.magic = KV5M_KEYBLOCK;
    keyblock.enctype = ENCTYPE_AES256_GCM;
    keyblock.length = sizeof(keybytes);
    keyblock.contents = keybytes;
    assert(krb5_k_create_key(context, &keyblock, &key) == 0);

    /* Create the IV */
    ivec.length = sizeof(iv);
    ivec.data = iv;

    /* Example 1. */
    memcpy(resultbuf, pt, sizeof(pt));
    iov[0].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[0].data = result;

    iov[1].flags = KRB5_CRYPTO_TYPE_TRAILER;
    iov[1].data = make_data(tag, sizeof(tag));

    assert(krb5int_aes_gcm_encrypt(key, &ivec, iov, 2) == 0);
    check_result("CT", result.data, expected_ct, sizeof(expected_ct));
    check_result("TAG", (char*)tag, expected_tag, sizeof(expected_tag));

    assert(krb5int_aes_gcm_decrypt(key, &ivec, iov, 2) == 0);
    check_result("PT", result.data, (char*)pt, sizeof(pt));

    printf("All AES-GCM tests passed.\n");
    krb5_k_free_key(context, key);
    return 0;
}
