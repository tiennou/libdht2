/*
 * Copyright 2005 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Niels Provos.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <assert.h>

#include <event.h>
#include <dnet.h>

#include <CUnit/CUnit.h>

#include "dht.h"
#include "dht_bits.h"
#include "dht_storage.h"
#include "dht_crypto.h"

#define STORAGE_ROOT "storage_test"

extern int debug;

static struct dht_storage *dhs = NULL;

int
dht_storage_test_init(void)
{
    /* Set some reasonable debug level */
    debug = 1;

    event_init();

    dht_init();

    dhs = dht_storage_new(NULL, NULL);

    return dhs == NULL;
}

int
dht_storage_test_cleanup(void)
{
    dht_storage_free(dhs);
    system("rm -Rf " STORAGE_ROOT);
    return 0;
}

/* Private functions */
/*static char *
dht_keyval_path_from_keyval(struct dht_keyvalue *keyval);
static u_char *
dht_keyval_key_from_path(const char *path, size_t *keylen);

void
testUtilitiesPathFromKeyVal(void)
{
    char *path;
    struct dht_keyvalue *kv;

    kv = dht_keyval_new((u_char*)"abcdef", 6, (u_char*)"whatever", 12);
    path = dht_keyval_path_from_keyval(kv);
    CU_ASSERT(path != NULL)

    CU_ASSERT(strcmp(path, "61/62/63/64/65/66/val") == 0);
    dht_keyval_free(kv);
    free(path);
}

void
testUtilitiesKeyValFromPath(void)
{
    char *path = "61/62/63/64/65/66/val";
    u_char *key;
    size_t key_size;

    key = dht_keyval_key_from_path(path, &key_size);

    CU_ASSERT(memcmp(key, "abcdef", key_size) == 0);

    free(key);
}*/

void
testInsertAndFind(void)
{
    const char *key = "lala";
    const char *value = "test";
    struct dht_keyvalue *keyval, *found;

    keyval = dht_keyval_new_char(key, value);
    CU_ASSERT(keyval != NULL);

    CU_ASSERT(dht_storage_insert(dhs, keyval, 300) == 0);

    found = dht_storage_find(dhs, (u_char*)key, strlen(key));
    CU_ASSERT(found == keyval);

    found = dht_storage_find(dhs, (u_char*)key, strlen(key) - 1);
    CU_ASSERT(found == NULL);

    dht_keyval_free(keyval);
}

void
testInsertAndFindDigest(void)
{
    struct dht_keyvalue *keyval, *found;
    char *datap;
    size_t datalen;
    u_char digest[SHA_DIGEST_LENGTH];
    RSA *mykey = NULL;
    BIO *bp = NULL;

    mykey = dht_crypto_getkey(".tmp.key");
    CU_ASSERT(mykey != NULL);
    dht_crypto_rsa_idkey(mykey, digest, sizeof(digest));

    bp = BIO_new(BIO_s_mem());
    CU_ASSERT(bp != NULL);
    i2d_RSAPublicKey_bio(bp, mykey);
    datalen = BIO_get_mem_data(bp, &datap);
    BIO_free(bp);

    keyval = dht_keyval_new(digest, sizeof(digest), (u_char*)datap, datalen);
    CU_ASSERT(keyval != NULL);

    CU_ASSERT(dht_storage_insert(dhs, keyval, 300) == 0);

    found = dht_storage_find(dhs, digest, sizeof(digest));
    CU_ASSERT(found == keyval);

    found = dht_storage_find(dhs, digest, sizeof(digest) - 1);
    CU_ASSERT(found == NULL);
}

void
testStoreAndRestore(void)
{
    struct dht_keyvalue *kv;

    /* Let's recreate it */
    dht_storage_free(dhs);
    dhs = dht_storage_new(NULL, NULL);

    dht_storage_insert(dhs, dht_keyval_new_char("test", "value"), 20);
    dht_storage_insert(dhs, dht_keyval_new_char("blop", "blah"), 20);

    CU_ASSERT_FATAL(dht_storage_store(dhs, STORAGE_ROOT) == 0);

    /* Let's recreate it again */
    dht_storage_free(dhs);
    dhs = dht_storage_new(NULL, NULL);
    CU_ASSERT_FATAL(dhs != NULL);

    CU_ASSERT_FATAL(dht_storage_restore(dhs, STORAGE_ROOT) == 0);

    kv = dht_storage_find(dhs, (u_char*)"test", 4);
    CU_ASSERT_FATAL(kv != NULL);
    CU_ASSERT_FATAL(memcmp(kv->val, "value", kv->vallen) == 0);
    kv = dht_storage_find(dhs, (u_char*)"blop", 4);
    CU_ASSERT_FATAL(kv != NULL);
    CU_ASSERT_FATAL(memcmp(kv->val, "blah", kv->vallen) == 0);
}

void
registerTestSuite(void)
{
    CU_TestInfo tests[] = {
/*        { "keyval-from-path", testUtilitiesKeyValFromPath }, */
/*        { "path-from-keyval", testUtilitiesPathFromKeyVal }, */
        { "insert&find",        testInsertAndFind                     },
        { "insert&find-digest", testInsertAndFindDigest               },
        { "store&restore",      testStoreAndRestore                   },
        CU_TEST_INFO_NULL,
    };
    CU_SuiteInfo suites[] = {
        { "dht_storage_test", dht_storage_test_init,
          dht_storage_test_cleanup, tests },
        CU_SUITE_INFO_NULL,
    };
    CU_ErrorCode err = CU_register_suites(suites);

    if (err != CUE_SUCCESS)
        warnx("got error registering %d", err);
}

