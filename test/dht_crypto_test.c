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

#include <openssl/rsa.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <assert.h>
#include <openssl/sha.h>
#include <assert.h>

#include <event.h>
#include <dnet.h>

#include <CUnit/CUnit.h>

#include "dht.h"
#include "dht_kademlia.h"
#include "dht_crypto.gen.h"
#include "dht_crypto.h"

#define KEYNAME ".tmp.key"
#define OTHER_KEYNAME ".tmp.key.other"

extern int debug;

int
dht_crypto_test_init(void)
{
    event_init();

    dht_init();

    return 0;
}

int
dht_crypto_test_cleanup(void)
{
    unlink(KEYNAME);
    unlink(OTHER_KEYNAME);
    return 0;
}

void
dht_crypto_test_signature_verification(void)
{
    RSA *key = dht_crypto_getkey(KEYNAME);
    const char *message = "Hello you Klotz";
    struct dht_crypto_sig *sig;
    int res;

    sig = dht_crypto_make_sig(key, (u_char*)message, strlen(message) + 1);
    CU_ASSERT_PTR_NOT_NULL(sig);

    res = dht_crypto_verify_sig(key, sig, (u_char*)message, strlen(
                                    message) + 1);
    CU_ASSERT(res == 0);

    RSA_free(key);
}

void
dht_crypto_test_authorization(void)
{
    RSA *mykey = dht_crypto_getkey(KEYNAME);
    RSA *otherkey = dht_crypto_getkey(OTHER_KEYNAME);
    struct dht_crypto_store *store;
    struct dht_crypto_pkinfo *pkinfo;
    struct dht_pkinfo *internal_pkinfo = NULL;
    struct dht_crypto_sig *sig;
    struct evbuffer *tmp = evbuffer_new();
    extern int debug;

    debug = 2;

    store = dht_crypto_authorize_key(otherkey, mykey, 0);
    CU_ASSERT_PTR_NOT_NULL(store);
    CU_ASSERT(dht_crypto_store_complete(store) == 0);

    dht_crypto_store_marshal(tmp, store);

    pkinfo = dht_crypto_make_pkinfo(otherkey, 0, "niels");
    CU_ASSERT_PTR_NOT_NULL(pkinfo);
    CU_ASSERT(EVTAG_ASSIGN(store, pkinfo, pkinfo) == 0);

    evbuffer_drain(tmp, -1);
    dht_crypto_pkinfo_marshal(tmp, pkinfo);

    sig = dht_crypto_make_sig(otherkey,
                              EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));
    CU_ASSERT(EVTAG_ASSIGN(store, pkinfo_sig, sig) == 0);
    CU_ASSERT(dht_crypto_verify_store(NULL, store) == 0);

    dht_crypto_sig_free(sig);

    /* Let's play with our convertors */
    internal_pkinfo = dht_crypto_internalize_pkinfo(pkinfo);
    CU_ASSERT_PTR_NOT_NULL(internal_pkinfo);

    evbuffer_free(tmp);
    RSA_free(mykey);
    RSA_free(otherkey);
}

void
registerTestSuite(void)
{
    CU_TestInfo tests[] = {
        { "sigverification", dht_crypto_test_signature_verification     },
        { "authorization",   dht_crypto_test_authorization              },
        CU_TEST_INFO_NULL,
    };
    CU_SuiteInfo suites[] = {
        { "dht_crypto_test", dht_crypto_test_init, dht_crypto_test_cleanup,
          tests },
        CU_SUITE_INFO_NULL,
    };
    CU_ErrorCode err = CU_register_suites(suites);

    if (err != CUE_SUCCESS)
        warnx("got error registering %d", err);
}

