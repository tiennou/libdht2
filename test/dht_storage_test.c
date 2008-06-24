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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <assert.h>
#include <sha1.h>

#include <event.h>
#include <dnet.h>

#include "dht.h"
#include "dht_bits.h"
#include "dht_storage.h"
#include "dht_crypto.h"

void
TestOne(struct dht_storage *dhs)
{
	const char *key = "lala";
	const char *value = "test";
	char *datap;
	size_t datalen;
	struct dht_keyvalue *keyval, *found;
	u_char digest[SHA1_DIGESTSIZE];
	RSA *mykey = NULL;
	BIO *bp = NULL;

	keyval = dht_keyval_new(key, strlen(key), value, strlen(value));
	assert(keyval != NULL);

	assert(dht_insert_keyval(dhs, keyval, 300) != -1);
	assert(dht_keyval_store(dhs, keyval) != -1);

	found = dht_find_keyval(dhs, key, strlen(key));
	assert(found == keyval);

	found = dht_find_keyval(dhs, key, strlen(key) -1 );
	assert(found == NULL);

	mykey = dht_crypto_getkey(".tmp.key");
	assert(mykey != NULL);
	dht_crypto_rsa_idkey(mykey, digest, sizeof(digest));

	bp = BIO_new(BIO_s_mem());
	assert(bp != NULL);
	i2d_RSAPublicKey_bio(bp, mykey);
	datalen = BIO_get_mem_data(bp, &datap);

	keyval = dht_keyval_new(digest, sizeof(digest), datap, datalen);
	assert(keyval != NULL);
	assert(dht_keyval_store(dhs, keyval) != -1);

	dht_keyval_restore(dhs);
}

int
main(int argc, char **argv)
{
	extern int debug;
	struct dht_storage *dhs = NULL;

	/* Set some reasonable debug level */
	debug = 1;

	event_init();

	dht_init();

	mkdir(".tmp", 0744);

	dhs = dht_storage_new(".tmp", NULL, NULL);
	assert(dhs != NULL);

	TestOne(dhs);

	fprintf(stderr, "OK\n");

	exit(0);
}
