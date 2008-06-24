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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <assert.h>
#include <sha1.h>
#include <assert.h>

#include <event.h>
#include <dnet.h>

#include "dht.h"
#include "dht_kademlia.h"
#include "dht_crypto.gen.h"
#include "dht_crypto.h"

void
Test_One(RSA *key)
{
	const char *message = "Hello you Klotz";
	struct dht_crypto_sig *sig;
	int res;

	fprintf(stderr, "\tTesting signature verification: ");

	sig = dht_crypto_make_sig(key, message, strlen(message) + 1);
	assert(sig != NULL);

	res = dht_crypto_verify_sig(key, sig, message, strlen(message) + 1);
	assert(res != -1);

	fprintf(stderr, "OK\n");
}

void
Test_Two(RSA *mykey, RSA *otherkey)
{
	struct dht_crypto_store *store;
	struct dht_crypto_pkinfo *pkinfo;
	struct dht_pkinfo *internal_pkinfo = NULL;
	struct dht_crypto_sig *sig;
	struct evbuffer *tmp = evbuffer_new();
	extern int debug;

	debug = 2;

	fprintf(stderr, "\tTesting authorization: ");

	store = dht_crypto_authorize_key(otherkey, mykey, 0);
	assert(store != NULL);
	assert(!dht_crypto_store_complete(store));

	dht_crypto_store_marshal(tmp, store);

	fprintf(stderr, "Length: %d ", EVBUFFER_LENGTH(tmp));

	pkinfo = dht_crypto_make_pkinfo(otherkey, 0, "niels");
	assert(pkinfo != NULL);
	assert(!EVTAG_ASSIGN(store, pkinfo, pkinfo));

	evbuffer_drain(tmp, -1);
	dht_crypto_pkinfo_marshal(tmp, pkinfo);

	sig = dht_crypto_make_sig(otherkey,
	    EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));
	assert(!EVTAG_ASSIGN(store, pkinfo_sig, sig));
	assert(!dht_crypto_verify_store(NULL, store));

	dht_crypto_sig_free(sig);

	/* Let's play with our convertors */
	internal_pkinfo = dht_crypto_internalize_pkinfo(pkinfo);
	assert(internal_pkinfo != NULL);
	
	evbuffer_free(tmp);

	fprintf(stderr, "OK\n");
}

int
main(int argc, char **argv)
{
	extern int debug;
	u_char digest[SHA1_DIGESTSIZE];
	RSA *mykey = NULL, *otherkey;

	/* Some simple debugging */
	debug = 1;

	event_init();

	dht_init();

	mykey = dht_crypto_getkey(".tmp.key");
	assert(mykey != NULL);
	dht_crypto_rsa_idkey(mykey, digest, sizeof(digest));
	dht_crypto_rsa_print_id(stderr, "key id", digest);

	Test_One(mykey);

	otherkey = dht_crypto_getkey(".tmp.key.other");
	assert(otherkey != NULL);
	dht_crypto_rsa_idkey(otherkey, digest, sizeof(digest));
	dht_crypto_rsa_print_id(stderr, "key id", digest);

	Test_Two(mykey, otherkey);

	fprintf(stderr, "OK\n");

	exit(0);
}
