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

#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <assert.h>
#include <fcntl.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include <dnet.h>
#include <event.h>

#include "dht.h"
#include "dht_bits.h"
#include "dht_crypto.h"
#include "dht_crypto.gen.h"

int
pkinfo_compare(struct dht_pkinfo *a, struct dht_pkinfo *b)
{
	return (memcmp(a->digest, b->digest, sizeof(a->digest)));
}

SPLAY_GENERATE(dht_pkinfotree, dht_pkinfo, node, pkinfo_compare);

void
dht_crypto_addrandom(void)
{
	extern rand_t *dht_rand;
	u_int32_t tmp[512];
	int i;

	/* Add some randomness */
	for (i = 0; i < 512; i++)
		tmp[i] = rand_uint32(dht_rand);
	RAND_add(tmp, sizeof(tmp), sizeof(tmp));
}

void
dht_crypto_init()
{
	dht_crypto_addrandom();
}

struct dht_pkinfo_store *
dht_crypto_pkinfo_store_new(void)
{
	struct dht_pkinfo_store *store;

	if ((store = calloc(1, sizeof(struct dht_pkinfo_store))) == NULL)
		err(1, "%s: calloc", __func__);

	SPLAY_INIT(&store->root);

	return (store);
}

int
dht_crypto_pkinfo_insert(struct dht_pkinfo_store *store,
    struct dht_pkinfo *pkinfo)
{
	if (SPLAY_FIND(dht_pkinfotree, &store->root, pkinfo) != NULL)
		return (-1);

	assert(SPLAY_INSERT(dht_pkinfotree, &store->root, pkinfo) == NULL);

	return (0);
}

int
dht_crypto_verify_store(struct dht_pkinfo_store *store,
    struct dht_crypto_store *update) 
{
	struct dht_crypto_sig *sig = NULL;
	struct evbuffer *tmp = evbuffer_new();

	if (EVTAG_HAS(update, pkinfo)) {
		struct dht_pkinfo *internal;
		struct dht_crypto_pkinfo *pkinfo;
		uint8_t *pkid;

		if (!EVTAG_HAS(update, pkinfo_sig)) {
			DFPRINTF(2,
			    (stderr, "Missing signature for pkinfo.\n"));
			goto error;
		}

		assert(!EVTAG_GET(update, pkinfo, &pkinfo));
		if ((internal = dht_crypto_internalize_pkinfo(pkinfo)) == NULL)
			goto error;

		assert(!EVTAG_GET(update, pkinfo_sig, &sig));
		assert(!EVTAG_GET(sig, pkid, &pkid));

		if (memcmp(internal->digest, pkid, sizeof(internal->digest))) {
			DFPRINTF(2,
			    (stderr, "Signature from the wrong key.\n"));
			goto error;
		}

		evbuffer_drain(tmp, -1);
		dht_crypto_pkinfo_marshal(tmp, pkinfo);
		if (dht_crypto_verify_sig(internal->public_key, sig,
			EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp)) == -1) {
			DFPRINTF(2,
			    (stderr, "Signature verification failed.\n"));
			goto error;
		}
	}

	/* Verify pkauth part */

	evbuffer_free(tmp);
	return (0);

 error:
	evbuffer_free(tmp);
	return (-1);
}

int
dht_crypto_merge_store(struct dht_pkinfo_store *store,
    struct dht_crypto_store *current,
    struct dht_crypto_store *update)
{
	uint32_t cur_number, up_number;
	struct evbuffer *tmp = evbuffer_new();
	int res = -1;
	assert(tmp != NULL);

	/* We update "current" with "update" */
	if (EVTAG_HAS(update, pkinfo)) {
		int copy = 1;

		if (EVTAG_HAS(current, pkinfo)) {
			struct dht_crypto_pkinfo *pkinfo;
			assert(!EVTAG_GET(current, pkinfo, &pkinfo));
			assert(!EVTAG_GET(pkinfo, serial_number, &cur_number));
			assert(!EVTAG_GET(update, pkinfo, &pkinfo));
			assert(!EVTAG_GET(pkinfo, serial_number, &up_number));

			/* Don't copy if the serial numbers are smaller */
			if (up_number <= cur_number)
				copy = 0;
		}

		if (copy) {
			struct dht_crypto_pkinfo *pkinfo;
			struct dht_pkinfo *in_pkinfo;
			assert(!EVTAG_GET(update, pkinfo, &pkinfo));

			in_pkinfo = dht_crypto_internalize_pkinfo(pkinfo);
			if (in_pkinfo == NULL)
				goto error;

			evbuffer_drain(tmp, -1);
			dht_crypto_pkinfo_marshal(tmp, pkinfo);
		}
	}


	/* We need a store where we can remember public keys */

	res = 0;

 error:
	evbuffer_free(tmp);

	return (res);
}

struct dht_pkinfo *
dht_crypto_internalize_pkinfo(struct dht_crypto_pkinfo *pkinfo)
{
	struct dht_pkinfo *intern;
	uint8_t *bytes;
	uint32_t bytelen;
	BIO *bp = NULL;

	if ((intern = calloc(1, sizeof(struct dht_pkinfo))) == NULL)
		err(1, "%s: calloc", __func__);

	assert(!EVTAG_GET(pkinfo, pk, &bytes, &bytelen));

	/* Convert the bytes into a public key */
	bp = BIO_new(BIO_s_mem());
	assert(bp != NULL);
	BIO_write(bp, bytes, bytelen);
	if (d2i_RSAPublicKey_bio(bp, &intern->public_key) == NULL) {
		/* bad public key? */
		DFPRINTF(1, (stderr, "%s: bad public key\n", __func__));
		BIO_free(bp);
		free(intern);
		return (NULL);
	}
	BIO_free(bp);
	
	dht_crypto_rsa_idkey(intern->public_key,
	    intern->digest, sizeof(intern->digest));

	return (intern);

}

struct dht_crypto_pkinfo *
dht_crypto_make_pkinfo(RSA *mykey, int serial, char *name)
{
	struct dht_crypto_pkinfo *pkinfo = dht_crypto_pkinfo_new();
	uint8_t *datap;
	size_t datalen;
	BIO *bp = NULL;

	if (pkinfo == NULL)
		err(1, "%s: malloc", __func__);

	bp = BIO_new(BIO_s_mem());
	assert(bp != NULL);
	i2d_RSAPublicKey_bio(bp, mykey);
	datalen = BIO_get_mem_data(bp, &datap);

	assert(!EVTAG_ASSIGN(pkinfo, pk, datap, datalen));
	assert(!EVTAG_ASSIGN(pkinfo, serial_number, serial));
	if (name != NULL)
		assert(!EVTAG_ASSIGN(pkinfo, name, name));
	assert(!dht_crypto_pkinfo_complete(pkinfo));

	BIO_free(bp);

	return (pkinfo);
}

struct dht_crypto_store *
dht_crypto_authorize_key(RSA *other_key, RSA *my_key, int serial)
{
	struct dht_crypto_store *dhs = dht_crypto_store_new();
	struct dht_crypto_pkauth *pkauth;
	struct dht_crypto_sig *sig;
	struct evbuffer *tmp = evbuffer_new();
	u_char pkid[SHA_DIGEST_LENGTH];

	if (dhs == NULL || tmp == NULL)
		err(1, "%s: malloc", __func__);

	/* Get the data structure so that we can fill it in */
	assert(!EVTAG_GET(dhs, pkauth, &pkauth));
	dht_crypto_rsa_idkey(other_key, pkid, sizeof(pkid));

	assert(!EVTAG_ASSIGN(pkauth, pkid, pkid));
	assert(!EVTAG_ASSIGN(pkauth, serial_number, serial));
	assert(!EVTAG_ASSIGN(pkauth, may_join, 1));

	dht_crypto_pkauth_marshal(tmp, pkauth);
	sig = dht_crypto_make_sig(my_key,
	    EVBUFFER_DATA(tmp), EVBUFFER_LENGTH(tmp));

	assert(!EVTAG_ASSIGN(dhs, pkauth_sig, sig));

	/* Clean up the allocated memory */
	dht_crypto_sig_free(sig);
	evbuffer_free(tmp);

	return (dhs);
}

struct dht_crypto_sig *
dht_crypto_make_sig(RSA *key, const u_char *data, size_t datlen)
{
	SHA_CTX ctx;
	struct dht_crypto_sig *dcs = NULL;
	u_char digest[SHA_DIGEST_LENGTH], pkid[SHA_DIGEST_LENGTH];
	u_char *sig;
	size_t sigsize;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data, datlen);
	SHA1_Final(digest, &ctx);

	sigsize = RSA_size(key);
	if ((sig = malloc(sigsize)) == NULL)
		return (NULL);

	if (RSA_private_encrypt(sizeof(digest), digest,
		sig, key, RSA_PKCS1_PADDING) == -1)
		goto error;

	if ((dcs = dht_crypto_sig_new()) == NULL)
		goto error;

	dht_crypto_rsa_idkey(key, pkid, sizeof(pkid));

	assert(!EVTAG_ASSIGN(dcs, sig, sig, sigsize));
	assert(!EVTAG_ASSIGN(dcs, pkid, pkid));

	assert(!dht_crypto_sig_complete(dcs));

	free(sig);

	return (dcs);

 error:
	free(sig);
	return (NULL);
}

int
dht_crypto_verify_sig(RSA *key, struct dht_crypto_sig *dcs,
    const u_char *data, size_t datlen)
{
	SHA_CTX ctx;
	u_char digest[SHA_DIGEST_LENGTH];
	u_char verify_pkid[SHA_DIGEST_LENGTH];
	u_char *pkid;
	u_char *sig;
	u_char *hash;
	size_t hashlen;
	uint32_t sigsize, siglen;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data, datlen);
	SHA1_Final(digest, &ctx);

	assert(!EVTAG_GET(dcs, sig, &sig, &sigsize));
	assert(!EVTAG_GET(dcs, pkid, &pkid));

	dht_crypto_rsa_idkey(key, verify_pkid, sizeof(verify_pkid));
	if (memcmp(pkid, verify_pkid, sizeof(verify_pkid)))
		return (-1);

	hashlen = RSA_size(key);
	if ((hash = malloc(hashlen)) == NULL)
		return (-1);

	siglen = RSA_public_decrypt(sigsize, sig, hash, key, RSA_PKCS1_PADDING);

	if (siglen != sizeof(digest)) {
		free(hash);
		return (-1);
	}

	if (memcmp(hash, digest, sizeof(digest))) {
		free(hash);
		return (-1);
	}

	free(hash);

	return (0);
}

RSA *
dht_crypto_getkey(char *keyname)
{
	RSA *srv_key = NULL;

	srv_key = dht_crypto_rsa_read_key(keyname, RSA_PRIVATE);
	if (srv_key == NULL) {
		char tmpname[1024];

		fprintf(stderr, "%s: Generating RSA key...\n", __func__);
		srv_key = RSA_generate_key(RSA_KEY_BITS, RSA_KEY_E,
					       NULL, NULL);
		if (srv_key == NULL)
			errx(1, "RSA_generate_key");

		dht_crypto_rsa_write_key(keyname, srv_key, RSA_PRIVATE);

		strlcpy(tmpname, keyname, sizeof (tmpname));
		strlcat(tmpname, ".pub", sizeof (tmpname));
		dht_crypto_rsa_write_key(tmpname, srv_key, RSA_PUBLIC);
	}

	return (srv_key);
}

void
dht_crypto_rsa_print_id(FILE *fp, char *text, u_char *digest)
{
	char hexdigest[41];

	hexdigest[40] = '\0';

	dht_bits_bin2hex(hexdigest, digest, 20);
	fprintf(fp, "%s: 0x%s\n", text, hexdigest);
}

RSA *
dht_crypto_rsa_read_key(char *name, enum keytype type)
{
	FILE *fp;
	RSA *key;

	if ((fp = fopen(name, "r")) == NULL)
		return (NULL);

	DFPRINTF(1, (stderr, "%s: reading key from %s\n", __func__, name));

	if (type == RSA_PRIVATE)
		key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	else
		key = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);

	if (key == NULL)
		fprintf(stderr, "%s: key in %s corrupt\n", __func__, name);

	fclose(fp);
	return (key);
}

void
dht_crypto_rsa_write_key(char *name, RSA *key, enum keytype type)
{
	FILE *fp;
	int fd;

	DFPRINTF(1, (stderr, "%s: writing key to %s\n", __func__, name));

	fd = open(name, O_WRONLY | O_CREAT | O_TRUNC,
		  type == RSA_PRIVATE ? 0600: 0644);
	if (fd < 0)
		err(1, "open %s failed", name);
		
	fp = fdopen(fd, "w");
	if (fp == NULL )
		err(1, "fdopen");

	if (type == RSA_PRIVATE) {
		if (PEM_write_RSAPrivateKey(fp, key, NULL, NULL, 0,
					    NULL, NULL) == 0)
			errx(1, "PEM_write_RSAPrivateKey");
	} else {
		if (PEM_write_RSAPublicKey(fp, key) == 0)
			errx(1, "PEM_write_RSAPublicKey");
	}
	fclose(fp);
}

int
dht_crypto_rsa_idkey(RSA *key, u_char *data, size_t size)
{
	SHA_CTX ctx;
	int len;
	u_char *tmp;
	u_char digest[20];

	len = BN_num_bytes(key->n);
	if ((tmp = malloc(len)) == NULL) {
		warn("%s: malloc", __func__);
		return (-1);
	}

	if (BN_bn2bin(key->n, tmp) != len) {
		free(tmp);
		return (-1);
	}

	/* Create SHA Id */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, tmp, len);
	SHA1_Final(digest, &ctx);
	free(tmp);

	if (sizeof(digest) < size)
		size = sizeof(digest);
	memcpy(data, digest, size);

	return (size);
}

