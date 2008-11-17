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
#ifndef _DHT_CRYPTO_
#define _DHT_CRYPTO_

#include <openssl/sha.h>

#define RSA_KEY_BITS	1024
#define RSA_KEY_E	37

enum keytype {
	RSA_PRIVATE, RSA_PUBLIC
};

struct dht_pkinfo {
	SPLAY_ENTRY(dht_pkinfo) node;

	u_char digest[SHA_DIGEST_LENGTH];
	RSA *public_key;
	struct dht_crypto_pkinfo *pkinfo;
};

SPLAY_HEAD(dht_pkinfotree, dht_pkinfo);

struct dht_pkinfo_store {
	struct dht_pkinfotree root;
};

int pkinfo_compare(struct dht_pkinfo *a, struct dht_pkinfo *b);
SPLAY_PROTOTYPE(dht_pkinfotree, dht_pkinfo, node, pkinfo_compare);

void	dht_crypto_init();

void	dht_crypto_addrandom(void);

RSA	*dht_crypto_getkey(char *keyname);
void	dht_crypto_rsa_print_id(FILE *fp, char *text, u_char *digest);
RSA	*dht_crypto_rsa_read_key(char *name, enum keytype type);
void	dht_crypto_rsa_write_key(char *name, RSA *key, enum keytype type);
int	dht_crypto_rsa_idkey(RSA *key, u_char *data, size_t size);

struct dht_crypto_sig *
	dht_crypto_make_sig(RSA *key, const u_char *data, size_t datlen);
int	dht_crypto_verify_sig(RSA *key, struct dht_crypto_sig *dcs,
	    const u_char *data, size_t datlen);

struct dht_crypto_store *
	dht_crypto_authorize_key(RSA *other_key, RSA *my_key, int serial);
struct dht_crypto_pkinfo *
	dht_crypto_make_pkinfo(RSA *mykey, int serial, char *name);

int	dht_crypto_verify_store(struct dht_pkinfo_store *store,
	    struct dht_crypto_store *update);

struct dht_pkinfo_store *dht_crypto_pkinfo_store_new();
struct dht_pkinfo *
	dht_crypto_internalize_pkinfo(struct dht_crypto_pkinfo *pkinfo);

#endif /* _DHT_CRYPTO_ */
