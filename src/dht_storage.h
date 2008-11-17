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

#ifndef _DHT_STORAGE_
#define _DHT_STORAGE_

struct dht_storage;

#define DHT_STORAGE_KEY_REFRESH		3600

struct dht_keyvalue {
	SPLAY_ENTRY(dht_keyvalue) node;

	u_char *key;
	size_t keylen;

	u_char *val;
	size_t vallen;

	struct dht_storage *parent;
	struct event ev_timeout;
	struct event ev_refresh;
};

struct dht_storage {
	SPLAY_HEAD(dht_keyvaltree, dht_keyvalue) head;

	const char *dir;	/* root of where we persist stuff */

	void (*refresh_cb)(struct dht_keyvalue *, void *);
	void *refresh_cb_arg;
};


/* Prototypes */

struct dht_storage  *	dht_storage_new(
			    const char *root,
			    void (*cb)(struct dht_keyvalue *, void *),
			    void *cb_arg);
struct dht_keyvalue *	dht_keyval_new(const u_char *key, size_t keylen,
			    const u_char *val, size_t vallen);
int			dht_insert_keyval(struct dht_storage *head,
			    struct dht_keyvalue *keyval, int timeout);
struct dht_keyvalue *	dht_find_keyval(struct dht_storage *head,
			    const u_char *key, size_t keylen);
void			dht_keyval_free(struct dht_keyvalue *keyval);

/* Stores the value on disk */
int			dht_keyval_store(struct dht_storage *head,
			    struct dht_keyvalue *keyval);

int			dht_keyval_restore(struct dht_storage *head);

#endif /* _DHT_STORAGE_ */
