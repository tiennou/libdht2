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
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/time.h>

#include <fcntl.h>
#include <fts.h>
#include <sha1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <assert.h>
#include <unistd.h>

#include <dnet.h>
#include <event.h>

#include "dht.h"
#include "dht_bits.h"
#include "dht_storage.h"

/* Prototypes */
static void dht_keyval_timeout(int fd, short what, void *arg);
static void dht_keyval_refresh(int fd, short what, void *arg);

static int
kv_compare(struct dht_keyvalue *a, struct dht_keyvalue *b)
{
	return (dht_byte_compare(a->key, a->keylen, b->key, b->keylen));
}

SPLAY_PROTOTYPE(dht_keyvaltree, dht_keyvalue, node, kv_compare);
SPLAY_GENERATE(dht_keyvaltree, dht_keyvalue, node, kv_compare);

struct dht_storage *
dht_storage_new(const char *root,
    void (*cb)(struct dht_keyvalue *, void *), void *cb_arg)
{
	struct dht_storage *head = calloc(1, sizeof(struct dht_storage));
	if (head == NULL)
		return (NULL);

	SPLAY_INIT(&head->head);

	/* Root of where we store stuff */
	head->dir = root;

	/* We might need to refresh the keys periodically */
	head->refresh_cb = cb;
	head->refresh_cb_arg = cb_arg;

	return (head);
}

/*
 * We allocate the whole keyvalue as a single chunk of data.
 */

struct dht_keyvalue *
dht_keyval_new(const u_char *key, size_t keylen,
    const u_char *val, size_t vallen)
{
	size_t totlen = keylen + vallen + sizeof(struct dht_keyvalue);
	u_char *data = malloc(totlen);
	struct dht_keyvalue *kv;

	if (data == NULL) {
		warn("%s: malloc", __func__);
		return (NULL);
	}

	kv = (struct dht_keyvalue *)data;

	kv->key = (u_char *)(kv + 1);
	kv->keylen = keylen;

	kv->val = kv->key + keylen;
	kv->vallen = vallen;

	memcpy(kv->key, key, keylen);
	memcpy(kv->val, val, vallen);
	
	evtimer_set(&kv->ev_timeout, dht_keyval_timeout, kv);
	evtimer_set(&kv->ev_refresh, dht_keyval_refresh, kv);

	return (kv);
}

void
dht_keyval_free(struct dht_keyvalue *keyval)
{
	evtimer_del(&keyval->ev_timeout);
	evtimer_del(&keyval->ev_refresh);
	free(keyval);
}

int
dht_insert_keyval(struct dht_storage *head, struct dht_keyvalue *keyval,
    int timeout)
{
	struct dht_keyvalue *tmp;
	struct timeval tv;

	tmp = SPLAY_FIND(dht_keyvaltree, &head->head, keyval);
	if (tmp != NULL) {
		/* Make sure that the values are the same? */
		if (tmp->vallen != keyval->vallen ||
		    dht_byte_compare(tmp->val, tmp->vallen,
			keyval->val, keyval->vallen)) {
			/* Values are different replace old value */
			SPLAY_REMOVE(dht_keyvaltree, &head->head, tmp);
			dht_keyval_free(tmp);
		} else {
			/* Values are the same just update current timers */
			return (-1);
		}
	}

	keyval->parent = head;

	SPLAY_INSERT(dht_keyvaltree, &head->head, keyval);

	/* Set the required timeout */
	if (timeout > 0) {
		timerclear(&tv);
		tv.tv_sec = timeout;
		evtimer_add(&keyval->ev_timeout, &tv);
	}

	/*
	 * Schedule refreshs only if we know how to handle them.  That
	 * means that the callback needs to reinsert the values into
	 * the DHT.
	 */
	if (head->refresh_cb != NULL) {
		timerclear(&tv);
		tv.tv_sec = DHT_STORAGE_KEY_REFRESH;
		evtimer_add(&keyval->ev_refresh, &tv);
	}

	return (0);
}

struct dht_keyvalue *
dht_find_keyval(struct dht_storage *head, const u_char *key, size_t keylen)
{
	struct dht_keyvalue tmp;

	tmp.key = (u_char *)key;
	tmp.keylen = keylen;

	return (SPLAY_FIND(dht_keyvaltree, &head->head, &tmp));
}

static void
dht_keyval_timeout(int fd, short what, void *arg)
{
	struct dht_keyvalue *keyval = arg;
	struct dht_storage *head = keyval->parent;

	assert(SPLAY_FIND(dht_keyvaltree, &head->head, keyval) == keyval);
	SPLAY_REMOVE(dht_keyvaltree, &head->head, keyval);

	DFPRINTF(1, (stderr, "%s: expiring %p\n", __func__, keyval));
	
	dht_keyval_free(keyval);
}

static void
dht_keyval_refresh(int fd, short what, void *arg)
{
	struct dht_keyvalue *keyval = arg;
	struct dht_storage *head = keyval->parent;
	struct timeval tv;

	/* Kick of the refresh */
	(head->refresh_cb)(keyval, head->refresh_cb_arg);

	timerclear(&tv);
	tv.tv_sec = DHT_STORAGE_KEY_REFRESH;
	evtimer_add(&keyval->ev_refresh, &tv);
}

static int
dht_keyval_chmkdir_one(const char *component)
{
	static char getcwdbuf[1024];
	mode_t mode = S_IRUSR|S_IWUSR|S_IXUSR|S_IXGRP|S_IRGRP;

	struct stat sb;
	if (stat(component, &sb) == -1) {
		if (mkdir(component, mode) == -1) {
			warn("%s: %s: mkdir(%s)",
			    __func__,
			    getcwd(getcwdbuf, sizeof(getcwdbuf)), component);
			return (-1);
		}
	} else if ((sb.st_mode & S_IFDIR) == 0) {
		warnx("%s: something in the way of directory: %s.",
		    __func__, component);
		return (-1);
	}
	if (chdir(component) == -1) {
		warn("%s: %s: chdir(%s)",
		    __func__, getcwd(getcwdbuf, sizeof(getcwdbuf)), component);
		return (-1);
	}

	return (0);
}

char *
dht_keyval_chmkdir(const char *dir, const char *address)
{
	static char path[1024];
	char comp[3];
	const char *p, *end = address + strlen(address);
	int old_fd, res = -1;

	/* Remember our old directory */
	old_fd = open(".", O_RDONLY, 0);
	if (old_fd == -1)
		err(1, "%s: open", __func__);

	if (chdir(dir) == -1) {
		warn("%s: chdir(%s)", __func__, dir);
		goto out;
	}

	strlcpy(path, dir, sizeof(path));

	for (p = address; p < end; p +=2) {
		/* get the current address component */
		strlcpy(comp, p, sizeof(comp));
		if (dht_keyval_chmkdir_one(comp) == -1)
			goto out;

		strlcat(path, "/", sizeof(path));
		strlcat(path, comp, sizeof(path));
	} 

	res = 0;

 out:

	if (fchdir(old_fd) == -1)
		err(1, "%s: fchdir", __func__);
	close(old_fd);

	return (res == -1 ? NULL : path);
}

int
dht_keyval_store(struct dht_storage *head, struct dht_keyvalue *keyval)
{
	static char filename[1024];
	char *path;
	char *hexbuf;
	int fd;

	if ((hexbuf = malloc(keyval->keylen * 2 + 1)) == NULL)
		err(1, "%s: malloc", __func__);

	dht_bits_bin2hex(hexbuf, keyval->key, keyval->keylen);
	if ((path = dht_keyval_chmkdir(head->dir, hexbuf)) == NULL)
		return (-1);

	free(hexbuf);

	snprintf(filename, sizeof(filename), "%s/val", path);
	DFPRINTF(1, (stderr, "%s: creating %s\n", __func__, filename));

	fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY);
	if (fd == -1) {
		warn("%s: open", __func__);
		return (-1);
	}

	if (write(fd, keyval->val, keyval->vallen) != keyval->vallen) {
		warn("%s: write", __func__);
		close(fd);
		return (-1);
	}

	close(fd);

	return (0);
}

int
dht_keyval_restore(struct dht_storage *head)
{
	FTS *fts;
	FTSENT *ent;
	char *paths[2];

	paths[0] = (char *)head->dir;
	paths[1] = NULL;

	fts = fts_open(paths, FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		warn("%s: fts_open", __func__);
		return (-1);
	}

	while ((ent = fts_read(fts)) != NULL) {
		if ((ent->fts_info & FTS_F) == 0)
			continue;

		fprintf(stderr, "%s: %s\n", ent->fts_path, ent->fts_name);
	}

	fts_close(fts);

	return (0);
}
