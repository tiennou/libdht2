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
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
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
    return dht_byte_compare(a->key, a->keylen, b->key, b->keylen);
}

SPLAY_PROTOTYPE(dht_keyvaltree, dht_keyvalue, node, kv_compare);
SPLAY_GENERATE(dht_keyvaltree, dht_keyvalue, node, kv_compare);

/*
 * We allocate the whole keyvalue as a single chunk of data.
 */
struct dht_keyvalue *
dht_keyval_new(const  u_char *key,
               size_t keylen,
               const  u_char *val,
               size_t vallen)
{
    size_t totlen = keylen + vallen + sizeof(struct dht_keyvalue);
    char *data = malloc(totlen);
    struct dht_keyvalue *kv;

    if (data == NULL) {
        warn("%s: malloc", __func__);
        return NULL;
    }

    kv = (struct dht_keyvalue *)data;

    kv->key = (void*)kv + sizeof(struct dht_keyvalue);
    kv->keylen = keylen;

    kv->val = kv->key + keylen;
    kv->vallen = vallen;

    memcpy(kv->key, key, keylen);
    memcpy(kv->val, val, vallen);

    evtimer_set(&kv->ev_timeout, dht_keyval_timeout, kv);
    evtimer_set(&kv->ev_refresh, dht_keyval_refresh, kv);

    return kv;
}

void
dht_keyval_free(struct dht_keyvalue *keyval)
{
    evtimer_del(&keyval->ev_timeout);
    evtimer_del(&keyval->ev_refresh);
    if (keyval->parent != NULL) {
        struct dht_keyvalue *tmp;
        tmp = SPLAY_FIND(dht_keyvaltree, &keyval->parent->head, keyval);
        if (tmp != NULL)
            SPLAY_REMOVE(dht_keyvaltree, &keyval->parent->head, tmp);
    }
    free(keyval);
}

void
dht_keyval_print(struct dht_keyvalue *keyvalue)
{
    char *key = calloc(sizeof(char*), keyvalue->keylen);
    char *val = calloc(sizeof(char*), keyvalue->vallen);

    assert(keyvalue != NULL);

    dht_bits_bin2hex(key, keyvalue->key, keyvalue->keylen);
    dht_bits_bin2hex(val, keyvalue->val, keyvalue->vallen);

    fprintf(stderr, "%s=%s\n", key, val);
    free(key);
    free(val);
}

int
dht_storage_insert(struct dht_storage * storage,
                   struct dht_keyvalue *keyval,
                   int                  timeout)
{
    struct dht_keyvalue *tmp;
    struct timeval tv;

    tmp = SPLAY_FIND(dht_keyvaltree, &storage->head, keyval);
    if (tmp != NULL) {
        /* Make sure that the values are the same? */
        if (tmp->vallen != keyval->vallen ||
            dht_byte_compare(tmp->val, tmp->vallen,
                             keyval->val, keyval->vallen)) {
            /* Values are different replace old value */
            SPLAY_REMOVE(dht_keyvaltree, &storage->head, tmp);
            dht_keyval_free(tmp);
        } else {
            /* Values are the same just update current timers */
            return -1;
        }
    }

    keyval->parent = storage;

    SPLAY_INSERT(dht_keyvaltree, &storage->head, keyval);

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
    if (storage->refresh_cb != NULL) {
        timerclear(&tv);
        tv.tv_sec = DHT_STORAGE_KEY_REFRESH;
        evtimer_add(&keyval->ev_refresh, &tv);
    }

    return 0;
}

struct dht_keyvalue *
dht_storage_find(struct dht_storage *storage,
                 const               u_char *key,
                 size_t              keylen)
{
    struct dht_keyvalue tmp;

    tmp.key = (u_char*)key;
    tmp.keylen = keylen;

    return SPLAY_FIND(dht_keyvaltree, &storage->head, &tmp);
}

static void
dht_keyval_timeout(int fd, short what, void *arg)
{
    struct dht_keyvalue *keyval = arg;
    struct dht_storage *storage = keyval->parent;

    assert(SPLAY_FIND(dht_keyvaltree, &storage->head, keyval) == keyval);
    SPLAY_REMOVE(dht_keyvaltree, &storage->head, keyval);

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

/* Function used to regenerate the key from its stored path
 * It'll collect each "??/" subpath into a buffer, then convert
 * it from ASCII to hex.
 */
static u_char *
dht_keyval_key_from_path(const char *path, size_t *keylen)
{
    const char *curr, *next;
    char hexkey[256 + 1] = "";
    u_char *key = NULL;
    size_t keysize = 0;

    assert(path != NULL);
    assert(keylen != NULL);

    /* Initial setup :
     * Have *curr point to the 1st non-'/' character, and *next point on the following '/'.
     * The loop will then extract [curr, next[ and put it in hexkey.
     */
    if (*path == '/') {
        curr = path + 1;
    } else {
        curr = path;
    }
    next = strchr(curr, '/');

    while (next != NULL) {
        char chars[3] = "";

        strlcat(chars, curr, next - curr + 1);

        strlcat(hexkey, chars, sizeof(hexkey));

        keysize += (next - curr) / 2;

        curr = strchr(curr, '/') + 1;
        next = strchr(curr, '/');
    }

    key = calloc(sizeof(key),  keysize);

    dht_bits_hex2bin(key, keysize, hexkey);

    *keylen = keysize;
    return key;
}

/* Function that generates a path given a key/value pair.
 * For key "abcd", it'll generate "61/62/63/64", which is the hexadecimal value of
 * the corresponding ASCII characters.
 */
static char *
dht_keyval_path_from_keyval(struct dht_keyvalue *keyval)
{
    char *path, *hexbuf, *comp, *p;

    assert(keyval != NULL);

    if ((hexbuf = malloc(keyval->keylen * 2 + 1)) == NULL)
        err(1, "%s: malloc", __func__);

    dht_bits_bin2hex(hexbuf, keyval->key, keyval->keylen);
    int hexlen = strlen(hexbuf);
    int pathlen = hexlen + hexlen / 2 + 4; /* hexlen + slashes + val + null */

    if ((path = calloc(pathlen, sizeof(char))) == NULL)
        err(1, "%s: malloc", __func__);

    for (p = hexbuf; p < hexbuf + hexlen; p += 2) {
        /* get the current address component */
        asprintf(&comp, "%c%c/", *p, *(p + 1));
        strlcat(path, comp, pathlen);
        free(comp);
    }
    strlcat(path, "val", pathlen);

    free(hexbuf);
    return path;
}

struct dht_storage *
dht_storage_new(void (*cb)(struct dht_keyvalue *, void *), void *cb_arg)
{
    struct dht_storage *storage = calloc(1, sizeof(struct dht_storage));

    if (storage == NULL)
        return NULL;

    SPLAY_INIT(&storage->head);

    /* We might need to refresh the keys periodically */
    storage->refresh_cb = cb;
    storage->refresh_cb_arg = cb_arg;

    return storage;
}

void
dht_storage_free(struct dht_storage * storage)
{
    struct dht_keyvalue *kv = NULL;
    struct dht_keyvalue *next = NULL;

    for (kv = SPLAY_MIN(dht_keyvaltree, &storage->head);
         kv != NULL;
         kv = next) {
        next = SPLAY_NEXT(dht_keyvaltree, &storage->head, kv);

        SPLAY_REMOVE(dht_keyvaltree, &storage->head, kv);
        dht_keyval_free(kv);
    }
    free(storage);
}

static int
dht_storage_mkdirs(const char *dir)
{
    char getcwdbuf[1024];
    char path[1024];
    const char *p, *s;
    char * component;
    mode_t mode = S_IRWXU | S_IXGRP | S_IRGRP;
    struct stat sb;

    memset(path, 0, sizeof(path));

    /* NULL + 1 because of the offset to strchr */
    for (p = dir; p != NULL + 1; p = strchr(p, '/') + 1) {
        /* get the current path component */
        s = strchr(p + 1, '/');
        /* If no next slash found, fallback on \0,
         * else we found and now points to it, go back */
        s = (s == NULL ? strchr(p + 1, '\0') : s + 1);

        int componentlen = s - p + 1;
        component = calloc(componentlen, sizeof(char));

        DFPRINTF(1,
                 (stderr, "%s: path component size %d\n", __func__,
                  componentlen));

        strlcpy(component, p, componentlen);

        DFPRINTF(1,
                 (stderr, "%s: creating path component %s\n", __func__,
                  component));

        strlcat(path, component, sizeof(path));

        DFPRINTF(1, (stderr, "%s: creating path %s\n", __func__, path));

        if (strcmp(component, "val") == 0) {
            free(component);
            break;
        }

        if (stat(path, &sb) == -1) {
            if (mkdir(path, mode) == -1) {
                warn("%s: %s: mkdir(%s)",
                     __func__,
                     getcwd(getcwdbuf, sizeof(getcwdbuf)), path);
                free(component);
                return -1;
            }
        } else if ((sb.st_mode & S_IFDIR) == 0) {
            warnx("%s: something in the way of directory: %s.",
                  __func__, path);
            free(component);
            return -1;
        }

        free(component);
    }

    return 0;
}

int
dht_storage_store(struct dht_storage *storage, const char *root)
{
    char *path;
    int fd;
    struct dht_keyvalue *keyval;

    if (mkdir(root, S_IRWXU | S_IXGRP | S_IRGRP)) {
        if (errno != EEXIST) {
            warn("%s: mkdir(%s)",
                 __func__,
                 path);
            return -1;
        }
    }

    SPLAY_FOREACH(keyval, dht_keyvaltree, &storage->head) {
        char *key_path = dht_keyval_path_from_keyval(keyval);

        asprintf(&path, "%s/%s", root, key_path);
        free(key_path);

        DFPRINTF(1, (stderr, "%s: creating %s\n", __func__, path));
        dht_storage_mkdirs(path);

        fd = open(path,
                  O_CREAT | O_TRUNC | O_WRONLY,
                  S_IRWXU | S_IXGRP | S_IRGRP);
        if (fd == -1) {
            warn("%s: open", __func__);
            free(path);
            return -1;
        }

        if (write(fd, keyval->val, keyval->vallen) != keyval->vallen) {
            warn("%s: write", __func__);
            free(path);
            close(fd);
            return -1;
        }

        close(fd);
        free(path);
    }

    return 0;
}

int
dht_storage_restore(struct dht_storage *storage, const char *path)
{
    FTS *fts;
    FTSENT *ent;

    char *paths[2];
    u_char *key, *buf, *pos;
    size_t keylen;
    int fd, nbytes, buflen;
    struct dht_keyvalue *keyvalue;

    paths[0] = (char *)path;
    paths[1] = NULL;

    fts = fts_open(paths, FTS_LOGICAL | FTS_NOCHDIR | FTS_NOSTAT, NULL);
    if (fts == NULL) {
        warn("%s: fts_open", __func__);
        return -1;
    }

    while ((ent = fts_read(fts)) != NULL) {
        if ((ent->fts_info & FTS_F) == 0 &&
            strcmp(ent->fts_name, "val") != 0)
            continue;

        key = dht_keyval_key_from_path(ent->fts_path + strlen(
                                           path), &keylen);

        fd = open(ent->fts_accpath, O_RDONLY);
        if (fd == -1) {
            warn("%s: open", __func__);
            return -1;
        }

#define bufstep 128
        buflen = bufstep;
        buf = calloc(buflen, sizeof(char));
        pos = buf;

        while (1) {
            void *tmp;
            nbytes = read(fd, pos, bufstep);
            if (nbytes == -1) {
                warn("%s: read", __func__);
                free(buf);
                close(fd);
                return -1;
            }

            /* We have no more data to read, bail! */
            if (nbytes == 0)
                break;

            /* We hit the end of our buffer */
            if (nbytes != bufstep) {
                /* Because we used less than bufstep bytes, and we need
                 * to know the real size afterward */
                buflen = buflen - bufstep + nbytes;
                continue;
            }

            /* Get more memory to store our data! */
            pos += buflen;
            buflen += bufstep;
            tmp = realloc(buf, buflen);
            if (tmp == NULL) {
                warn("%s: realloc", __func__);
                free(buf);
                close(fd);
                return -1;
            }
            buf = tmp;
#undef bufstep
        }

        keyvalue = dht_keyval_new(key, keylen, buf, buflen);
        /* XXX: We need the timeout here */
        dht_storage_insert(storage, keyvalue, 10);
        free(key);
        free(buf);
        close(fd);
    }

    fts_close(fts);

    return 0;
}

void
dht_storage_print(struct dht_storage *storage)
{
    struct dht_keyvalue *kv = NULL;
    int count = 0;

    SPLAY_FOREACH(kv, dht_keyvaltree, &storage->head) {
        fprintf(stderr, "%d:", count);
        dht_keyval_print(kv);
        count++;
    }
    if (count == 0)
        fprintf(stderr, "No key/value");
}

