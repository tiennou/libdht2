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

#include <ctype.h>
#include <openssl/sha.h>
#include <string.h>

/* Globals */
static char h2btab[] = {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	'a', 'b', 'c', 'd', 'e', 'f'
};


#define nibbletobin(y)	((y) >= 'a' ? 10 + (y) - 'a' : (y) - '0')
#define hextobin(x)	(nibbletobin((x)[0])*16 + nibbletobin((x)[1]))

int
dht_bits_hex2bin(u_char *bin, char *hex, size_t len)
{
	char asc[2];
	int i;

	if (strlen(hex) / 2 < len)
		return (-1);

	for (i = 0; i < len; i++) {
		asc[0] = tolower(hex[2*i]);
		asc[1] = tolower(hex[2*i + 1]);	
		if (!isxdigit(asc[0]) || !isxdigit(asc[1]))
			return (-1);
		bin[i] = hextobin(asc);
	}

	return (i);
}

void
dht_bits_bin2hex(char *hex, u_char *bin, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		hex[i*2 + 0] = h2btab[bin[i] >> 4];
		hex[i*2 + 1] = h2btab[bin[i] & 0xf];
	}
	hex[i*2 + 0] = '\0';
}

/* 
 * Returns the first bit position that differs.  Bits are numbered starting
 * at one.  A return value of zero means that the identifiers were equal.
 *
 *   length: number of octets
 */

static int bit_set[256];
static int bit_set_init;

static
void bit_init()
{
	int i, j;

	bit_set_init = 1;
	for (i = 0; i < 8; i++) {
		int mask = 0x80 >> i;
		for (j = 0; j < mask; ++j)
			bit_set[mask | j] = i;
	}
}

int
dht_bits_compare(u_char *a, u_char *b, size_t length)
{
	int i;

	if (!bit_set_init)
		bit_init();

	for (i = 0; i < length; ++i) {
		u_char diff = a[i] ^ b[i];

		if (diff) {
			int bit = bit_set[diff];
			return (8*i + bit + 1);
		}
	}

	return (0);
}

int
dht_byte_compare(u_char *a, size_t alen, u_char *b, size_t blen)
{
	int i;

	for (i = 0; i < SHA_DIGEST_LENGTH && i < alen && i < blen; ++i) {
		if (a[i] < b[i])
			return (-1);
		if (a[i] > b[i])
			return (1);
	}

	if (alen < blen)
		return (-1);
	if (alen > blen)
		return (1);

	return (0);
}

int
dht_kademlia_compare(u_char *a, u_char *b)
{
	int i;

	for (i = 0; i < SHA_DIGEST_LENGTH; ++i) {
		if (a[i] < b[i])
			return (-1);
		if (a[i] > b[i])
			return (1);
	}

	return (0);
}

u_char *
dht_kademlia_xor(u_char *dst, u_char *a, u_char *b)
{
	int i;

	for (i = 0; i < SHA_DIGEST_LENGTH; ++i) {
		dst[i] = a[i] ^ b[i];
	}
	
	return (dst);
}

u_char *
dht_kademlia_distance(u_char *a, u_char *b)
{
	static u_char diff[2][SHA_DIGEST_LENGTH];
	static int where;
	u_char *p = diff[++where % 2];

	return (dht_kademlia_xor(p, a, b));
}

/*
 * Assumes that dst might be populated already.  This allows us to copy
 * just a prefix and leave the rest for example random.
 */

void
dht_copy_bits(u_char *dst, u_char *src, int bits)
{
	int octets = (bits + 7) / 8;
	int remain = bits % 8;
	int mask = 0xff << (7 - remain);
	
	memcpy(dst, src, octets - 1);

	dst[octets - 1] = (src[octets-1] & mask) | (dst[octets-1] & ~mask);
}

/*
 * Bits are being numbered starting at 0.
 */

int
dht_bit_set(u_char *a, int bit)
{
	int octets = bit / 8;
	int remain = bit % 8;
	int mask = 1 << (7 - remain);

	return ((a[octets] & mask) != 0);
}
