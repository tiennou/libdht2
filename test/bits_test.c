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

#include <stdlib.h>
#include <stdio.h>
#include <err.h>

#include "dht_bits.h"

#define TEST(a,b) do { \
	if ((a) != (b)) \
		errx(1, "Failed: %s == %s", #a, #b); \
} while (0)

int
SimpleTest(void)
{
	u_char a[] = { 0xaa, 0xbb, 0xcc, 0xdd };
	u_char b[] = { 0xaa, 0xbb, 0xcc, 0xfd };
	int i, res;

	for (i = 0; i < 3; i++) {
		res = dht_bits_compare(a, b, i + 1);
		if (res != 0)
			errx(1, "%s: dht_bits_compare: %d (%d)", 
			    __func__, res, i);
	}

	res = dht_bits_compare(a, b, sizeof(a));
	if (res != 27)
		errx(1, "%s: dht_bits_compare: %d", __func__, res);

	TEST(dht_bit_set(a, 0), 1);
	TEST(dht_bit_set(a, 1), 0);
	TEST(dht_bit_set(a, 2), 1);
	TEST(dht_bit_set(a, 3), 0);
	TEST(dht_bit_set(a, 4), 1);
	TEST(dht_bit_set(a, 5), 0);
	TEST(dht_bit_set(a, 6), 1);
	TEST(dht_bit_set(a, 7), 0);
	TEST(dht_bit_set(a, 8), 1);
	TEST(dht_bit_set(a, 9), 0);
	TEST(dht_bit_set(a,10), 1);
	TEST(dht_bit_set(a,11), 1);
	TEST(dht_bit_set(a,12), 1);
	TEST(dht_bit_set(a,13), 0);
	TEST(dht_bit_set(a,14), 1);
	TEST(dht_bit_set(a,15), 1);

	return (0);
}

int
main(int argc, char **argv)
{
	SimpleTest();

	fprintf(stderr, "OK\n");

	exit(0);
}
