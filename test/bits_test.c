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

#include <CUnit/CUnit.h>

#include "dht_bits.h"

int
bits_test_init(void)
{
    return 0;
}

int
bits_test_cleanup(void)
{
    return 0;
}

void
bits_test_one(void)
{
    u_char a[] = { 0xaa, 0xbb, 0xcc, 0xdd };
    u_char b[] = { 0xaa, 0xbb, 0xcc, 0xfd };
    int i;

    for (i = 0; i < 3; i++) {
        CU_ASSERT(dht_bits_compare(a, b, i + 1) == 0)
    }

    CU_ASSERT(dht_bits_compare(a, b, sizeof(a)) == 27)

    CU_ASSERT(dht_bit_set(a, 0) == 1);
    CU_ASSERT(dht_bit_set(a, 1) == 0);
    CU_ASSERT(dht_bit_set(a, 2) == 1);
    CU_ASSERT(dht_bit_set(a, 3) == 0);
    CU_ASSERT(dht_bit_set(a, 4) == 1);
    CU_ASSERT(dht_bit_set(a, 5) == 0);
    CU_ASSERT(dht_bit_set(a, 6) == 1);
    CU_ASSERT(dht_bit_set(a, 7) == 0);
    CU_ASSERT(dht_bit_set(a, 8) == 1);
    CU_ASSERT(dht_bit_set(a, 9) == 0);
    CU_ASSERT(dht_bit_set(a, 10) == 1);
    CU_ASSERT(dht_bit_set(a, 11) == 1);
    CU_ASSERT(dht_bit_set(a, 12) == 1);
    CU_ASSERT(dht_bit_set(a, 13) == 0);
    CU_ASSERT(dht_bit_set(a, 14) == 1);
    CU_ASSERT(dht_bit_set(a, 15) == 1);
}

void
registerTestSuite(void)
{
    CU_TestInfo tests[] = {
        { "test1", bits_test_one },
        CU_TEST_INFO_NULL,
    };
    CU_SuiteInfo suites[] = {
        { "bits_test", bits_test_init, bits_test_cleanup, tests },
        CU_SUITE_INFO_NULL,
    };
    CU_ErrorCode err = CU_register_suites(suites);

    if (err != CUE_SUCCESS)
        warnx("got error registering %d", err);
}

