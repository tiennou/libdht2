AM_CFLAGS= \
	-I. -I$(top_srcdir) -I$(top_srcdir)/src -I$(top_srcdir)/compat @CFLAGS@

AM_LDFLAGS= \
	-L$(top_builddir)/src -ldht \
	@LDFLAGS@ -lz

if HAVE_LIBCUNIT
noinst_PROGRAMS = bits_test dht_group_test dht_crypto_test \
	dht_storage_test dht_test irc_proxy kad_test

#check_PROGRAMS = bits_test dht_group_test dht_crypto_test \
#	dht_storage_test dht_test kad_test

TESTS = bits_test dht_group_test dht_crypto_test \
	dht_test dht_storage_test kad_test

bits_test_SOURCES = bits_test.c test_harness.c
bits_test_LDADD = -lcunit

dht_group_test_SOURCES = dht_group_test.c test_harness.c
dht_group_test_LDADD = -lcunit

dht_crypto_test_SOURCES = dht_crypto_test.c test_harness.c
dht_crypto_test_LDADD = -lcunit

dht_storage_test_SOURCES = dht_storage_test.c test_harness.c
dht_storage_test_LDADD = -lcunit

dht_test_SOURCES = dht_test.c

kad_test_SOURCES = kad_test.c

irc_proxy_SOURCES = irc_proxy.c irc_proxy.h

endif

DISTCLEANFILES = *~
