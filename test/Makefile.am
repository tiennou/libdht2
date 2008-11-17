AM_CFLAGS= \
	-I. -I$(top_srcdir) -I$(top_srcdir)/src -I$(top_srcdir)/compat @CFLAGS@

AM_LDFLAGS= \
	-L$(top_builddir)/src -ldht \
	@LDFLAGS@ -lz

noinst_PROGRAMS = bits_test kad_test dht_test dht_group_test \
    dht_crypto_test irc_proxy dht_storage_test

check_PROGRAMS = bits_test kad_test dht_test dht_group_test \
    dht_crypto_test irc_proxy dht_storage_test

bits_test_SOURCES = bits_test.c
kad_test_SOURCES = kad_test.c
dht_test_SOURCES = dht_test.c
dht_storage_test_SOURCES = dht_storage_test.c
dht_group_test_SOURCES = dht_group_test.c
dht_crypto_test_SOURCES = dht_crypto_test.c
irc_proxy_SOURCES = irc_proxy.c irc_proxy.h

TESTS = bits_test kad_test dht_test dht_storage_test dht_group_test \
	dht_crypto_test

DISTCLEANFILES = *~
