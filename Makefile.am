AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = .

EXTRA_DIST = dht_group_message.rpc dht_crypto.rpc

lib_LTLIBRARIES = libdht.la

BUILT_SOURCES = dht_group_message.gen.c dht_group_message.gen.c \
	dht_crypto.gen.c dht_crypto.gen.h
libdht_la_SOURCES = dht_bits.c dht_bits.h dht_kademlia.c dht_kademlia.h \
	dht.c dht.h dht_storage.c dht_storage.h dht_group.c dht_group.h \
	dht_group_message.gen.c dht_group_message.gen.h dht_crypto.c \
	dht_crypto.gen.c dht_crypto.gen.h dht_irc_proxy.c dht_irc_proxy.h
libdht_la_LIBADD = @LIBOBJS@
libdht_la_LDFLAGS = -version-info 0:1:0

include_HEADERS = dht.h

CFLAGS = -Wall -O0 -g -DDEBUG
INCLUDES = -I$(top_srcdir)/compat @EVENTINC@ @DNETINC@ @ZINC@ @SSLINC@

man_MANS = dht.3

noinst_PROGRAMS = bits_test kad_test dht_test dht_group_test dht_crypto_test \
	irc_proxy dht_storage_test
bits_test_SOURCES = test/bits_test.c
bits_test_INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @ZINC@ @SSLINC@
bits_test_LDADD = -L$(top_buildir) -ldht @EVENTLIB@ @DNETLIB@ @ZLIB@ @SSLLIB@
kad_test_SOURCES = test/kad_test.c
kad_test_INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @ZINC@ @SSLINC@
kad_test_LDADD = -L$(top_buildir) -ldht @EVENTLIB@ @DNETLIB@ @ZLIB@ @SSLLIB@
dht_test_SOURCES = test/dht_test.c
dht_test_INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @ZINC@ @SSLINC@
dht_test_LDADD = -L$(top_buildir) -ldht @EVENTLIB@ @DNETLIB@ @ZLIB@ @SSLLIB@
dht_storage_test_SOURCES = test/dht_storage_test.c
dht_storage_test_INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @ZINC@ @SSLINC@
dht_storage_test_LDADD = -L$(top_buildir) -ldht @EVENTLIB@ @DNETLIB@ @ZLIB@ @SSLLIB@
dht_group_test_SOURCES = test/dht_group_test.c
dht_group_test_INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @ZINC@ @SSLINC@
dht_group_test_LDADD = -L$(top_buildir) -ldht @EVENTLIB@ @DNETLIB@ @ZLIB@ @SSLLIB@
dht_crypto_test_SOURCES = test/dht_crypto_test.c
dht_crypto_test_INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @ZINC@ @SSLINC@
dht_crypto_test_LDADD = -L$(top_buildir) -ldht @EVENTLIB@ @DNETLIB@ @ZLIB@ @SSLLIB@
irc_proxy_SOURCES = test/irc_proxy.c test/irc_proxy.h
irc_proxy_INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @ZINC@ @SSLINC@
irc_proxy_LDADD = -L$(top_buildir) -ldht @EVENTLIB@ @DNETLIB@ @ZLIB@ @SSLLIB@

dht_group_message.gen.c dht_group_message.gen.h: dht_group_message.rpc
	event_rpcgen.py dht_group_message.rpc

dht_crypto.gen.c dht_crypto.gen.h: dht_crypto.rpc
	event_rpcgen.py dht_crypto.rpc

DISTCLEANFILES = *~ test/*~
