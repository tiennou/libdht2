AM_CFLAGS= \
	-I. -I$(top_srcdir) -I$(top_srcdir)/compat

EXTRA_DIST = dht_group_message.rpc dht_crypto.rpc

lib_LTLIBRARIES = libdht.la

BUILT_SOURCES = dht_group_message.gen.c dht_group_message.gen.c \
	dht_crypto.gen.c dht_crypto.gen.h
libdht_la_SOURCES = dht_bits.c dht_bits.h dht_kademlia.c dht_kademlia.h \
	dht.c dht.h dht_storage.c dht_storage.h dht_group.c dht_group.h \
	dht_group_message.gen.c dht_group_message.gen.h dht_crypto.c \
	dht_crypto.gen.c dht_crypto.gen.h dht_irc_proxy.c dht_irc_proxy.h
libdht_la_LDFLAGS = -version-info 0:1:0

include_HEADERS = dht.h

libdht_la_MANS = dht.3

dht_group_message.gen.c dht_group_message.gen.h: dht_group_message.rpc
	event_rpcgen.py dht_group_message.rpc

dht_crypto.gen.c dht_crypto.gen.h: dht_crypto.rpc
	event_rpcgen.py dht_crypto.rpc

CLEANFILES = dht_group_message.gen.c dht_group_message.gen.h dht_crypto.gen.c \
	dht_crypto.gen.h

DISTCLEANFILES = *~
