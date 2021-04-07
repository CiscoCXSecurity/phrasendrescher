EXTRA_DIST = plugins/README
if BUILD_PLUGINS
SUBDIRS = plugins
endif
pdprgdir=$(prefix)/bin
pdprg_PROGRAMS=pd
pd_LDFLAGS=$(PHRASENDRESCHER_LDFLAGS)
pd_CFLAGS=-Wall -O2
pd_SOURCES=phrasendrescher.c worker.c utils.c source.c dictionary.c incremental.c rewriter.c rules.c plugin.c \
			phrasendrescher.h worker.h utils.h source.h dictionary.h incremental.h rewriter.h rules.h plugin.h
