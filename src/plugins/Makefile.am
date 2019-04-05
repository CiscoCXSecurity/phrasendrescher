LT_LDFLAGS=$(PLUGIN_LDFLAGS) -module  -avoid-version -shrext .pd -export-dynamic
COMMON_SOURCES =  ../plugin.c ../utils.c ../plugin.h ../utils.h

pkglib_LTLIBRARIES = mssql.la ssh.la pkey.la enc-file.la http-raw.la

mssql_la_SOURCES = mssql.c $(COMMON_SOURCES)
mssql_la_LDFLAGS = $(LT_LDFLAGS) -lssl
mssql_la_CFLAGS = $(PLUGIN_CFLAGS)

ssh_la_SOURCES = ssh.c  $(COMMON_SOURCES)
ssh_la_LDFLAGS = $(LT_LDFLAGS) -lssl -lssh2
ssh_la_CFLAGS =  $(PLUGIN_CFLAGS)

pkey_la_SOURCES = pkey.c  $(COMMON_SOURCES)
pkey_la_LDFLAGS = $(LT_LDFLAGS) -lssl
pkey_la_CFLAGS =  $(PLUGIN_CFLAGS)

enc_file_la_SOURCES = enc-file.c  $(COMMON_SOURCES)
enc_file_la_LDFLAGS = $(LT_LDFLAGS) -lgpgme
enc_file_la_CFLAGS =  $(PLUGIN_CFLAGS)

http_raw_la_SOURCES = http-raw.c  $(COMMON_SOURCES)
http_raw_la_LDFLAGS = $(LT_LDFLAGS)
http_raw_la_CFLAGS =  $(PLUGIN_CFLAGS)
