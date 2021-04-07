LT_LDFLAGS=$(PLUGIN_LDFLAGS) -module -avoid-version
COMMON_SOURCES =  ../plugin.c ../utils.c ../plugin.h ../utils.h

noinst_LTLIBRARIES = mssql.so ssh.so rsa-dsa.so http-raw.so

mssql_so_SOURCES = mssql.c $(COMMON_SOURCES)
mssql_so_LDFLAGS = $(LT_LDFLAGS) -lssl
mssql_so_CFLAGS = $(PLUGIN_CFLAGS)

ssh_so_SOURCES = ssh.c  $(COMMON_SOURCES)
ssh_so_LDFLAGS = $(LT_LDFLAGS) -lssl -lssh2
ssh_so_CFLAGS =  $(PLUGIN_CFLAGS)

rsa_dsa_so_SOURCES = rsa-dsa.c  $(COMMON_SOURCES)
rsa_dsa_so_LDFLAGS = $(LT_LDFLAGS) -lssl
rsa_dsa_so_CFLAGS =  $(PLUGIN_CFLAGS)

http_raw_so_SOURCES = http-raw.c  $(COMMON_SOURCES)
http_raw_so_LDFLAGS = $(LT_LDFLAGS)
http_raw_so_CFLAGS =  $(PLUGIN_CFLAGS)
