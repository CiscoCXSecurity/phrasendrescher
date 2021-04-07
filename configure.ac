
AC_PREREQ(2.50)

AC_INIT(phrasendrescher, 1.1.1, nico@leidecker.info)

AC_CANONICAL_TARGET

AC_CONFIG_SRCDIR([src/phrasendrescher.c])

AM_INIT_AUTOMAKE

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

AC_HEADER_STDC

SYSTEM_OS=unknown

case $target in
    *-linux*) 
    	SYSTEM_OS=LINUX
    	PHRASENDRESCHER_LDFLAGS="-ldl"
		PLUGIN_LDFLAGS="-shared -lssl -lssh2"
		PLUGIN_CFLAGS="-fPIC";;
    *-darwin*) 
		SYSTEM_OS=MACOS
		PLUGIN_LDFLAGS="-dynamiclib -fno-common -lcrypto -lssl -lssh2"
		PLUGIN_CFLAFS="";;
    *-freebsd*) 
		SYSTEM_OS=FREEBSD
		PLUGIN_LDFLAGS="-shared -lssl -lssh2"
		PLUGIN_CFLAGS="-fPIC";;
    *-netbsd*) 
		SYSTEM_OS=NETBSD
		PLUGIN_LDFLAGS="-shared -lssl -lssh2"
		PLUGIN_CFLAGS="-fPIC";;
    *-openbsd*) 
		SYSTEM_OS=NETBSD
		PLUGIN_LDFLAGS="-shared -lssl -lssh2"
		PLUGIN_CFLAGS="-fPIC";;
esac


AC_ARG_WITH(plugins, [--with-plugins compile plugins], build_plugins=true)

if test $build_plugins = true
then
	AC_CHECK_LIB(ssh2, libssh2_userauth_list, [], [
			AC_MSG_ERROR(["Error! You need to have libssh2 or use --with-libssl"])
		])

	if test "$SYSTEM_OS" = "MACOS"
	then
		SSL_LIB="crypto"
	else
		SSL_LIB="ssl"
	fi

	AC_CHECK_LIB(${SSL_LIB}, PEM_read_PrivateKey, [], [
			echo "Error! You need to have lib$SSL_LIB"
			exit
		])
else
	echo "#########################################################"
	echo "#  not building plugins                                 #"
	echo "#  (use --with-plugins if you want to build plugins)    #"
	echo "#########################################################"
fi

AC_SUBST(PLUGIN_LDFLAGS)
AC_SUBST(PLUGIN_CFLAGS)
AM_CONDITIONAL([BUILD_PLUGINS], [test $build_plugins = true])

AC_SUBST(PHRASENDRESCHER_LDFLAGS)

AC_OUTPUT(Makefile src/Makefile src/plugins/Makefile)
