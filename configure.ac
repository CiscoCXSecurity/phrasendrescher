
AC_PREREQ(2.50)

AC_INIT(phrasendrescher, 1.2.2c, nico@leidecker.info)

AC_CANONICAL_TARGET

AC_CONFIG_SRCDIR([src/phrasendrescher.c])


AM_INIT_AUTOMAKE

AC_PROG_CC
AM_PROG_CC_C_O

#AC_PROG_LIBTOOL

LT_INIT([shared,dlopen])
AC_SUBST([LIBTOOL_DEPS])

AC_HEADER_STDC

SYSTEM_OS=unknown

case $target in
    *-linux*) 
    		SYSTEM_OS=LINUX		
    		PHRASENDRESCHER_CFLAGS="-ldl -DLINUX"
		PHRASENDRESCHER_LDFLAGS="-ldl"
		PLUGIN_LDFLAGS="-shared -lssl -lssh2 -lcrypto -lgpgme"
		PLUGIN_CFLAGS="-DLINUX -fPIC";;
    *-darwin*)
		SYSTEM_OS=MACOS
    		PHRASENDRESCHER_CFLAGS="-ldl -DMACOS"
		PLUGIN_LDFLAGS="-dynamiclib -fno-common -lcrypto -lssl -lssh2 -lgpgme"
		PLUGIN_CFLAGS="-DMACOS";;
    *-freebsd*) 
		SYSTEM_OS=FREEBSD
    		PHRASENDRESCHER_CFLAGS="-ldl -DFREEBSD"
		PLUGIN_LDFLAGS="-shared -lssl -lssh2 -lgpgme"
		PLUGIN_CFLAGS="-DFREEBSD -fPIC";;
    *-netbsd*) 
		SYSTEM_OS=NETBSD
    		PHRASENDRESCHER_CFLAGS="-ldl -DNETBSD"
		PLUGIN_LDFLAGS="-shared -lssl -lssh2 -lgpgme"
		PLUGIN_CFLAGS="-DNETBSD -fPIC";;
    *-openbsd*) 
		SYSTEM_OS=OPENBSD
    		PHRASENDRESCHER_CFLAGS="-ldl -DOPENBSD"
		PLUGIN_LDFLAGS="-shared -lssl -lssh2 -lgpgme"
		PLUGIN_CFLAGS="-DOPENBSD -fPIC";;
esac

AC_ARG_WITH(fixed-plugin-dir, [--with-fixed-plugin-dir=DIR], AC_DEFINE_UNQUOTED(FIXED_PLUGIN_DIR,"${withval}"))

AC_ARG_WITH(plugins, [--with-plugins compile plugins], build_plugins="true")

if test "$build_plugins" = "true" 
then
	AC_CHECK_LIB(ssh2, libssh2_userauth_list, [], [
			AC_MSG_ERROR(["Error! You need to have libssh2 or use --with-libssh2"])
		])

	if test "$SYSTEM_OS" = "MACOS" 
	then
		SSL_LIB="crypto"
	else
		SSL_LIB="ssl"
	fi

	AC_CHECK_LIB(crypto, CRYPTO_new_ex_data, [], [AC_MSG_ERROR(["Error! You need to have library 'crypto' installed"])])
	FOUND_SSL_LIB="no"
	AC_CHECK_LIB(ssl, OPENSSL_init_ssl, [FOUND_SSL_LIB="yes"])
	AC_CHECK_LIB(ssl, SSL_library_init, [FOUND_SSL_LIB="yes"])
	AS_IF([test "x$FOUND_SSL_LIB" = xno], [AC_MSG_ERROR([Error! You need to have lib$SSL_LIB installed])])

	#AC_CHECK_LIB([${SSL_LIB}], [SSL_library_init], [], [
	#		AC_MSG_ERROR(["Error! You need to have lib$SSL_LIB installed"])
	#	])
	
	AC_CHECK_LIB([gpgme], [gpgme_check_version], [], [
			AC_MSG_ERROR(["Error! You need to have libgpgme installed"])
		])
	AC_SYS_LARGEFILE
else
	echo "#########################################################"
	echo "#  not building plugins                                 #"
	echo "#  (use --with-plugins if you want to build plugins)    #"
	echo "#########################################################"
fi

AC_SUBST(PLUGIN_LDFLAGS)
AC_SUBST(PLUGIN_CFLAGS)
AM_CONDITIONAL([BUILD_PLUGINS], [test "$build_plugins" = "true"])

AC_SUBST(PHRASENDRESCHER_LDFLAGS)

AC_OUTPUT(Makefile src/Makefile src/plugins/Makefile)
