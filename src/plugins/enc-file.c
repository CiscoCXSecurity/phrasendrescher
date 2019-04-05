/*
 * Copyright (c) 2009, Nico Leidecker
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the organization nor the names of its contributors 
 *       may be used to endorse or promote products derived from this software 
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <errno.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <gpgme.h>

#include "../plugin.h"
#include "../utils.h"

PLUGIN_NAME("enc-file");
PLUGIN_AUTHOR("Nico Leidecker");
PLUGIN_VERSION("1.0");

PLUGIN_OPTIONS("f:p:");

PLUGIN_USAGE (
	"f file/directory", "encrypted file or a directory containing multiple encrypted files",
	"p protocol", "cryptographic protocol to use: 'openpgp' or 'cms' (default is 'openpgp')"
);
	
PLUGIN_INFO(
	"  This module cracks files that have been encrypted with a symmetric\n" 
	"  cipher. E.g.: gpg -c --cipher-algo blowfish file-to-encrypt\n"
	"  Supported is whatever is supported by GnuPG:\n"
	"    3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH"
);


static char *password = 0;
static char *filename = 0;
static int protocol = GPGME_PROTOCOL_OpenPGP;
static gpgme_ctx_t ctx;
static gpgme_data_t out;
static gpgme_data_t data;
static gpgme_data_t out;

gpgme_error_t passphrase_cb (void *opaque, const char *uid_hint, 
						const char *passphrase_info, int last_was_bad, int fd)
{
	char phrase[103];
	
	if (password) {
		strncpy(phrase, password, 100);
		strcat(phrase, "\n");
  		write (fd, phrase, strlen(phrase));
	}

  return 0;
}


PLUGIN_FUNCTION plugin_get_opts(int opt, char *arg)
{
	switch (opt) {
		case 'f':
			if (arg) {
				filename = strdup(arg);
			}
			break;
		case 'p':
			if (arg) {
				if (strcmp(arg, "cms") == 0) {
					protocol = GPGME_PROTOCOL_CMS;
				} else {
					protocol = GPGME_PROTOCOL_OpenPGP;
				}
			}
			break;
	}
    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_init(int wnum)
{	
	gpgme_error_t err;
	char *version;
	char *proto_name;
	
	// get version
	version = (char *) gpgme_check_version(0);
	plugin_error_printf("gpgme version: %s\n", version);
	
	// check engine
	err = gpgme_engine_check_version (protocol);
	if (err != GPG_ERR_NO_ERROR) {
		plugin_error_printf("engine for the protocol not installed\n");
		return PLUGIN_RETURN_FAILURE;
	}
	
	// get protocol name
	proto_name = gpgme_get_protocol_name(protocol);
	if (proto_name) {
		plugin_verbose_printf("using cryptographic protocol: %s\n", proto_name);
	} else {
		plugin_error_printf("invalid protocol: %i\n", protocol);
		return PLUGIN_RETURN_FAILURE;
	}
	
	// create new context
	err = gpgme_new(&ctx);
	if (err != GPG_ERR_NO_ERROR) {
		plugin_error_printf("cannot create gpgme context\n");
		return PLUGIN_RETURN_FAILURE;
	}

	// get data from file
	err = gpgme_data_new_from_file(&data, filename, 1);
	if (err) {
		plugin_error_printf("cannot load data from file: %s\n", filename);
		return PLUGIN_RETURN_FAILURE;
	}
	
	// set passphrase callback function
	gpgme_set_passphrase_cb(ctx, passphrase_cb, 0);
	
	err = gpgme_data_new(&out);
	if (err) {
		plugin_error_printf("cannot create gpgme context\n");
		return PLUGIN_RETURN_FAILURE;
	}		
	plugin_verbose_printf("data loaded from file: %s\n", filename);

  return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_finish()
{
	gpgme_release(ctx);
    return PLUGIN_RETURN_SUCCESS;    
}

PLUGIN_FUNCTION plugin_worker_init(int wid)
{
	/* nothing to do here */
    return PLUGIN_RETURN_SUCCESS;    
}

PLUGIN_FUNCTION plugin_worker_try_phrase(int wid, char *phrase)
{
  	gpgme_error_t err;
	gpgme_decrypt_result_t result;

	password = phrase;

	gpgme_data_seek(data, 0, SEEK_SET);
	
	err = gpgme_op_decrypt_verify(ctx, data, out);
	if (err == GPG_ERR_NO_ERROR) {
		plugin_register_password(filename, phrase);
	    return PLUGIN_RETURN_COMPLETED;
	} 
		
	return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_worker_finish(int wid)
{
	/* nothing to do here */
	return PLUGIN_RETURN_SUCCESS;
}
