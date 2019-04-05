/*
 * Copyright (c) 2008, Mark Lowe
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

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/sha.h>

#include "../plugin.h"

#define DIGEST_LENGTH 20

#define MSSQL_2000 0
#define MSSQL_2005 1

struct hash_t {
	int id;
	char version[5];
	char salt_hex[9];
	char *salt;
	char sha1_mcase_hex[41];
	char *sha1_mcase;
	char sha1_ucase_hex[41];
	char *sha1_ucase;
	char *ucase_password;
	char *mcase_password;
	int mssql_version;
};

static struct hash_t *hash;


PLUGIN_NAME("mssql");
PLUGIN_VERSION("1.0");
PLUGIN_AUTHOR("Mark Lowe");

PLUGIN_OPTIONS("H:");

PLUGIN_USAGE (
    "H", "SHA-1 hash (mandatory)"
);

PLUGIN_INFO (
    "  The mssql plugin can crack password hashes from SQL Server 2000 and SQL Server 2005\n"
    "  For MSSQL 2000:\n"
    "    Hash format: 0x01006d75a401ba0a8bfc2beab5b86efc930300d1a2561a783aace6237cf01f98b490ef56f57b2b8c0ed82b8675f9\n"
    "    SQL query:   SELECT name, password from master..sysxlogins\n\n"
    "  For MSSQL 2005:\n"
    "    Hash format: 0x01006d75a401ba0a8bfc2beab5b86efc930300d1a2561a783aac\n"
    "    SQL query:   SELECT name, password_hash FROM master.sys.sql_logins"
);


char* hex2bin(char* hex_string_orig) 
{
	char *hex_string = strdup(hex_string_orig);
	int bin_len = strlen(hex_string) / 2;
	char *bin = (char *) malloc(bin_len);
	int i_bin;
	int i = bin_len - 1;
	char *p;
	
	for (p = hex_string + strlen(hex_string) - 2; hex_string <= p; p -= 2) {
		// check hash contains only hex digits
		if (!isxdigit(*p) || !isxdigit(*(p+1))) {
			plugin_error_printf("ERROR: Hash should only contain hex digits like 00112233445566778899aabbccddeeff11223344 not '%c' or '%c'\n", *p, *(p+1));
			return 0;
		}
			
		sscanf(p, "%x", &i_bin);
		bin[i] = (char)i_bin;
		i--;
		*p = '\0';
	}

	return bin;
}

int load_hash(char *ihash)
{
	char *p;
	
	hash = (struct hash_t *) malloc(sizeof(struct hash_t));
	
	if ((strlen(ihash) !=94 && strlen(ihash) != 54) || ihash[0] != '0' || ihash[1] != 'x') {
		plugin_error_printf("ERROR: Invalid format for password hash\n\n");

		plugin_error_printf("For MSSQL 2000:\n");
		plugin_error_printf("  Hash format: 0x01006d75a401ba0a8bfc2beab5b86efc930300d1a2561a783aace6237cf01f98b490ef56f57b2b8c0ed82b8675f9\n");
		plugin_error_printf("  SQL query:   SELECT name, password from master..sysxlogins\n\n");
		
		plugin_error_printf("For MSSQL 2005:\n");
		plugin_error_printf("  Hash format: 0x01006d75a401ba0a8bfc2beab5b86efc930300d1a2561a783aac\n");	
		plugin_error_printf("  SQL query:   SELECT name, password_hash FROM master.sys.sql_logins\n");	
		return PLUGIN_RETURN_FAILURE;
	}
	
	// Make sure PHRASENDRESCHER_MAP is set.  It's the only
	// way to communicate our char set to the PD API.
	setenv("PD_CHARMAP", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789-_.,+:;!\"$%^&*()[]{}@#~'?/\\<>|", 0);
	
	if (strlen(ihash) == 54) {
		plugin_verbose_printf("MS SQL Version:  2005\n");
	} else {
		plugin_verbose_printf("MS SQL Version:  2000\n");

		// Convert supplied char set to uppercase.
		// Duplicates don't matter.  PD will take care of that for us.
		char *oldcharmap = getenv("PD_CHARMAP");
		char *newcharmap = strdup(getenv("PD_CHARMAP"));
		int o;     // pos in oldcharmap
		int n = 0; // pos in newcharmap
		for (o = 0; o < strlen(oldcharmap); o++) {
			if (!index(oldcharmap + o + 1, toupper(oldcharmap[o]))) {
				newcharmap[n++] = toupper(oldcharmap[o]);
			}
		}
		newcharmap[n] = '\0';
		setenv("PHRASENDRESCHER_MAP", newcharmap, 1);
	}
	
	plugin_verbose_printf("Character set:   %s\n", getenv("PD_CHARMAP"));
	p = ihash + 2;
	
	strncpy(hash->version, p, 4);
	plugin_verbose_printf("Version:         %s\n", hash->version);
	p += 4;
	
	strncpy(hash->salt_hex, p, 8);
	plugin_verbose_printf("Salt:            %s\n", hash->salt_hex);
	p += 8;
	
	strncpy(hash->sha1_mcase_hex, p, 40);
	plugin_verbose_printf("Mixed-case SHA1: %s\n", hash->sha1_mcase_hex);
	p += 40;
	
	hash->salt = hex2bin(hash->salt_hex);
	hash->sha1_mcase = hex2bin(hash->sha1_mcase_hex);
	hash->ucase_password = 0;
	hash->mcase_password = 0;
	hash->id = 0;
	
	if (strlen(ihash) == 54) {
		hash->mssql_version = MSSQL_2005;
		// If we're cracking an MSSQL 2005 hash, we won't have a uppercase hash.
		hash->sha1_ucase = 0;
	} else {
		hash->mssql_version = MSSQL_2000;
		strncpy(hash->sha1_ucase_hex, p, 40);
		plugin_verbose_printf("Upper-case SHA1: %s\n", hash->sha1_ucase_hex);
		p += 40;
		hash->sha1_ucase = hex2bin(hash->sha1_ucase_hex);
	}
	
    return PLUGIN_RETURN_SUCCESS;
}


PLUGIN_FUNCTION plugin_get_opts(int opt, char *arg)
{
    switch (opt) {
	case 'H':
		load_hash(strdup(arg));
		break;
    }
    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_init(int wnum)
{
    plugin_printf("MSSQL plugin by Mark Lowe (mrl@portcullis-security.com)\n\n");
    if (!hash) {
	plugin_error_printf("please specify a hash with -H.\n");
	return PLUGIN_RETURN_FAILURE;
    }
    return PLUGIN_RETURN_SUCCESS;
}


PLUGIN_FUNCTION plugin_finish()
{
    return PLUGIN_RETURN_SUCCESS;    
}

PLUGIN_FUNCTION plugin_worker_try_phrase(int wid, char *phrase)
{
	int i, phrase_len, perm_count, cracked;
	char unicode_phrase_salt[105];
	int unicode_salt_length;
	static unsigned char digest[DIGEST_LENGTH];
	size_t digest_len = DIGEST_LENGTH;
	
	phrase_len = strlen(phrase);

	// Convert phrase to uppercase unicode
	memset(unicode_phrase_salt, 0, 105);
	unicode_salt_length = phrase_len * 2;
	if (phrase_len > 50) {
		plugin_error_printf("ERROR: Password %s is too long. Skipping.\n", phrase);
		return PLUGIN_RETURN_SUCCESS;
	}

	if (hash->mssql_version == MSSQL_2005) {
		// MSSQL 2005
		for (i = 0; i < phrase_len; i++) {
			unicode_phrase_salt[i * 2] = phrase[i];   // Unicode
		}
	
		// Append salt
		memcpy(unicode_phrase_salt + unicode_salt_length, hash->salt, 4);
		unicode_salt_length += 4;
		
		// Calculate SHA1(unicode(uppercase(phrase)) + salt)
		SHA_CTX context;
		SHA1_Init(&context);
		SHA1_Update(&context, (unsigned char *)unicode_phrase_salt, unicode_salt_length);
		SHA1_Final(digest, &context);
		
		if (memcmp(hash->sha1_mcase, digest, digest_len) == 0) {
		    hash->ucase_password = strdup(phrase);
		    if (phrase_len == 0) {
				plugin_register_password(hash->sha1_mcase_hex, "{empty passphrase}");
			} else {
				plugin_register_password(hash->sha1_mcase_hex, phrase);
			}
			return PLUGIN_RETURN_COMPLETED;
		}

	} else {
		// MSSQL 2000
		for (i = 0; i < phrase_len; i++) {
			phrase[i] = toupper(phrase[i]);           // Uppercase
			unicode_phrase_salt[i * 2] = phrase[i];   // Unicode
		}

		// Append salt
		memcpy(unicode_phrase_salt + unicode_salt_length, hash->salt, 4);
		unicode_salt_length += 4;

		// Calculate SHA1(unicode(uppercase(phrase)) + salt)
		SHA_CTX context;
		SHA1_Init(&context);
		SHA1_Update(&context, (unsigned char *)unicode_phrase_salt, unicode_salt_length);
		SHA1_Final(digest, &context);

		// Is this the hash we're looking for?
		if (memcmp(hash->sha1_ucase, digest, digest_len) == 0) {
			hash->ucase_password = strdup(phrase);
			if (strlen(phrase) == 0) {
				plugin_register_password(hash->sha1_ucase_hex, "{empty passphrase}");
			} else {
				plugin_register_password(hash->sha1_ucase_hex, phrase);
			}
			
			cracked = 0;
			// For every case permutation
			for (perm_count = 0; perm_count < (1 << phrase_len); perm_count++) {
				
				// Convert back to all uppercase before we tinker with the case
				for(i=0; i < phrase_len; i++) {
					phrase[i] = toupper(phrase[i]);
				}
				 
				// Generate string for this case-permutation
				for (i = 0; i < phrase_len; i++) {
					if ((1 << i) & perm_count) {
				    	phrase[i] = tolower(phrase[i]);
				   	}
				}
				
				// Convert phrase into unicode
				memset(unicode_phrase_salt, 0, 105);
				unicode_salt_length = phrase_len * 2;
				for (i = 0; i < phrase_len; i++) {
					unicode_phrase_salt[i * 2] = phrase[i];   // Unicode
				}
				
				// Append salt
				memcpy(unicode_phrase_salt + unicode_salt_length, hash->salt, 4);
				unicode_salt_length += 4;
				
				// Calculate SHA1(unicode(uppercase(phrase)) + salt)
				SHA1_Init(&context);
				SHA1_Update(&context, (unsigned char *)unicode_phrase_salt, unicode_salt_length);
				SHA1_Final(digest, &context);
				
				if (memcmp(hash->sha1_mcase, digest, digest_len) == 0) {
					hash->mcase_password = strdup(phrase);
				   	if (strlen(phrase) == 0) {
						plugin_register_password(hash->sha1_mcase_hex, "{empty passphrase}");
					} else {
						plugin_register_password(hash->sha1_mcase_hex, phrase);
					}
					cracked = 1;
					break;
				}
	
			}
		
			if (!cracked) {
				plugin_error_printf("ERROR: Didn't manage to recover case of password.  This shouldn't happen!  Typo in hash?\n");
			}	
			return PLUGIN_RETURN_COMPLETED;
		}
	}

    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_worker_init(int wid)
{
	/* nothing to do here */
    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_worker_finish(int wid)
{
	/* nothing to do here */
	return PLUGIN_RETURN_SUCCESS;
}
