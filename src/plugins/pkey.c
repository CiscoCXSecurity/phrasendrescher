/*
 * Copyright (c) 2008, Nico Leidecker
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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <dirent.h>
#include <string.h>

#include "../plugin.h"
#include "../utils.h"

#define ABSOLUTE_PATH_LENGTH	256

// key file pointer structure
struct keys_t {
	int id;
	char *fn;
	FILE *fp;
};

static struct keys_t **keys = 0;
static unsigned int key_num = 0;
static unsigned int completed = 0;

PLUGIN_NAME("pkey");
PLUGIN_AUTHOR("Nico Leidecker");
PLUGIN_VERSION("1.0");

PLUGIN_OPTIONS("K:");

PLUGIN_USAGE(
	"K key/directory", "key file or a directory containing multiple key files. Keys must be in PEM format."
	);

PLUGIN_NO_INFO;

int load_key(char *path)
{
	DIR *dir;
	FILE *file;
	char absolute_path[ABSOLUTE_PATH_LENGTH];
	struct stat key_stat;
	struct dirent *entry;
	int i;

	if (!path) {
	    plugin_error_printf("missing credentials\n");
	    return PLUGIN_RETURN_FAILURE;
	}
	
	key_num = 0;
	
	if (stat(path, &key_stat) == -1) {
		plugin_error_printf("stat failed for %s: %s\n", path, strerror(errno));
		return PLUGIN_RETURN_FAILURE;
	}
	
	if (S_ISDIR(key_stat.st_mode)) {
		// read in every file in directory
		dir = opendir(path);
		if (!dir) {
			plugin_error_printf("could not open directory %s: %s\n",
                         								path, strerror(errno));
			return PLUGIN_RETURN_FAILURE;
		}
		
		while((entry = readdir(dir))) {
			// skip everything beginning with a dot
			if (*(entry->d_name) != '.') {
				
				if (path[strlen(path) - 1] == '/') {
                	snprintf(absolute_path, ABSOLUTE_PATH_LENGTH,"%s%s", path, entry->d_name);
				} else {
					snprintf(absolute_path, ABSOLUTE_PATH_LENGTH,"%s/%s", path, entry->d_name);
				}
				file = fopen(absolute_path, "r"); 
				if (!file) {
					plugin_error_printf("could not open file %s: %s\n",
                                 				absolute_path, strerror(errno));
				} else {
					keys = (struct keys_t **) realloc(keys,
                    				sizeof(struct keys_t *) * (key_num + 1));
					
					keys[key_num] = (struct keys_t *)malloc(sizeof(struct keys_t));
					keys[key_num]->fn = strdup(absolute_path);
					keys[key_num]->id = key_num;
					keys[key_num]->fp = file;
					key_num++;
					
				}
			}
		}
	} else {		
		// read in a single key file
		file = fopen(path, "r");
		if (!file) {
			plugin_error_printf("could not open file %s: %s\n", path, strerror(errno));
		} else {
			keys = (struct keys_t **) malloc(sizeof(struct keys_t *));
			*keys = (struct keys_t *) malloc(sizeof(struct keys_t));
			(*keys)->fn = strdup(path);
			(*keys)->fp = file;
			(*keys)->id = 0;
			
			key_num++;
		}
	}

	// print key files
	plugin_verbose_printf("%i key files read:\n", key_num);
	for (i = 0; i < key_num; i++) {
		plugin_verbose_printf("%i): %s\n", i, keys[i]->fn);
	}

    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_get_opts(int opt, char *arg)
{
    switch (opt) {
		case 'K':
	    	return load_key(arg);
    }
    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_init(int wnum)
{
    // prepare openssl
    OpenSSL_add_all_algorithms();
	
    completed = 0;

    if (keys == 0) {
	plugin_error_printf("please specify a key or a directory containing keys with -K.\n");
	return PLUGIN_RETURN_FAILURE;
    }

    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_finish()
{
	/* nothing to do here */
    return PLUGIN_RETURN_SUCCESS;    
}

PLUGIN_FUNCTION plugin_worker_init(int wid)
{
	/* nothing to do here */
    return PLUGIN_RETURN_SUCCESS;    
}

/* beware that this has to be thread-safe */
PLUGIN_FUNCTION plugin_worker_try_phrase(int wid, char *phrase)
{
	struct keys_t *key;
	FILE *fp;
	int k;
	int all_done;
	
	all_done = 1;
	
	
	for (k = 0; k < key_num; k++) {
		key = keys[k];
		if (key) {
			all_done = 0;
			fp = freopen(0, "r", key->fp);
			if (PEM_read_PrivateKey(fp, 0, 0, phrase)) {
			    if (strlen(phrase) == 0) {
					plugin_register_password(key->fn, "{empty passphrase}");
			    } else {
					plugin_register_password(key->fn, phrase);
			    }
			    completed++;
			    keys[k] = 0;
			}
		}
	}

	if (all_done) {
		return PLUGIN_RETURN_COMPLETED;
	}

    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_worker_finish(int wid)
{
	/* nothing to do here */
	return PLUGIN_RETURN_SUCCESS;
}
