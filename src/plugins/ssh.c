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

#include <libssh2.h>

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "../plugin.h"

PLUGIN_NAME("ssh");
PLUGIN_AUTHOR("Nico Leidecker");
PLUGIN_VERSION("1.1");


PLUGIN_OPTIONS("u:U:P:t:T:e:pnk");

PLUGIN_USAGE(
    "u user"		, "the name of the user (default user is `root')",
    "U user-file"	, "user names file",
    "P port"		, "port to connect to (default is 22)",
    "t host"		, "target host",
    "T host-file"	, "target host file",
    "p"				, "enforce password authentication",
    "n"				, "enforce keyboard interactive authentication",
    "k"				, "enforce key based authentication (keys must be stored in the dictinary file)",
    "e n|s|ns"			, "try empty passwords ('n') and/or usernames as password ('s')"
);

PLUGIN_INFO (
"  The authentication mechanism is chosen automatically if not enforced with \n"
"  -p, -k or -s. The choice depends on the servers configuration in the order\n"
"  password and keyboard-interactive."
);


#define AUTH_AUTO 					-1
#define AUTH_KEYBOARD_INTERACTIVE	0
#define AUTH_PASSWORD				1
#define AUTH_PUBLIC_KEY				2

#define DEFAULT_PORT 				22
#define LINE_BUFFER_SIZE			256

#define CONNECTION_TIMEOUT			10	// in ms

#define DEFAULT_USER				"root"

// per target structure
typedef struct {
	int sockfd;
	plugin_target_port port;
	plugin_target_ip *host;
	LIBSSH2_SESSION *session;
	int auth;
	char **usernames;
	int user_num;
} target_t;

static target_t **targets = 0;

// global variables
static plugin_target_ip **hosts = 0;
static plugin_target_port default_port = DEFAULT_PORT;	
static int auth = AUTH_AUTO;
static int host_num = 0;
static char *password;
static char **usernames = 0;
static int user_num = 0;
static int try_empty_pwd = 0;
static int try_username_pwd = 0;

/*
 * establish a connection to the target server
 */ 
int establish_connection(target_t *target, int initial)
{
	const char *fingerprint;
    const char *authlist;
    int i;
      
    // open connection
    target->sockfd = plugin_socket_open(target->host, target->port, CONNECTION_TIMEOUT);
    if (target->sockfd < 0) {
    	plugin_error_printf("cannot connect to host\n");
    	return PLUGIN_RETURN_FAILURE;
    }

	// initialize ssh session
	target->session = libssh2_session_init();
    if (!(target->session)) {
  		plugin_error_printf("cannot initialize ssh session to host\n");
  		return PLUGIN_RETURN_FAILURE;
    }

    if (libssh2_session_startup(target->session, target->sockfd) != 0) {
		plugin_error_printf(
		    "cannot establish SSH connection to %s although TCP connection is established;\n"
	    	"please make sure the target service is supporting SSH version 2\n", plugin_host_to_string(target->host));
		return PLUGIN_RETURN_FAILURE;
    }

    if (initial) {
    //	plugin_verbose_printf("Host %s:\n",plugin_host_to_string(target->host));
    	// show the host fingerprint hash
     	fingerprint = libssh2_hostkey_hash(target->session, LIBSSH2_HOSTKEY_HASH_MD5);
		plugin_verbose_printf("  Fingerprint: ");
		for (i = 0; i < 16; i++) {
		    verbose_printf("%02X ", (unsigned char) fingerprint[i]);
		} 
		verbose_printf("\n");
	   	   
		// get the available authentication mechanisms
		authlist = libssh2_userauth_list(target->session, 0, 0);
		plugin_verbose_printf("  Authentication mechanisms: %s ", authlist);
	
		if (auth == AUTH_AUTO) {
			if (strstr(authlist, "password")) {
			    target->auth = AUTH_PASSWORD;
		    	    verbose_printf("(using: password)\n");
			} else if (strstr(authlist, "keyboard-interactive")) {
			    target->auth = AUTH_KEYBOARD_INTERACTIVE;
			    verbose_printf("(using: keyboard-interactive)\n");
			}
		} else {
		   	switch (auth) {
		   	    case AUTH_PASSWORD:
		   			verbose_printf("(enforcing: password)\n");
					if (!strstr(authlist, "password")) {
					    plugin_error_printf("enforced authentication mechanism is not supported by the server\n");
					    return PLUGIN_RETURN_FAILURE;
					}
		   			break;
		   		case AUTH_KEYBOARD_INTERACTIVE:
		   			verbose_printf("(enforcing: keyboard-interactive)\n");
					if (!strstr(authlist, "keyboard-interactive")) {
					    plugin_error_printf("enforced authentication mechanism is not supported by the server\n");
					    return PLUGIN_RETURN_FAILURE;
					}
		   			break;
		   		case AUTH_PUBLIC_KEY:
		   			verbose_printf("(enforcing: publickey)\n");
					if (!strstr(authlist, "publickey")) {
					    plugin_error_printf("enforced authentication mechanism is not supported by the server\n");
					    return PLUGIN_RETURN_FAILURE;
					}
		    		break;
			}
			target->auth = auth;
		}
    }
    return PLUGIN_RETURN_SUCCESS;
}

/*
 * disestablish an existing connection 
 */
int disestablish_connection(target_t *target)
{
    libssh2_session_disconnect(target->session, "");
    libssh2_session_free(target->session);
    plugin_socket_close(target->sockfd);
    return 1;
}


void keyboard_interactive(const char *name, int name_len, const char *instr, int instr_len, 
			    int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts, LIBSSH2_USERAUTH_KBDINT_RESPONSE *res, 
															void **abstract)
{
    res[0].text = strdup(password);
    res[0].length = strlen(password);
}

int try_phrase(target_t *target, char *username, char *phrase) 
{
	char found_password_key[256];
	char *pub_key;
	
	if (establish_connection(target, 0) == PLUGIN_RETURN_FAILURE) {
		return PLUGIN_RETURN_FAILURE;
	}
				   		  
	switch(target->auth) {
	 	case AUTH_KEYBOARD_INTERACTIVE:
			// keyboard interactive autehntication
			password = phrase;
			if (libssh2_userauth_keyboard_interactive(target->session, username, &keyboard_interactive) == 0) {
				snprintf(found_password_key, sizeof(found_password_key), 
							"'%s' on %s", username, plugin_host_to_string(target->host));
				plugin_register_password(found_password_key, phrase);
				return PLUGIN_RETURN_COMPLETED;
			}
			break;
		case AUTH_PASSWORD:
			// password authentication
			if (libssh2_userauth_password(target->session, username, phrase) == 0) {
				snprintf(found_password_key, sizeof(found_password_key), 
							"'%s' on %s", username, plugin_host_to_string(target->host));
				plugin_register_password(found_password_key, phrase);
				return PLUGIN_RETURN_COMPLETED;
			}
			break;
		case AUTH_PUBLIC_KEY:
			// key based authentication (phrase is the path to a private key)
			pub_key = (char *) malloc(strlen(phrase) + 5);
			strcpy(pub_key, phrase);
			strcat(pub_key, ".pub");
			if (libssh2_userauth_publickey_fromfile(target->session, username, pub_key, phrase, 0) == 0) {
				snprintf(found_password_key, sizeof(found_password_key), 
							"'%s' on %s", username, plugin_host_to_string(target->host));
				plugin_register_password(found_password_key, phrase);
				free(pub_key);
				return PLUGIN_RETURN_COMPLETED;
			}
			free(pub_key);
	}
	disestablish_connection(target);
	
	return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_get_opts(int opt, char *arg)
{
	int t, fport;
	char **raw_targets, *ptr;
		
    switch(opt) {
		case 'u': 
			if (arg) {
				usernames = (char **) malloc(sizeof(char *));
				usernames[0] = strdup(arg);
				user_num = 1;
			}
			break;
		case 'U':
			if (arg) {
				usernames = plugin_load_file(arg, LINE_BUFFER_SIZE, &user_num);
				if (user_num == -1) {
					plugin_error_printf("cannot open user file %s\n", arg);
					return PLUGIN_RETURN_FAILURE;
				}
			}
			break;
		case 'P':
			if (arg) {
			    default_port = atoi(arg);
			}
			break;
		case 't':
			if (arg) {
				targets = (target_t **) malloc(sizeof(target_t *));
				if (!targets) {
					plugin_error_printf("cannot allocate memory for target structure\n");
					return PLUGIN_RETURN_FAILURE;
				}
				targets[0] = (target_t *) malloc(sizeof(target_t));
				if (!targets[0]) {
					error_printf("cannot allocate memory for target structure\n");
					return PLUGIN_RETURN_FAILURE;
				}
				memset(targets[0], 0x00, sizeof(target_t));
				targets[0]->host = plugin_host_by_name(arg);
				targets[0]->port = 0; // 0 means use default port or port specified by -p
				host_num = 1;
			}
			break;
		case 'T':
			if (arg) {
				raw_targets = plugin_load_file(arg, LINE_BUFFER_SIZE, &host_num);
				if (host_num > 0) {
					targets = (target_t **) malloc(host_num * sizeof(target_t *));	
					if (!targets) {
						plugin_error_printf("cannot allocate memory for target structure\n");
						return PLUGIN_RETURN_FAILURE;
					}
					for (t = 0; t < host_num; t++) {
						targets[t] = (target_t *) malloc(sizeof(target_t));
						if (!targets[t]) {
							plugin_error_printf("cannot allocate memory for target structure\n");
							return PLUGIN_RETURN_FAILURE;
						}

						memset(targets[t], 0x00, sizeof(target_t));
						
						ptr = strchr(raw_targets[t], ':');
						if (ptr) {
							targets[t]->port = atoi(ptr + 1);
							*ptr = '\0';
						}
						
						targets[t]->host = plugin_host_by_name(raw_targets[t]);
						
						if (!(targets[t]->host)) {
							plugin_error_printf("host %s cannot be resolved\n", raw_targets[t]);
							targets[t] = 0;
						}
						free(raw_targets[t]);
					}
					free(raw_targets);
				}
			}
			break;
		case 'p':
			auth = AUTH_PASSWORD;
			break;
		case 'n':
			auth = AUTH_KEYBOARD_INTERACTIVE;
			break;
		case 'k':
			auth = AUTH_PUBLIC_KEY;
			break;
		case 'e':
			if (arg) {
				if (strchr(arg, 'n')) {
					try_empty_pwd = 1;
				}
				if (strchr(arg, 's')) {
					try_username_pwd = 1;
				}
			}
			break;
		default:
			return PLUGIN_RETURN_FAILURE;
    }
    
    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_init(int wnum)
{
    int t, u;
    
    if (!targets) {
		plugin_error_printf("Please specify a target using -t or -T.\n");
		return PLUGIN_RETURN_FAILURE;
    }
	
	if (!usernames) {
		usernames = (char **) malloc(sizeof(char *));
		usernames[0] = DEFAULT_USER;
		user_num = 1;
	}
	 
 	// test connection for all targets;
 	for (t = 0; t < host_num; t++) {
		if (targets[t]) {
			
			// set port
	 		if (targets[t]->port == 0) {
	 			targets[t]->port = default_port;
	 		}
	 		
	 		// copy list of users
	 		targets[t]->user_num = user_num;
	 		targets[t]->usernames = (char **) malloc(sizeof(char *) * user_num);
	 		for (u = 0; u < user_num; u++) {
	 			targets[t]->usernames[u] = strdup(usernames[u]);
	 		}
	 		
	 		plugin_verbose_printf("Trying host %s:%u...\n", plugin_host_to_string(targets[t]->host), targets[t]->port);
	   		if (establish_connection(targets[t], 1) == PLUGIN_RETURN_FAILURE) {
	   			plugin_error_printf("establishing the initial connection failed for host; will remove target from list!\n");
	   			targets[t] = 0;
	    	} else {
	    	    disestablish_connection(targets[t]);
	    	}
		}
 	}
        
    plugin_verbose_printf("Complete List of targets:\n");
    for (t = 0; t < host_num; t++) {
    	if (targets[t]) {
    		plugin_verbose_printf("  %s:%i\n", plugin_host_to_string(targets[t]->host), targets[t]->port);
    	}
    }

	plugin_verbose_printf("Users:\n");
	for (u = 0; u < user_num; u++) {
		plugin_verbose_printf("  %s\n", usernames[u]);
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
	int t, u;
	
	if (wid == 0) {
		// try empty passwords and usernames for passwords
		if (try_empty_pwd || try_username_pwd) {
			plugin_verbose_printf("Initially trying %s%s%s on every host...\n", 
										try_empty_pwd ? "empty passwords" : "",
										try_empty_pwd && try_username_pwd ? " and " : "",
										try_username_pwd ? "usernames as password" : "");
			for (t = 0; t < host_num; t++) {
				for (u = 0; u < user_num && targets[t]; u++) {
					if (try_empty_pwd) {
						if (try_phrase(targets[t], usernames[u], "") == PLUGIN_RETURN_COMPLETED) {
							targets[t]->usernames[u] = 0;
						}
					}
					if (try_username_pwd) {
						if (try_phrase(targets[t], usernames[u], usernames[u]) == PLUGIN_RETURN_COMPLETED) {
							targets[t]->usernames[u] = 0;
						}
					}
				}
			}
		}
	}
	
	return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_worker_try_phrase(int wid, char *phrase)
{    
	int t, u;
	int all_targets_done = 1;
	int all_users_done = 1;
	
	for (t = 0; t < host_num; t++) {
		if (targets[t]) {
			all_users_done = 1;
			for (u = 0; u < targets[t]->user_num; u++) {
				if (targets[t]->usernames[u]) {
					all_users_done = 0;
				    if (try_phrase(targets[t], targets[t]->usernames[u], phrase) == PLUGIN_RETURN_COMPLETED) {
				    	targets[t]->usernames[u] = 0;
				    }
				}
			}
			if (!all_users_done) {
		    	all_targets_done = 0;
			}
		}
	}
	
	if (all_targets_done) {
		return PLUGIN_RETURN_COMPLETED;
	}
    
    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_worker_finish(int wid)
{
    /* nothing to do here */
    return PLUGIN_RETURN_SUCCESS;
}
