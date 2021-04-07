/*
 * Copyright (c) 2008, Nico Leidecker
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
1 *     * Redistributions in binary form must reproduce the above copyright
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
PLUGIN_VERSION("1.0");


PLUGIN_OPTIONS("U:P:H:pnk");

PLUGIN_USAGE(
    "U name", "the name of the user (default user is `root')",
    "P port", "port to connect to (default is 22)",
    "H host", "target host (mandatory)",
    "p"		, "enforce password authentication",
    "n"		, "enforce keyboard interactive authentication",
    "k"		, "enforce key based authentication"
);

PLUGIN_INFO (
"  The authentication mechanism is chosen automatically if not enforced with \n"
"  -p, -k or -s. The choice depends on the servers configuration in the order\n"
"  password and keyboard-interactive."
);


#define AUTH_AUTO 						-1
#define AUTH_KEYBOARD_INTERACTIVE 		0
#define AUTH_PASSWORD 					1
#define AUTH_PUBLIC_KEY 				2

// global variables
static LIBSSH2_SESSION *session;
static int sockfd;
static char *username = "root";
static plugin_target *host = 0;
static plugin_port port = 22;
static char *password;
static int auth = AUTH_AUTO;


/*
 * establish a connection to the target server
 */ 
int establish_connection(int initial)
{
	const char *fingerprint;
    const char *authlist;
    int i;
    
    // open connection
    sockfd = plugin_socket_open(host, port);
    if (sockfd == -1) {
    	plugin_error_printf("cannot create socket\n");
    	return PLUGIN_RETURN_FAILURE;
    } 

	// initialize ssh session
    session = libssh2_session_init();
    if (libssh2_session_startup(session, sockfd) != 0) {
		plugin_error_printf("cannot establish SSH connection to host\n");
		return PLUGIN_RETURN_FAILURE;
    }
    
    if (initial) {
    	// show the host fingerprint hash
     	fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
		plugin_verbose_printf("Host fingerprint: ");
		for (i = 0; i < 16; i++) {
		    verbose_printf("%02X ", (unsigned char) fingerprint[i]);
		} 
		verbose_printf("\n");
	   
	   
		// get the available authentication mechanisms
		authlist = libssh2_userauth_list(session, username, strlen(username));
		plugin_verbose_printf("Authentication mechanisms: %s ", authlist);
		
		if (auth == AUTH_AUTO) {
			if (strstr(authlist, "password")) {
			    auth = AUTH_PASSWORD;
		    	verbose_printf("(using: password)\n");
			} else if (strstr(authlist, "keyboard-interactive")) {
		    	auth = AUTH_KEYBOARD_INTERACTIVE;
		    	verbose_printf("(using: keyboard-interactive)\n");
			}
	    } else {
	    	switch (auth) {
	    		case AUTH_PASSWORD:
	    				verbose_printf("(enforcing: password)\n");
	    				break;
	    		case AUTH_KEYBOARD_INTERACTIVE:
	    				verbose_printf("(enforcing: keyboard-interactive)\n");
	    				break;
	    		case AUTH_PUBLIC_KEY:
	    				verbose_printf("(enforcing: publickey)\n");
	    				break;
	    	}
	    }
    }
    return PLUGIN_RETURN_SUCCESS;
}

/*
 * disestablish an existing connection 
 */
int disestablish_connection()
{
    libssh2_session_disconnect(session, "");
    libssh2_session_free(session);
    plugin_socket_close(sockfd);
    return 1;
}


void keyboard_interactive(const char *name, int name_len, const char *instr, int instr_len, 
			    int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts, LIBSSH2_USERAUTH_KBDINT_RESPONSE *res, 
															void **abstract)
{
    res[0].text = strdup(password);
    res[0].length = strlen(password);
}

PLUGIN_FUNCTION plugin_get_opts(int opt, char *arg)
{
    switch(opt) {
		case 'U': 
			if (arg) {
			    username = strdup(arg);
			}
			break;
		case 'P':
			if (arg) {
			    port = atoi(arg);
			}
			break;
		case 'H':
			if (arg) {
			    host = plugin_host_by_name(arg);
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
		default:
			return PLUGIN_RETURN_FAILURE;
    }
    
    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_init(int wnum)
{
    
    if (!host) {
		plugin_error_printf("Please specify a host using -H.\n");
		return PLUGIN_RETURN_FAILURE;
    }

    // test connection
    if (!host || !username || !port) {
		plugin_error_printf("Target: host %s  port %i  user %s\n", plugin_host_to_string(host), port, username);
		plugin_error_printf("missing credentials\n");
		return PLUGIN_RETURN_FAILURE;
    }   
 
    plugin_verbose_printf("testing connection %s:%u...\n", plugin_host_to_string(host), port);
    if (establish_connection(1) == PLUGIN_RETURN_FAILURE) {
		return PLUGIN_RETURN_FAILURE;
    }
    disestablish_connection();

    plugin_verbose_printf("success!\n");

    plugin_verbose_printf("host: %s  port: %i  user: %s\n", plugin_host_to_string(host), port, username);
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

PLUGIN_FUNCTION plugin_worker_try_phrase(int wid, char *phrase)
{    
	char *pub_key;
	
    if (establish_connection(0) == PLUGIN_RETURN_FAILURE) {
		return PLUGIN_RETURN_FAILURE;
    }
    
    switch(auth) {
    	case AUTH_KEYBOARD_INTERACTIVE:
	    	// keyboard interactive autehntication
			password = phrase;
			if (libssh2_userauth_keyboard_interactive(session, username, &keyboard_interactive) == 0) {
			    plugin_register_password(username, phrase);
			    return PLUGIN_RETURN_COMPLETED;
			}
			break;
    	case AUTH_PASSWORD:
    		// password authentication
			if (libssh2_userauth_password(session, username, phrase) == 0) {
			    plugin_register_password(username, phrase);
			    return PLUGIN_RETURN_COMPLETED;
			}
			break;
    	case AUTH_PUBLIC_KEY:
    		// key based authentication (phrase is the path to a private key)
   			pub_key = (char *) malloc(strlen(phrase) + 5);
   			strcpy(pub_key, phrase);
   			strcat(pub_key, ".pub");
    		if (libssh2_userauth_publickey_fromfile(session, username, pub_key, phrase, 0) == 0) {
			    plugin_register_password(username, phrase);
			    free(pub_key);
			    return PLUGIN_RETURN_COMPLETED;
			}
		    free(pub_key);
    }
    disestablish_connection();
 
    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_worker_finish(int wid)
{
    /* nothing to do here */
    return PLUGIN_RETURN_SUCCESS;
}
