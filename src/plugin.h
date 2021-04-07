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
 
#ifndef _PLUGIN_H
#define _PLUGIN_H

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "utils.h"

#define PLUGIN_RETURN_SUCCESS 	 1
#define PLUGIN_RETURN_FAILURE 	-1
#define PLUGIN_RETURN_COMPLETED -2


#define PLUGIN_FUNCTION 				int

#define PLUGIN_NAME(arg)				char plugin_keyword_name[] = arg;
#define PLUGIN_AUTHOR(arg)				char plugin_keyword_author[] = arg;
#define PLUGIN_VERSION(arg)				char plugin_keyword_version[] = arg;

#define PLUGIN_OPTIONS(arg)				char plugin_keyword_opts[] = arg;

#define PLUGIN_USAGE(arg, args...)		char *plugin_keyword_usage[] = { arg, ##args, 0 };
#define PLUGIN_NO_USAGE					char *plugin_keyword_usage[] = { 0 };

#define PLUGIN_INFO(arg)				char plugin_keyword_info[] = arg;
#define PLUGIN_NO_INFO					char plugin_keyword_info[] = "";

typedef struct in_addr plugin_target;
typedef unsigned int plugin_port;

#define plugin_printf(fmt, args...)			printf("[%s] " fmt, plugin_keyword_name, ##args);
#define plugin_verbose_printf(fmt, args...)		verbose_printf("[%s] " fmt, plugin_keyword_name, ##args);
#define plugin_error_printf(fmt, args...)		error_printf("[%s] " fmt, plugin_keyword_name, ##args);

struct plugin_t {
	char *dir;
	void *handle;
	char *name;
	PLUGIN_FUNCTION (*plugin_init)(int);
	PLUGIN_FUNCTION (*plugin_finish)();
//	PLUGIN_FUNCTION (*plugin_load_credentials)(char *);
	PLUGIN_FUNCTION (*plugin_get_opts)(int opt, char *arg);
	PLUGIN_FUNCTION (*plugin_worker_init)(int);
	PLUGIN_FUNCTION (*plugin_worker_try_phrase)(int, char *);
	PLUGIN_FUNCTION (*plugin_worker_finish)(int);
};	

void plugin_register_password(const char *key, const char *password);

char *plugin_host_to_string(plugin_target *host);
plugin_target *plugin_host_by_name(char *host);
int plugin_socket_open(plugin_target *host, plugin_port port);
void plugin_socket_close(int sockfd);

#endif
