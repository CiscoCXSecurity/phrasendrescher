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

#include "plugin.h"
#include "utils.h"

void plugin_register_password(const char *key, const char *password)
{
    printf("password for %s: %s\n", key, password);
}

char *plugin_host_to_string(plugin_target *host)
{
	return inet_ntoa(*host);
}

plugin_target *plugin_host_by_name(char *host)
{
	struct hostent *he;
	plugin_target *ip;
	
	ip = (plugin_target *) malloc(sizeof(plugin_target));
	
	if (!inet_aton(host, ip)) {
		free(ip);
		he = gethostbyname(host);
        if (!he) {        
            return 0;
        }
        ip = (plugin_target *) he->h_addr;
    }
    
    return ip;
}

int plugin_socket_open(plugin_target *host, plugin_port port)
{
    int sockfd;
    struct sockaddr_in addr;
    
    addr.sin_addr = *host;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
		return -1;
    }
    
    if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		return -2;
    }
    
    return sockfd;
}

void plugin_socket_close(int sockfd)
{
    close(sockfd);
}

