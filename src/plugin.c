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

char *plugin_host_to_string(plugin_target_ip *host)
{
//	static char ip[20];
	
//	addr2ascii(AF_INET, host, sizeof(plugin_target_ip), ip);
	
//	return (char *) ip;
	return inet_ntoa(*host);
}

plugin_target_ip *plugin_host_by_name(char *host)
{
	struct hostent *he;
	plugin_target_ip *ip;
	
	ip = (plugin_target_ip *) malloc(sizeof(plugin_target_ip));
	if (!ip) {
		error_printf("cannot allocate memory\n");
		return 0;
	}
	
	if (!inet_aton(host, ip)) {
		free(ip);
		he = gethostbyname(host);
        if (!he) {        
            return 0;
        }
        memcpy(ip, he->h_addr, sizeof(plugin_target_ip));
    }
    
    return ip;
}

int plugin_socket_open(plugin_target_ip *host, plugin_target_port port, int timeout)
{
    int sockfd;
    struct sockaddr_in addr;
    int flag;
    struct timeval tv;
    fd_set fds;
    int err, len;
    
    addr.sin_addr = *host;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
		return -1;
    }
    
    // Set non-blocking 
	flag = fcntl(sockfd, F_GETFL, 0);
	if (flag == -1) {
	  	return -2;
	}
	
	if (fcntl(sockfd, F_SETFL, flag | O_NONBLOCK) == -1) {
	  	return -3; 
	}

    FD_ZERO(&fds);
    FD_SET(sockfd, &fds);

    // attempt to connect
    if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
    	if (errno == EINPROGRESS) {
    		tv.tv_sec = timeout;
    		tv.tv_usec = 0;
    		switch(select(FD_SETSIZE, 0, &fds, 0, &tv)) {
    			case -1:
    				// error
    				return -4;
    			case 0:
    				// timed out
	    			return -5;
    			default:
	    			getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &len);
	    			if (err > 0) {
	    				errno = err;
	    				return -6;
	    			}
    		}
    	} else {
    		return -7;
    	}
  
    }
    
    // reset socket settings
    fcntl(sockfd, F_SETFL, flag);
    
    return sockfd;
}

void plugin_socket_close(int sockfd)
{
    close(sockfd);
}

char **plugin_load_file(char *file, int line_size, int *line_num)
{
	FILE *fp = 0;
	char **lines = 0;
	
	*line_num = 0;
	
	fp = fopen(file, "r");
	if (!fp) {
		*line_num = -1;
		return 0;
	}

	do {
		if (!line_num) {
			lines = (char **) malloc(sizeof(char *));
		} else {
			lines = (char **) realloc(lines, sizeof(char *) * (*line_num + 1));
		}
		lines[*line_num] = (char *) malloc(line_size + 1);
		if (fgets(lines[*line_num], line_size, fp)) {
			if (strlen(lines[*line_num]) > 0 && lines[*line_num][strlen(lines[*line_num]) - 1] == '\n') {
				lines[*line_num][strlen(lines[*line_num]) - 1] = '\0';
				if (strlen(lines[*line_num]) > 0 && lines[*line_num][strlen(lines[*line_num]) - 1] == '\r') {
					lines[*line_num][strlen(lines[*line_num]) - 1] = '\0';
				}
			}
			
			if (strlen(lines[*line_num]) > 0) {
				(*line_num)++;
			} else {
				free(lines[*line_num]);
			}
		}
	} while (!feof(fp));
	
	fclose(fp);
	
	return lines;
}
