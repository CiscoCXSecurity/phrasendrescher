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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h> 
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
	  
#include "../plugin.h"

PLUGIN_NAME("http-raw");
PLUGIN_AUTHOR("Nico Leidecker");
PLUGIN_VERSION("1.0");


PLUGIN_OPTIONS("R:T:P:m:");

PLUGIN_USAGE (
	"R file", "the file containing the raw HTTP request (mandatory)",
	"T host", "an alternative target host if not the server specified in the HOST header field",
	"P port", "an alternative port other than 80",
	"m message", "the message that indicates an failed login attempt"
);

PLUGIN_INFO (
    "  A simple plugin for raw HTTP requests. The request is read from a file which\n"
    "  is passed to as credentials. The placeholder {PASSWORD} will be replaced with\n" 
    "  the password. The target host is taken from the HOST field in the HTTP request\n"
    "  header. Default port is 80."
);

static int sockfd;
static plugin_target *host = 0;
static plugin_port port = 80;
static char *body;
static char *message = "nvalid";
static int req_size;
static int pw_in_content_length;

static char *request = 0;

int load_request(char *filename)
{
    FILE *file;
    struct stat sb;
    char *p, *pbuf;
    char line[256];
    char buf[512 + 2];
    int buf_len, had_connection_close;
    char *chost;
    	
    file = fopen(filename, "r");
    if (!file) {
		return PLUGIN_RETURN_FAILURE;
    }
    
    if (fstat(fileno(file), &sb) != 0) {
		return PLUGIN_RETURN_FAILURE;
    }
    req_size = sb.st_size * 2;
    
    // allocate memory for request
    request = (char *) malloc(req_size);
    if (!request) {
		return PLUGIN_RETURN_FAILURE;        
    }
    
    // read request from file, double each % and replace <<PASSWORD>> and Content-Length (if any)
    *request = '\0';
    body = 0;
    had_connection_close = 0;
    while (!feof(file)) {
    	if (!fgets(line, 256, file)) {
    		break;
    	}
  		// double each % 
       	p = line;
       	pbuf = buf;
       	while (*p) {
       		if (*p == '%') {
       			*pbuf = '%';
       			pbuf++;
       		}
       		*pbuf = *p;
       		p++;
       		pbuf++;
       	}
       	*pbuf = '\0';
       	
       	// replace \n with \r\n
       	buf_len = strlen(buf);
       	if (buf_len >= 2) {
       		if (buf[buf_len - 1] == '\n' && buf[strlen(buf) - 2] != '\r') {
       			buf[buf_len - 1] = '\r';
       			buf[buf_len] = '\n';
       			buf[buf_len + 1] = '\0';
       		}	
       	} else {
       		buf[0] = '\r';
       		buf[1] = '\n';
       		buf[2] = '\0';
       	}

		// find password place holder
       	if ( (p = strstr(buf, "{PASSWORD}")) ) { 
       		memmove(p, p + 6, strlen(p + 6) + 1);
       		memcpy(p, "%1$s", 4);
       		if (body) {
       			pw_in_content_length = 1;
       		}
       	}
       	
       	// if line is a single \r\n, the body part begins with the next line
       	if (strcmp(buf, "\r\n") == 0 && !body) {
       		// if there was no connection header field, then we add it
       		if (!had_connection_close) {
       			strcat(request, "Connection: close\r\n");
       		}
       		// body points to end of request (which is either beginning of body or \0)
       		body = request + strlen(request) + 2;
       	} else if (strncasecmp(buf, "CONTENT-LENGTH:", 15) == 0) {
       		// make content length variable
       		strcpy(buf, "Content-length: %2$u\n");
       	} else if (strncasecmp(buf, "CONNECTION:", 11) == 0) {
       		strcpy(buf, "Connection: close\r\n");
       		had_connection_close = 1;
       	} else if (!host && strncasecmp(buf, "HOST: ", 5) == 0) {
       		chost = strdup(buf + 5);
    		// remove trailing \r\n
    		if ((p = strstr(chost, "\r\n"))) {
    			*p = '\0';
    			while (*chost == ' ') {
    				chost++;
    			}
    		}
    		host = plugin_host_by_name(chost);
    		if (!host) {
				plugin_error_printf("cannot resolve host: %s\n", chost);
				return PLUGIN_RETURN_FAILURE;
    		}
       	}
		
		strcat(request, buf);
    }
  
    plugin_verbose_printf("Target host: %s\nRaw HTTP request:\n%s\n", plugin_host_to_string(host), request);
    
    return PLUGIN_RETURN_SUCCESS;
}


PLUGIN_FUNCTION plugin_get_opts(int opt, char *arg)
{
	switch (opt) {
		case 'R':
			return load_request(arg);
		case 'T':
			host = plugin_host_by_name(arg);
			if (!host) {
			    plugin_error_printf("cannot resolve host: %s\n", arg);
			    return PLUGIN_RETURN_FAILURE;
			}
			break;
		case 'P':
			port = atoi(arg);
			break;
		case 'm':
			message = strdup(message);
			break;
	}
    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_init(int wnum)
{
    if (!request) {
	plugin_error_printf("Please specify a request file with -R.\n");
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

PLUGIN_FUNCTION plugin_worker_try_phrase(int wid, char *phrase)
{   
	int content_length;
	int i;
	int response_size, alloc_response_size;
	char *response, *rptr;
	char req[4092];

	sockfd = plugin_socket_open(host, port);
    if (sockfd == -1) {
    	plugin_error_printf("cannot create socket\n");
    	return PLUGIN_RETURN_FAILURE;
    }
    
    // send request
    content_length = 0;
    if (body && *body) {
    	// calculate content length from the body minus the trailing \r\n\r\n
    	content_length = strlen(body) - 4;
    	if (pw_in_content_length) {
    	// subtract the format string parameter for the password and add the 
    	// actual length of the phrase
    		content_length += strlen(phrase) - 4;
    	}
    }
    
    snprintf(req, 4091, request, phrase, content_length);
    if (write(sockfd, req, strlen(req)) == -1) {
    	plugin_error_printf("cannot send data\n");
    	return PLUGIN_RETURN_FAILURE;
    }
   
   // read response
    alloc_response_size = 256 + 1;
    response_size = 0;
    response = malloc(alloc_response_size);
    rptr = response;
    while((i = read(sockfd, response + response_size, 256)) > 0) {
    	response_size += i;
    	alloc_response_size += 256;
    	response = (char *) realloc(response, alloc_response_size);
    }
    *rptr = '\0';
   
	plugin_socket_close(sockfd);

	// find string
    if (!strstr(response, message)) {
    	plugin_register_password(plugin_host_to_string(host), phrase);			
    	return PLUGIN_RETURN_COMPLETED;
    }
    
    return PLUGIN_RETURN_SUCCESS;
}

PLUGIN_FUNCTION plugin_worker_finish(int wid)
{
    /* nothing to do here */
    return PLUGIN_RETURN_SUCCESS;
}
