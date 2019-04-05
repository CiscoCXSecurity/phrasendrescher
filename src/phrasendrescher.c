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
  
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>
     
#include "phrasendrescher.h"
#include "plugin.h"
#include "utils.h"
#include "worker.h"
#include "source.h"
#include "rules.h"

static char plugin_dir[MAX_PATH_LENGTH] = DEFAULT_PLUGIN_DIR;

static struct source_t source = { -1, { { 0 } } };

static char *credentials;

static int worker_num;
static int *worker;

// global status variables
extern int terminate;

// plugin reference
struct plugin_t plugin;

void signal_stats (int signo)
{
	/* do nothing */
}

void signal_terminate (int i)
{
	terminate = worker_num;
}

void signal_complete (int i)
{
	if (++terminate == worker_num) {
	    exit(0);
	}
}

void banner()
{
	printf("phrasen|drescher %s - the passphrase cracker\n", VERSION);
	printf("Copyright (C) 2008 Nico Leidecker; http://www.leidecker.info\n\n");
}

void list_plugins()
{
	DIR *dir;
	char *ext;
	struct dirent *entry;
	
	dir = opendir(plugin_dir);
	if (!dir) {
		error_printf("cannot open plugin directory %s: %s\n", 
			plugin_dir, strerror(errno));
		return;
	}
	
	while((entry = readdir(dir))) {
		// skip everything beginning with a dot
		if (*(entry->d_name) != '.') {
			ext = strrchr(entry->d_name, '.');
			if (ext && strcmp(ext, ".pd") == 0) {
				*ext = 0;
				printf("%s  ", entry->d_name);
			}
		}
	}
}

void usage(char *path)
{
	char **usg;
	char *info, *version, *author;
	
	printf("Usage: %s plugin [options]\n", path);
	
	// show plugin information
	if (plugin.name) {
		printf("\n Plugin '%s' loaded!\n", plugin.name);
		if ((version = dlsym(plugin.handle, "plugin_keyword_version"))) {
			printf(" Version: %s\n", version );
		} else {
		    error_printf("version in plugin not found\n");
		}
	
		if ((author = dlsym(plugin.handle, "plugin_keyword_author"))) {
			printf(" Author: %s\n", author);
		} else {
		    error_printf("author in plugin not found\n");
		}

		if (!(usg = dlsym(plugin.handle, "plugin_keyword_usage"))) {
			error_printf("plugin opts: %s\n", dlerror());
		} else {
			// show plugin options
			printf("\n Plugin Specific Options:\n");
			if (*usg && *(usg + 1)) {
				do {
					printf("    %s\t: %s\n", *usg, *(usg + 1));
					usg += 2;
				} while(*usg && *(usg + 1));
			} else {
				printf("    no options\n");
			}
		}
		
		if ((info = dlsym(plugin.handle, "plugin_keyword_info"))) {
		    printf("\n%s\n", info);
		} else {
		    printf("info text in plugin not found\n");
		}
		printf("-------------------------------------------------------------------------------\n");
	}
	
	printf("\n Available plugins:\n   ");
	list_plugins();
	printf("\n");
	
	printf("\n General Options:\n");
	printf("   h           : print this message\n");
	printf("   v           : verbose mode\n");
	printf("   i from[:to] : incremental mode beginning with word length `from'\n");
	printf("                 and going to `to'\n");
	printf("   d file      : run dictionary based with words from `file'\n");
	printf("   w number    : number of worker threads (default is one)\n");
	printf("   r rules     : specify rewriting rules for the dictionary mode:\n");
	printf("                   A = all characters upper case\n");
	printf("                   F = first character upper case\n");
	printf("                   L = last character upper case\n");
	printf("                   W = first letter of each word to upper case\n");
	printf("                   a = all characters lower case\n");
	printf("                   f = first character lower case\n");
	printf("                   l = last character lower case\n");
	printf("                   w = first letter of each word to lower case\n");
	printf("                   D = prepend digit\n");
	printf("                   d = append digit\n");
	printf("                   e = 1337 characters\n");
	printf("                   x = all rules\n\n");
	
	printf(" Environment Variables:\n");
#ifndef FIXED_PLUGIN_DIR
	printf("   PD_PLUGINS : the directory containing plugins\n");
	printf("                (current is %s)\n", plugin_dir);
#endif
	printf("   PD_CHARMAP : the characters for the incremental mode are\n");
	printf("                taken from a character list. A customized list\n");
	printf("                can be specified in the environment variable\n\n");
}

void teardown()
{
	reset_tty();
	printf("bye, bye...\n");
}


int
parse_opts(int argc, char **argv)
{
	int o;
	void (*plugin_verbose)();
	char *plugin_options;
	char options[256] = "hvi:d:r:w:";

	//verbose = 0;
	worker_num = 1;
	
	if ((plugin_options = dlsym(plugin.handle, "plugin_keyword_opts"))) {
		for (o = 0; o < strlen(options); o++) {
			if (options[o] != ':' && strchr(plugin_options, options[o])) {
				error_printf("option parameter `%c' from plugin is already used by p|d and will be ignored\n");
			}
		}
		strncat(options, plugin_options, sizeof(options) - strlen(options) - 1);
	} else {
		error_printf("plugin options not found\n");
	}
	
	opterr = 0;
	// parse options
	while((o = getopt(argc, argv, options)) != -1) {
		switch(o) {
			case 'h':
				return 0;
			case 'v':
				set_verbose();
				plugin_verbose = dlsym(plugin.handle, "set_verbose");
				plugin_verbose();
				break;
			case 'i':
				if (sscanf(optarg, "%i:%i",
					&source.un.incremental.from,
					&source.un.incremental.to) < 2) {
						source.un.incremental.from = atoi(optarg);
						source.un.incremental.to = atoi(optarg);
					}
            				// get the char map, if there is one
					source.mode = SOURCE_MODE_INCREMENTAL;
					break;
			case 'd':
				source.un.dictionary.path = strdup(optarg);
				source.mode = SOURCE_MODE_DICTIONARY;
				break;
			case 'r':
				while(*optarg) {
					switch(*optarg) {
						case 'A':
							source.un.dictionary.rules |= RULES_ALL_UPPER;
							break;
						case 'F':
							source.un.dictionary.rules |= RULES_FIRST_UPPER;
							break;
						case 'L':
							source.un.dictionary.rules |= RULES_LAST_UPPER;
							break;
						case 'W':
							source.un.dictionary.rules |= RULES_UPPER_WORD_BEGINNING;
							break;
						case 'a':
							source.un.dictionary.rules |= RULES_ALL_LOWER;
							break;
						case 'f':
							source.un.dictionary.rules |= RULES_FIRST_LOWER;
							break;
						case 'l':
							source.un.dictionary.rules |= RULES_LAST_LOWER;
							break;
						case 'w':
							source.un.dictionary.rules |= RULES_LOWER_WORD_BEGINNING;
							break;
						case 'D':
							source.un.dictionary.rules |= RULES_PREPEND_DIGIT;
							break;
						case 'd':
							source.un.dictionary.rules |= RULES_APPEND_DIGIT;
							break;
						case 'e':
							source.un.dictionary.rules |= RULES_1337;
							break;
						case 'x':
							source.un.dictionary.rules = RULES_ALL_UPPER
									|	RULES_FIRST_UPPER
									|	RULES_LAST_UPPER
									|	RULES_ALL_LOWER
									|	RULES_FIRST_LOWER
									|	RULES_LAST_LOWER
									|	RULES_PREPEND_DIGIT
									|	RULES_APPEND_DIGIT
									|	RULES_1337
									|	RULES_UPPER_WORD_BEGINNING
									|	RULES_LOWER_WORD_BEGINNING;
							break;
					}
					optarg++;
				}
				break;
			case 'w':
				worker_num = atoi(optarg);
				if (worker_num < 1) {
					worker_num = 1;
				}
				break;
			default:
				if (strchr(options, o)) {
					if (plugin.plugin_get_opts(o, optarg) == PLUGIN_RETURN_FAILURE) {
						return 0;
					}
				} else {
					error_printf("unrecognized option -%c\n", optopt);
					return 0;
				}
		}
	}
	
	return 1;
}

int load_plugin(char *name)
{
    char plugin_path[MAX_PATH_LENGTH];
//    int s;

//    for (s = 0; s < strlen(name); s++) {
//	if (strstr("\\\"$.%@", name[s])) {
//	    name[s] = '_';
//	}
//    }
    plugin.name = name;
    	
    sprintf(plugin_path, "%s/%s.pd", plugin_dir, plugin.name);
	
    plugin.handle = dlopen(plugin_path, RTLD_LAZY);
    if (!plugin.handle) {
    	error_printf("load plugin: %s\n", dlerror());
    	return 0;
    }
    if (!(plugin.plugin_init = dlsym(plugin.handle, "plugin_init"))) {
    	error_printf("load plugin: %s\n", dlerror());
    	return 0;
    }
    if (!(plugin.plugin_finish = dlsym(plugin.handle, "plugin_finish"))) {
    	error_printf("load plugin: %s\n", dlerror());
    	return 0;
    }
    if (!(plugin.plugin_get_opts = dlsym(plugin.handle, "plugin_get_opts"))) {
    	error_printf("load plugin: %s\n", dlerror());
    	return 0;
    }
    if (!(plugin.plugin_worker_init = dlsym(plugin.handle, "plugin_worker_init"))) {
    	error_printf("load plugin: %s\n", dlerror());
    	return 0;
    }
    if (!(plugin.plugin_worker_try_phrase = dlsym(plugin.handle, "plugin_worker_try_phrase"))) {
    	error_printf("load plugin: %s\n", dlerror());
    	return 0;
    }
    if (!(plugin.plugin_worker_finish = dlsym(plugin.handle, "plugin_worker_finish"))) {
    	error_printf("load plugin: %s\n", dlerror());
    	return 0;
    }

    return 1;
}

int main(int argc, char **argv)
{
	
	int i, st, pid;
	char *dir;
	
	banner();

	// get plugin directory from env
#ifndef FIXED_PLUGIN_DIR
	dir = getenv("PD_PLUGINS");
	if (dir) {
		strncpy(plugin_dir, dir, MAX_PATH_LENGTH);
	}
#endif

	// parse options and show usage
	if (argc <= 2) {
		if (argc == 1) {
			printf("Usage: %s plugin [options] credentials\n", *argv);
			printf("Please choose a plugin first or use -h for more help\n");
			printf("Available plugins:\n  ");  
			list_plugins();
#ifndef FIXED_PLUGIN_DIR
			printf("\n\nSet the plugin directory in the environment variable PD_PLUGINS if required.\n");
#endif
		} else {
			if (strcmp(argv[1], "-h") != 0) {
				// load plugin
				if (!load_plugin(argv[1])) {
					return -1;
				}
			}
			usage(*argv);
		}
		return 0;
	}

	if (!load_plugin(argv[1])) {
		return -1;
	}

	switch(parse_opts(argc - 1, argv + 1)) {
		case 0:
			usage(*argv);
			return 0;
		case -1:
			return 0;
	}

	// init plugin
	if (plugin.plugin_init(worker_num) == PLUGIN_RETURN_FAILURE) {
		error_printf("%s: plugin function returned with failure status\n", plugin.name);
		return -1;
	}

	terminate = 0;

	verbose_printf("\nplugin %s loaded. Running now (%i workers)...\n", plugin.name, worker_num);
	verbose_printf("--------------------------------------------------\n");

	signal(SIG_TERMINATE, signal_terminate);

	worker = (int *) malloc(worker_num * sizeof(int));
	// spawn worker processes
	for (i = 0; i < worker_num; i++) {
		pid = fork();
		if (pid == 0) {			 		
			switch(worker_run(i, worker_num, &plugin, &source, credentials)) {	
				case WORKER_RETURN_SUCCESS:
					// we're finished and send term signal to parent process
					kill(0, SIG_TERMINATE);
					break;
				case WORKER_RETURN_COMPLETED:
					exit(0);
				case WORKER_RETURN_FAILURE:
				default:
					error_printf("worker #%i run failed!\n", i);
			}
			exit(0);
		} else {
			worker[i] = pid;
		}
	}

	signal(SIGCHLD, signal_complete);
	signal(SIG_WORKER_STATS, signal_stats);

 
	atexit(teardown);
	prepare_tty();
	handle_user_input(worker_num);
	
	if (plugin.plugin_finish() == PLUGIN_RETURN_FAILURE) {
		error_printf("%s: could not finish\n", plugin.name);
		return -1;
	}

	while(worker_num--) {
		wait(&st);
	}
	
	printf("finished!\n");
	
	return 0;
}
