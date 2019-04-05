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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#include "worker.h"
#include "phrasendrescher.h"
#include "plugin.h"
#include "source.h"
#include "utils.h"

static int worker_id = -1;
static int nworker = 0;
static unsigned int nphrases = 0;
static unsigned long long kphrases = 0;
static char *latest_word;

extern int terminate;

void worker_stats(int signo)
{
    if (worker_id == 0){
    	if (!kphrases) {
	        printf("%u phrases (%i workers)  latest: %s\n", nphrases * nworker, nworker, latest_word);
    	} else {   
    		printf("%lluk phrases (%i workers)  latest: %s\n", kphrases, nworker, latest_word);
    	}
    }
}

int worker_run (int id, int worker_num, struct plugin_t *plugin, struct source_t *source, char *credentials)
{
    unsigned int w, word_num;
    char **word_buf;
    int (*try_phrase)(int, char *);

    worker_id = id;
    nworker = worker_num;

    signal(SIG_WORKER_STATS, worker_stats);

    if (!source_init(id, worker_num, source)) {
    	return WORKER_RETURN_FAILURE;
    }
	
    // allocate word buffer	
    word_buf = (char **) malloc(WORD_BUFFER_SIZE * sizeof(char *));
    for (w = 0; w < WORD_BUFFER_SIZE; w++) {
		word_buf[w] = (char *) malloc(MAX_WORD_LENGTH + 1);
    }
    
    plugin->plugin_worker_init(id);
    
    
    // set passphrase cracking function reference
    try_phrase = plugin->plugin_worker_try_phrase;

    // worker main loop
    while (((word_num = source_get_words(id, worker_num, WORD_BUFFER_SIZE, MAX_WORD_LENGTH, word_buf)) > 0) && terminate < worker_num) {
		for (w = 0; w < word_num; w++) {
		    
		    switch(try_phrase(id, word_buf[w])) {
	    	    case PLUGIN_RETURN_COMPLETED:
		    		return WORKER_RETURN_SUCCESS;
		    	case PLUGIN_RETURN_FAILURE:
		    		error_printf("an error occured while trying phrase '%s'\n", word_buf[w]);
		    		break;
		    	case PLUGIN_RETURN_SUCCESS:
		    		/* fall through */;
		    	default:
		    		/* do nothing */;
		    }
		    if ((++nphrases * worker_num) > 1000) {
		    	kphrases++;
		    	nphrases = 0;
		    }
		    latest_word = word_buf[w];
		}
    }
    
    plugin->plugin_worker_finish(id);
    
    return WORKER_RETURN_COMPLETED;
}

