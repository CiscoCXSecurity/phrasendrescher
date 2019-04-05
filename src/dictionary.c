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
#include <pthread.h>

#include "dictionary.h"
#include "phrasendrescher.h"
#include "source.h"

#include "rewriter.h"
#include "rules.h"

// for dictionary based attack
static FILE *dfp;

static int use_rewriter;

int dictionary_get_words(int id, int worker_num, unsigned int buf_size, unsigned int max_word_length, char **buf)
{
	static int more_rewriting = 0;
	static char last_word[MAX_WORD_LENGTH];
	static unsigned int block_read = 0;
	int word_num, has_rewritten = 0;
	char *nl;
	char tmp[MAX_WORD_LENGTH];
	int skip;
	
	// get words
	for (word_num = 0; word_num < buf_size; word_num++) {
		if (more_rewriting) {
			has_rewritten = 0;
			do {
				more_rewriting = rewriter_get(last_word);
			} while (more_rewriting == -1);
			// append to buf
			if (more_rewriting) {
				strcpy(buf[word_num], last_word);
				has_rewritten = 1;
			} 
		} 
		if (!has_rewritten) {
			if (!fgets(buf[word_num], MAX_WORD_LENGTH, dfp)) {
				break;
			}
			// remove new line
			if ((nl = strrchr(buf[word_num], '\n'))) {
				*nl = '\0';
			}
			strncpy(last_word, buf[word_num], MAX_WORD_LENGTH);
			more_rewriting = use_rewriter;
			// if we read all lines of the workers block, we need to skip some
			if (++block_read == buf_size) {
				block_read = 0;
				skip = (worker_num - 1) * buf_size;
				while(skip--) {
					fgets(tmp, MAX_WORD_LENGTH, dfp);
				}
			}
		}
	}
	
	return word_num;
}

int dictionary_init(int id, int worker_num, char *path, int rules) 
{
	int w;
	char tmp[MAX_WORD_LENGTH];
	
	dfp = fopen(path, "r");
	if (!dfp) {
		return 0;
	}

 	// skip initial number of words
 	for (w = id * WORD_BUFFER_SIZE; w > 0; w--) {
		fgets(tmp, MAX_WORD_LENGTH, dfp);
    }

	if (rules != 0) {
		use_rewriter = 1;
		rewriter_add_rules(rules);
	}
	
	return 1;
}
