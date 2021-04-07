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
#include <string.h>
#include <errno.h>

#include "source.h"
#include "phrasendrescher.h"
#include "utils.h"
#include "dictionary.h"
#include "incremental.h"

static int (*source_callback)(int id, int worker_num, unsigned int buf_size, unsigned int max_word_length, char **buf) = 0;

int source_init(int id, int worker_num, struct source_t *source)
{
	if (source->mode == -1) {
		if (id == 0) {
			error_printf("source not explicitely specified; assuming incremental from 1 to 8.\n");
			source->mode = SOURCE_MODE_INCREMENTAL;
			source->un.incremental.from = 1;
			source->un.incremental.to = 8;
			
		}
	}
	
	switch(source->mode) {
		case SOURCE_MODE_DICTIONARY:
			if (!dictionary_init(id, worker_num, source->un.dictionary.path, source->un.dictionary.rules)) {
				if (id == 0) {
					error_printf("could not load dictionary %s: %s\n", source->un.dictionary.path, strerror(errno));
				}
				return 0;
			}
			
			source_callback = dictionary_get_words;
			
			if (id == 0) {
				verbose_printf("mode: dictionary (%s)\n",
						   						source->un.dictionary.path);
			}
			break;
		case SOURCE_MODE_INCREMENTAL:
			if (!incremental_init(id, worker_num, source->un.incremental.from,
				 						source->un.incremental.to,
				 							getenv("PD_CHARMAP"))) {
				if (id == 0) {
					error_printf("could not initialize incremental mode\n");
				}
				return 0;
			}

			source_callback = incremental_get_words;
			
			if (id == 0) {
				verbose_printf("mode: incremental from %i to %i\n",
											source->un.incremental.from,
												source->un.incremental.to);
			}
			break;
	}
	
	return 1;
}


int source_get_words(int id, int worker_num, unsigned int buf_size, unsigned int max_word_length, char **buf)
{
	return source_callback(id, worker_num, buf_size, max_word_length, buf);
}

