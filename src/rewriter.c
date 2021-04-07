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
#include <ctype.h>

#include "dictionary.h"
#include "rewriter.h"
#include "rules.h"
#include "source.h"

static unsigned int rules = 0x00000000;
static struct rule_set_t *rule_set = 0;

extern rules_map_t rules_map[];

static void rewriter_reset()
{
	if (!rule_set) {
		rule_set = (struct rule_set_t *) malloc(sizeof(struct rule_set_t));
	}
	
	rule_set->rules = rules;
	rule_set->remaining_runs = 0;
	rule_set->current_rule = -1;
}

void rewriter_add_rules(unsigned int r)
{
	rules |= r;
	rewriter_reset();
}

int rewriter_get(char *word)
{
    static char original_word[MAX_WORD_LENGTH];
    int r; 
    	
	if (word == '\0') {
		*original_word = '\0';
		rewriter_reset(rule_set);
		return 0;
	}
	
	// if a rule was done
	if (!rule_set->remaining_runs && rule_set->current_rule != -1) {
	    rule_set->rules &= ~rules_map[rule_set->current_rule].flag;
	    rule_set->current_rule = -1;
	}

	if (!rule_set->rules) {
		*original_word = '\0';
		rewriter_reset();
		return 0;
	}

	if (*original_word == '\0') {
		strncpy(original_word, word, MAX_WORD_LENGTH - 1);
	} else {
		// restore to original word for rule rewriting
		strncpy(word, original_word, MAX_WORD_LENGTH - 1);
	}

    if (rule_set->rules) {
	
		// find next rule
		if (rule_set->current_rule == -1) {
			r = 0;
			while (!(rule_set->rules & rules_map[r].flag)) {
				r++;
			}
			rule_set->current_rule = r;
			rule_set->remaining_runs = rules_map[r].runs;
		}
		
		// apply rule
		rule_set->remaining_runs--;
		rules_map[rule_set->current_rule].func(word, &(rule_set->remaining_runs));

		// skip rewritten words without any difference to the original word
		if (strcmp(word, original_word) == 0) {
			return -1;
		}
		
		return 1;
    }

    return 0;
}
