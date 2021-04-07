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

#include "rules.h"
#include "dictionary.h"

void
rules_first_upper(char *word, void *arg)
{
	word[0] = toupper(word[0]);
}

void
rules_last_upper(char *word, void *arg)
{
	word[strlen(word) - 1] = toupper(word[strlen(word) - 1]);
}

void
rules_all_upper(char *word, void *arg)
{
	while(*word) {
		*word = toupper(*word);
		word++;
	}
}

void
rules_first_lower(char *word, void *arg)
{
	word[0] = tolower(word[0]);

}

void
rules_last_lower(char *word, void *arg)
{
	word[strlen(word) - 1] = tolower(word[strlen(word) - 1]);
}

void
rules_all_lower(char *word, void *arg)
{
	while(*word) {
		*word = tolower(*word);
		word++;
	}
}

void
rules_prepend_digit(char *word, void *arg)
{
	int len;
	int c;

	len = strlen(word);
	if (len < MAX_LINE_LENGTH - 1 && len > 0) {
		// move all bytes by one to the right
		for (c = len - 1; c >= 0; c--) {
			word[c + 1] = word[c];
		}
		word[0] = (*(int *) arg) + 48;
		word[len + 1] = '\0';
	}
}

void
rules_append_digit(char *word, void *arg)
{
	int len;
	
	len = strlen(word);

	if (len < MAX_LINE_LENGTH - 1) {
		word[len] = (*(int *) arg) + 48;
		word[len + 1] = '\0';
	}
}

void
rules_1337(char *word, void *arg)
{
	while(*word++) {
		switch(toupper(*word)) {
			case 'L':
				*word = '1';
				break;
			case 'E':
				*word = '3';
				break;
			case 'T':
				*word = '7';
				break;
			case 'S':
				*word = '5';
				break;
			case 'G':
				*word = '9';
				break;
			case 'O':
				*word = '0';
				break;
			case 'A':
				*word = '4';
				break;
		}
	}
}

void
rules_upper_word_beginning(char *word, void *arg)
{
	int c, len;

	len = strlen(word);
	word[0] = toupper(word[0]);
	
	for (c = 1; c < len; c++) {
		if (word[c] == ' ' && (c + 1) < len) {
			word[c + 1] = toupper(word[c + 1]);
		}
	}
}

void
rules_lower_word_beginning(char *word, void *arg)
{
	int c;

	word[0] = tolower(word[0]);
	
	for (c = 1; c < strlen(word); c++) {
		if (word[c] == ' ') {
			word[c-1] = tolower(word[c-1]);
		}
	}
}
