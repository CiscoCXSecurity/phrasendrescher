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
#include <math.h>

#include "incremental.h"
#include "utils.h"

static int from, to;

static char *map = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789-_.,+:;!\"$%^&*()[]{}@#~'?/\\<>|";

static int *mi = 0;

static void                                                                                                                                 
incremental_reset(char *word, int length)                                                                                                   
{
	memset(word, map[0], length);
	word[length] = '\0';
	memset(mi, 0x00, length * sizeof(int));
	mi[length - 1] = -1;                                                                                                              
}
 
static int                                                                                                                                  
incremental_do(char *word, int length)                                                                                                      
{                                                                                                                                           
        while(length--) {                                                                                                                   
                word[length] = map[mi[length] + 1];                                                                                         
                if (mi[length] != strlen(map) - 1) {                                                                                        
                        mi[length]++;                                                                                                       
                        break;                                                                                                              
                } else {                                                                                                                    
                        word[length] = map[0];                                                                                              
                        mi[length] = 0;                                                                                                     
                        if (length == 0) {                                                                                                  
                                return 0;                                                                                                   
                        }                                                                                                                   
                }                                                                                                                           
        }                                                                                                                                   
                                                                                                                                            
        return 1;                                                                                                                           
} 

static int
incremental_fill_buffer(unsigned int buf_size, unsigned int max_word_length, char **buf, int skip)
{
    static int length = 0;
    static char *word;
    int w;

    if (length > to) {
		return 0;
    }

    if (length == 0) {
		word = (char *) malloc(max_word_length);
		length = from;
		incremental_reset(word, length);
    }

    // fill word buffer with words    
    for (w = 0; w < buf_size; w++) {
        if (!incremental_do(word, length)) {
    	    length++;
		    if (length > to) {
				return w;
	    	} else {
				incremental_reset(word, length);
	    	}
		} else {
			if (!skip) {
	 			strcpy(buf[w], word);
			}
		}
    }

    return w;
}

int incremental_get_words(int id, int worker_num, unsigned int buf_size, unsigned int max_word_length, char **buf)
{
	int word_num;
	
	incremental_fill_buffer(id * buf_size, max_word_length, 0, 1);
	
	word_num = incremental_fill_buffer(buf_size, max_word_length, buf, 0);
	
	incremental_fill_buffer((worker_num - id - 1) * buf_size, max_word_length, 0, 1);
	
	return word_num;
}

int incremental_init(int id, int worker_num, int inc_from, int inc_to, char *custom_map)
{	
	char *c1, *c2;
	
	from = inc_from;
	to = inc_to;

	if (custom_map) {
		// strip out double characters from the custom map
		for (c1 = custom_map; *c1; c1++) {
			for (c2 = c1 + 1; *c2; c2++) {
				if (*c1 == *c2) {
					memmove(c2, c2 + 1, strlen(c2 + 1));
					custom_map[strlen(custom_map) - 1] = 0;
					c2--;
				}
			}
		}
		map = custom_map;
		if (id == 0) {
			verbose_printf("using customized map: %s\n", map);
		}
	}

	
	mi = (int *) malloc(to * sizeof(int));

	return 1;
}
