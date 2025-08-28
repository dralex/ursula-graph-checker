/* -----------------------------------------------------------------------------
 * The Cyberiada Ursula game engine CyberiadaML diagram checker
 *
 * The C library implementation
 *
 * Copyright (C) 2025 Alexey Fedoseev <aleksey@fedoseev.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/
 *
 * ----------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ursulacheck.h"
#include <cyberiada/cyberiadaml.h>
#include "sha256.h"

/* -----------------------------------------------------------------------------
 * The internal structure
 * ----------------------------------------------------------------------------- */

typedef struct _UrsulaCheckerTask {
	char*                         name;      /* task identifier */
	CyberiadaDocument*            valid_doc; /* the valid graphml document (w/o geometry) */
	struct _UrsulaCheckerTask*    next;
} UrsulaCheckerTask;

struct _UrsulaCheckerData {
	char*                         secret;
	UrsulaCheckerTask*            tasks;
};

#define MAX_STR_LEN   4096
#define DELIMITER     ':'
#define SECRET_STRING "secret"

/* -----------------------------------------------------------------------------
 * The checker library functions
 * ----------------------------------------------------------------------------- */

static int copy_string(char** target, size_t* size, const char* source)
{
	char* target_str;
	size_t strsize;
	if (!source) {
		*target = NULL;
		*size = 0;
		return URSULA_CHECK_NO_ERROR;
	}
	strsize = strlen(source);  
	if (strsize > MAX_STR_LEN - 1) {
		strsize = MAX_STR_LEN - 1;
	}
	target_str = (char*)malloc(strsize + 1);
	strncpy(target_str, source, strsize);
	target_str[strsize] = 0;
	*target = target_str;
	if (size) {
		*size = strsize;
	}
	return URSULA_CHECK_NO_ERROR;
}

int cyberiada_decode_buffer(CyberiadaDocument** doc, const char* buffer)
{
	int res;

	if (!doc || !buffer) {
		fprintf(stderr, "Bad parameters for decoding GraphML document\n");
		return URSULA_CHECK_BAD_PARAMETERS;
	}
	
	*doc = cyberiada_new_sm_document();
	res = cyberiada_decode_sm_document(*doc, buffer, strlen(buffer),
									   cybxmlCyberiada10, CYBERIADA_FLAG_SKIP_GEOMETRY);
	if (res != CYBERIADA_NO_ERROR) {
		fprintf(stderr, "Error while decodnig GraphML document: %d\n", res);
		cyberiada_destroy_sm_document(*doc);
		if (res == CYBERIADA_BAD_PARAMETER) {
			return URSULA_CHECK_BAD_PARAMETERS;
		} else {
			return URSULA_CHECK_FORMAT_ERROR;
		}
	}
	
	return URSULA_CHECK_NO_ERROR;
}

int cyberiada_read_graph_file(CyberiadaDocument** doc, const char* graphml_file)
{
	FILE*  f;
	char*  buffer;
	size_t buffer_size, size;
	int    res;

	if (!doc) {
		fprintf(stderr, "Bad document parameter for decoding GraphML file\n");
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	f = fopen(graphml_file, "r");

	if (!f) {
		fprintf(stderr, "Cannot open GraphML file %s for decoding\n", graphml_file);
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	fseek(f, 0, SEEK_END);
	buffer_size = size = ftell(f);
	fseek(f, 0, SEEK_SET);

	buffer = (char*)malloc(sizeof(char)* (buffer_size + 1));
	while(size > 0) {
		size_t r = fread(buffer, 1, size, f);
		if (r < size) {
			free(buffer);
			fclose(f);
			fprintf(stderr, "Cannot read GraphML file %s for decoding\n", graphml_file);
			return URSULA_CHECK_BAD_PARAMETERS;
		}
		size -= r;
	}
	buffer[buffer_size] = 0;

	res = cyberiada_decode_buffer(doc, buffer);
	
	free(buffer);
	fclose(f);
	
	return res;	
}

int cyberiada_ursula_checker_init(UrsulaCheckerData** checker, const char* config_file)
{
	FILE* cfg;
	char *buffer;
	int res;
	UrsulaCheckerTask* last_task = NULL;
	
	if (!checker || !config_file) {
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	cfg = fopen(config_file, "r");
	if (!cfg) {
		return URSULA_CHECK_BAD_PARAMETERS;		
	}
	buffer = (char*)malloc(sizeof(char) * MAX_STR_LEN);

	*checker = (UrsulaCheckerData*)malloc(sizeof(UrsulaCheckerData));
	memset(*checker, 0, sizeof(UrsulaCheckerData));
	
	while(!feof(cfg)) {
		size_t size = MAX_STR_LEN - 1;
		ssize_t strsize = getline(&buffer, &size, cfg);
		if (strsize != -1) {
			char *graphml;
			UrsulaCheckerTask* task;
			
			if (strsize > 0 && buffer[strsize - 1] == '\n') {
				buffer[strsize - 1] = 0;
			}

			graphml = strchr(buffer, DELIMITER);
			if (!graphml || !*(graphml + 1)) {
				/* skip bad lines */
				continue;
			}

			*graphml = 0;
			graphml++;

			if (strcmp(buffer, SECRET_STRING) == 0) {
				copy_string(&((*checker)->secret), NULL, graphml);
			} else {
				task = (UrsulaCheckerTask*)malloc(sizeof(UrsulaCheckerTask));
				memset(task, 0, sizeof(UrsulaCheckerTask));
				copy_string(&(task->name), NULL, buffer);
				
				res = cyberiada_read_graph_file(&(task->valid_doc), graphml);
				if (res != URSULA_CHECK_NO_ERROR) {
					if(task->name) free(task->name);
					free(task);
					continue;
				}
			
				if (!last_task) {
					(*checker)->tasks = task;
				} else {
					last_task->next = task;
				}
				last_task = task;
			}
		}
	}
	
	fclose(cfg);
	free(buffer);

	printf("Checker initialized:\n");
	printf("Secret: %s\n", (*checker)->secret);
	printf("Tasks:\n");
	last_task = (*checker)->tasks;
	while (last_task) {
		printf("\t%s\tSM %s\n",
			   last_task->name,
			   last_task->valid_doc->state_machines->nodes->id);
		last_task = last_task->next;
	}
	printf("\n");

	return URSULA_CHECK_NO_ERROR;
}
	
/* Free the checker internal structure */
int cyberiada_ursula_checker_free(UrsulaCheckerData* checker)
{
	UrsulaCheckerTask* task;
	
	if (!checker) {
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	task = checker->tasks;
	while(task) {
		UrsulaCheckerTask* next;
		next = task->next;
		if (task->name) free(task->name);
		cyberiada_destroy_sm_document(task->valid_doc);
		free(task);
		task = next;
	}
	if (checker->secret) free(checker->secret);
	free(checker);
	
	return URSULA_CHECK_NO_ERROR;
}

static char* generate_code(const char* secret, const char* task_name, int salt, UrsulaCheckerResult result)
{
	unsigned char hash[32];
	char* result_code = NULL;
	char buffer[MAX_STR_LEN];
	size_t i;
	int buffer_size = snprintf(buffer, MAX_STR_LEN, "%s:%s:%d:%d", secret, task_name, salt, (int)result);
	sha256_hash(hash, (unsigned char*)buffer, buffer_size);
	result_code = (char*)malloc(sizeof(char) * (32 * 2 + 1));
	for (i = 0; i < 32; i++) {
		snprintf(result_code + i * 2, 3, "%02x", hash[i]);
	}
	return result_code;
}

/* Check the CyberiadaML program from the buffer in the context of the task */
int cyberiada_ursula_checker_check_program(UrsulaCheckerData* checker,
										   const char* task_name,
										   int salt,
										   const char* program_buffer,
										   UrsulaCheckerResult* result,
										   char** result_code)
{
	int res;
	CyberiadaDocument* check_doc = NULL;
	UrsulaCheckerTask* task;

	int result_flags;
	size_t sm_diff_nodes_size = 0, sm2_new_nodes_size = 0, sm1_missing_nodes_size = 0,
		sm_diff_edges_size = 0, sm2_new_edges_size = 0, sm1_missing_edges_size = 0;
	CyberiadaNode *new_initial = NULL, **sm_diff_nodes = NULL, **sm1_missing_nodes = NULL, **sm2_new_nodes = NULL;
	CyberiadaEdge **sm_diff_edges = NULL, **sm2_new_edges = NULL, **sm1_missing_edges = NULL;
	size_t *sm_diff_nodes_flags = NULL, *sm_diff_edges_flags = NULL;
	size_t i;
	
	if (!checker || !task_name || !program_buffer) {
		fprintf(stderr, "Bad check program arguments!\n");
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	task = checker->tasks;
	while (task) {
		if (strcmp(task->name, task_name) == 0) {
			/* found! */
			break;
		}
		task = task->next;
	}
	if (!task) {
		fprintf(stderr, "Cannot find task with name %s\n", task_name);
		return URSULA_CHECK_BAD_PARAMETERS;
	}


	if ((res = cyberiada_decode_buffer(&check_doc, program_buffer)) != URSULA_CHECK_NO_ERROR) {
		fprintf(stderr, "Error while decoding GraphML document from buffer: %d\n", res);
		cyberiada_destroy_sm_document(check_doc);
		return URSULA_CHECK_FORMAT_ERROR;
	}

	if (!check_doc->state_machines || check_doc->state_machines->next) {
		/* only single SM is allowed */
		if (result) {
			*result = URSULA_CHECK_RESULT_ERROR;
		}
		if (result_code) {
			*result_code = generate_code(checker->secret, task_name, salt, *result);
		}
		cyberiada_destroy_sm_document(check_doc);
		return URSULA_CHECK_NO_ERROR;		
	}
	
	res = cyberiada_check_isomorphism(task->valid_doc->state_machines,
									  check_doc->state_machines, 1, 1,
									  &result_flags, &new_initial,
									  &sm_diff_nodes_size, &sm_diff_nodes, &sm_diff_nodes_flags,
									  &sm2_new_nodes_size, &sm2_new_nodes,
									  &sm1_missing_nodes_size, &sm1_missing_nodes,
									  &sm_diff_edges_size, &sm_diff_edges, &sm_diff_edges_flags,
									  &sm2_new_edges_size, &sm2_new_edges,
									  &sm1_missing_edges_size, &sm1_missing_edges);
	if (res != CYBERIADA_NO_ERROR) {
		fprintf(stderr, "Error while checking isomorphism: %d\n", res);
		cyberiada_destroy_sm_document(check_doc);
		if (res == CYBERIADA_BAD_PARAMETER) {			
			return URSULA_CHECK_BAD_PARAMETERS;
		} else {
			return URSULA_CHECK_FORMAT_ERROR;			
		}
	}
	
	if (result_flags & (CYBERIADA_ISOMORPH_FLAG_IDENTICAL |
						CYBERIADA_ISOMORPH_FLAG_EQUAL)) {
		if (result) {
			*result = URSULA_CHECK_RESULT_OK;
		}
	} else if (result_flags & CYBERIADA_ISOMORPH_FLAG_ISOMORPHIC_MASK) {
		
		int diff_actions = 0;

		for (i = 0; i < sm_diff_nodes_size; i++) {
			if (sm_diff_nodes_flags[i] & CYBERIADA_NODE_DIFF_ACTIONS) {
				fprintf(stderr, "node %s with diff actions found!\n", sm_diff_nodes[i]->id);
				diff_actions = 1;
				break;
			}
		}

		if (!diff_actions) {
			for (i = 0; i < sm_diff_edges_size; i++) {
				if (sm_diff_edges_flags[i] & CYBERIADA_NODE_DIFF_ACTIONS) {
					fprintf(stderr, "edge %s with diff actions found!\n", sm_diff_edges[i]->id);
					diff_actions = 1;
					break;
				}
			}
		}
		
		if (!diff_actions) {
			if (result) {
				*result = URSULA_CHECK_RESULT_OK;
			}
		} else {
			if (result) {
				*result = URSULA_CHECK_RESULT_PARTIAL;
			}
		}
	} else {
		if (result) {
			*result = URSULA_CHECK_RESULT_ERROR;
		}		
	}

	if (result_code) {
		*result_code = generate_code(checker->secret, task_name, salt, *result);
	}
	
	if (sm_diff_nodes) free(sm_diff_nodes);
	if (sm_diff_nodes_flags) free(sm_diff_nodes_flags);
	if (sm1_missing_nodes) free(sm1_missing_nodes);
	if (sm2_new_nodes) free(sm2_new_nodes);
	if (sm_diff_edges) free(sm_diff_edges);
	if (sm_diff_edges_flags) free(sm_diff_edges_flags);
	if (sm2_new_edges) free(sm2_new_edges);
	if (sm1_missing_edges) free(sm1_missing_edges);
	
	cyberiada_destroy_sm_document(check_doc);
	return URSULA_CHECK_NO_ERROR;		
}
