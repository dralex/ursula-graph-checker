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

#ifdef __DEBUG__
#include <stdio.h>
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

#ifndef __SILENT__
#include <stdio.h>
#define ERROR(...) fprintf(stderr, __VA_ARGS__)
#else
#define ERROR(...)
#endif

/* -----------------------------------------------------------------------------
 * The internal structure
 * ----------------------------------------------------------------------------- */

#define CYBML_DELTA_ARG             CYBERIADA_ACTION_DIFF_BEHAVIOR_ARG
#define CYBML_DELTA_ORDER           CYBERIADA_ACTION_DIFF_BEHAVIOR_ORDER
#define CYBML_DELTA_ACTION          CYBERIADA_ACTION_DIFF_BEHAVIOR_ACTION
#define CYBML_DELTA_MISS            0x8
#define CYBML_DELTA_EDGETO          0x10

#define CYBML_DELTA_ARG_STR         "ARG"
#define CYBML_DELTA_ORDER_STR       "ORDER"
#define CYBML_DELTA_ACTION_STR      "ACTION"
#define CYBML_DELTA_MISS_STR        "MISS"
#define CYBML_DELTA_EDGETO_STR      "EDGETO"

#define CYBML_DELTA_PREFIX_ALLOWED  '+'
#define CYBML_DELTA_PREFIX_REQUIRED '~'

typedef struct _UrsulaCheckerDelta {
    char*                           node_id;
	int                             allowed_flags;
	int                             required_flags;
	struct _UrsulaCheckerDelta*     next;
} UrsulaCheckerDelta;

typedef struct _UrsulaCheckerTask {
	char*                           name;      /* task identifier */
	CyberiadaDocument*              valid_doc; /* the valid graphml document (w/o geometry) */
	UrsulaCheckerDelta*             deltas;    /* allowed/required deltas in the document */
	struct _UrsulaCheckerTask*      next;
} UrsulaCheckerTask;

struct _UrsulaCheckerData {
	char*                           secret;    /* the global secret */
	UrsulaCheckerTask*              tasks;
};

#define MAX_STR_LEN      4096
#define DELIMITER        ':'
#define SECRET_STRING    "secret"
#define DELTA_DELIMITERS "|"

#define MIN(a,b)         (((a)<(b))?(a):(b))

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

static int cyberiada_decode_buffer(CyberiadaDocument** doc, const char* buffer)
{
	int res;

	if (!doc || !buffer) {
		ERROR("Bad parameters for decoding GraphML document\n");
		return URSULA_CHECK_BAD_PARAMETERS;
	}
	
	*doc = cyberiada_new_sm_document();
	res = cyberiada_decode_sm_document(*doc, buffer, strlen(buffer),
									   cybxmlCyberiada10,
									   CYBERIADA_FLAG_SKIP_GEOMETRY | CYBERIADA_FLAG_SKIP_EMPTY_BEHAVIOR);
	if (res != CYBERIADA_NO_ERROR) {
		ERROR("Error while decodnig GraphML document: %d\n", res);
		cyberiada_destroy_sm_document(*doc);
		if (res == CYBERIADA_BAD_PARAMETER) {
			return URSULA_CHECK_BAD_PARAMETERS;
		} else {
			return URSULA_CHECK_FORMAT_ERROR;
		}
	}
	
	return URSULA_CHECK_NO_ERROR;
}

static int cyberiada_read_graph_file(CyberiadaDocument** doc, const char* graphml_file)
{
	FILE*  f;
	char*  buffer;
	size_t buffer_size, size;
	int    res;

	if (!doc) {
		ERROR("Bad document parameter for decoding GraphML file\n");
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	f = fopen(graphml_file, "r");

	if (!f) {
		ERROR("Cannot open GraphML file %s for decoding\n", graphml_file);
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
			ERROR("Cannot read GraphML file %s for decoding\n", graphml_file);
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

static int cyberiada_collect_deltas(UrsulaCheckerDelta** deltas, CyberiadaNode* nodes)
{
	CyberiadaNode* n;
	int res;
	
	if (!deltas) {
		return URSULA_CHECK_BAD_PARAMETERS;
	}
	
	for (n = nodes; n; n = n->next) {
		if (n->title) {
			/* DEBUG("Collect deltas %s for %s\n", n->title, n->id); */
			int allowed_flags = 0, required_flags = 0;
			char *s = strtok(n->title, DELTA_DELIMITERS);
			s = strtok(NULL, DELTA_DELIMITERS); /* go to the second token */
			while(s) {
				int flag = 0;
				if (strstr(s, CYBML_DELTA_ARG_STR)) {
					flag = CYBML_DELTA_ARG;
				} else if (strstr(s, CYBML_DELTA_ORDER_STR)) {
					flag = CYBML_DELTA_ORDER;
				} else if (strstr(s, CYBML_DELTA_MISS_STR)) {
					flag = CYBML_DELTA_MISS;
				} else if (strstr(s, CYBML_DELTA_EDGETO_STR)) {
					flag = CYBML_DELTA_EDGETO;
				} else if (strstr(s, CYBML_DELTA_ACTION_STR)) {
					flag = CYBML_DELTA_ACTION;
				} else {
					ERROR("Error while collecting deltas: unknown token %s in the node %s",
						  s, n->id);
					return URSULA_CHECK_BAD_PARAMETERS;
				}
				if (*s == CYBML_DELTA_PREFIX_ALLOWED) {
					allowed_flags |= flag;
				} else if (*s == CYBML_DELTA_PREFIX_REQUIRED) {
					required_flags |= flag;
				} else {
					ERROR("Error while collecting deltas: unknown token prefix %c in the node %s",
						  *s, n->id);
					return URSULA_CHECK_BAD_PARAMETERS;
				}
				s = strtok(NULL, DELTA_DELIMITERS);
			}
			if (allowed_flags || required_flags) {
				UrsulaCheckerDelta* d = (UrsulaCheckerDelta*)malloc(sizeof(UrsulaCheckerDelta));
				memset(d, 0, sizeof(UrsulaCheckerDelta));
				copy_string(&(d->node_id), NULL, n->id);
				d->allowed_flags = allowed_flags;
				d->required_flags = required_flags;
				if (*deltas) {
					UrsulaCheckerDelta* last = *deltas;
					while (last->next) last = last->next;
					last->next = d;
				} else {
					*deltas = d;
				}
				/* DEBUG("\tAdd deltas a: %d r: %d\n", allowed_flags, required_flags); */
			}
		}
		if (n->children) {
			if ((res = cyberiada_collect_deltas(deltas, n->children)) != URSULA_CHECK_NO_ERROR) {
				return res;
			}
		}
	}
	
	return URSULA_CHECK_NO_ERROR;
}

static int cyberiada_node_deltas_flags(UrsulaCheckerDelta* deltas, const char* node_id, int* allowed_flags, int* required_flags)
{
	if (!node_id) {
		return URSULA_CHECK_BAD_PARAMETERS;		
	}

	while (deltas) {
		if (strcmp(deltas->node_id, node_id) == 0) {
			if (allowed_flags) *allowed_flags = deltas->allowed_flags; 
			if (required_flags) *required_flags = deltas->required_flags;
			return URSULA_CHECK_NO_ERROR;
		}
		deltas = deltas->next;
	}

	return URSULA_CHECK_BAD_PARAMETERS;	
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
		ERROR("Cannot open config file %s\n", config_file);
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
				if ((*checker)->secret) {
					ERROR("Trying to inialize the checker secret twice!\n");
					free(*checker);
					fclose(cfg);
					free(buffer);
					return URSULA_CHECK_BAD_PARAMETERS;
				}
				copy_string(&((*checker)->secret), NULL, graphml);
			} else {
				task = (UrsulaCheckerTask*)malloc(sizeof(UrsulaCheckerTask));
				memset(task, 0, sizeof(UrsulaCheckerTask));
				copy_string(&(task->name), NULL, buffer);
				
				res = cyberiada_read_graph_file(&(task->valid_doc), graphml);
				if (res != URSULA_CHECK_NO_ERROR) {
					ERROR("Cannot read graph file %s from config: %d\n", graphml, res);
					if(task->name) free(task->name);
					free(task);
					continue;
				}
				if (task->valid_doc->state_machines) {
					cyberiada_collect_deltas(&(task->deltas),
											 task->valid_doc->state_machines->nodes);
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

	DEBUG("Checker initialized:\n");
	DEBUG("Secret: %s\n", (*checker)->secret);
	DEBUG("Tasks:\n");
	last_task = (*checker)->tasks;
	while (last_task) {
		UrsulaCheckerDelta* d;
		
		DEBUG("\t%s\tSM %s\n",
			  last_task->name,
			  last_task->valid_doc->state_machines->nodes->id);
		DEBUG("\tDeltas:\n");
		d = last_task->deltas;
		while (d) {
			DEBUG("\t\t%s", d->node_id);
			if (d->allowed_flags) {
				int allowed_flags = d->allowed_flags;
				DEBUG(" allowed: ");
				if (allowed_flags & CYBML_DELTA_ARG) {
					DEBUG("A");
				}
				if (allowed_flags & CYBML_DELTA_ORDER) {
					DEBUG("O");
				}
				if (allowed_flags & CYBML_DELTA_MISS) {
					DEBUG("M");
				}
				if (allowed_flags & CYBML_DELTA_EDGETO) {
					DEBUG("E");
				}
				if (allowed_flags & CYBML_DELTA_ACTION) {
					DEBUG("C");
				}
			}
			if (d->required_flags) {
				int required_flags = d->required_flags;
				DEBUG(" required: ");
				if (required_flags & CYBML_DELTA_ARG) {
					DEBUG("A");
				}
				if (required_flags & CYBML_DELTA_ORDER) {
					DEBUG("O");
				}
				if (required_flags & CYBML_DELTA_MISS) {
					DEBUG("M");
				}
				if (required_flags & CYBML_DELTA_EDGETO) {
					DEBUG("E");
				}
				if (required_flags & CYBML_DELTA_ACTION) {
					DEBUG("C");
				}
			}
			DEBUG("\n");
			d = d->next;
		}
		last_task = last_task->next;
	}
	DEBUG("\n");
	
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
		while (task->deltas) {
			UrsulaCheckerDelta* d = task->deltas;
			task->deltas = task->deltas->next;
			free(d->node_id);
			free(d);
		}
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
	CyberiadaNode *new_initial = NULL, **sm1_missing_nodes = NULL, **sm2_new_nodes = NULL;
	CyberiadaNodePair *sm_diff_nodes = NULL;
	CyberiadaEdge **sm2_new_edges = NULL, **sm1_missing_edges = NULL;
	CyberiadaEdgePair *sm_diff_edges = NULL;
	size_t *sm_diff_nodes_flags = NULL, *sm_diff_edges_flags = NULL;
	size_t i;
	
	if (!checker || !task_name || !program_buffer) {
		ERROR("Bad check program arguments!\n");
		if (result) {
			*result = URSULA_CHECK_RESULT_CRITICAL;
		}
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
		ERROR("Cannot find task with name %s\n", task_name);
		if (result) {
			*result = URSULA_CHECK_RESULT_CRITICAL;
		}
		return URSULA_CHECK_BAD_PARAMETERS;
	}

	if ((res = cyberiada_decode_buffer(&check_doc, program_buffer)) != URSULA_CHECK_NO_ERROR) {
		ERROR("Error while decoding GraphML document from buffer: %d\n", res);
		if (result) {
			*result = URSULA_CHECK_RESULT_CRITICAL;
		}
		return URSULA_CHECK_FORMAT_ERROR;
	}

	if (!check_doc->state_machines || check_doc->state_machines->next || !check_doc->state_machines->nodes) {
		/* only single SM is allowed */
		cyberiada_destroy_sm_document(check_doc);
		if (result) {
			*result = URSULA_CHECK_RESULT_CRITICAL;
		}
		return URSULA_CHECK_NO_ERROR;		
	}

	DEBUG("Comparing graphs %s and %s\n",
		  task->valid_doc->state_machines->nodes->id,
		  check_doc->state_machines->nodes->id);
	
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
		ERROR("Error while checking isomorphism: %d\n", res);
		cyberiada_destroy_sm_document(check_doc);
		if (result) {
			*result = URSULA_CHECK_RESULT_CRITICAL;
		}
		if (res == CYBERIADA_BAD_PARAMETER) {			
			return URSULA_CHECK_BAD_PARAMETERS;
		} else {
			return URSULA_CHECK_FORMAT_ERROR;			
		}
	}

	DEBUG("Isomorphism check results: %d\n", result_flags);
	
	if (result_flags & (CYBERIADA_ISOMORPH_FLAG_IDENTICAL |
						CYBERIADA_ISOMORPH_FLAG_EQUAL)) {
		DEBUG("Graphs are identical/equal\n");
		/* The presented graph is actually the same as the required */
		if (result) {
			*result = URSULA_CHECK_RESULT_OK;
		}
	} else if (result_flags & CYBERIADA_ISOMORPH_FLAG_DIFF_INITIAL) {
		/* The presented graph has different edges or different initial state - not valid */
		DEBUG("Graphs have different initial states\n");
		if (result) {
			*result = URSULA_CHECK_RESULT_ERROR;
		}	
	} else {
		UrsulaCheckerResult r = URSULA_CHECK_RESULT_OK;

		if (result_flags != CYBERIADA_ISOMORPH_FLAG_ISOMORPHIC) {
			if (sm1_missing_edges_size > 0) {
				int permitted = 1;
				DEBUG("Missing edges found:\n");
				for (i = 0; i < sm1_missing_edges_size; i++) {
					int allowed_flags, required_flags;
					const char* source_id = sm1_missing_edges[i]->source->id;
					const char* target_id = sm1_missing_edges[i]->target->id;
					DEBUG("\tedge %s\n", sm1_missing_edges[i]->id);
					allowed_flags = required_flags = 0;
					cyberiada_node_deltas_flags(task->deltas, source_id,
												&allowed_flags, &required_flags);
					if (allowed_flags & CYBML_DELTA_MISS) {
						continue;
					} else if (required_flags & CYBML_DELTA_MISS) {
						DEBUG("Required missing source node found\n");
					} else {
						DEBUG("Permitted missing source node found\n");
						r = URSULA_CHECK_RESULT_ERROR;
						break;
					}
					allowed_flags = required_flags = 0;
					cyberiada_node_deltas_flags(task->deltas, target_id,
												&allowed_flags, &required_flags);
					if (allowed_flags & CYBML_DELTA_MISS) {
						continue;
					} else if (required_flags & CYBML_DELTA_MISS) {
						DEBUG("Required missing target node found\n");
					} else {
						DEBUG("Permitted missing target node found\n");
						r = URSULA_CHECK_RESULT_ERROR;
						break;
					}					
				}
				if (!permitted) {
					r = URSULA_CHECK_RESULT_ERROR;
				} else {
					r = URSULA_CHECK_RESULT_PARTIAL;
				}
			} else if (sm2_new_edges_size > 0) {
				DEBUG("New edges found:\n");
				for (i = 0; i < sm2_new_edges_size; i++) {
					DEBUG("\tedge %s\n", sm2_new_edges[i]->id);
				}
				r = URSULA_CHECK_RESULT_ERROR;
			} else {
				for (i = 0; i < sm1_missing_nodes_size; i++) {
					int allowed_flags = 0, required_flags = 0;
					cyberiada_node_deltas_flags(task->deltas, sm1_missing_nodes[i]->id,
												&allowed_flags, &required_flags);
					if (allowed_flags & CYBML_DELTA_MISS) {
						continue;
					} else if (required_flags & CYBML_DELTA_MISS) {
						DEBUG("Required missing node found\n");
						r = URSULA_CHECK_RESULT_PARTIAL;
					} else {
						DEBUG("Permitted missing node found\n");
						r = URSULA_CHECK_RESULT_ERROR;
						break;
					}
				}
			}
		}

		if (r != URSULA_CHECK_RESULT_ERROR) {
			for (i = 0; i < sm_diff_nodes_size; i++) {
				DEBUG("Found nodes %s [%s] and %s [%s]: %ld\n",
					  sm_diff_nodes[i].n1->id, sm_diff_nodes[i].n1->title,
					  sm_diff_nodes[i].n2->id, sm_diff_nodes[i].n2->title,
					  sm_diff_nodes_flags[i]);
				if (sm_diff_nodes_flags[i] == CYBERIADA_NODE_DIFF_TITLE) {
					continue;
				}
				if (sm_diff_nodes_flags[i] & CYBERIADA_NODE_DIFF_ACTIONS) {
					int allowed_flags = 0, required_flags = 0, flags = 0;
					cyberiada_node_deltas_flags(task->deltas, sm_diff_nodes[i].n1->id,
												&allowed_flags, &required_flags);
					cyberiada_compare_node_actions(sm_diff_nodes[i].n1->actions,
												   sm_diff_nodes[i].n2->actions,
												   &flags);
					DEBUG("Comparing node %s [%s] and %s [%s] actions: %d\n",
						  sm_diff_nodes[i].n1->id, sm_diff_nodes[i].n1->title,
						  sm_diff_nodes[i].n2->id, sm_diff_nodes[i].n2->title,
						  flags);
					if (flags & ~allowed_flags & ~required_flags) {
						r = URSULA_CHECK_RESULT_ERROR;
						break;					
					} else if (flags & ~allowed_flags & required_flags) {
						r = URSULA_CHECK_RESULT_PARTIAL;
					}
				}
			}
		}
		
/*		for (i = 0; i < sm_diff_edges_size; i++) {
			if (sm_diff_edges_flags[i] & CYBERIADA_NODE_DIFF_ACTIONS) {
				fprintf(stderr, "edge %s with diff actions found!\n", sm_diff_edges[i].e1->id);
				diff_actions = 1;
				break;
			}
			}*/
		
		if (result) {
			*result = r;
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
