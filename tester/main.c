/* -----------------------------------------------------------------------------
 * The Cyberiada Ursula game engine CyberiadaML diagram checker
 *
 * The command line checker program
 *
 * Copyright (C) 2025 Alexey Fedoseev <aleksey@fedoseev.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/
 * ----------------------------------------------------------------------------- */

#include <stdio.h>
#include <stdlib.h>

#include "ursulacheck.h"

static void print_usage(const char* name)
{
	fprintf(stderr, "Usage: %s <config-file> <task-id> <salt> <graph-file>\n", name);
	fprintf(stderr, "\n");
}

int main(int argc, char** argv)
{
	const char *config_file = NULL, *task_id = NULL, *graph_file = NULL;
	int salt = 0;
	UrsulaCheckerData* checker = NULL;
	UrsulaCheckerResult result = 0;
	char* result_code = NULL;
	FILE* f = NULL;
	size_t graph_file_size = 0, bytes_read = 0;
	char* program_buffer = NULL;
	int res = 0;
	
	if (argc != 5) {
		print_usage(argv[0]);
		return 99;
	}

	config_file = argv[1];
	task_id = argv[2];
	salt = atoi(argv[3]);
	graph_file = argv[4];

	res = cyberiada_ursula_checker_init(&checker, config_file);
	if (res != URSULA_CHECK_NO_ERROR) {
		fprintf(stderr, "Cannot initialize Ursula checker library: %d\n", res);
		return res;
	}

	f = fopen(graph_file, "r");
	if (!f) {
		fprintf(stderr, "Cannot open graph file: %s\n", graph_file);
		cyberiada_ursula_checker_free(checker);		
		return 98;
	}

	fseek(f, 0, SEEK_END);
	graph_file_size = ftell(f);
	fseek(f, 0, SEEK_SET);
	program_buffer = (char*)malloc(sizeof(char) * graph_file_size + 1);

	bytes_read = 0;
	while(bytes_read < graph_file_size) {
		size_t bytes = fread(program_buffer + bytes_read, sizeof(char), graph_file_size - bytes_read, f);
		bytes_read += bytes;
	}
	program_buffer[graph_file_size] = 0;
	
	res = cyberiada_ursula_checker_check_program(checker,
												 task_id,
												 salt,
												 program_buffer,
												 &result,
												 &result_code);
	if (res != URSULA_CHECK_NO_ERROR) {
		fprintf(stderr, "Program checking error: %d\n", res);
	} else {
		printf("Checking completed!\n");
		printf("Result code: %d\n", result);
		printf("Code string: %s\n", result_code);
	}

	if (result_code) free(result_code);
	if (program_buffer) free(program_buffer);
	cyberiada_ursula_checker_free(checker);

	fclose(f);
	
	return res;
}
