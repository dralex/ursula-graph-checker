/* -----------------------------------------------------------------------------
 * The Cyberiada Ursula game engine CyberiadaML diagram checker
 *
 * The SHA-256 hashing algorighm implementation test
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

#include "sha256.h"

#define MAX_BUFFER_SIZE 4096
#define SHA256_LEN      32

extern int calculate_hash(const char* buffer, char** hash);

int main()
{
	char buffer[MAX_BUFFER_SIZE + 1];
	size_t buffer_size = 0;
	unsigned char hash[SHA256_LEN];
	int i;

	while(!feof(stdin)) {
		size_t bytes = fread(buffer, sizeof(char), MAX_BUFFER_SIZE - buffer_size, stdin);
		buffer_size += bytes;
		if (buffer_size == MAX_BUFFER_SIZE) {
			break;
		}
	}
	buffer[buffer_size] = 0;
	/*printf("string: len %lu '%s'\n", buffer_size, buffer);*/
	sha256_hash((unsigned char*)hash, buffer, buffer_size);
	for (i = 0; i < SHA256_LEN; i++) {
		printf("%02x", hash[i]);
	}
	printf("\n");
	return 0;
}
