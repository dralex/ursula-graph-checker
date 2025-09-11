/* -----------------------------------------------------------------------------
 * The Cyberiada Ursula game engine CyberiadaML diagram checker
 *
 * The C library header
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

#ifndef __URSULA_CHECK_H
#define __URSULA_CHECK_H

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------------
 * The internal structure
 * ----------------------------------------------------------------------------- */
	
struct _UrsulaCheckerData;
typedef struct _UrsulaCheckerData UrsulaCheckerData;

/* -----------------------------------------------------------------------------
 * The library checker result codes
 * ----------------------------------------------------------------------------- */
	
typedef char UrsulaCheckerResult; 


#define URSULA_CHECK_RESULT_CRITICAL 0
#define URSULA_CHECK_RESULT_ERROR    1
#define URSULA_CHECK_RESULT_PARTIAL  2
#define URSULA_CHECK_RESULT_OK       3

/* -----------------------------------------------------------------------------
 * The library error codes
 * ----------------------------------------------------------------------------- */
	
#define URSULA_CHECK_NO_ERROR       0
#define URSULA_CHECK_BAD_PARAMETERS 1
#define URSULA_CHECK_FORMAT_ERROR   2

/* -----------------------------------------------------------------------------
 * The checker library functions
 * ----------------------------------------------------------------------------- */

	/* Initialize the checker internal structure using the config file located
	   at the path from config_file */
	int cyberiada_ursula_checker_init(UrsulaCheckerData** checker, const char* config_file);
	
	/* Free the checker internal structure */
	int cyberiada_ursula_checker_free(UrsulaCheckerData* checker);

	/* Check the CyberiadaML program from the buffer in the context of the task.
       Returns the actual result and the encoded result string */
	int cyberiada_ursula_checker_check_program(UrsulaCheckerData* checker,
											   const char* task_id,
											   int salt,
											   const char* program_buffer,
											   UrsulaCheckerResult* result,
											   char** result_code);

#ifdef __cplusplus
}
#endif
    
#endif
