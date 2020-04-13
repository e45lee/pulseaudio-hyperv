#ifndef foomessagehelperhfoo
#define foomessagehelperhfoo

/***
  This file is part of PulseAudio.

  PulseAudio is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  PulseAudio is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with PulseAudio; if not, see <http://www.gnu.org/licenses/>.
***/

#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>

#include <pulse/cdecl.h>
#include <pulse/version.h>

/** \file
 * Utility functions for reading and writing message parameters.
 * All read functions return a value from pa_message_params_error_code
 * and the read value in result (or *result for string functions).
 * The string read functions read_string() and read_raw() return a pointer
 * to a sub-string within the parameter list in *result, therefore the
 * string in *result must not be freed and is only valid within the
 * message handler callback function. If the string is needed outside
 * the callback, it must be copied using pa_xstrdup().
 * When a read function is called, the state pointer is advanced to the
 * next list element. The variable state points to should be initialized
 * to NULL before the first call.\n
 * Write functions operate on a pa_message_params structure which is a
 * wrapper for pa_strbuf. A parameter list or sub-list is started by a
 * call to begin_list() and ended by a call to end_list().
 * A pa_message_params structure must be converted to a string using
 * pa_message_params_to_string_free() before it can be passed to a
 * message handler. */

PA_C_DECL_BEGIN

/** Structure which holds a parameter list. Wrapper for pa_strbuf  \since 15.0 */
typedef struct pa_message_params pa_message_params;

/** Read function return values  \since 15.0 */
enum pa_message_params_error_code {
    /** No value (empty element) found for numeric or boolean value */
    PA_PARAMS_IS_NULL = -2,
    /** Error encountered while parsing a value */
    PA_PARAMS_PARSE_ERROR = -1,
    /** End of parameter list reached */
    PA_PARAMS_LIST_END = 0,
    /** Parsing successful */
    PA_PARAMS_OK = 1,
};

/** @{ \name Read functions */

/** Read a boolean from parameter list in c. \since 15.0 */
int pa_message_params_read_bool(char *c, bool *result, void **state);

/** Read a double from parameter list in c. \since 15.0 */
int pa_message_params_read_double(char *c, double *result, void **state);

/** Read an integer from parameter list in c. \since 15.0 */
int pa_message_params_read_int64(char *c, int64_t *result, void **state);

/** Read raw data from parameter list in c. Used to split a message parameter
 * string into list elements. The string returned in *result must not be freed.  \since 15.0 */
int pa_message_params_read_raw(char *c, char **result, void **state);

/** Read a string from a parameter list in c. Escaped curly braces and backslashes
 * will be unescaped. \since 15.0 */
int pa_message_params_read_string(char *c, const char **result, void **state);

/** Read an unsigned integer from parameter list in c. \since 15.0 */
int pa_message_params_read_uint64(char *c, uint64_t *result, void **state);

/** @} */

/** @{ \name Write functions */

/** Create a new pa_message_params structure.  \since 15.0 */
pa_message_params *pa_message_params_new(void);

/** Free a pa_message_params structure.  \since 15.0 */
void pa_message_params_free(pa_message_params *param);

/** Convert pa_message_params to string, free pa_message_params structure.  \since 15.0 */
char *pa_message_params_to_string_free(pa_message_params *param);

/** Start a list by writing an opening brace.  \since 15.0 */
void pa_message_params_begin_list(pa_message_params *param);

/** End a list by writing a closing brace.  \since 15.0 */
void pa_message_params_end_list(pa_message_params *param);

/** Append a boolean to parameter list. \since 15.0 */
void pa_message_params_write_bool(pa_message_params *param, bool value);

/** Append a double to parameter list. Precision gives the number of
 * significant digits. \since 15.0 */
void pa_message_params_write_double(pa_message_params *param, double value, int precision);

/** Append an integer to parameter list. \since 15.0 */
void pa_message_params_write_int64(pa_message_params *param, int64_t value);

/** Append string to parameter list. Curly braces and backslashes will be escaped.  \since 15.0 */
void pa_message_params_write_string(pa_message_params *param, const char *value);

/** Append raw string to parameter list. Used to write incomplete strings
 * or complete parameter lists (for example arrays). Adds curly braces around
 * the string if add_braces is true.  \since 15.0 */
void pa_message_params_write_raw(pa_message_params *param, const char *value, bool add_braces);

/** Append an unsigned integer to parameter list. \since 15.0 */
void pa_message_params_write_uint64(pa_message_params *param, uint64_t value);

/** @} */

PA_C_DECL_END

#endif
