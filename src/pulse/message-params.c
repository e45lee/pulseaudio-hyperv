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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <sys/types.h>

#include <pulse/xmalloc.h>

#include <pulsecore/macro.h>
#include <pulsecore/strbuf.h>
#include <pulsecore/core-util.h>

#include "message-params.h"

/* Message parameter structure, a wrapper for pa_strbuf */
struct pa_message_params {
    pa_strbuf *buffer;
};

/* Helper functions */

/* Count number of top level elements in parameter list */
static int count_elements(const char *c) {
    const char *s;
    uint32_t element_count;
    bool found_element, found_backslash;
    int open_braces;

    if (!c || *c == 0)
        return PA_PARAMS_LIST_END;

    element_count = 0;
    open_braces = 0;
    found_element = false;
    found_backslash = false;
    s = c;

    /* Count elements in list */
    while (*s != 0) {

        /* Skip escaped curly braces. */
        if (*s == '\\' && !found_backslash) {
            found_backslash = true;
            s++;
            continue;
        }

        if (*s == '{' && !found_backslash) {
            found_element = true;
            open_braces++;
        }
        if (*s == '}' && !found_backslash)
            open_braces--;

        /* unexpected closing brace, parse error */
        if (open_braces < 0)
            return PA_PARAMS_PARSE_ERROR;

        if (open_braces == 0 && found_element) {
            element_count++;
            found_element = false;
        }

        found_backslash = false;
        s++;
    }

    /* missing closing brace, parse error */
    if (open_braces > 0)
        return PA_PARAMS_PARSE_ERROR;

    return element_count;
}

/* Split the specified string into elements. An element is defined as
 * a sub-string between curly braces. The function is needed to parse
 * the parameters of messages. Each time it is called it returns the
 * position of the current element in result and the state pointer is
 * advanced to the next list element. On return, the parameter
 * *is_unpacked indicates if the string is plain text or contains a
 * sub-list. is_unpacked may be NULL.
 *
 * The variable state points to, should be initialized to NULL before
 * the first call. The function returns 1 on success, 0 if end of string
 * is encountered and -1 on parse error.
 *
 * result is set to NULL on end of string or parse error. */
static int split_list(char *c, char **result, bool *is_unpacked, void **state) {
    char *current = *state ? *state : c;
    uint32_t open_braces;
    bool found_backslash = false;

    pa_assert(result);

    *result = NULL;

    /* Empty or no string */
    if (!current || *current == 0)
        return PA_PARAMS_LIST_END;

    /* Find opening brace */
    while (*current != 0) {

        /* Skip escaped curly braces. */
        if (*current == '\\' && !found_backslash) {
            found_backslash = true;
            current++;
            continue;
        }

        if (*current == '{' && !found_backslash)
            break;

        /* unexpected closing brace, parse error */
        if (*current == '}' && !found_backslash)
            return PA_PARAMS_PARSE_ERROR;

        found_backslash = false;
        current++;
    }

    /* No opening brace found, end of string */
    if (*current == 0)
        return PA_PARAMS_LIST_END;

    if (is_unpacked)
        *is_unpacked = true;
    *result = current + 1;
    found_backslash = false;
    open_braces = 1;

    while (open_braces != 0 && *current != 0) {
        current++;

        /* Skip escaped curly braces. */
        if (*current == '\\' && !found_backslash) {
            found_backslash = true;
            continue;
        }

        if (*current == '{' && !found_backslash) {
            open_braces++;
            if (is_unpacked)
                *is_unpacked = false;
        }
        if (*current == '}' && !found_backslash)
            open_braces--;

        found_backslash = false;
    }

    /* Parse error, closing brace missing */
    if (open_braces != 0) {
        *result = NULL;
        return PA_PARAMS_PARSE_ERROR;
    }

    /* Replace } with 0 */
    *current = 0;

    *state = current + 1;

    return PA_PARAMS_OK;
}

/* Read functions */

/* Read a string from the parameter list. The state pointer is
 * advanced to the next element of the list. Returns a pointer
 * to a sub-string within c. Escape characters will be removed
 * from the string. The result must not be freed. */
int pa_message_params_read_string(char *c, const char **result, void **state) {
    char *start_pos;
    char *value = NULL;
    int r;
    bool is_unpacked = true;

    pa_assert(result);

    if ((r = split_list(c, &start_pos, &is_unpacked, state)) == PA_PARAMS_OK)
        value = start_pos;

    /* Check if we got a plain string not containing further lists */
    if (!is_unpacked) {
        /* Parse error */
        r = PA_PARAMS_PARSE_ERROR;
        value = NULL;
    }

    if (value)
        *result = pa_unescape(value);

    return r;
}

/* A wrapper for split_list() to distinguish between reading pure
 * string data and raw data which may contain further lists. */
int pa_message_params_read_raw(char *c, char **result, void **state) {
    return split_list(c, result, NULL, state);
}

/* Read a double from the parameter list. The state pointer is
 * advanced to the next element of the list. */
int pa_message_params_read_double(char *c, double *result, void **state) {
    char *start_pos, *end_pos, *s;
    int err;
    struct lconv *locale;
    double value;
    bool is_unpacked = true;

    pa_assert(result);

    if ((err = split_list(c, &start_pos, &is_unpacked, state)) != PA_PARAMS_OK)
        return err;

    /* Empty element */
    if (!*start_pos)
        return PA_PARAMS_IS_NULL;

    /* Check if we got a plain string not containing further lists */
    if (!is_unpacked)
        return PA_PARAMS_PARSE_ERROR;

    /* Get decimal separator for current locale */
    locale = localeconv();

    /* Replace decimal point with the correct character for the
     * current locale. This assumes that no thousand separator
     * is used. */
    for (s = start_pos; *s; s++) {
        if (*s == '.' || *s == ',')
            *s = *locale->decimal_point;
     }

    /* Convert to double */
    errno = 0;
    value = strtod(start_pos, &end_pos);

    /* Conversion error or string contains invalid characters. If the
     * whole string was used for conversion, end_pos should point to
     * the end of the string. */
    if (errno != 0 || *end_pos != 0 || end_pos == start_pos)
        return PA_PARAMS_PARSE_ERROR;

    *result = value;
    return PA_PARAMS_OK;
}

/* Read an integer from the parameter list. The state pointer is
 * advanced to the next element of the list. */
int pa_message_params_read_int64(char *c, int64_t *result, void **state) {
    char *start_pos;
    int err;
    int64_t value;
    bool is_unpacked = true;

    pa_assert(result);

    if ((err = split_list(c, &start_pos, &is_unpacked, state)) != PA_PARAMS_OK)
        return err;

    /* Empty element */
    if (!*start_pos)
        return PA_PARAMS_IS_NULL;

    /* Check if we got a plain string not containing further lists */
    if (!is_unpacked)
        return PA_PARAMS_PARSE_ERROR;

    /* Convert to int64 */
    if ((err = pa_atoi64(start_pos, &value)) < 0)
        return PA_PARAMS_PARSE_ERROR;

    *result = value;
    return PA_PARAMS_OK;
}

/* Read an unsigned integer from the parameter list. The state pointer is
 * advanced to the next element of the list. */
int pa_message_params_read_uint64(char *c, uint64_t *result, void **state) {
    char *start_pos;
    int err;
    uint64_t value;
    bool is_unpacked = true;

    pa_assert(result);

    if ((err = split_list(c, &start_pos, &is_unpacked, state)) != PA_PARAMS_OK)
        return err;

    /* Empty element */
    if (!*start_pos)
        return PA_PARAMS_IS_NULL;

    /* Check if we got a plain string not containing further lists */
    if (!is_unpacked)
        return PA_PARAMS_PARSE_ERROR;

    /* Convert to int64 */
    if ((err = pa_atou64(start_pos, &value)) < 0)
        return PA_PARAMS_PARSE_ERROR;

    *result = value;
    return PA_PARAMS_OK;
}

/* Read a boolean from the parameter list. The state pointer is
 * advanced to the next element of the list. */
int pa_message_params_read_bool(char *c, bool *result, void **state) {
    int err;
    uint64_t value;

    pa_assert(result);

    if ((err = pa_message_params_read_uint64(c, &value, state)) != PA_PARAMS_OK)
        return err;

    *result = false;
    if (value)
        *result = true;

    return PA_PARAMS_OK;
}

/* Converts a parameter list to a string array. Escaping is removed from
 * the strings. Returns an array of pointers to sub-strings within c in
 * *results. The returned array must be freed, but not the strings
 * within the array. The function returns the number of strings in the
 * array. */
int pa_message_params_read_string_array(char *c, const char ***results) {
    void *state = NULL;
    uint32_t element_count, i;
    int err;
    const char **values;

    pa_assert(results);

    /* Count elements, return if no element was found or parse error. */
    if ((element_count = count_elements(c)) <= 0)
        return element_count;

    /* Allocate array */
    values = pa_xmalloc0(element_count * sizeof(char *));

    for (i = 0; (err = pa_message_params_read_string(c, &(values[i]), &state)) > 0; i++)
        ;

    if (err < 0) {
        pa_xfree(values);
        return PA_PARAMS_PARSE_ERROR;
    }

    /* Free default array and replace with the result */
    pa_xfree(*results);
    *results = values;
    return element_count;
}

/* Converts a parameter list to a double array. Empty elements in the parameter
 * list are interpreted as 0. */
int pa_message_params_read_double_array(char *c, double **results) {
    double  *values;
    void *state = NULL;
    uint32_t element_count, i;
    int err;

    pa_assert(results);

    /* Count elements, return if no element was found or parse error. */
    if ((element_count = count_elements(c)) <= 0)
        return element_count;

    /* Allocate array */
    values = pa_xmalloc0(element_count * sizeof(double));

    for (i = 0; (err = pa_message_params_read_double(c, &(values[i]), &state)) > 0; i++)
        ;

    if (err < 0) {
        pa_xfree(values);
        return PA_PARAMS_PARSE_ERROR;
    }

    /* Free default array and replace with the result */
    pa_xfree(*results);
    *results = values;
    return element_count;
}

/* Converts a parameter list to an int64 array. Empty elements in the parameter
 * list are interpreted as 0. */
int pa_message_params_read_int64_array(char *c, int64_t **results) {
    int64_t  *values;
    void *state = NULL;
    uint32_t element_count, i;
    int err;

    pa_assert(results);

    /* Count elements, return if no element was found or parse error. */
    if ((element_count = count_elements(c)) <= 0)
        return element_count;

    /* Allocate array */
    values = pa_xmalloc0(element_count * sizeof(int64_t));

    for (i = 0; (err = pa_message_params_read_int64(c, &(values[i]), &state)) > 0; i++)
        ;

    if (err < 0) {
        pa_xfree(values);
        return PA_PARAMS_PARSE_ERROR;
    }

    /* Free default array and replace with the result */
    pa_xfree(*results);
    *results = values;
    return element_count;
}

/* Converts a parameter list to an uint64 array. Empty elements in the parameter
 * list are interpreted as 0. */
int pa_message_params_read_uint64_array(char *c, uint64_t **results) {
    uint64_t  *values;
    void *state = NULL;
    uint32_t element_count, i;
    int err;

    pa_assert(results);

    /* Count elements, return if no element was found or parse error. */
    if ((element_count = count_elements(c)) <= 0)
        return element_count;

    /* Allocate array */
    values = pa_xmalloc0(element_count * sizeof(uint64_t));

    for (i = 0; (err = pa_message_params_read_uint64(c, &(values[i]), &state)) > 0; i++)
        ;

    if (err < 0) {
        pa_xfree(values);
        return PA_PARAMS_PARSE_ERROR;
    }

    /* Free default array and replace with the result */
    pa_xfree(*results);
    *results = values;
    return element_count;
}

/* Write functions. The functions are wrapper functions around pa_strbuf,
 * so that the client does not need to use pa_strbuf directly. */

/* Creates a new pa_message_param structure */
pa_message_params *pa_message_params_new(void) {
    pa_message_params *param;

    param = pa_xnew(pa_message_params, 1);
    param->buffer = pa_strbuf_new();

    return param;
}

/* Frees a pa_message_params structure */
void pa_message_params_free(pa_message_params *param) {
    pa_assert(param);

    pa_strbuf_free(param->buffer);
    pa_xfree(param);
}

/* Converts a pa_message_param structure to string and frees the structure.
 * The returned string needs to be freed with pa_xree(). */
char *pa_message_params_to_string_free(pa_message_params *param) {
    char *result;

    pa_assert(param);

    result = pa_strbuf_to_string_free(param->buffer);

    pa_xfree(param);
    return result;
}

/* Writes an opening curly brace */
void pa_message_params_begin_list(pa_message_params *param) {

    pa_assert(param);

    pa_strbuf_putc(param->buffer, '{');
}

/* Writes a closing curly brace */
void pa_message_params_end_list(pa_message_params *param) {

    pa_assert(param);

    pa_strbuf_putc(param->buffer, '}');
}

/* Writes a string to a message_params structure, adding curly braces
 * around the string and escaping curly braces within the string. */
void pa_message_params_write_string(pa_message_params *param, const char *value) {
    char *output;

    pa_assert(param);

    /* Null value is written as empty element */
    if (!value)
        value = "";

    output = pa_escape(value, "{}");
    pa_strbuf_printf(param->buffer, "{%s}", output);

    pa_xfree(output);
}

/* Writes a raw string to a message_params structure, adding curly braces
 * around the string if add_braces is true. This function can be used to
 * write parts of a string or whole parameter lists that have been prepared
 * elsewhere (for example an array). */
void pa_message_params_write_raw(pa_message_params *param, const char *value, bool add_braces) {
    pa_assert(param);

    /* Null value is written as empty element if add_braces is true.
     * Otherwise nothing is written. */
    if (!value)
        value = "";

    if (add_braces)
        pa_strbuf_printf(param->buffer, "{%s}", value);
    else
        pa_strbuf_puts(param->buffer, value);
}

/* Writes a double to a message_params structure, adding curly braces.
 * precision gives the number of significant digits, not digits after
 * the decimal point. */
void pa_message_params_write_double(pa_message_params *param, double value, int precision) {
    char *buf, *s;

    pa_assert(param);

    /* We do not care about locale because we do not know which locale is
     * used on the server side. If the decimal separator is a comma, we
     * replace it with a dot to achieve consistent output on all locales. */
    buf = pa_sprintf_malloc("{%.*g}",  precision, value);
    for (s = buf; *s; s++) {
        if (*s == ',') {
            *s = '.';
            break;
        }
     }

    pa_strbuf_puts(param->buffer, buf);

    pa_xfree(buf);
}

/* Writes an integer to a message_param structure, adding curly braces. */
void pa_message_params_write_int64(pa_message_params *param, int64_t value) {

    pa_assert(param);

    pa_strbuf_printf(param->buffer, "{%lli}", (long long)value);
}

/* Writes an unsigned integer to a message_params structure, adding curly braces. */
void pa_message_params_write_uint64(pa_message_params *param, uint64_t value) {

    pa_assert(param);

    pa_strbuf_printf(param->buffer, "{%llu}", (unsigned long long)value);
}

/* Writes a boolean to a message_params structure, adding curly braces. */
void pa_message_params_write_bool(pa_message_params *param, bool value) {

    pa_assert(param);

    if (value)
        pa_strbuf_puts(param->buffer, "{1}");
    else
        pa_strbuf_puts(param->buffer, "{0}");
}
