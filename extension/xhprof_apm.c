/*
 *  Copyright (c) 2009 Facebook
 *  Copyright (c) 2017 Xinhui Long
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>

#if __APPLE__
#include <mach/mach_init.h>
#include <mach/mach_time.h>
#endif

#include "ext/standard/info.h"
#include "php_xhprof_apm.h"
#include "zend_extensions.h"
#include "ext/pcre/php_pcre.h"
#include "ext/pdo/php_pdo_driver.h"
#include "ext/standard/php_rand.h"
#include "ext/json/php_json.h"
#include "main/SAPI.h"

/**
 * *********************
 * PHP EXTENSION GLOBALS
 * *********************
 */
/* List of functions implemented/exposed by xhprof */
zend_function_entry xhprof_apm_functions[] = {
	{NULL, NULL, NULL}
};

ZEND_DECLARE_MODULE_GLOBALS(apm)

/* Callback functions for the xhprof_apm extension */
zend_module_entry xhprof_apm_module_entry = {
	STANDARD_MODULE_HEADER,
	"xhprof_apm",                        /* Name of the extension */
	xhprof_apm_functions,                /* List of functions exposed */
	PHP_MINIT(xhprof_apm),               /* Module init callback */
	PHP_MSHUTDOWN(xhprof_apm),           /* Module shutdown callback */
	PHP_RINIT(xhprof_apm),               /* Request init callback */
	PHP_RSHUTDOWN(xhprof_apm),           /* Request shutdown callback */
	PHP_MINFO(xhprof_apm),               /* Module info callback */
	XHPROF_APM_VERSION,
	PHP_MODULE_GLOBALS(apm),   /* globals descriptor */
	PHP_GINIT(apm),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};

PHP_INI_BEGIN()

PHP_INI_ENTRY("xhprof_apm.config_ini", "", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("xhprof_apm.export", "php", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("xhprof_apm.php_file", "", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("xhprof_apm.curl_uri", "", PHP_INI_ALL, NULL)
PHP_INI_ENTRY("xhprof_apm.curl_timeout_ms", "1000", PHP_INI_ALL, NULL)

PHP_INI_END()

/* Init module */
ZEND_GET_MODULE(xhprof_apm)

PHP_GINIT_FUNCTION(apm)
{
	apm_globals->enabled = 0;
	apm_globals->ever_enabled = 0;
	apm_globals->xhprof_flags = 0;
	apm_globals->stats_count = NULL;
	apm_globals->entries = NULL;
    apm_globals->root = NULL;
	apm_globals->trace_callbacks = NULL;
    apm_globals->ignored_functions = NULL;
	apm_globals->debug = 0;
	apm_globals->timebase_factor = get_timebase_factor();
}

/**
 * Module init callback.
 *
 * @author cjiang
 */
PHP_MINIT_FUNCTION(xhprof_apm) {
	int i;

	REGISTER_INI_ENTRIES();

	hp_register_constants(INIT_FUNC_ARGS_PASSTHRU);

    APM_G(timebase_factor) = get_timebase_factor();

	APM_G(stats_count) = NULL;
	APM_G(trace_callbacks) = NULL;

	/* no free hp_entry_t structures to start with */
	APM_G(entry_free_list) = NULL;

	for (i = 0; i < 256; i++) {
		APM_G(func_hash_counters[i]) = 0;
	}

    APM_STORE_ZEND_HANDLE();

#if defined(DEBUG)
    /* To make it random number generator repeatable to ease testing. */
    srand(0);
#endif

	return SUCCESS;
}

/**
 * Module shutdown callback.
 */
PHP_MSHUTDOWN_FUNCTION(xhprof_apm) {
	/* free any remaining items in the free list */
	hp_free_the_free_list(TSRMLS_C);

    APM_RESTORE_ZEND_HANDLE();

	UNREGISTER_INI_ENTRIES();

	return SUCCESS;
}

/**
 * ***************************************************
 * COMMON HELPER FUNCTION DEFINITIONS AND LOCAL MACROS
 * ***************************************************
 */

static void hp_register_constants(INIT_FUNC_ARGS) {
	REGISTER_LONG_CONSTANT("APM_FLAGS_NO_BUILTINS",
						   APM_FLAGS_NO_BUILTINS,
						   CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("APM_FLAGS_CPU",
						   APM_FLAGS_CPU,
						   CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("APM_FLAGS_MEMORY",
                           APM_FLAGS_MEMORY,
						   CONST_CS | CONST_PERSISTENT);
}

/**
 * A hash function to calculate a 8-bit hash code for a function name.
 * This is based on a small modification to 'zend_inline_hash_func' by summing
 * up all bytes of the ulong returned by 'zend_inline_hash_func'.
 *
 * @param str, char *, string to be calculated hash code for.
 *
 * @author cjiang
 */
static inline uint8 hp_inline_hash(char *str) {
	ulong h = 5381;
	uint i = 0;
	uint8 res = 0;

	while (*str) {
		h += (h << 5);
		h ^= (ulong) *str++;
	}

	for (i = 0; i < sizeof(ulong); i++) {
		res += ((uint8 *)&h)[i];
	}
	return res;
}

static void hp_parse_options_from_config(zval *config TSRMLS_DC) {
	hp_clean_profiler_options_state(TSRMLS_C);

	if (config == NULL) {
		return;
	}

	zval *pzval;
	pzval = hp_zval_at_key("ignored", config);
	/* Set up filter of functions which may be ignored during profiling */
	APM_G(ignored_functions) = hp_ignored_functions_init(hp_strings_in_zval(pzval));
}

static hp_ignored_function_map *hp_ignored_functions_init(char **names) {
	if (names == NULL) {
        return NULL;
    }

	hp_ignored_function_map *function_map;

    function_map = emalloc(sizeof(hp_ignored_function_map));
    function_map->names = names;

    memset(function_map->filter, 0, APM_IGNORED_FUNCTION_FILTER_SIZE);

    int i = 0;
    for(; names[i] != NULL; i++) {
        char *str  = names[i];
        uint8 hash = hp_inline_hash(str);
        int   idx  = INDEX_2_BYTE(hash);
        function_map->filter[idx] |= INDEX_2_BIT(hash);
    }

    return function_map;
}

static void hp_ignored_functions_clear(hp_ignored_function_map *map) {
    if (map == NULL) {
        return;
    }

    hp_array_del(map->names);
    map->names = NULL;

    memset(map->filter, 0, APM_IGNORED_FUNCTION_FILTER_SIZE);
    efree(map);
}

/**
 * Check if function collides in filter of functions to be ignored.
 *
 * @author mpal
 */
int hp_ignored_functions_filter_collision(hp_ignored_function_map *map, uint8 hash) {
	uint8 mask = INDEX_2_BIT(hash);
	return map->filter[INDEX_2_BYTE(hash)] & mask;
}

/**
 * Initialize profiler state
 *
 * @author kannan, veeve
 */
void hp_init_profiler_state(TSRMLS_D) {
	/* Setup globals */
	if (!APM_G(ever_enabled)) {
		APM_G(ever_enabled)  = 1;
		APM_G(entries) = NULL;
	}

	/* Init stats_count */
	if (APM_G(stats_count)) {
        zval_ptr_dtor(&(APM_G(stats_count)));
	}

	MAKE_STD_ZVAL(APM_G(stats_count));
	array_init(APM_G(stats_count));

	hp_init_trace_callbacks(TSRMLS_C);
}

/**
 * Cleanup profiler state
 *
 * @author kannan, veeve
 */
void hp_clean_profiler_state(TSRMLS_D) {
	/* Clear globals */
	if (APM_G(stats_count)) {
		zval_ptr_dtor(&(APM_G(stats_count)));
		APM_G(stats_count) = NULL;
	}

	APM_G(entries) = NULL;
	APM_G(ever_enabled) = 0;
	APM_G(debug) = 0;

	hp_clean_profiler_options_state(TSRMLS_C);
}

static void hp_clean_profiler_options_state(TSRMLS_D) {
	/* Delete the array storing ignored function names */
	hp_ignored_functions_clear(APM_G(ignored_functions));
	APM_G(ignored_functions) = NULL;

	if (APM_G(trace_callbacks)) {
		zend_hash_destroy(APM_G(trace_callbacks));
		FREE_HASHTABLE(APM_G(trace_callbacks));
		APM_G(trace_callbacks) = NULL;
	}
}

/**
 * Returns formatted function name
 *
 * @param  entry        hp_entry
 * @param  result_buf   ptr to result buf
 * @param  result_len   max size of result buf
 * @return total size of the function name returned in result_buf
 * @author veeve
 */
static size_t hp_get_entry_name(hp_entry_t *entry, char *result_buf, size_t result_len) {
	/* Validate result_len */
	if (result_len <= 1) {
		/* Insufficient result_bug. Bail! */
		return 0;
	}

	/* Add '@recurse_level' if required */
	/* NOTE:  Dont use snprintf's return val as it is compiler dependent */
	if (entry->rlvl_hprof) {
		snprintf(result_buf, result_len,
				 "%s@%d",
				 entry->name_hprof, entry->rlvl_hprof);
	}
	else {
		snprintf(result_buf, result_len,
				 "%s",
				 entry->name_hprof);
	}

	/* Force null-termination at MAX */
	result_buf[result_len - 1] = 0;

	return strlen(result_buf);
}

/**
 * Check if this entry should be ignored, first with a conservative Bloomish
 * filter then with an exact check against the function names.
 *
 * @author mpal
 */
static inline int hp_ignore_entry_work(uint8 hash_code, char *curr_func TSRMLS_DC) {
	if (APM_G(ignored_functions) == NULL) {
		return 0;
	}

	hp_ignored_function_map *map = APM_G(ignored_functions);

	if (hp_ignored_functions_filter_collision(map, hash_code)) {
		int i = 0;
		for (; map->names[i] != NULL; i++) {
			char *name = map->names[i];
			if (strcmp(curr_func, name) == 0) {
				return 1;
			}
		}
	}

	return 0;
}

/**
 * Build a caller qualified name for a callee.
 *
 * For example, if A() is caller for B(), then it returns "A==>B".
 * Recursive invokations are denoted with @<n> where n is the recursion
 * depth.
 *
 * For example, "foo==>foo@1", and "foo@2==>foo@3" are examples of direct
 * recursion. And  "bar==>foo@1" is an example of an indirect recursive
 * call to foo (implying the foo() is on the call stack some levels
 * above).
 *
 * @author kannan, veeve
 */
size_t hp_get_function_stack(hp_entry_t *entry,
							 int            level,
							 char          *result_buf,
							 size_t         result_len) {
	size_t         len = 0;

	/* End recursion if we dont need deeper levels or we dont have any deeper
     * levels */
	if (!entry->prev_hprof || (level <= 1)) {
        return hp_get_entry_name(entry, result_buf, result_len);
	}

	/* Take care of all ancestors first */
	len = hp_get_function_stack(entry->prev_hprof,
								level - 1,
								result_buf,
								result_len);

	/* Append the delimiter */
# define    HP_STACK_DELIM        "==>"
# define    HP_STACK_DELIM_LEN    (sizeof(HP_STACK_DELIM) - 1)

	if (result_len < (len + HP_STACK_DELIM_LEN)) {
		/* Insufficient result_buf. Bail out! */
		return len;
	}

	/* Add delimiter only if entry had ancestors */
	if (len) {
		strncat(result_buf + len,
				HP_STACK_DELIM,
				result_len - len);
		len += HP_STACK_DELIM_LEN;
	}

# undef     HP_STACK_DELIM_LEN
# undef     HP_STACK_DELIM

	/* Append the current function name */
	return len + hp_get_entry_name(entry,
								   result_buf + len,
								   result_len - len);
}

static char *hp_concat_char(const char *s1, const char *s2, const char *seperator)
{
    char *result;
    spprintf(&result, 0, "%s%s%s", s1, seperator, s2);

    return result;
}

/**
 * Takes an input of the form /a/b/c/d/foo.php and returns
 * a pointer to one-level directory and basefile name
 * (d/foo.php) in the same string.
 */
static const char *hp_get_base_filename(const char *filename) {
	const char *ptr;
	int   found = 0;

	if (!filename)
		return "";

	/* reverse search for "/" and return a ptr to the next char */
	for (ptr = filename + strlen(filename) - 1; ptr >= filename; ptr--) {
		if (*ptr == '/') {
			found++;
		}
		if (found == 2) {
			return ptr + 1;
		}
	}

	/* no "/" char found, so return the whole string */
	return filename;
}

/**
 * Get the name of the current function. The name is qualified with
 * the class name if the function is in a class.
 *
 * @author kannan, hzhao
 */
static char *hp_get_function_name(zend_execute_data *execute_data TSRMLS_DC) {
	const char        *func = NULL;
	const char        *cls = NULL;
	char              *ret = NULL;
	zend_function     *curr_func;

	if (!execute_data) {
		return NULL;
	}

    /* shared meta data for function on the call stack */
    curr_func = execute_data->function_state.function;

    /* extract function name from the meta info */
    func = curr_func->common.function_name;

    if (!func) {
        return NULL;
    }

    /* previously, the order of the tests in the "if" below was
     * flipped, leading to incorrect function names in profiler
     * reports. When a method in a super-type is invoked the
     * profiler should qualify the function name with the super-type
     * class name (not the class name based on the run-time type
     * of the object.
     */
    if (curr_func->common.scope) {
        cls = curr_func->common.scope->name;
    } else if (execute_data->object) {
        cls = Z_OBJCE(*execute_data->object)->name;
    }

    if (cls) {
        char* sep = "::";
        ret = hp_concat_char(cls, func, sep);
    } else {
        ret = estrdup(func);
    }

	return ret;
}

/**
 * Free any items in the free list.
 */
static void hp_free_the_free_list(TSRMLS_D) {
	hp_entry_t *p = APM_G(entry_free_list);
	hp_entry_t *cur;

	while (p) {
		cur = p;
		p = p->prev_hprof;
		free(cur);
	}
}

/**
 * Fast allocate a hp_entry_t structure. Picks one from the
 * free list if available, else does an actual allocate.
 *
 * Doesn't bother initializing allocated memory.
 *
 * @author kannan
 */
static hp_entry_t *hp_fast_alloc_hprof_entry(TSRMLS_D) {
	hp_entry_t *p;

	p = APM_G(entry_free_list);

	if (p) {
		APM_G(entry_free_list) = p->prev_hprof;
		return p;
	} else {
		return (hp_entry_t *)malloc(sizeof(hp_entry_t));
	}
}

/**
 * Fast free a hp_entry_t structure. Simply returns back
 * the hp_entry_t to a free list and doesn't actually
 * perform the free.
 *
 * @author kannan
 */
static void hp_fast_free_hprof_entry(hp_entry_t *p TSRMLS_DC) {

	/* we use/overload the prev_hprof field in the structure to link entries in
     * the free list. */
	p->prev_hprof = APM_G(entry_free_list);
	APM_G(entry_free_list) = p;
}

/**
 * Increment the count of the given stat with the given count
 * If the stat was not set before, inits the stat to the given count
 *
 * @param  zval *counts   Zend hash table pointer
 * @param  char *name     Name of the stat
 * @param  long  count    Value of the stat to incr by
 * @return void
 * @author kannan
 */
void hp_inc_count(zval *counts, char *name, long count TSRMLS_DC) {
	HashTable *ht;
	void *data;

	if (!counts) {
        return;
    }

	ht = HASH_OF(counts);
	if (!ht) {
        return;
    }

	if (zend_hash_find(ht, name, strlen(name) + 1, &data) == SUCCESS) {
		ZVAL_LONG(*(zval**)data, Z_LVAL_PP((zval**)data) + count);
	} else {
		add_assoc_long(counts, name, count);
	}
}

/**
 * Truncates the given timeval to the nearest slot begin, where
 * the slot size is determined by intr
 *
 * @param  tv       Input timeval to be truncated in place
 * @param  intr     Time interval in microsecs - slot width
 * @return void
 * @author veeve
 */
void hp_trunc_time(struct timeval *tv,
				   uint64          intr) {
	uint64 time_in_micro;

	/* Convert to microsecs and trunc that first */
	time_in_micro = (tv->tv_sec * 1000000) + tv->tv_usec;
	time_in_micro /= intr;
	time_in_micro *= intr;

	/* Update tv */
	tv->tv_sec  = (time_in_micro / 1000000);
	tv->tv_usec = (time_in_micro % 1000000);
}

/**
 * ***********************
 * High precision timer related functions.
 * ***********************
 */

/**
 * Get time stamp counter (TSC) value via 'rdtsc' instruction.
 *
 * @return 64 bit unsigned integer
 * @author cjiang
 */
static inline uint64 cycle_timer() {
#ifdef __APPLE__
    return mach_absolute_time();
#else
    struct timespec s;
    clock_gettime(CLOCK_MONOTONIC, &s);

    return s.tv_sec * 1000000 + s.tv_nsec / 1000;
#endif
}

/**
 * Get the current real CPU clock timer
 */
static uint64 cpu_timer() {
#if defined(CLOCK_PROCESS_CPUTIME_ID)
    struct timespec s;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &s);

    return s.tv_sec * 1000000 + s.tv_nsec / 1000;
#else
    struct rusage ru;

    getrusage(RUSAGE_SELF, &ru);

    return ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec +
        ru.ru_stime.tv_sec * 1000000 + ru.ru_stime.tv_usec;
#endif
}

/**
 * Convert from TSC counter values to equivalent microseconds.
 *
 * @param uint64 count, TSC count value
 * @param double cpu_frequency, the CPU clock rate (MHz)
 * @return 64 bit unsigned integer
 *
 * @author cjiang
 */
static inline double get_us_from_tsc(uint64 count TSRMLS_DC) {
	return count / APM_G(timebase_factor);
}

static double get_timebase_factor()
{
#ifdef __APPLE__
    mach_timebase_info_data_t sTimebaseInfo;
    (void) mach_timebase_info(&sTimebaseInfo);
    return (sTimebaseInfo.numer / sTimebaseInfo.denom) * 1000;
#else
	return 1.0;
#endif
}

/**
 * Convert microseconds to equivalent TSC counter ticks
 *
 * @param uint64 microseconds
 * @param double cpu_frequency, the CPU clock rate (MHz)
 * @return 64 bit unsigned integer
 *
 * @author veeve
 */
static inline uint64 get_tsc_from_us(uint64 usecs, double cpu_frequency) {
	return (uint64) (usecs * cpu_frequency);
}

/**
 * ************************************
 * XHPROF BEGIN FUNCTION CALLBACKS
 * ************************************
 */

/**
 * XHPROF_MODE_HIERARCHICAL's begin function callback
 *
 * @author kannan
 */
void hp_mode_hier_beginfn_cb(hp_entry_t **entries, hp_entry_t *current TSRMLS_DC)
{
	hp_entry_t   *p;
    /* This symbol's recursive level */
    int    recurse_level = 0;
    /* Get start tsc counter */
	current->tsc_start = cycle_timer();

    if (APM_G(func_hash_counters[current->hash_code]) > 0) {
        /* Find this symbols recurse level */
        for(p = (*entries); p; p = p->prev_hprof) {
            if (!strcmp(current->name_hprof, p->name_hprof)) {
                recurse_level = (p->rlvl_hprof) + 1;
                break;
            }
        }
    }

    APM_G(func_hash_counters[current->hash_code])++;

    /* Init current function's recurse level */
    current->rlvl_hprof = recurse_level;

	/* Get CPU usage */
	if (APM_G(xhprof_flags) & APM_FLAGS_CPU) {
        current->cpu_start = cpu_timer();
	}

	/* Get memory usage */
	if (APM_G(xhprof_flags) & APM_FLAGS_MEMORY) {
		current->mu_start_hprof  = zend_memory_usage(0 TSRMLS_CC);
		current->pmu_start_hprof = zend_memory_peak_usage(0 TSRMLS_CC);
	}
}

/**
 * **********************************
 * XHPROF END FUNCTION CALLBACKS
 * **********************************
 */

/**
 * XHPROF_MODE_HIERARCHICAL's end function callback
 *
 * @author kannan
 */
void hp_mode_hier_endfn_cb(hp_entry_t **entries TSRMLS_DC) {
	hp_entry_t    *top = (*entries);
	zval          *counts;
	char          symbol[SCRATCH_BUF_LEN];
	long int      mu_end;
	long int      pmu_end;
    double        wt, cpu;
    void          *data;

    /* Get end tsc counter */
    wt = get_us_from_tsc(cycle_timer() - top->tsc_start TSRMLS_CC);

    /* Get the stat array */
    hp_get_function_stack(top, 2, symbol, sizeof(symbol));

    /* Lookup our hash table */
    if (zend_hash_find(Z_ARRVAL_P(APM_G(stats_count)), symbol, strlen(symbol) + 1, &data) == SUCCESS) {
        /* Symbol already exists */
        counts = *(zval **) data;
    } else {
        /* Add symbol to hash table */
        MAKE_STD_ZVAL(counts);
        array_init(counts);
        add_assoc_zval(APM_G(stats_count), symbol, counts);
    }

    /* Bump stats in the counts hashtable */
    hp_inc_count(counts, "ct", 1  TSRMLS_CC);
    hp_inc_count(counts, "wt", wt TSRMLS_CC);

    if (APM_G(xhprof_flags) & APM_FLAGS_CPU) {
        cpu = get_us_from_tsc(cpu_timer() - top->cpu_start TSRMLS_CC);
        /* Bump CPU stats in the counts hashtable */
        hp_inc_count(counts, "cpu", cpu TSRMLS_CC);
    }

    if (APM_G(xhprof_flags) & APM_FLAGS_MEMORY) {
        /* Get Memory usage */
        mu_end  = zend_memory_usage(0 TSRMLS_CC);
        pmu_end = zend_memory_peak_usage(0 TSRMLS_CC);

        /* Bump Memory stats in the counts hashtable */
        hp_inc_count(counts, "mu",  mu_end - top->mu_start_hprof    TSRMLS_CC);
        hp_inc_count(counts, "pmu", pmu_end - top->pmu_start_hprof  TSRMLS_CC);
    }

    APM_G(func_hash_counters[top->hash_code])--;
}

/**
 * ***************************
 * PHP EXECUTE/COMPILE PROXIES
 * ***************************
 */

/**
 * XHProf enable replaced the zend_execute function with this
 * new execute function. We can do whatever profiling we need to
 * before and after calling the actual zend_execute().
 *
 * @author hzhao, kannan
 */
#if PHP_VERSION_ID < 50500
ZEND_DLEXPORT void hp_execute (zend_op_array *ops TSRMLS_DC) {
    zend_execute_data *execute_data = EG(current_execute_data);
    zend_execute_data *real_execute_data = execute_data;
#else
ZEND_DLEXPORT void hp_execute_ex (zend_execute_data *execute_data TSRMLS_DC) {
	zend_op_array *ops = execute_data->op_array;
    zend_execute_data *real_execute_data = execute_data->prev_execute_data;
#endif
	char          *func = NULL;
	int hp_profile_flag = 1;

    if (!APM_G(enabled)) {
#if PHP_VERSION_ID < 50500
        _zend_execute(ops TSRMLS_CC);
#else
        _zend_execute_ex(execute_data TSRMLS_CC);
#endif
        return;
    }

	func = hp_get_function_name(real_execute_data TSRMLS_CC);
	if (!func) {
#if PHP_VERSION_ID < 50500
		_zend_execute(ops TSRMLS_CC);
#else
		_zend_execute_ex(execute_data TSRMLS_CC);
#endif
		return;
	}

	BEGIN_PROFILING(&APM_G(entries), func, hp_profile_flag, real_execute_data);
#if PHP_VERSION_ID < 50500
	_zend_execute(ops TSRMLS_CC);
#else
	_zend_execute_ex(execute_data TSRMLS_CC);
#endif
	if (APM_G(entries)) {
		END_PROFILING(&APM_G(entries), hp_profile_flag);
	}
	efree(func);
}

#undef EX
#define EX(element) ((execute_data)->element)

/**
 * Very similar to hp_execute. Proxy for zend_execute_internal().
 * Applies to zend builtin functions.
 *
 * @author hzhao, kannan
 */

#if PHP_VERSION_ID < 50500
#define EX_T(offset) (*(temp_variable *)((char *) EX(Ts) + offset))

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data,
                                       int ret TSRMLS_DC) {
#else
#define EX_T(offset) (*EX_TMP_VAR(execute_data, offset))

ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data,
									   struct _zend_fcall_info *fci, int ret TSRMLS_DC) {
#endif
	zend_execute_data *current_data;
	char             *func = NULL;
	int    hp_profile_flag = 1;

    if (!APM_G(enabled) || (APM_G(xhprof_flags) & APM_FLAGS_NO_BUILTINS) > 0) {
#if PHP_VERSION_ID < 50500
        execute_internal(execute_data, ret TSRMLS_CC);
#else
        execute_internal(execute_data, fci, ret TSRMLS_CC);
#endif
        return;
    }

	func = hp_get_function_name(execute_data TSRMLS_CC);

	if (func) {
		BEGIN_PROFILING(&APM_G(entries), func, hp_profile_flag, execute_data);
	}

    if (!_zend_execute_internal) {
#if PHP_VERSION_ID < 50500
        execute_internal(execute_data, ret TSRMLS_CC);
#else
        execute_internal(execute_data, fci, ret TSRMLS_CC);
#endif
    } else {
        /* call the old override */
#if PHP_VERSION_ID < 50500
        _zend_execute_internal(execute_data, ret TSRMLS_CC);
#else
        _zend_execute_internal(execute_data, fci, ret TSRMLS_CC);
#endif
    }

	if (func) {
		if (APM_G(entries)) {
			END_PROFILING(&APM_G(entries), hp_profile_flag);
		}
		efree(func);
	}

}

/**
 * Proxy for zend_compile_file(). Used to profile PHP compilation time.
 *
 * @author kannan, hzhao
 */
ZEND_DLEXPORT zend_op_array* hp_compile_file(zend_file_handle *file_handle, int type TSRMLS_DC) {
    if (!APM_G(enabled)) {
        return _zend_compile_file(file_handle, type TSRMLS_CC);
    }

	const char     *filename;
	char           *func;
	int             len;
	zend_op_array  *ret;
	int             hp_profile_flag = 1;

	filename = hp_get_base_filename(file_handle->filename);
	len      = strlen("load") + strlen(filename) + 3;
	func      = (char *)emalloc(len);
	snprintf(func, len, "load::%s", filename);

	BEGIN_PROFILING(&APM_G(entries), func, hp_profile_flag, NULL);
	ret = _zend_compile_file(file_handle, type TSRMLS_CC);
	if (APM_G(entries)) {
		END_PROFILING(&APM_G(entries), hp_profile_flag);
	}

	efree(func);
	return ret;
}

/**
 * Proxy for zend_compile_string(). Used to profile PHP eval compilation time.
 */
ZEND_DLEXPORT zend_op_array* hp_compile_string(zval *source_string, char *filename TSRMLS_DC) {
    if (!APM_G(enabled)) {
        return _zend_compile_string(source_string, filename TSRMLS_CC);
    }

	char          *func;
	int            len;
	zend_op_array *ret;
	int            hp_profile_flag = 1;

	len  = strlen("eval") + strlen(filename) + 3;
	func = (char *)emalloc(len);
	snprintf(func, len, "eval::%s", filename);

	BEGIN_PROFILING(&APM_G(entries), func, hp_profile_flag, NULL);
	ret = _zend_compile_string(source_string, filename TSRMLS_CC);
	if (APM_G(entries)) {
		END_PROFILING(&APM_G(entries), hp_profile_flag);
	}

	efree(func);
	return ret;
}

/**
 * **************************
 * MAIN XHPROF CALLBACKS
 * **************************
 */

/**
 * This function gets called once when xhprof gets enabled.
 * It replaces all the functions like zend_execute, zend_execute_internal,
 * etc that needs to be instrumented with their corresponding proxies.
 */
static void hp_begin(long xhprof_flags TSRMLS_DC) {
	if (!APM_G(enabled)) {
		int hp_profile_flag = 1;

		APM_G(enabled)      = 1;
		APM_G(xhprof_flags) = (uint32)xhprof_flags;

		/* one time initializations */
		hp_init_profiler_state(TSRMLS_C);

        APM_G(root) = estrdup(ROOT_SYMBOL);

		/* start profiling from fictitious main() */
		BEGIN_PROFILING(&APM_G(entries), APM_G(root), hp_profile_flag, NULL);
	}
}

/**
 * Called at request shutdown time. Cleans the profiler's global state.
 */
static void hp_end(TSRMLS_D) {
    /* Bail if not ever enabled */
    if (!APM_G(ever_enabled)) {
        return;
    }

    /* Stop profiler if enabled */
    if (APM_G(enabled)) {
        hp_stop(TSRMLS_C);
    }

    /* Clean up state */
	hp_clean_profiler_state(TSRMLS_C);
}

/**
 * Called from xhprof_disable(). Removes all the proxies setup by
 * hp_begin() and restores the original values.
 */
static void hp_stop(TSRMLS_D) {
	int   hp_profile_flag = 1;

	/* End any unfinished calls */
	while (APM_G(entries)) {
		END_PROFILING(&APM_G(entries), hp_profile_flag);
	}

    if (APM_G(root)) {
        efree(APM_G(root));
        APM_G(root) = NULL;
    }

	/* Stop profiling */
	APM_G(enabled) = 0;
}


/**
 * *****************************
 * XHPROF ZVAL UTILITY FUNCTIONS
 * *****************************
 */

/** Look in the PHP assoc array to find a key and return the zval associated
 *  with it.
 *
 *  @author mpal
 **/
static zval *hp_zval_at_key(char *key, zval *values) {
	zval *result = NULL;

	if (Z_TYPE_P(values) == IS_ARRAY) {
		HashTable *ht;
		zval     **value;
		uint       len = strlen(key) + 1;

		ht = Z_ARRVAL_P(values);
		if (zend_hash_find(ht, key, len, (void**)&value) == SUCCESS) {
			result = *value;
		}
	} else {
		result = NULL;
	}

	return result;
}

/** Convert the PHP array of strings to an emalloced array of strings. Note,
 *  this method duplicates the string data in the PHP array.
 *
 *  @author mpal
 **/
static char **hp_strings_in_zval(zval *values) {
	char   **result;
	size_t   count;
	size_t   ix = 0;

	if (!values) {
		return NULL;
	}

	if (Z_TYPE_P(values) == IS_ARRAY) {
		HashTable *ht;

		ht    = Z_ARRVAL_P(values);
		count = zend_hash_num_elements(ht);

		if ((result = (char**)emalloc(sizeof(char*) * (count + 1))) == NULL) {
			return result;
		}

		for (zend_hash_internal_pointer_reset(ht);
			 zend_hash_has_more_elements(ht) == SUCCESS;
			 zend_hash_move_forward(ht)) {
			char  *str;
			uint   len;
			ulong  idx;
			int    type;
			zval **data;

			type = zend_hash_get_current_key_ex(ht, &str, &len, &idx, 0, NULL);
			/* Get the names stored in a standard array */
			if (type == HASH_KEY_IS_LONG) {
				if ((zend_hash_get_current_data(ht, (void**)&data) == SUCCESS) &&
					Z_TYPE_PP(data) == IS_STRING && strcmp(Z_STRVAL_PP(data), ROOT_SYMBOL)) {
                    /* do not ignore "main" */
					result[ix] = estrdup(Z_STRVAL_PP(data));
					ix++;
				}
			}
		}
	} else if (Z_TYPE_P(values) == IS_STRING) {
		if ((result = (char**)emalloc(sizeof(char*) * 2)) == NULL) {
			return result;
		}
		result[0] = estrdup(Z_STRVAL_P(values));
		ix = 1;
	} else {
		result = NULL;
	}

	/* NULL terminate the array */
	if (result != NULL) {
		result[ix] = NULL;
	}

	return result;
}

/* Free this memory at the end of profiling */
static inline void hp_array_del(char **name_array) {
	if (name_array != NULL) {
		int i = 0;
		for (; name_array[i] != NULL && i < APM_MAX_IGNORED_FUNCTIONS; i++) {
			efree(name_array[i]);
		}
		efree(name_array);
	}
}

static void hp_ini_parser_cb(zval *key, zval *value, zval *index, int callback_type, zval *arr TSRMLS_DC) {
	zval *element;
	switch (callback_type) {
		case ZEND_INI_PARSER_ENTRY :
			{
				zval **ppzval, *dst;
				char *skey, *seg, *ptr;

				if (!value) {
					break;
				}

				dst = arr;
				skey = estrndup(Z_STRVAL_P(key), Z_STRLEN_P(key));
				if ((seg = php_strtok_r(skey, ".", &ptr))) {
					do {
						char *real_key = seg;
						seg = php_strtok_r(NULL, ".", &ptr);
						if (zend_symtable_find(Z_ARRVAL_P(dst), real_key, strlen(real_key) + 1, (void **) &ppzval) == FAILURE) {
							if (seg) {
								zval *tmp;
								MAKE_STD_ZVAL(tmp);
								array_init(tmp);
								zend_symtable_update(Z_ARRVAL_P(dst), real_key, strlen(real_key) + 1, (void **)&tmp, sizeof(zval *), (void **)&ppzval);
							} else {
								MAKE_STD_ZVAL(element);
								ZVAL_ZVAL(element, value, 1, 0);
								zend_symtable_update(Z_ARRVAL_P(dst),real_key, strlen(real_key) + 1, (void **)&element, sizeof(zval *), NULL);
								break;
							}
						}
						dst = *ppzval;
					} while (seg);
				}
				efree(skey);
			}
		break;

		case ZEND_INI_PARSER_POP_ENTRY:
			{
				zval *hash, **find_hash, *dst;

				if (!value) {
					break;
				}

				if (!(Z_STRLEN_P(key) > 1 && Z_STRVAL_P(key)[0] == '0')
					&& is_numeric_string(Z_STRVAL_P(key), Z_STRLEN_P(key), NULL, NULL, 0) == IS_LONG) {
					ulong skey = (ulong)zend_atol(Z_STRVAL_P(key), Z_STRLEN_P(key));
					if (zend_hash_index_find(Z_ARRVAL_P(arr), skey, (void **) &find_hash) == FAILURE) {
						MAKE_STD_ZVAL(hash);
						array_init(hash);
						zend_hash_index_update(Z_ARRVAL_P(arr), skey, &hash, sizeof(zval *), NULL);
					} else {
						hash = *find_hash;
					}
				} else {
					char *seg, *ptr;
					char *skey = estrndup(Z_STRVAL_P(key), Z_STRLEN_P(key));

					dst = arr;
					if ((seg = php_strtok_r(skey, ".", &ptr))) {
						while (seg) {
							if (zend_symtable_find(Z_ARRVAL_P(dst), seg, strlen(seg) + 1, (void **) &find_hash) == FAILURE) {
								MAKE_STD_ZVAL(hash);
								array_init(hash);
								zend_symtable_update(Z_ARRVAL_P(dst),
													 seg, strlen(seg) + 1, (void **)&hash, sizeof(zval *), (void **)&find_hash);
							}
							dst = *find_hash;
							seg = php_strtok_r(NULL, ".", &ptr);
						}
						hash = dst;
					} else {
						if (zend_symtable_find(Z_ARRVAL_P(dst), seg, strlen(seg) + 1, (void **)&find_hash) == FAILURE) {
							MAKE_STD_ZVAL(hash);
							array_init(hash);
							zend_symtable_update(Z_ARRVAL_P(dst), seg, strlen(seg) + 1, (void **)&hash, sizeof(zval *), NULL);
						} else {
							hash = *find_hash;
						}
					}
					efree(skey);
				}

				if (Z_TYPE_P(hash) != IS_ARRAY) {
					zval_dtor(hash);
					INIT_PZVAL(hash);
					array_init(hash);
				}

				MAKE_STD_ZVAL(element);
				ZVAL_ZVAL(element, value, 1, 0);

				if (index && Z_STRLEN_P(index) > 0) {
					add_assoc_zval_ex(hash, Z_STRVAL_P(index), Z_STRLEN_P(index) + 1, element);
				} else {
					add_next_index_zval(hash, element);
				}
			}
			break;

		case ZEND_INI_PARSER_SECTION:
			break;

	}
}

static char *hp_get_trace_callback(char* symbol, zend_execute_data *data TSRMLS_DC) {
    char *result;
    hp_trace_callback *callback;

    if (zend_hash_find(APM_G(trace_callbacks), symbol, strlen(symbol) + 1, (void **)&callback) == SUCCESS) {
        result = (*callback)(symbol, data TSRMLS_CC);
    } else {
        spprintf(&result, 0, "%s", symbol);
    }

    efree(symbol);

    return result;
}

static zval *hp_pcre_match(char *pattern, int len, zval *data TSRMLS_DC) {
	zval matches, *subparts;
	pcre_cache_entry *pce_regexp;

	if ((pce_regexp = pcre_get_compiled_regex_cache(pattern, len TSRMLS_CC)) == NULL) {
		return NULL;
	}

	MAKE_STD_ZVAL(subparts);
	ZVAL_NULL(subparts);

	php_pcre_match_impl(pce_regexp, Z_STRVAL_P(data), Z_STRLEN_P(data), &matches, subparts /* subpats */,
						0/* global */, 0/* ZEND_NUM_ARGS() >= 4 */, 0/*flags PREG_OFFSET_CAPTURE*/, 0/* start_offset */ TSRMLS_CC);

    if (!zend_hash_num_elements(Z_ARRVAL_P(subparts))) {
        zval_ptr_dtor(&subparts);
        return NULL;
    }

    return subparts;
}

static char* hp_pcre_replace(char *pattern, int len, zval* repl, zval *data, int limit TSRMLS_DC) {
	int res_len, rep_cnt = 0;
	zval *subparts;
	char *res;
	pcre_cache_entry *pce_regexp;

	if ((pce_regexp = pcre_get_compiled_regex_cache(pattern, len TSRMLS_CC)) == NULL) {
		return NULL;
	}

	MAKE_STD_ZVAL(subparts);
	ZVAL_NULL(subparts);

	res = php_pcre_replace_impl(pce_regexp, Z_STRVAL_P(data), Z_STRLEN_P(data), repl,
								0, &res_len, limit, &rep_cnt TSRMLS_CC);

    zval_ptr_dtor(&subparts);
	return res;
}

static inline zval *hp_get_execute_argument(zend_execute_data *ex, int n) {
    int arg_count = (int)(zend_uintptr_t) *(ex->function_state.arguments);
    return *(ex->function_state.arguments - (arg_count - (n - 1)));
}

static char* hp_trace_callback_pdo_connect(char *symbol, zend_execute_data *data TSRMLS_DC) {
	char *result;
    zval *match, **hash_find;
	zval *dsn = hp_get_execute_argument(data, 1);

	if ((match = hp_pcre_match("(^(mysql|sqlite|pgsql|odbc|oci):)", sizeof("(^(mysql|sqlite|pgsql|odbc|oci):)") - 1, dsn TSRMLS_CC))) {
        if (zend_hash_index_find(Z_ARRVAL_P(match), 1, (void**)&hash_find) == SUCCESS) {
            spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL_PP(hash_find));
        }

        zval_ptr_dtor(&match);

        if ((match = hp_pcre_match("(host=([^;\\s]+))", sizeof("(host=([^;\\s]+))") - 1, dsn TSRMLS_CC))) {
            if (zend_hash_index_find(Z_ARRVAL_P(match), 1, (void**)&hash_find) == SUCCESS) {
                spprintf(&result, 0, "%s@%s", result, Z_STRVAL_PP(hash_find));
            }
            zval_ptr_dtor(&match);
        }

        if ((match = hp_pcre_match("(port=([^;\\s]+))", sizeof("(port=([^;\\s]+))") - 1, dsn TSRMLS_CC))) {
            if (zend_hash_index_find(Z_ARRVAL_P(match), 1, (void**)&hash_find) == SUCCESS) {
                spprintf(&result, 0, "%s:%s", result, Z_STRVAL_PP(hash_find));
            }
            zval_ptr_dtor(&match);
        }

        if ((match = hp_pcre_match("(dbname=([^;\\s]+))", sizeof("(dbname=([^;\\s]+))") - 1, dsn TSRMLS_CC))) {
            if (zend_hash_index_find(Z_ARRVAL_P(match), 1, (void**)&hash_find) == SUCCESS) {
                spprintf(&result, 0, "%s@%s", result, Z_STRVAL_PP(hash_find));
            }
            zval_ptr_dtor(&match);
        }
    }

	return result;
}

static char* hp_trace_callback_sql_query(char *symbol, zend_execute_data *data TSRMLS_DC) {
    char *result;

    if (strcmp(symbol, "mysqli_query") == 0) {
        zval *arg = hp_get_execute_argument(data, 2);
        spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL_P(arg));
    } else {
        zval *arg = hp_get_execute_argument(data, 1);
        spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL_P(arg));
    }

    return result;
}

static char* hp_trace_callback_pdo_statement_execute(char *symbol, zend_execute_data *data TSRMLS_DC) {
	char *result;
	char *pattern_str = NULL;
	int pattern_len;
	pdo_stmt_t *stmt = (pdo_stmt_t*)zend_object_store_get_object(data->object TSRMLS_CC);
    zval *arg = hp_get_execute_argument(data, 1);

	if (arg == NULL || Z_TYPE_P(arg) != IS_ARRAY) {
		spprintf(&result, 0, "%s#%s", symbol, stmt->query_string);
		return result;
	}

	if (strstr(stmt->query_string, "?") != NULL) {
		pattern_str = "([\?])";
		pattern_len = sizeof("([\?])") - 1;
	} else if (strstr(stmt->query_string, ":") != NULL) {
		pattern_str = "(:([^\\s]+))";
		pattern_len = sizeof("(:([^\\s]+))") - 1;
	}

    if (pattern_str) {
		zval *match, *sql_query;
		MAKE_STD_ZVAL(sql_query);
		ZVAL_STRING(sql_query, stmt->query_string, 1);
        if ((match = hp_pcre_match(pattern_str, pattern_len, sql_query TSRMLS_CC)) == NULL) {
			spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL_P(sql_query));
			zval_ptr_dtor(&sql_query);
			return result;
		}

		zval *repl, **ppzval;
		char *key;
		uint len = 0;
		ulong idx = 0;
		HashTable *ht;
		ht = Z_ARRVAL_P(arg);

		for (zend_hash_internal_pointer_reset(ht);
			zend_hash_has_more_elements(ht) == SUCCESS;
			zend_hash_move_forward(ht)) {

			zend_hash_get_current_key_ex(ht, &key, &len, &idx, 0, NULL);
			if (zend_hash_get_current_data(ht, (void**)&ppzval) == FAILURE) {
				continue;
			}

            convert_to_string_ex(ppzval);

            MAKE_STD_ZVAL(repl);
            ZVAL_STRINGL(repl, Z_STRVAL_PP(ppzval), Z_STRLEN_PP(ppzval), 1);

			char *repl_str = hp_pcre_replace(pattern_str, pattern_len, repl, sql_query, 1 TSRMLS_CC);

            if (repl_str != NULL) {
                zval_ptr_dtor(&sql_query);
                MAKE_STD_ZVAL(sql_query);
                ZVAL_STRING(sql_query, repl_str, 0);
                //efree(repl_str);
            }

            zval_ptr_dtor(&repl);
		}

        spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL_P(sql_query));

        zval_ptr_dtor(&sql_query);
		zval_ptr_dtor(&match);
    } else {
        spprintf(&result, 0, "%s#%s", symbol, stmt->query_string);
    }

    return result;
}

static char* hp_trace_callback_curl_exec(char *symbol, zend_execute_data *data TSRMLS_DC) {
    char *result;
    zval *func, **ppzval, *retval = NULL;
    zval *arg = hp_get_execute_argument(data, 1);

    if (arg == NULL || Z_TYPE_P(arg) != IS_RESOURCE) {
        spprintf(&result, 0, "%s", symbol);
        return result;
    }

    zval **params[1] = {&arg};

    MAKE_STD_ZVAL(func);
    ZVAL_STRINGL(func, "curl_getinfo", strlen("curl_getinfo"), 1);

	zend_fcall_info fci = {
		size: sizeof(zend_fcall_info),
		function_table: EG(function_table),
		function_name: func,
		symbol_table: NULL,
		retval_ptr_ptr: &retval,
		param_count: 1,
		params: (zval ***)params,
		object_ptr: NULL,
		no_separation: 1
	};

    if (zend_call_function(&fci, NULL TSRMLS_CC) == FAILURE) {
        if (retval) {
            zval_ptr_dtor(&retval);
        }

        zval_ptr_dtor(&func);
        return NULL;
    }

    if (zend_hash_find(Z_ARRVAL_P(retval), "url", sizeof("url"), (void**)&ppzval) == SUCCESS) {
        spprintf(&result, 0, "%s#%s", symbol, Z_STRVAL_PP(ppzval));
    }

    zval_ptr_dtor(&func);
    zval_ptr_dtor(&retval);

    return result;
}

static inline void hp_free_trace_cb(void *p) {
}

static void hp_init_trace_callbacks(TSRMLS_D) {
	hp_trace_callback callback;

	ALLOC_HASHTABLE(APM_G(trace_callbacks));
	if (!APM_G(trace_callbacks)) {
		return;
	}

	zend_hash_init(APM_G(trace_callbacks), 16, NULL, (dtor_func_t)hp_free_trace_cb, 0);

    callback = hp_trace_callback_sql_query;
    register_trace_callback("PDO::exec", callback);
    register_trace_callback("PDO::query", callback);
    register_trace_callback("mysql_query", callback);
    register_trace_callback("mysqli_query", callback);
    register_trace_callback("mysqli::query", callback);

    callback = hp_trace_callback_pdo_statement_execute;
    register_trace_callback("PDOStatement::execute", callback);

    callback = hp_trace_callback_curl_exec;
    register_trace_callback("curl_exec", callback);

    //callback = hp_trace_callback_pdo_connect;
	//register_trace_callback("PDO::__construct", callback);
}

zval *hp_request_query(uint type, char * name, uint len TSRMLS_DC) {
    zval **carrier = NULL, **ret;

#if (PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 4)
    zend_bool 	jit_initialization = (PG(auto_globals_jit) && !PG(register_globals) && !PG(register_long_arrays));
#else
    zend_bool 	jit_initialization = PG(auto_globals_jit);
#endif

    switch (type) {
        case TRACK_VARS_POST:
        case TRACK_VARS_GET:
        case TRACK_VARS_FILES:
        case TRACK_VARS_COOKIE:
            carrier = &PG(http_globals)[type];
            break;
        case TRACK_VARS_ENV:
            if (jit_initialization) {
                zend_is_auto_global(ZEND_STRL("_ENV") TSRMLS_CC);
            }
            carrier = &PG(http_globals)[type];
            break;
        case TRACK_VARS_SERVER:
            if (jit_initialization) {
                zend_is_auto_global(ZEND_STRL("_SERVER") TSRMLS_CC);
            }
            carrier = &PG(http_globals)[type];
            break;
        case TRACK_VARS_REQUEST:
            if (jit_initialization) {
                zend_is_auto_global(ZEND_STRL("_REQUEST") TSRMLS_CC);
            }
            (void)zend_hash_find(&EG(symbol_table), ZEND_STRS("_REQUEST"), (void **)&carrier);
            break;
        default:
            break;
    }

    if (!carrier || !(*carrier)) {
        zval *empty;
        MAKE_STD_ZVAL(empty);
        ZVAL_NULL(empty);
        return empty;
    }

    if (!len) {
        Z_ADDREF_P(*carrier);
        return *carrier;
    }

    if (zend_hash_find(Z_ARRVAL_PP(carrier), name, len + 1, (void **)&ret) == FAILURE) {
        zval *empty;
        MAKE_STD_ZVAL(empty);
        ZVAL_NULL(empty);
        return empty;
    }

    Z_ADDREF_P(*ret);
    return *ret;
}

static zval *hp_get_export_data(zval *data, int debug TSRMLS_DC) {
    zval *meta, *result, *root, *repl, *pzurl;
	char *scheme, *url;
    int request_date;

    MAKE_STD_ZVAL(meta);
    array_init(meta);

    MAKE_STD_ZVAL(result);
    array_init(result);

    zval *server = hp_request_query(TRACK_VARS_SERVER, NULL, 0 TSRMLS_CC);
    zval *uri = hp_request_query(TRACK_VARS_SERVER, ZEND_STRL("REQUEST_URI") TSRMLS_CC);
    zval *ssl = hp_request_query(TRACK_VARS_SERVER, ZEND_STRL("HTTPS") TSRMLS_CC);
    zval *server_name = hp_request_query(TRACK_VARS_SERVER, ZEND_STRL("SERVER_NAME") TSRMLS_CC);
	zval *get = hp_request_query(TRACK_VARS_GET, NULL, 0 TSRMLS_CC);

    if (Z_TYPE_P(ssl) == IS_NULL) {
        scheme = "http";
    } else {
		scheme = "https";
    }

	if (Z_TYPE_P(server_name) == IS_STRING && Z_TYPE_P(uri)) {
		spprintf(&url, 0, "%s://%s%s", scheme, Z_STRVAL_P(server_name), Z_STRVAL_P(uri));
	} else {
		spprintf(&url, 0, "%s", "unknown");
	}

    MAKE_STD_ZVAL(repl);
    ZVAL_EMPTY_STRING(repl);

    MAKE_STD_ZVAL(pzurl);
    ZVAL_STRING(pzurl, url, 1);

    char *simple_url = hp_pcre_replace("(=[^&]+)", sizeof("(=[^&]+)") - 1, repl, pzurl, -1 TSRMLS_CC);

    add_assoc_string_ex(meta, ZEND_STRS("url"), url, 1);
    add_assoc_string_ex(meta, ZEND_STRS("simple_url"), simple_url, 1);
    add_assoc_long_ex(meta, ZEND_STRS("request_date"), SG(global_request_time));
    add_assoc_zval_ex(meta, ZEND_STRS("SERVER"), server);
    add_assoc_zval_ex(meta, ZEND_STRS("GET"), get);

    add_assoc_zval_ex(result, ZEND_STRS("meta"), meta);
    add_assoc_zval_ex(result, ZEND_STRS("profile"), data);

    root = hp_zval_at_key(ROOT_SYMBOL, data);
    zval *wt = hp_zval_at_key("wt", root);
	if (wt) {
		add_assoc_long_ex(result, ZEND_STRS("wt"), Z_LVAL_P(wt));
	} else {
		add_assoc_long_ex(result, ZEND_STRS("wt"), 0);
	}

    zval *cpu = hp_zval_at_key("cpu", root);
	if (cpu) {
		add_assoc_long_ex(result, ZEND_STRS("cpu"), Z_LVAL_P(cpu));
	} else {
		add_assoc_long_ex(result, ZEND_STRS("cpu"), 0);
	}

    zval *mu = hp_zval_at_key("mu", root);
	if (cpu) {
		add_assoc_long_ex(result, ZEND_STRS("mu"), Z_LVAL_P(mu));
	} else {
		add_assoc_long_ex(result, ZEND_STRS("mu"), 0);
	}

	add_assoc_long_ex(result, ZEND_STRS("debug"), debug);

	zval_ptr_dtor(&uri);
	zval_ptr_dtor(&ssl);
	zval_ptr_dtor(&server_name);
	zval_ptr_dtor(&repl);
	zval_ptr_dtor(&pzurl);

	efree(url);
	efree(simple_url);

    return result;
}

static int hp_rshutdown_php(zval *data, int debug TSRMLS_DC) {
	char realpath[MAXPATHLEN];
	char *path;

    if (!INI_STR("xhprof_apm.php_file")) {
        return 0;
    }

    spprintf(&path, 0, "%s", INI_STR("xhprof_apm.php_file"));
    if (!VCWD_REALPATH(path, realpath)) {
		efree(path);
		zval *document_root = hp_request_query(TRACK_VARS_SERVER, ZEND_STRL("DOCUMENT_ROOT") TSRMLS_CC);
		spprintf(&path, 0, "%s%c%s", Z_STRVAL_P(document_root), DEFAULT_SLASH, INI_STR("xhprof_apm.php_file"));
		zval_ptr_dtor(&document_root);

        if (!VCWD_REALPATH(path, realpath)) {
			zval_ptr_dtor(&data);
			efree(path);
            return 0;
        }
	}

	zend_file_handle file_handle = {
		filename: realpath,
		free_filename: 0,
		type: ZEND_HANDLE_FILENAME,
		opened_path: NULL,
		handle: {fp: NULL},
	};

	zend_op_array *op_array = zend_compile_file(&file_handle, ZEND_INCLUDE TSRMLS_CC);

	if (op_array && file_handle.handle.stream.handle) {
		int dummy = 1;

		if (!file_handle.opened_path) {
			file_handle.opened_path = path;
		}

		zend_hash_add(&EG(included_files), file_handle.opened_path, strlen(file_handle.opened_path) + 1, (void *)&dummy, sizeof(int), NULL);
	}

	zend_destroy_file_handle(&file_handle TSRMLS_CC);

	if (op_array) {
		zval *result = NULL;
		HashTable *calling_symbol_table;

		zval **_return_value_pp =  EG(return_value_ptr_ptr);
		zend_op **_opline_ptr = EG(opline_ptr);
		zend_op_array *_op_array = EG(active_op_array);

		EG(return_value_ptr_ptr) = &result;
		EG(active_op_array) 	 = op_array;

		if (EG(active_symbol_table)) {
			calling_symbol_table = EG(active_symbol_table);
		} else {
			calling_symbol_table = NULL;
		}

		ALLOC_HASHTABLE(EG(active_symbol_table));
		zend_hash_init(EG(active_symbol_table), 0, NULL, ZVAL_PTR_DTOR, 0);

#if ((PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION > 2)) || (PHP_MAJOR_VERSION > 5)
		if (!EG(active_symbol_table)) {
#if PHP_MINOR_VERSION < 5
			zval *orig_this = EG(This);
			EG(This) = NULL;
			zend_rebuild_symbol_table(TSRMLS_C);
			EG(This) = orig_this;
#else
			zend_rebuild_symbol_table(TSRMLS_C);
#endif
		}
#endif

        zend_try {
            zval *export_data = hp_get_export_data(data, debug TSRMLS_CC);
            ZEND_SET_SYMBOL(EG(active_symbol_table), "_apm_export", export_data);
            zend_execute(op_array TSRMLS_CC);
        } zend_catch {

        } zend_end_try();

		destroy_op_array(op_array TSRMLS_CC);
		efree(op_array);

		if (!EG(exception)) {
			if (EG(return_value_ptr_ptr) && *EG(return_value_ptr_ptr)) {
				zval_ptr_dtor(EG(return_value_ptr_ptr));
			}
		}

		EG(return_value_ptr_ptr) = _return_value_pp;
		EG(opline_ptr) = _opline_ptr;
		EG(active_op_array) = _op_array;

		if (calling_symbol_table) {
			zend_hash_destroy(EG(active_symbol_table));
			FREE_HASHTABLE(EG(active_symbol_table));
			EG(active_symbol_table) = calling_symbol_table;
		}

        efree(path);
		return 1;
	}

    efree(path);
	return 0;
}

static size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
}

static int hp_rshutdown_curl(zval *data, int debug TSRMLS_DC) {
	char *uri = INI_STR("xhprof_apm.curl_uri");

	if (!uri) {
		zval_ptr_dtor(&data);
		return 0;
	}

	smart_str buf = {0};
	zval *export_data = hp_get_export_data(data, debug TSRMLS_CC);

#if ((PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 3))
	php_json_encode(&buf, export_data TSRMLS_CC);
#else
	php_json_encode(&buf, export_data, 0 TSRMLS_CC); /* options */
#endif

	smart_str_0(&buf);

	CURL *curl = curl_easy_init();
	if (curl) {
        CURLcode res;
		struct curl_slist *headers = NULL;
		double timeout = INI_FLT("xhprof_apm.curl_timeout_ms");

		headers = curl_slist_append(headers, "User-Agent: Xhprof-apm");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		curl_easy_setopt(curl, CURLOPT_URL, uri);
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf.c);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (int)timeout);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (int)ceil(timeout / 1000));

		curl_easy_setopt(curl, CURLOPT_NETRC, 0);
		curl_easy_setopt(curl, CURLOPT_HEADER, 0);
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);

		smart_str_free(&buf);
		curl_slist_free_all(headers);

		zval_ptr_dtor(&export_data);
		return 1;
	}

	smart_str_free(&buf);
	zval_ptr_dtor(&export_data);
	return 0;
}

/**
 * Request init callback. Nothing to do yet!
 */
PHP_RINIT_FUNCTION(xhprof_apm) {
	int enable = 0;
	long flags = 0;

	if (SG(request_info).request_method) {
		zval *self_curl = hp_request_query(TRACK_VARS_SERVER, ZEND_STRL("HTTP_USER_AGENT") TSRMLS_CC);
		if (Z_TYPE_P(self_curl) == IS_STRING && strcmp(Z_STRVAL_P(self_curl), "Xhprof-apm") == 0) {
			zval_ptr_dtor(&self_curl);
			return SUCCESS;
		}

		zval_ptr_dtor(&self_curl);

		char *config_ini;
		char realpath[MAXPATHLEN];
		spprintf(&config_ini, 0, "%s", INI_STR("xhprof_apm.config_ini"));

		if (!VCWD_REALPATH(config_ini, realpath)) {
			efree(config_ini);
			zval *document_root = hp_request_query(TRACK_VARS_SERVER, ZEND_STRL("DOCUMENT_ROOT") TSRMLS_CC);
			spprintf(&config_ini, 0, "%s%c%s", Z_STRVAL_P(document_root), DEFAULT_SLASH, INI_STR("xhprof_apm.config_ini"));
			zval_ptr_dtor(&document_root);

			if (!VCWD_REALPATH(config_ini, realpath)) {
				efree(config_ini);
				return SUCCESS;
			}
		}

		efree(config_ini);

		struct stat sb;
		zend_file_handle fh = {0};
		zval *configs, *apm_config, *pzval;

		ALLOC_INIT_ZVAL(configs);

		if (VCWD_STAT(realpath, &sb) == 0 && S_ISREG(sb.st_mode)) {
			if ((fh.handle.fp = VCWD_FOPEN(realpath, "r"))) {
				fh.filename = realpath;
				fh.type = ZEND_HANDLE_FP;

				array_init(configs);
				if (zend_parse_ini_file(&fh, 0, 0 /* ZEND_INI_SCANNER_NORMAL */,
										(zend_ini_parser_cb_t)hp_ini_parser_cb, configs TSRMLS_CC) == FAILURE) {
					zval_ptr_dtor(&configs);
					return SUCCESS;
				}
			}
		} else {
			zval_ptr_dtor(&configs);
			return SUCCESS;
		}

		apm_config = hp_zval_at_key("apm", configs);
		if (!apm_config) {
			zval_ptr_dtor(&configs);
			return SUCCESS;
		}

		pzval = hp_zval_at_key("auto", apm_config);
		if (pzval) {
			convert_to_long(pzval);
			enable = Z_LVAL_P(pzval);
		}

		pzval = hp_zval_at_key("debug", apm_config);
		if (pzval) {
			convert_to_string(pzval);
			zval *zval_param = hp_request_query(TRACK_VARS_GET, Z_STRVAL_P(pzval), Z_STRLEN_P(pzval) TSRMLS_CC);
			if (Z_TYPE_P(zval_param) != IS_NULL) {
				APM_G(debug) = 1;
				enable = 1;
			}

			zval_ptr_dtor(&zval_param);
		}

		if (!enable) {
			zval_ptr_dtor(&configs);
			return SUCCESS;
		}

		if (!APM_G(debug)) {
			pzval = hp_zval_at_key("rate", apm_config);
			if (pzval) {
				convert_to_long(pzval);
				int sample_rate = Z_LVAL_P(pzval);

				if (!sample_rate) {
					zval_ptr_dtor(&configs);
					return SUCCESS;
				}

				long number = php_rand(TSRMLS_C);
				RAND_RANGE(number, 0, 100, PHP_RAND_MAX);

				if (sample_rate < number) {
					zval_ptr_dtor(&configs);
					return SUCCESS;
				}
			}
		}

		pzval = hp_zval_at_key("flags", apm_config);
		if (pzval) {
			convert_to_long(pzval);
			flags = Z_LVAL_P(pzval);
		}

		hp_parse_options_from_config(apm_config TSRMLS_CC);
        hp_begin(flags TSRMLS_CC);
		zval_ptr_dtor(&configs);
	}

	return SUCCESS;
}

/**
 * Request shutdown callback. Stop profiling and return.
 */
PHP_RSHUTDOWN_FUNCTION(xhprof_apm) {
	if (APM_G(enabled)) {
		hp_stop(TSRMLS_C);

		zval *pzval;
		MAKE_STD_ZVAL(pzval);
		ZVAL_ZVAL(pzval, APM_G(stats_count), 1, 0);

		int debug = APM_G(debug);

		hp_end(TSRMLS_C);

		char *export = INI_STR("xhprof_apm.export");
		if (strcmp(export, "php") == 0) {
			hp_rshutdown_php(pzval, debug TSRMLS_CC);
		} else if (strcmp(export, "curl") == 0) {
			hp_rshutdown_curl(pzval, debug TSRMLS_CC);
		}
	}

	return SUCCESS;
}

/**
 * Module info callback. Returns the xhprof version.
 */
PHP_MINFO_FUNCTION(xhprof_apm)
{
	char buf[SCRATCH_BUF_LEN];
	char tmp[SCRATCH_BUF_LEN];
	int i;
	int len;

	php_info_print_table_start();
    php_info_print_table_header(2, "xhprof_apm support", "enabled");
    php_info_print_table_row(2, "Version", XHPROF_APM_VERSION);
	php_info_print_table_end();
    DISPLAY_INI_ENTRIES();
}