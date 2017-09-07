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

#ifdef linux
/* To enable CPU_ZERO and CPU_SET, etc.     */
# define _GNU_SOURCE
#endif

#ifdef __FreeBSD__
# if __FreeBSD_version >= 700110
#   include <sys/resource.h>
#   include <sys/cpuset.h>
#   define cpu_set_t cpuset_t
#   define SET_AFFINITY(pid, size, mask) \
           cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, size, mask)
#   define GET_AFFINITY(pid, size, mask) \
           cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, size, mask)
# else
#   error "This version of FreeBSD does not support cpusets"
# endif /* __FreeBSD_version */
#elif __APPLE__
/*
 * Patch for compiling in Mac OS X Leopard
 * @author Svilen Spasov <s.spasov@gmail.com>
 */
#    include <mach/mach_init.h>
#    include <mach/thread_policy.h>
#    define cpu_set_t thread_affinity_policy_data_t
#    define CPU_SET(cpu_id, new_mask) \
        (*(new_mask)).affinity_tag = (cpu_id + 1)
#    define CPU_ZERO(new_mask)                 \
        (*(new_mask)).affinity_tag = THREAD_AFFINITY_TAG_NULL
#   define SET_AFFINITY(pid, size, mask)       \
        thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY, mask, \
                          THREAD_AFFINITY_POLICY_COUNT)
#else
/* For sched_getaffinity, sched_setaffinity */
# include <sched.h>
# define SET_AFFINITY(pid, size, mask) sched_setaffinity(0, size, mask)
# define GET_AFFINITY(pid, size, mask) sched_getaffinity(0, size, mask)
#endif /* __FreeBSD__ */

#include "ext/standard/info.h"
#include "php_xhprof_apm.h"
#include "zend_extensions.h"
#include "ext/pcre/php_pcre.h"
#include "ext/pdo/php_pdo_driver.h"
#include "ext/standard/php_rand.h"
#include "ext/json/php_json.h"
#include "main/SAPI.h"

/**
 * ***********************
 * GLOBAL STATIC VARIABLES
 * ***********************
 */
#if PHP_VERSION_ID < 50500
/* Pointer to the original execute function */
static ZEND_DLEXPORT void (*_zend_execute) (zend_op_array *ops TSRMLS_DC);

/* Pointer to the origianl execute_internal function */
static ZEND_DLEXPORT void (*_zend_execute_internal) (zend_execute_data *data, int ret TSRMLS_DC);
#else
/* Pointer to the original execute function */
static void (*_zend_execute_ex) (zend_execute_data *execute_data TSRMLS_DC);

/* Pointer to the origianl execute_internal function */
static void (*_zend_execute_internal) (zend_execute_data *data, struct _zend_fcall_info *fci, int ret TSRMLS_DC);
#endif

/* Pointer to the original compile function */
static zend_op_array * (*_zend_compile_file) (zend_file_handle *file_handle, int type TSRMLS_DC);

/* Pointer to the original compile string function (used by eval) */
static zend_op_array * (*_zend_compile_string) (zval *source_string, char *filename TSRMLS_DC);

ZEND_DLEXPORT zend_op_array* hp_compile_file(zend_file_handle *file_handle, int type TSRMLS_DC);
ZEND_DLEXPORT zend_op_array* hp_compile_string(zval *source_string, char *filename TSRMLS_DC);

ZEND_DLEXPORT void hp_execute_ex (zend_execute_data *execute_data TSRMLS_DC);
ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, struct _zend_fcall_info *fci, int ret TSRMLS_DC);

/* Bloom filter for function names to be ignored */
#define INDEX_2_BYTE(index)  (index >> 3)
#define INDEX_2_BIT(index)   (1 << (index & 0x7));

/**
 * ****************************
 * STATIC FUNCTION DECLARATIONS
 * ****************************
 */
static void hp_register_constants(INIT_FUNC_ARGS);

static void hp_begin(long xhprof_flags TSRMLS_DC);
static void hp_stop(TSRMLS_D);
static void hp_end(TSRMLS_D);

static inline uint64 cycle_timer();
static double get_cpu_frequency();
static void clear_frequencies();

static void hp_free_the_free_list();
static hp_entry_t *hp_fast_alloc_hprof_entry();
static void hp_fast_free_hprof_entry(hp_entry_t *p);
static inline uint8 hp_inline_hash(char * str);
static void get_all_cpu_frequencies();
static long get_us_interval(struct timeval *start, struct timeval *end);
static void incr_us_interval(struct timeval *start, uint64 incr);

static void hp_get_ignored_functions_from_arg(zval *args);
static void hp_ignored_functions_filter_clear();
static void hp_ignored_functions_filter_init();

static inline zval *hp_zval_at_key(char  *key,
									zval  *values);
static inline char **hp_strings_in_zval(zval  *values);
static inline void hp_array_del(char **name_array);

static char *hp_get_trace_callback(char *symbol, zend_execute_data *data TSRMLS_DC);
static void hp_init_trace_callbacks(TSRMLS_D);

/**
 * *********************
 * FUNCTION PROTOTYPES
 * *********************
 */
int restore_cpu_affinity(cpu_set_t * prev_mask);
int bind_to_cpu(uint32 cpu_id);

typedef char* (*hp_trace_callback)(char *symbol, zend_execute_data *data TSRMLS_DC);

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

	/* Get the number of available logical CPUs. */
	APM_G(cpu_num) = sysconf(_SC_NPROCESSORS_CONF);

	/* Get the cpu affinity mask. */
#ifndef __APPLE__
	if (GET_AFFINITY(0, sizeof(cpu_set_t), &APM_G(prev_mask)) < 0) {
    perror("getaffinity");
    return FAILURE;
  }
#else
	CPU_ZERO(&(APM_G(prev_mask)));
#endif

	/* Initialize cpu_frequencies and cur_cpu_id. */
	APM_G(cpu_frequencies) = NULL;
	APM_G(cur_cpu_id) = 0;

	APM_G(stats_count) = NULL;

	/* no free hp_entry_t structures to start with */
	APM_G(entry_free_list) = NULL;

	for (i = 0; i < 256; i++) {
		APM_G(func_hash_counters[i]) = 0;
	}

	hp_ignored_functions_filter_clear();

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
	/* Make sure cpu_frequencies is free'ed. */
	clear_frequencies();

	/* free any remaining items in the free list */
	hp_free_the_free_list();

    APM_RESTORE_ZEND_HANDLE();

	UNREGISTER_INI_ENTRIES();

	if (APM_G(trace_callbacks)) {
		zend_hash_destroy(APM_G(trace_callbacks));
		pefree(APM_G(trace_callbacks), 1);
	}

	return SUCCESS;
}

/**
 * ***************************************************
 * COMMON HELPER FUNCTION DEFINITIONS AND LOCAL MACROS
 * ***************************************************
 */

static void hp_register_constants(INIT_FUNC_ARGS) {
	REGISTER_LONG_CONSTANT("APM_FLAGS_NO_BUILTINS",
						   XHPROF_FLAGS_NO_BUILTINS,
						   CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("APM_FLAGS_CPU",
						   XHPROF_FLAGS_CPU,
						   CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("APM_FLAGS_MEMORY",
						   XHPROF_FLAGS_MEMORY,
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
static inline uint8 hp_inline_hash(char * str) {
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

/**
 * Parse the list of ignored functions from the zval argument.
 *
 * @author mpal
 */
static void hp_get_ignored_functions_from_arg(zval *args) {

	if (APM_G(ignored_function_names)) {
		hp_array_del(APM_G(ignored_function_names));
	}

	if (args != NULL) {
		zval  *zresult = NULL;

		zresult = hp_zval_at_key("ignored", args);
		APM_G(ignored_function_names) = hp_strings_in_zval(zresult);
	} else {
		APM_G(ignored_function_names) = NULL;
	}
}

/**
 * Clear filter for functions which may be ignored during profiling.
 *
 * @author mpal
 */
static void hp_ignored_functions_filter_clear() {
	memset(APM_G(ignored_function_filter), 0,
		   XHPROF_IGNORED_FUNCTION_FILTER_SIZE);
}

/**
 * Initialize filter for ignored functions using bit vector.
 *
 * @author mpal
 */
static void hp_ignored_functions_filter_init() {
	if (APM_G(ignored_function_names) != NULL) {
		int i = 0;
		for(; APM_G(ignored_function_names[i]) != NULL; i++) {
			char *str  = APM_G(ignored_function_names[i]);
			uint8 hash = hp_inline_hash(str);
			int   idx  = INDEX_2_BYTE(hash);
			APM_G(ignored_function_filter[idx]) |= INDEX_2_BIT(hash);
		}
	}
}

/**
 * Check if function collides in filter of functions to be ignored.
 *
 * @author mpal
 */
int hp_ignored_functions_filter_collision(uint8 hash) {
	uint8 mask = INDEX_2_BIT(hash);
	return APM_G(ignored_function_filter[INDEX_2_BYTE(hash)]) & mask;
}



/**
 * Initialize profiler state
 *
 * @author kannan, veeve
 */
void hp_init_profiler_state() {
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

	/* NOTE(cjiang): some fields such as cpu_frequencies take relatively longer
     * to initialize, (5 milisecond per logical cpu right now), therefore we
     * calculate them lazily. */
	if (APM_G(cpu_frequencies) == NULL) {
		get_all_cpu_frequencies();
		restore_cpu_affinity(&APM_G(prev_mask));
	}

	/* bind to a random cpu so that we can use rdtsc instruction. */
	bind_to_cpu((int) (rand() % APM_G(cpu_num)));

	/* Set up filter of functions which may be ignored during profiling */
	hp_ignored_functions_filter_init();

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

	/* Delete the array storing ignored function names */
	hp_array_del(APM_G(ignored_function_names));
	APM_G(ignored_function_names) = NULL;
}

/*
 * Start profiling - called just before calling the actual function
 * NOTE:  PLEASE MAKE SURE TSRMLS_CC IS AVAILABLE IN THE CONTEXT
 *        OF THE FUNCTION WHERE THIS MACRO IS CALLED.
 *        TSRMLS_CC CAN BE MADE AVAILABLE VIA TSRMLS_DC IN THE
 *        CALLING FUNCTION OR BY CALLING TSRMLS_FETCH()
 *        TSRMLS_FETCH() IS RELATIVELY EXPENSIVE.
 */
#define BEGIN_PROFILING(entries, symbol, profile_curr, execute_data)                  \
  do {                                                                  \
    /* Use a hash code to filter most of the string comparisons. */     \
    uint8 hash_code  = hp_inline_hash(symbol);                          \
    profile_curr = !hp_ignore_entry(hash_code, symbol);                 \
    if (profile_curr) {                                                 \
        if (execute_data != NULL) {                                             \
            symbol = hp_get_trace_callback(symbol, execute_data TSRMLS_CC);                     \
        }                                                               \
        hp_entry_t *cur_entry = hp_fast_alloc_hprof_entry();              \
        (cur_entry)->hash_code = hash_code;                               \
        (cur_entry)->name_hprof = symbol;                                 \
        (cur_entry)->prev_hprof = (*(entries));                           \
        hp_mode_hier_beginfn_cb((entries), (cur_entry));    \
        /* Update entries linked list */                                  \
        (*(entries)) = (cur_entry);                                       \
    }                                                                   \
  } while (0)

/*
 * Stop profiling - called just after calling the actual function
 * NOTE:  PLEASE MAKE SURE TSRMLS_CC IS AVAILABLE IN THE CONTEXT
 *        OF THE FUNCTION WHERE THIS MACRO IS CALLED.
 *        TSRMLS_CC CAN BE MADE AVAILABLE VIA TSRMLS_DC IN THE
 *        CALLING FUNCTION OR BY CALLING TSRMLS_FETCH()
 *        TSRMLS_FETCH() IS RELATIVELY EXPENSIVE.
 */
#define END_PROFILING(entries, profile_curr)                            \
  do {                                                                  \
    if (profile_curr) {                                                 \
      hp_entry_t *cur_entry;                                            \
      /* Call the mode's endfn callback. */                             \
      /* NOTE(cjiang): we want to call this 'end_fn_cb' before */       \
      /* 'hp_mode_common_endfn' to avoid including the time in */       \
      /* 'hp_mode_common_endfn' in the profiling results.      */       \
      hp_mode_hier_endfn_cb((entries) TSRMLS_CC);                       \
      cur_entry = (*(entries));                                         \
      /* Call the universal callback */                                 \
      hp_mode_common_endfn((entries), (cur_entry) TSRMLS_CC);           \
      /* Free top entry and update entries linked list */               \
      (*(entries)) = (*(entries))->prev_hprof;                          \
      hp_fast_free_hprof_entry(cur_entry);                              \
    }                                                                   \
  } while (0)


/**
 * Returns formatted function name
 *
 * @param  entry        hp_entry
 * @param  result_buf   ptr to result buf
 * @param  result_len   max size of result buf
 * @return total size of the function name returned in result_buf
 * @author veeve
 */
size_t hp_get_entry_name(hp_entry_t  *entry,
						 char           *result_buf,
						 size_t          result_len) {

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
int  hp_ignore_entry_work(uint8 hash_code, char *curr_func) {
	int ignore = 0;
	if (hp_ignored_functions_filter_collision(hash_code)) {
		int i = 0;
		for (; APM_G(ignored_function_names[i]) != NULL; i++) {
			char *name = APM_G(ignored_function_names[i]);
			if ( !strcmp(curr_func, name)) {
				ignore++;
				break;
			}
		}
	}

	return ignore;
}

static inline int  hp_ignore_entry(uint8 hash_code, char *curr_func) {
	/* First check if ignoring functions is enabled */
	return APM_G(ignored_function_names) != NULL &&
		   hp_ignore_entry_work(hash_code, curr_func);
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
	int                len;
	zend_function      *curr_func;

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
static void hp_free_the_free_list() {
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
static hp_entry_t *hp_fast_alloc_hprof_entry() {
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
static void hp_fast_free_hprof_entry(hp_entry_t *p) {

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
 * Looksup the hash table for the given symbol
 * Initializes a new array() if symbol is not present
 *
 * @author kannan, veeve
 */
zval * hp_hash_lookup(char *symbol  TSRMLS_DC) {
	HashTable   *ht;
	void        *data;
	zval        *counts = (zval *) 0;

	/* Bail if something is goofy */
	if (!APM_G(stats_count) || !(ht = HASH_OF(APM_G(stats_count)))) {
		return (zval *) 0;
	}

	/* Lookup our hash table */
	if (zend_hash_find(ht, symbol, strlen(symbol) + 1, &data) == SUCCESS) {
		/* Symbol already exists */
		counts = *(zval **) data;
	}
	else {
		/* Add symbol to hash table */
		MAKE_STD_ZVAL(counts);
		array_init(counts);
		add_assoc_zval(APM_G(stats_count), symbol, counts);
	}

	return counts;
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
 * Sample the stack. Add it to the stats_count global.
 *
 * @param  tv            current time
 * @param  entries       func stack as linked list of hp_entry_t
 * @return void
 * @author veeve
 */
void hp_sample_stack(hp_entry_t  **entries  TSRMLS_DC) {
	char key[SCRATCH_BUF_LEN];
	char symbol[SCRATCH_BUF_LEN * 1000];

	/* Build key */
	snprintf(key, sizeof(key),
			 "%d.%06d",
			 APM_G(last_sample_time).tv_sec,
			 APM_G(last_sample_time).tv_usec);

	/* Init stats in the global stats_count hashtable */
	hp_get_function_stack(*entries,
						  INT_MAX,
						  symbol,
						  sizeof(symbol));

	add_assoc_string(APM_G(stats_count),
					 key,
					 symbol,
					 1);
	return;
}

/**
 * Checks to see if it is time to sample the stack.
 * Calls hp_sample_stack() if its time.
 *
 * @param  entries        func stack as linked list of hp_entry_t
 * @param  last_sample    time the last sample was taken
 * @param  sampling_intr  sampling interval in microsecs
 * @return void
 * @author veeve
 */
void hp_sample_check(hp_entry_t **entries  TSRMLS_DC) {
	/* Validate input */
	if (!entries || !(*entries)) {
		return;
	}

	/* See if its time to sample.  While loop is to handle a single function
     * taking a long time and passing several sampling intervals. */
	while ((cycle_timer() - APM_G(last_sample_tsc))
		   > APM_G(sampling_interval_tsc)) {

		/* bump last_sample_tsc */
		APM_G(last_sample_tsc) += APM_G(sampling_interval_tsc);

		/* bump last_sample_time - HAS TO BE UPDATED BEFORE calling hp_sample_stack */
		incr_us_interval(&APM_G(last_sample_time), XHPROF_SAMPLING_INTERVAL);

		/* sample the stack */
		hp_sample_stack(entries  TSRMLS_CC);
	}

	return;
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
	uint32 __a,__d;
	uint64 val;
	asm volatile("rdtsc" : "=a" (__a), "=d" (__d));
	(val) = ((uint64)__a) | (((uint64)__d)<<32);
	return val;
}

/**
 * Bind the current process to a specified CPU. This function is to ensure that
 * the OS won't schedule the process to different processors, which would make
 * values read by rdtsc unreliable.
 *
 * @param uint32 cpu_id, the id of the logical cpu to be bound to.
 * @return int, 0 on success, and -1 on failure.
 *
 * @author cjiang
 */
int bind_to_cpu(uint32 cpu_id) {
	cpu_set_t new_mask;

	CPU_ZERO(&new_mask);
	CPU_SET(cpu_id, &new_mask);

	if (SET_AFFINITY(0, sizeof(cpu_set_t), &new_mask) < 0) {
		perror("setaffinity");
		return -1;
	}

	/* record the cpu_id the process is bound to. */
	APM_G(cur_cpu_id) = cpu_id;

	return 0;
}

/**
 * Get time delta in microseconds.
 */
static long get_us_interval(struct timeval *start, struct timeval *end) {
	return (((end->tv_sec - start->tv_sec) * 1000000)
			+ (end->tv_usec - start->tv_usec));
}

/**
 * Incr time with the given microseconds.
 */
static void incr_us_interval(struct timeval *start, uint64 incr) {
	incr += (start->tv_sec * 1000000 + start->tv_usec);
	start->tv_sec  = incr/1000000;
	start->tv_usec = incr%1000000;
	return;
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
static inline double get_us_from_tsc(uint64 count, double cpu_frequency) {
	return count / cpu_frequency;
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
 * This is a microbenchmark to get cpu frequency the process is running on. The
 * returned value is used to convert TSC counter values to microseconds.
 *
 * @return double.
 * @author cjiang
 */
static double get_cpu_frequency() {
	struct timeval start;
	struct timeval end;

	if (gettimeofday(&start, 0)) {
		perror("gettimeofday");
		return 0.0;
	}
	uint64 tsc_start = cycle_timer();
	/* Sleep for 5 miliseconds. Comparaing with gettimeofday's  few microseconds
     * execution time, this should be enough. */
	usleep(5000);
	if (gettimeofday(&end, 0)) {
		perror("gettimeofday");
		return 0.0;
	}
	uint64 tsc_end = cycle_timer();
	return (tsc_end - tsc_start) * 1.0 / (get_us_interval(&start, &end));
}

/**
 * Calculate frequencies for all available cpus.
 *
 * @author cjiang
 */
static void get_all_cpu_frequencies() {
	int id;
	double frequency;

	APM_G(cpu_frequencies) = malloc(sizeof(double) * APM_G(cpu_num));
	if (APM_G(cpu_frequencies) == NULL) {
		return;
	}

	/* Iterate over all cpus found on the machine. */
	for (id = 0; id < APM_G(cpu_num); ++id) {
		/* Only get the previous cpu affinity mask for the first call. */
		if (bind_to_cpu(id)) {
			clear_frequencies();
			return;
		}

		/* Make sure the current process gets scheduled to the target cpu. This
         * might not be necessary though. */
		usleep(0);

		frequency = get_cpu_frequency();
		if (frequency == 0.0) {
			clear_frequencies();
			return;
		}
		APM_G(cpu_frequencies[id]) = frequency;
	}
}

/**
 * Restore cpu affinity mask to a specified value. It returns 0 on success and
 * -1 on failure.
 *
 * @param cpu_set_t * prev_mask, previous cpu affinity mask to be restored to.
 * @return int, 0 on success, and -1 on failure.
 *
 * @author cjiang
 */
int restore_cpu_affinity(cpu_set_t * prev_mask) {
	if (SET_AFFINITY(0, sizeof(cpu_set_t), prev_mask) < 0) {
		perror("restore setaffinity");
		return -1;
	}
	/* default value ofor cur_cpu_id is 0. */
	APM_G(cur_cpu_id) = 0;
	return 0;
}

/**
 * Reclaim the memory allocated for cpu_frequencies.
 *
 * @author cjiang
 */
static void clear_frequencies() {
	if (APM_G(cpu_frequencies)) {
		free(APM_G(cpu_frequencies));
		APM_G(cpu_frequencies) = NULL;
	}
	restore_cpu_affinity(&APM_G(prev_mask));
}

/**
 * ****************************
 * XHPROF COMMON CALLBACKS
 * ****************************
 */
/**
 * XHPROF universal end function.  This function is called for all modes after
 * the mode's specific end_function callback is called.
 *
 * @param  hp_entry_t **entries  linked list (stack) of hprof entries
 * @return void
 * @author kannan, veeve
 */
void hp_mode_common_endfn(hp_entry_t **entries, hp_entry_t *current TSRMLS_DC) {
	APM_G(func_hash_counters[current->hash_code])--;
}

/**
 * *********************************
 * XHPROF INIT MODULE CALLBACKS
 * *********************************
 */
/**
 * XHPROF_MODE_SAMPLED's init callback
 *
 * @author veeve
 */
void hp_mode_sampled_init_cb(TSRMLS_D) {
	struct timeval  now;
	uint64 truncated_us;
	uint64 truncated_tsc;
	double cpu_freq = APM_G(cpu_frequencies[APM_G(cur_cpu_id)]);

	/* Init the last_sample in tsc */
	APM_G(last_sample_tsc) = cycle_timer();

	/* Find the microseconds that need to be truncated */
	gettimeofday(&APM_G(last_sample_time), 0);
	now = APM_G(last_sample_time);
	hp_trunc_time(&APM_G(last_sample_time), XHPROF_SAMPLING_INTERVAL);

	/* Subtract truncated time from last_sample_tsc */
	truncated_us  = get_us_interval(&APM_G(last_sample_time), &now);
	truncated_tsc = get_tsc_from_us(truncated_us, cpu_freq);
	if (APM_G(last_sample_tsc) > truncated_tsc) {
		/* just to be safe while subtracting unsigned ints */
		APM_G(last_sample_tsc) -= truncated_tsc;
	}

	/* Convert sampling interval to ticks */
	APM_G(sampling_interval_tsc) =
			get_tsc_from_us(XHPROF_SAMPLING_INTERVAL, cpu_freq);
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
void hp_mode_hier_beginfn_cb(hp_entry_t **entries, hp_entry_t *current)
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
	if (APM_G(xhprof_flags) & XHPROF_FLAGS_CPU) {
		getrusage(RUSAGE_SELF, &(current->ru_start_hprof));
	}

	/* Get memory usage */
	if (APM_G(xhprof_flags) & XHPROF_FLAGS_MEMORY) {
		current->mu_start_hprof  = zend_memory_usage(0 TSRMLS_CC);
		current->pmu_start_hprof = zend_memory_peak_usage(0 TSRMLS_CC);
	}
}


/**
 * XHPROF_MODE_SAMPLED's begin function callback
 *
 * @author veeve
 */
void hp_mode_sampled_beginfn_cb(hp_entry_t **entries,
								hp_entry_t  *current  TSRMLS_DC) {
	/* See if its time to take a sample */
	hp_sample_check(entries  TSRMLS_CC);
}


/**
 * **********************************
 * XHPROF END FUNCTION CALLBACKS
 * **********************************
 */

/**
 * XHPROF shared end function callback
 *
 * @author kannan
 */
zval * hp_mode_shared_endfn_cb(hp_entry_t *top, char *symbol TSRMLS_DC) {
	zval    *counts;
	uint64   tsc_end;

	/* Get end tsc counter */
	tsc_end = cycle_timer();

	/* Get the stat array */
	if (!(counts = hp_hash_lookup(symbol TSRMLS_CC))) {
		return (zval *) 0;
	}

	/* Bump stats in the counts hashtable */
	hp_inc_count(counts, "ct", 1  TSRMLS_CC);

	hp_inc_count(counts, "wt", get_us_from_tsc(tsc_end - top->tsc_start,
											   APM_G(cpu_frequencies[APM_G(cur_cpu_id)])) TSRMLS_CC);
	return counts;
}

/**
 * XHPROF_MODE_HIERARCHICAL's end function callback
 *
 * @author kannan
 */
void hp_mode_hier_endfn_cb(hp_entry_t **entries  TSRMLS_DC) {
	hp_entry_t   *top = (*entries);
	zval            *counts;
	struct rusage    ru_end;
	char             symbol[SCRATCH_BUF_LEN];
	long int         mu_end;
	long int         pmu_end;

	/* Get the stat array */
	hp_get_function_stack(top, 2, symbol, sizeof(symbol));
	if (!(counts = hp_mode_shared_endfn_cb(top, symbol  TSRMLS_CC))) {
		return;
	}

	if (APM_G(xhprof_flags) & XHPROF_FLAGS_CPU) {
		/* Get CPU usage */
		getrusage(RUSAGE_SELF, &ru_end);

		/* Bump CPU stats in the counts hashtable */
		hp_inc_count(counts, "cpu", (get_us_interval(&(top->ru_start_hprof.ru_utime),
													 &(ru_end.ru_utime)) +
									 get_us_interval(&(top->ru_start_hprof.ru_stime),
													 &(ru_end.ru_stime)))
					 TSRMLS_CC);
	}

	if (APM_G(xhprof_flags) & XHPROF_FLAGS_MEMORY) {
		/* Get Memory usage */
		mu_end  = zend_memory_usage(0 TSRMLS_CC);
		pmu_end = zend_memory_peak_usage(0 TSRMLS_CC);

		/* Bump Memory stats in the counts hashtable */
		hp_inc_count(counts, "mu",  mu_end - top->mu_start_hprof    TSRMLS_CC);
		hp_inc_count(counts, "pmu", pmu_end - top->pmu_start_hprof  TSRMLS_CC);
	}
}

/**
 * XHPROF_MODE_SAMPLED's end function callback
 *
 * @author veeve
 */
void hp_mode_sampled_endfn_cb(hp_entry_t **entries  TSRMLS_DC) {
	/* See if its time to take a sample */
	hp_sample_check(entries  TSRMLS_CC);
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

    if (!APM_G(enabled) || (APM_G(xhprof_flags) & XHPROF_FLAGS_NO_BUILTINS) > 0) {
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
		hp_init_profiler_state();

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
        hp_stop();
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

	/* Resore cpu affinity. */
	restore_cpu_affinity(&APM_G(prev_mask));

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
static zval *hp_zval_at_key(char  *key,
							zval  *values) {
	zval *result = NULL;

	if (values->type == IS_ARRAY) {
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
static char **hp_strings_in_zval(zval  *values) {
	char   **result;
	size_t   count;
	size_t   ix = 0;

	if (!values) {
		return NULL;
	}

	if (values->type == IS_ARRAY) {
		HashTable *ht;

		ht    = Z_ARRVAL_P(values);
		count = zend_hash_num_elements(ht);

		if((result =
					(char**)emalloc(sizeof(char*) * (count + 1))) == NULL) {
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
			if(type == HASH_KEY_IS_LONG) {
				if ((zend_hash_get_current_data(ht, (void**)&data) == SUCCESS) &&
					Z_TYPE_PP(data) == IS_STRING &&
					strcmp(Z_STRVAL_PP(data), ROOT_SYMBOL)) { /* do not ignore "main" */
					result[ix] = estrdup(Z_STRVAL_PP(data));
					ix++;
				}
			}
		}
	} else if(values->type == IS_STRING) {
		if((result = (char**)emalloc(sizeof(char*) * 2)) == NULL) {
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
		for(; name_array[i] != NULL && i < XHPROF_MAX_IGNORED_FUNCTIONS; i++) {
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

static zval *hp_pcre_match(char *pattern, int len, zval *data) {
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

static char* hp_pcre_replace(char *pattern, int len, zval* repl, zval *data, int limit) {
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
	pdo_stmt_t *stmt = (pdo_stmt_t*)zend_object_store_get_object(data->object);
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

			char *repl_str = hp_pcre_replace(pattern_str, pattern_len, repl, sql_query, 1);

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
    zval *func, *option, **ppzval, *retval = NULL;
    zval *arg = hp_get_execute_argument(data, 1);

    if (arg == NULL || Z_TYPE_P(arg) != IS_RESOURCE) {
        spprintf(&result, 0, "%s", symbol);
        return result;
    }

    zval **params[1] = {&arg};

    MAKE_STD_ZVAL(func);
    ZVAL_STRINGL(func, "curl_getinfo", strlen("curl_getinfo"), 1);

    zend_fcall_info fci = {
        sizeof(fci),
        EG(function_table),
        func,
        NULL,
        &retval,
        1,
        (zval ***)params,
        NULL,
        1
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

static void hp_free_trace_cb(void *p) {
}

static void hp_init_trace_callbacks(TSRMLS_D) {
	hp_trace_callback callback;

	if (APM_G(trace_callbacks)) {
		return;
	}

	APM_G(trace_callbacks) = (HashTable *)pemalloc(sizeof(HashTable), 1);
	if (!APM_G(trace_callbacks)) {
		return;
	}
	zend_hash_init(APM_G(trace_callbacks), 16, NULL, (dtor_func_t) hp_free_trace_cb, 1);

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

static zval *hp_get_export_data(zval *data) {
    zval *meta, *result, *root, *repl, *pzurl;
	char *scheme, *url;
    int request_date;

    MAKE_STD_ZVAL(meta);
    array_init(meta);

    MAKE_STD_ZVAL(result);
    array_init(result);

    zval *server = hp_request_query(TRACK_VARS_SERVER, NULL, 0 TSRMLS_CC);
    zval *uri = hp_request_query(TRACK_VARS_SERVER, "REQUEST_URI", strlen("REQUEST_URI") TSRMLS_CC);
    zval *ssl = hp_request_query(TRACK_VARS_SERVER, "HTTPS", strlen("HTTPS") TSRMLS_CC);
    zval *server_name = hp_request_query(TRACK_VARS_SERVER, "SERVER_NAME", strlen("SERVER_NAME") TSRMLS_CC);
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

    char *simple_url = hp_pcre_replace("(=[^&]+)", sizeof("(=[^&]+)") - 1, repl, pzurl, -1);

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

	zval_ptr_dtor(&uri);
	zval_ptr_dtor(&ssl);
	zval_ptr_dtor(&server_name);
	zval_ptr_dtor(&repl);
	zval_ptr_dtor(&pzurl);

	efree(url);
	efree(simple_url);

    return result;

}

static int hp_rshutdown_php(zval *data TSRMLS_DC) {
	zend_file_handle file_handle;
	zend_op_array *op_array = NULL;
	char realpath[MAXPATHLEN];
	char *path;

    if (!INI_STR("xhprof_apm.php_file")) {
        return 0;
    }

    spprintf(&path, 0, "%s", INI_STR("xhprof_apm.php_file"));

    if (!VCWD_REALPATH(path, realpath)) {
        char *buffer;
        buffer = getcwd(NULL, 0);
        spprintf(&path, 0, "%s%s", buffer, INI_STR("xhprof_apm.php_file"));

        if (!VCWD_REALPATH(path, realpath)) {
            efree(path);
            return 0;
        }
	}

	file_handle.filename = path;
	file_handle.free_filename = 0;
	file_handle.type = ZEND_HANDLE_FILENAME;
	file_handle.opened_path = NULL;
	file_handle.handle.fp = NULL;

	op_array = zend_compile_file(&file_handle, ZEND_INCLUDE TSRMLS_CC);

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
            zval *export_data = hp_get_export_data(data);
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

static int hp_rshutdown_curl(zval *data TSRMLS_DC) {
	char *uri = INI_STR("xhprof_apm.curl_uri");

	if (!uri) {
		return 0;
	}

	smart_str buf = {0};

#if ((PHP_MAJOR_VERSION == 5) && (PHP_MINOR_VERSION < 3))
	php_json_encode(&buf, data TSRMLS_CC);
#else
	php_json_encode(&buf, data, 0 TSRMLS_CC); /* options */
#endif

	smart_str_0(&buf);

	CURL *curl = curl_easy_init();
	if (curl) {
		CURLcode res;
		struct curl_slist *headers = NULL;

		headers = curl_slist_append(headers, "User-Agent: Xhprof-apm");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		curl_easy_setopt(curl, CURLOPT_URL, uri);
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf.c);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3);
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);

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
		return 1;
	}

	smart_str_free(&buf);
	return 0;
}

/**
 * Request init callback. Nothing to do yet!
 */
PHP_RINIT_FUNCTION(xhprof_apm) {
	int enable = 0;
	long flags = 0;

	if (SG(request_info).request_method) {
		zval *self_curl = hp_request_query(TRACK_VARS_SERVER, "HTTP_USER_AGENT", strlen("HTTP_USER_AGENT") TSRMLS_CC);
		if (Z_TYPE_P(self_curl) == IS_STRING && strcmp(Z_STRVAL_P(self_curl), "Xhprof-apm") == 0) {
			zval_ptr_dtor(&self_curl);
			return SUCCESS;
		}

		zval_ptr_dtor(&self_curl);

		char *config_ini;
		char realpath[MAXPATHLEN];
		spprintf(&config_ini, 0, "%s", INI_STR("xhprof_apm.config_ini"));

		if (!VCWD_REALPATH(config_ini, realpath)) {
			zval *document_root = hp_request_query(TRACK_VARS_SERVER, "DOCUMENT_ROOT", strlen("DOCUMENT_ROOT") TSRMLS_CC);
			spprintf(&config_ini, 0, "%s/%s", Z_STRVAL_P(document_root), INI_STR("xhprof_apm.config_ini"));
			zval_ptr_dtor(&document_root);

			if (!VCWD_REALPATH(config_ini, realpath)) {
				efree(config_ini);
				return SUCCESS;
			}
		}

		efree(config_ini);

		struct stat sb;
		zend_file_handle fh = {0};
		zval *configs, *apm_config;

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
			return SUCCESS;
		}

		zval *zval_auto = hp_zval_at_key("auto", apm_config);
		if (zval_auto) {
			convert_to_long(zval_auto);
			enable = Z_LVAL_P(zval_auto);
		}

		if (!enable) {
			return SUCCESS;
		}

        zval *zval_rate = hp_zval_at_key("rate", apm_config);
        if (zval_rate) {
            convert_to_long(zval_rate);
            int sample_rate = Z_LVAL_P(zval_rate);

            if (!sample_rate) {
                return SUCCESS;
            }

			long number = php_rand(TSRMLS_C);
			RAND_RANGE(number, 0, 100, PHP_RAND_MAX);

			if (sample_rate < number) {
				return SUCCESS;
			}
        }

		zval *zval_flags = hp_zval_at_key("flags", apm_config);
		if (zval_flags) {
			convert_to_long(zval_flags);
			flags = Z_LVAL_P(zval_flags);
		}

		hp_get_ignored_functions_from_arg(apm_config);
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

		zval *data;
		MAKE_STD_ZVAL(data);
		ZVAL_ZVAL(data, APM_G(stats_count), 1, 0);

		hp_end(TSRMLS_C);

		char *export = INI_STR("xhprof_apm.export");
		if (strcmp(export, "php") == 0) {
			hp_rshutdown_php(data TSRMLS_CC);
		} else if (strcmp(export, "curl") == 0) {
			hp_rshutdown_curl(data TSRMLS_CC);
		}

        zval_ptr_dtor(&data);
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
	php_info_print_table_header(2, "xhprof_apm", XHPROF_APM_VERSION);
	len = snprintf(buf, SCRATCH_BUF_LEN, "%d", APM_G(cpu_num));
	buf[len] = 0;
	php_info_print_table_header(2, "CPU num", buf);

	if (APM_G(cpu_frequencies)) {
		/* Print available cpu frequencies here. */
		php_info_print_table_header(2, "CPU logical id", " Clock Rate (MHz) ");
		for (i = 0; i < APM_G(cpu_num); ++i) {
			len = snprintf(buf, SCRATCH_BUF_LEN, " CPU %d ", i);
			buf[len] = 0;
			len = snprintf(tmp, SCRATCH_BUF_LEN, "%f", APM_G(cpu_frequencies[i]));
			tmp[len] = 0;
			php_info_print_table_row(2, buf, tmp);
		}
	}

	php_info_print_table_end();
}