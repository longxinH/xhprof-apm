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

#ifndef PHP_XHPROF_APM_H
#define PHP_XHPROF_APM_H

extern zend_module_entry xhprof_apm_module_entry;
#define phpext_xhprof_apm_ptr &xhprof_apm_module_entry

#ifdef PHP_WIN32
#	define PHP_XHPROF_APM_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_XHPROF_APM_API __attribute__ ((visibility("default")))
#else
#	define PHP_XHPROF_APM_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

/**
 * **********************
 * GLOBAL MACRO CONSTANTS
 * **********************
 */

/* XHProf_APM version                           */
#define XHPROF_APM_VERSION       "0.1.0"

/* Fictitious function name to represent top of the call tree. The paranthesis
 * in the name is to ensure we don't conflict with user function names.  */
#define ROOT_SYMBOL                "main()"

/* Hierarchical profiling flags.
 *
 * Note: Function call counts and wall (elapsed) time are always profiled.
 * The following optional flags can be used to control other aspects of
 * profiling.
 */
#define APM_FLAGS_NO_BUILTINS   0x0001         /* do not profile builtins */
#define APM_FLAGS_CPU           0x0002      /* gather CPU times for funcs */
#define APM_FLAGS_MEMORY        0x0004   /* gather memory usage for funcs */

/* Constant for ignoring functions, transparent to hierarchical profile */
#define APM_MAX_IGNORED_FUNCTIONS  256
#define APM_IGNORED_FUNCTION_FILTER_SIZE                           \
               ((APM_MAX_IGNORED_FUNCTIONS + 7)/8)

#if PHP_VERSION_ID > 50500
#define APM_STORE_ZEND_HANDLE() \
		/* Replace zend_compile with our proxy */ \
        _zend_compile_file = zend_compile_file; \
        zend_compile_file  = hp_compile_file; \
        /* Replace zend_compile_string with our proxy */ \
        _zend_compile_string = zend_compile_string; \
        zend_compile_string = hp_compile_string; \
        /* Replace zend_execute with our proxy */ \
        _zend_execute_ex = zend_execute_ex; \
        zend_execute_ex  = hp_execute_ex; \
        /* Replace zend_execute_internal with our proxy */  \
        _zend_execute_internal = zend_execute_internal;  \
        zend_execute_internal = hp_execute_internal;
#define APM_RESTORE_ZEND_HANDLE() \
		zend_execute_ex = _zend_execute_ex; \
		zend_execute_internal = _zend_execute_internal; \
		zend_compile_file     = _zend_compile_file; \
		zend_compile_string   = _zend_compile_string;
#else

#define APM_STORE_ZEND_HANDLE() \
		/* Replace zend_compile with our proxy */ \
        _zend_compile_file = zend_compile_file; \
        zend_compile_file  = hp_compile_file; \
        /* Replace zend_compile_string with our proxy */ \
        _zend_compile_string = zend_compile_string; \
        zend_compile_string = hp_compile_string; \
        /* Replace zend_execute with our proxy */ \
        _zend_execute = zend_execute; \
        zend_execute  = hp_execute; \
        /* Replace zend_execute_internal with our proxy */  \
        _zend_execute_internal = zend_execute_internal;  \
        zend_execute_internal = hp_execute_internal;
#define APM_RESTORE_ZEND_HANDLE() \
        /* Remove proxies, restore the originals */ \
		zend_execute = _zend_execute; \
		zend_execute_internal = _zend_execute_internal; \
		zend_compile_file     = _zend_compile_file; \
		zend_compile_string   = _zend_compile_string;
#endif

/*
 * Start profiling - called just before calling the actual function
 * NOTE:  PLEASE MAKE SURE TSRMLS_CC IS AVAILABLE IN THE CONTEXT
 *        OF THE FUNCTION WHERE THIS MACRO IS CALLED.
 *        TSRMLS_CC CAN BE MADE AVAILABLE VIA TSRMLS_DC IN THE
 *        CALLING FUNCTION OR BY CALLING TSRMLS_FETCH()
 *        TSRMLS_FETCH() IS RELATIVELY EXPENSIVE.
 */
#define BEGIN_PROFILING(entries, symbol, profile_curr, execute_data)         \
  do {                                                                       \
    /* Use a hash code to filter most of the string comparisons. */          \
    uint8 hash_code  = hp_inline_hash(symbol);                               \
    profile_curr = !hp_ignore_entry_work(hash_code, symbol TSRMLS_CC);                 \
    if (profile_curr) {                                                      \
        if (execute_data != NULL) {                                          \
            symbol = hp_get_trace_callback(symbol, execute_data TSRMLS_CC);  \
        }                                                                    \
        hp_entry_t *cur_entry = hp_fast_alloc_hprof_entry(TSRMLS_C);                 \
        (cur_entry)->hash_code = hash_code;                                  \
        (cur_entry)->name_hprof = symbol;                                    \
        (cur_entry)->prev_hprof = (*(entries));                              \
        hp_mode_hier_beginfn_cb((entries), (cur_entry) TSRMLS_CC);                     \
        /* Update entries linked list */                                     \
        (*(entries)) = (cur_entry);                                          \
    }                                                                        \
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
      /* Free top entry and update entries linked list */               \
      (*(entries)) = (*(entries))->prev_hprof;                          \
      hp_fast_free_hprof_entry(cur_entry TSRMLS_CC);                              \
    }                                                                   \
  } while (0)

#define register_trace_callback(function_name, cb) zend_hash_update(APM_G(trace_callbacks), function_name, sizeof(function_name), &cb, sizeof(hp_trace_callback*), NULL);


/**
 * *****************************
 * GLOBAL DATATYPES AND TYPEDEFS
 * *****************************
 */
#if !defined(uint64)
typedef unsigned long long uint64;
#endif
#if !defined(uint32)
typedef unsigned int uint32;
#endif
#if !defined(uint8)
typedef unsigned char uint8;
#endif

/* XHProf maintains a stack of entries being profiled. The memory for the entry
 * is passed by the layer that invokes BEGIN_PROFILING(), e.g. the hp_execute()
 * function. Often, this is just C-stack memory.
 *
 * This structure is a convenient place to track start time of a particular
 * profile operation, recursion depth, and the name of the function being
 * profiled. */
typedef struct hp_entry_t {
    char                   *name_hprof;                       /* function name */
    int                    rlvl_hprof;        /* recursion level for function */
    uint64                 tsc_start;         /* start value for TSC counter  */
    uint64                 cpu_start;
    long int               mu_start_hprof;                    /* memory usage */
    long int               pmu_start_hprof;              /* peak memory usage */
    struct hp_entry_t      *prev_hprof;    /* ptr to prev entry being profiled */
    uint8                  hash_code;     /* hash_code for the function name  */
} hp_entry_t;

typedef struct hp_ignored_function_map {
    char **names;
    uint8 filter[APM_MAX_IGNORED_FUNCTIONS];
} hp_ignored_function_map;

typedef char* (*hp_trace_callback)(char *symbol, zend_execute_data *data TSRMLS_DC);

/* Xhprof's global state.
 *
 * This structure is instantiated once.  Initialize defaults for attributes in
 * hp_init_profiler_state() Cleanup/free attributes in
 * hp_clean_profiler_state() */
ZEND_BEGIN_MODULE_GLOBALS(apm)

    /*       ----------   Global attributes:  -----------       */

    /* Indicates if xhprof is currently enabled */
    int              enabled;

    /* Indicates if xhprof was ever enabled during this request */
    int              ever_enabled;

    /* Holds all the xhprof statistics */
    zval            *stats_count;

    /* Top of the profile stack */
    hp_entry_t      *entries;

    /* freelist of hp_entry_t chunks for reuse... */
    hp_entry_t      *entry_free_list;

    double timebase_factor;

    /* XHProf flags */
    uint32 xhprof_flags;

    char *root;

    int debug;

    /* counter table indexed by hash value of function names. */
    uint8  func_hash_counters[256];

    HashTable *trace_callbacks;

    /* Table of ignored function names and their filter */
    hp_ignored_function_map *ignored_functions;

ZEND_END_MODULE_GLOBALS(apm)

PHP_MINIT_FUNCTION(xhprof_apm);
PHP_MSHUTDOWN_FUNCTION(xhprof_apm);
PHP_RINIT_FUNCTION(xhprof_apm);
PHP_RSHUTDOWN_FUNCTION(xhprof_apm);
PHP_MINFO_FUNCTION(xhprof_apm);
PHP_GINIT_FUNCTION(apm);

/* In every utility function you add that needs to use variables 
   in php_xhprof_apm_globals, call TSRMLS_FETCH(); after declaring other 
   variables used by that function, or better yet, pass in TSRMLS_CC
   after the last function argument and declare your utility function
   with TSRMLS_DC after the last declared argument.  Always refer to
   the globals in your function as XHPROF_APM_G(variable).  You are 
   encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/

#ifdef ZTS
#define APM_G(v) TSRMG(apm_globals_id, zend_apm_globals *, v)
#else
#define APM_G(v) (apm_globals.v)
#endif

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

static void hp_free_the_free_list(TSRMLS_D);
static hp_entry_t *hp_fast_alloc_hprof_entry(TSRMLS_D);
static void hp_fast_free_hprof_entry(hp_entry_t *p TSRMLS_DC);
static inline uint8 hp_inline_hash(char *str);
static double get_timebase_factor();

static inline zval *hp_zval_at_key(char *key, zval *values);
static inline char **hp_strings_in_zval(zval *values);
static inline void hp_array_del(char **name_array);
static void hp_clean_profiler_options_state(TSRMLS_D);

static char *hp_get_trace_callback(char *symbol, zend_execute_data *data TSRMLS_DC);
static void hp_init_trace_callbacks(TSRMLS_D);

static hp_ignored_function_map *hp_ignored_functions_init(char **names);

extern ZEND_DECLARE_MODULE_GLOBALS(apm);

#endif	/* PHP_XHPROF_APM_H */
