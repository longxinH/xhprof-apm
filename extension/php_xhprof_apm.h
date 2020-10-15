/*
  +----------------------------------------------------------------------+
  | Xhprof APM                                                           |
  +----------------------------------------------------------------------+
  | Copyright (c) 2013-2013 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: Xinhui Long <longxinhui@php.net>                             |
  +----------------------------------------------------------------------+
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
#define XHPROF_APM_VERSION       "1.0.0"

#define APM_FUNC_HASH_COUNTERS_SIZE   1024

/* Size of a temp scratch buffer            */
#define SCRATCH_BUF_LEN            512

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
    /* Replace zend_execute_internal with our proxy */ \
    _zend_execute_internal = zend_execute_internal; \
    zend_execute_internal = hp_execute_internal;

#define APM_RESTORE_ZEND_HANDLE() \
		zend_execute_ex = _zend_execute_ex; \
		zend_execute_internal = _zend_execute_internal; \
		zend_compile_file     = _zend_compile_file; \
		zend_compile_string   = _zend_compile_string;

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
    zend_ulong hash_code = ZSTR_HASH(symbol);                                \
    profile_curr = !hp_ignore_entry_work(hash_code, symbol);                 \
    if (profile_curr) {                                                      \
        if (execute_data != NULL) {                                          \
            symbol = hp_get_trace_callback(symbol, execute_data);            \
        }                                                                    \
        hp_entry_t *cur_entry = hp_fast_alloc_hprof_entry();                 \
        (cur_entry)->hash_code = hash_code % APM_FUNC_HASH_COUNTERS_SIZE; \
        (cur_entry)->name_hprof = symbol;                                    \
        (cur_entry)->prev_hprof = (*(entries));                              \
        hp_mode_hier_beginfn_cb((entries), (cur_entry));                     \
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
      hp_mode_hier_endfn_cb((entries));                       \
      cur_entry = (*(entries));                                         \
      /* Free top entry and update entries linked list */               \
      (*(entries)) = (*(entries))->prev_hprof;                          \
      hp_fast_free_hprof_entry(cur_entry);                              \
    }                                                                   \
  } while (0)

#define register_trace_callback(function_name, cb) zend_hash_str_update_mem(APM_G(trace_callbacks), function_name, sizeof(function_name) - 1, &cb, sizeof(hp_trace_callback));


/**
 * *****************************
 * GLOBAL DATATYPES AND TYPEDEFS
 * *****************************
 */
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
    struct hp_entry_t       *prev_hprof;    /* ptr to prev entry being profiled */
    zend_string             *name_hprof;                       /* function name */
    int                     rlvl_hprof;        /* recursion level for function */
    zend_ulong              tsc_start;
    zend_ulong              cpu_start;/* start value for TSC counter  */
    long int                mu_start_hprof;                    /* memory usage */
    long int                pmu_start_hprof;              /* peak memory usage */
    zend_ulong              hash_code;     /* hash_code for the function name  */
} hp_entry_t;

typedef struct hp_ignored_functions {
    zend_string **names;
    zend_ulong filter[APM_MAX_IGNORED_FUNCTIONS];
} hp_ignored_functions;

typedef zend_string* (*hp_trace_callback) (zend_string *symbol, zend_execute_data *data);

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
    zval            stats_count;

    /* Top of the profile stack */
    hp_entry_t      *entries;

    /* freelist of hp_entry_t chunks for reuse... */
    hp_entry_t      *entry_free_list;

    /* XHProf flags */
    uint32 xhprof_flags;

    zend_string *root;

    int debug;

    /* counter table indexed by hash value of function names. */
    uint8  func_hash_counters[256];

    HashTable *trace_callbacks;

    /* Table of ignored function names and their filter */
    hp_ignored_functions *ignored_functions;

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

extern ZEND_DECLARE_MODULE_GLOBALS(apm);

/**
 * ***********************
 * GLOBAL STATIC VARIABLES
 * ***********************
 */
/* Pointer to the original execute function */
static void (*_zend_execute_ex) (zend_execute_data *execute_data);
ZEND_DLEXPORT void hp_execute_ex (zend_execute_data *execute_data);

/* Pointer to the origianl execute_internal function */
static void (*_zend_execute_internal) (zend_execute_data *data, zval *return_value);
ZEND_DLEXPORT void hp_execute_internal(zend_execute_data *execute_data, zval *return_value);

/* Pointer to the original compile function */
static zend_op_array * (*_zend_compile_file) (zend_file_handle *file_handle, int type);
ZEND_DLEXPORT zend_op_array* hp_compile_file(zend_file_handle *file_handle, int type);

/* Pointer to the original compile string function (used by eval) */
static zend_op_array * (*_zend_compile_string) (zval *source_string, char *filename);
ZEND_DLEXPORT zend_op_array* hp_compile_string(zval *source_string, char *filename);

/* Bloom filter for function names to be ignored */
#define INDEX_2_BYTE(index)  (index >> 3)
#define INDEX_2_BIT(index)   (1 << (index & 0x7));

/**
 * ****************************
 * STATIC FUNCTION DECLARATIONS
 * ****************************
 */
static void hp_register_constants(INIT_FUNC_ARGS);

static void hp_begin(long xhprof_flags);
static void hp_stop();
static void hp_end();

static inline zend_ulong cycle_timer();

static void hp_free_the_free_list();
static hp_entry_t *hp_fast_alloc_hprof_entry();
static void hp_fast_free_hprof_entry(hp_entry_t *p);

static inline zval *hp_zval_at_key(char *key, zval *values);
static inline void hp_array_del(zend_string **names);
static void hp_clean_profiler_options_state();

zend_string *hp_get_trace_callback(zend_string *symbol, zend_execute_data *data);
static void hp_init_trace_callbacks();

static hp_ignored_functions *hp_ignored_functions_init(zval *values);

static zval *hp_request_query_ex(uint type, zend_bool fetch_type, void *name, size_t len);

#define hp_request_query(type, name)  hp_request_query_ex((type), 1, (name), 0)
#define hp_request_query_str(type, name, len)  hp_request_query_ex((type), 0, (name), (len))

#endif	/* PHP_XHPROF_APM_H */
