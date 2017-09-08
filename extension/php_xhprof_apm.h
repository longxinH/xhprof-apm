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

/* Size of a temp scratch buffer            */
#define SCRATCH_BUF_LEN            512

/* Various XHPROF modes. If you are adding a new mode, register the appropriate
 * callbacks in hp_begin() */
#define XHPROF_MODE_HIERARCHICAL            1
#define XHPROF_MODE_SAMPLED            620002      /* Rockfort's zip code */

/* Hierarchical profiling flags.
 *
 * Note: Function call counts and wall (elapsed) time are always profiled.
 * The following optional flags can be used to control other aspects of
 * profiling.
 */
#define XHPROF_FLAGS_NO_BUILTINS   0x0001         /* do not profile builtins */
#define XHPROF_FLAGS_CPU           0x0002      /* gather CPU times for funcs */
#define XHPROF_FLAGS_MEMORY        0x0004   /* gather memory usage for funcs */

/* Constants for XHPROF_MODE_SAMPLED        */
#define XHPROF_SAMPLING_INTERVAL       100000      /* In microsecs        */

/* Constant for ignoring functions, transparent to hierarchical profile */
#define XHPROF_MAX_IGNORED_FUNCTIONS  256
#define XHPROF_IGNORED_FUNCTION_FILTER_SIZE                           \
               ((XHPROF_MAX_IGNORED_FUNCTIONS + 7)/8)

#if !defined(uint64)
typedef unsigned long long uint64;
#endif
#if !defined(uint32)
typedef unsigned int uint32;
#endif
#if !defined(uint8)
typedef unsigned char uint8;
#endif

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

#define register_trace_callback(function_name, cb) zend_hash_update(APM_G(trace_callbacks), function_name, sizeof(function_name), &cb, sizeof(hp_trace_callback*), NULL);

/**
 * *****************************
 * GLOBAL DATATYPES AND TYPEDEFS
 * *****************************
 */

/* XHProf maintains a stack of entries being profiled. The memory for the entry
 * is passed by the layer that invokes BEGIN_PROFILING(), e.g. the hp_execute()
 * function. Often, this is just C-stack memory.
 *
 * This structure is a convenient place to track start time of a particular
 * profile operation, recursion depth, and the name of the function being
 * profiled. */
typedef struct hp_entry_t {
    char                   *name_hprof;                       /* function name */
    int                     rlvl_hprof;        /* recursion level for function */
    uint64                  tsc_start;         /* start value for TSC counter  */
    long int                mu_start_hprof;                    /* memory usage */
    long int                pmu_start_hprof;              /* peak memory usage */
    struct rusage           ru_start_hprof;             /* user/sys time start */
    struct hp_entry_t      *prev_hprof;    /* ptr to prev entry being profiled */
    uint8                   hash_code;     /* hash_code for the function name  */
} hp_entry_t;

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

    /*       ----------   Mode specific attributes:  -----------       */

    /* Global to track the time of the last sample in time and ticks */
    struct timeval   last_sample_time;
    uint64           last_sample_tsc;
    /* XHPROF_SAMPLING_INTERVAL in ticks */
    uint64           sampling_interval_tsc;

    /* This array is used to store cpu frequencies for all available logical
     * cpus.  For now, we assume the cpu frequencies will not change for power
     * saving or other reasons. If we need to worry about that in the future, we
     * can use a periodical timer to re-calculate this arrary every once in a
     * while (for example, every 1 or 5 seconds). */
    double *cpu_frequencies;

    /* The number of logical CPUs this machine has. */
    uint32 cpu_num;

    /* The saved cpu affinity. */
    cpu_set_t prev_mask;

    /* The cpu id current process is bound to. (default 0) */
    uint32 cur_cpu_id;

    /* XHProf flags */
    uint32 xhprof_flags;

    char *root;

    int debug;

    /* counter table indexed by hash value of function names. */
    uint8  func_hash_counters[256];

    HashTable *trace_callbacks;

    /* Table of ignored function names and their filter */
    char  **ignored_function_names;
    uint8   ignored_function_filter[XHPROF_IGNORED_FUNCTION_FILTER_SIZE];

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

#endif	/* PHP_XHPROF_APM_H */
