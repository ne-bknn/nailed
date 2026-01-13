/* SPDX-License-Identifier: Apache-2.0
 * Nailed PKCS#11 logging utilities
 *
 * Build flags:
 *   NAILED_DEBUG        - Enable debug logging to stderr
 *   NAILED_DEBUG_FILE   - Enable verbose logging to /tmp/nailed.log
 */

#ifndef NAILED_LOG_H
#define NAILED_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>

#ifdef NAILED_DEBUG_FILE

static inline FILE* nailed_log_file(void) {
    static FILE *log_fp = NULL;
    static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    pthread_mutex_lock(&log_mutex);
    if (!log_fp) {
        log_fp = fopen("/tmp/nailed.log", "a");
        if (log_fp) {
            setvbuf(log_fp, NULL, _IOLBF, 0); /* Line buffered */
        }
    }
    pthread_mutex_unlock(&log_mutex);
    return log_fp;
}

static inline void nailed_log_write(const char *tag, const char *fmt, ...) {
    FILE *fp = nailed_log_file();
    if (!fp) return;
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm = localtime(&tv.tv_sec);
    
    fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d.%03d [%s] ",
            tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
            tm->tm_hour, tm->tm_min, tm->tm_sec,
            (int)(tv.tv_usec / 1000), tag);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(fp, fmt, args);
    va_end(args);
    
    fprintf(fp, "\n");
}

#define NAILED_LOG(tag, fmt, ...) nailed_log_write(tag, fmt, ##__VA_ARGS__)

#elif defined(NAILED_DEBUG)

#define NAILED_LOG(tag, fmt, ...) fprintf(stderr, "[%s] " fmt "\n", tag, ##__VA_ARGS__)

#else

#define NAILED_LOG(tag, fmt, ...) ((void)0)

#endif

/* Convenience macros for different components */
#define LOG_PKCS11(fmt, ...) NAILED_LOG("pkcs11", fmt, ##__VA_ARGS__)
#define LOG_CLIENT(fmt, ...) NAILED_LOG("nailed", fmt, ##__VA_ARGS__)

#endif /* NAILED_LOG_H */

