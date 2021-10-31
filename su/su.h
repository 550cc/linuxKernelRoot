#ifndef _SU_H_
#define _SU_H_
#include <unistd.h>

//安静输出模式
#define QUIET_PRINTF

#ifdef QUIET_PRINTF
#define TRACE(fmt, ...)
#else
#define TRACE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif

#define DEFAULT_SHELL "/system/bin/sh"

// Constants for atty
#define ATTY_IN    (1 << 0)
#define ATTY_OUT   (1 << 1)
#define ATTY_ERR   (1 << 2)

#define UID_ROOT   0
#define UID_SHELL  2000

#endif /* _SU_H_ */
