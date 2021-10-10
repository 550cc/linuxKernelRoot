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


#define ROOT_KEY 0x7F6766F8

#define DEFAULT_MAIN_SOCKET "d40138f231789fb9c54a3e0c21f58591"


#define DEFAULT_SHELL "/system/bin/sh"

// Constants for atty
#define ATTY_IN    (1 << 0)
#define ATTY_OUT   (1 << 1)
#define ATTY_ERR   (1 << 2)

#define UID_ROOT   0
#define UID_SHELL  2000

#endif /* _SU_H_ */
