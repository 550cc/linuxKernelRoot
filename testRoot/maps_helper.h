#ifndef MAPS_HELPER_H_
#define MAPS_HELPER_H_
#include <unistd.h>

//安静输出模式
//#define QUIET_PRINTF

#ifdef QUIET_PRINTF
#define TRACE(fmt, ...)
#else
#define TRACE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif


void* get_module_base(pid_t pid, const char* module_name);

void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr);
#endif /* MAPS_HELPER_H_ */
