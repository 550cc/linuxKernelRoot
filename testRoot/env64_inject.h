#ifndef ENV64_INJECT_H_
#define ENV64_INJECT_H_
#include <unistd.h>

//安静输出模式
//#define QUIET_PRINTF

#ifdef QUIET_PRINTF
#define TRACE(fmt, ...)
#else
#define TRACE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif

//注入远程进程添加PATH变量路径（提权ROOT密匙，远程进程PID，欲添加的新PATH路径），备注：此命令会自动提权到ROOT、并且关闭SELinux。结束运行后可根据自己的需要决定是否手动重新打开SELinux
ssize_t inject_process_env64_PATH_wrapper(unsigned long rootKey, int target_pid, const char *lpszAddPath);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_process_env64_PATH_wrapper(unsigned long rootKey, int target_pid, const char *lpszAddPath);
#endif /* ENV64_INJECT_H_ */
