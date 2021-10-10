#ifndef ADB_INJECT_H_
#define ADB_INJECT_H_
#include <unistd.h>

//安静输出模式
#define QUIET_PRINTF

#ifdef QUIET_PRINTF
#define TRACE(fmt, ...)
#else
#define TRACE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif

//注入ADB进程远程执行命令（提权ROOT密匙，命令），备注：此命令会自动提权到ROOT、并且关闭SELinux。结束运行后可根据自己的需要决定是否手动重新打开SELinux
ssize_t inject_adb64_process_run_shell_wrapper(unsigned long rootKey, const char *lpszShell, bool bKeepAdbRoot = false, const char* lpOutResultBuf = NULL, size_t nOutResultBufSize = 0);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_inject_adb64_process_run_shell_wrapper(unsigned long rootKey, const char *lpszShell, bool bKeepAdbRoot = false, const char* lpOutResultBuf = NULL, size_t nOutResultBufSize = 0);
#endif /* ADB_INJECT_H_ */
