#ifndef ADB_INJECT_H_
#define ADB_INJECT_H_
#include <unistd.h>

//�������ģʽ
#define QUIET_PRINTF

#ifdef QUIET_PRINTF
#define TRACE(fmt, ...)
#else
#define TRACE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif

//ע��ADB����Զ��ִ�������ȨROOT�ܳף��������ע����������Զ���Ȩ��ROOT�����ҹر�SELinux���������к�ɸ����Լ�����Ҫ�����Ƿ��ֶ����´�SELinux
ssize_t inject_adb64_process_run_shell_wrapper(unsigned long rootKey, const char *lpszShell, bool bKeepAdbRoot = false, const char* lpOutResultBuf = NULL, size_t nOutResultBufSize = 0);
//fork��ȫ�汾�������ڰ�׿APPֱ�ӵ��ã�
ssize_t safe_inject_adb64_process_run_shell_wrapper(unsigned long rootKey, const char *lpszShell, bool bKeepAdbRoot = false, const char* lpOutResultBuf = NULL, size_t nOutResultBufSize = 0);
#endif /* ADB_INJECT_H_ */
