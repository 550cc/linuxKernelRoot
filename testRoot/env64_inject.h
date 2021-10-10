#ifndef ENV64_INJECT_H_
#define ENV64_INJECT_H_
#include <unistd.h>

//�������ģʽ
//#define QUIET_PRINTF

#ifdef QUIET_PRINTF
#define TRACE(fmt, ...)
#else
#define TRACE(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif

//ע��Զ�̽������PATH����·������ȨROOT�ܳף�Զ�̽���PID������ӵ���PATH·��������ע����������Զ���Ȩ��ROOT�����ҹر�SELinux���������к�ɸ����Լ�����Ҫ�����Ƿ��ֶ����´�SELinux
ssize_t inject_process_env64_PATH_wrapper(unsigned long rootKey, int target_pid, const char *lpszAddPath);
//fork��ȫ�汾�������ڰ�׿APPֱ�ӵ��ã�
ssize_t safe_inject_process_env64_PATH_wrapper(unsigned long rootKey, int target_pid, const char *lpszAddPath);
#endif /* ENV64_INJECT_H_ */
