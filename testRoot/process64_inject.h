#ifndef _PROCESS64_INJECT_H_
#define _PROCESS64_INJECT_H_
#include "testRoot.h"
#include <unistd.h>
#include <vector>


//ע��64λ����Զ��ִ�������ע����������Զ���Ȩ��ROOT�����ҹر�SELinux���������к�ɸ����Լ�����Ҫ�����Ƿ��ֶ����´�SELinux
struct process64_env 
{
	char key[0x1000]; //key��name��ֵ���ܴ���pagesize
	char value[0x1000];
};
ssize_t inject_process64_run_cmd_wrapper(
	unsigned int root_key,
	pid_t target_pid,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0,
	bool user_root_auth = true,
	bool after_recovery_last_uid = false,
	bool after_recovery_last_gid = false,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL);
//fork��ȫ�汾�������ڰ�׿APPֱ�ӵ��ã�
ssize_t safe_inject_process64_run_cmd_wrapper(
	unsigned int root_key,
	pid_t target_pid,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0,
	bool user_root_auth = true,
	bool after_recovery_last_uid = false,
	bool after_recovery_last_gid = false,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL);

//ע��Զ�̽������PATH����·������ע����������Զ���Ȩ��ROOT�����ҹر�SELinux���������к�ɸ����Լ�����Ҫ�����Ƿ��ֶ����´�SELinux
ssize_t inject_process_env64_PATH_wrapper(unsigned int root_key, int target_pid, const char *add_path);
//fork��ȫ�汾�������ڰ�׿APPֱ�ӵ��ã�
ssize_t safe_inject_process_env64_PATH_wrapper(unsigned int root_key, int target_pid, const char *add_path);

//ע��64λ���̶�̬���ӿ�so����ע����������Զ���Ȩ��ROOT�����ҹر�SELinux���������к�ɸ����Լ�����Ҫ�����Ƿ��ֶ����´�SELinux
ssize_t inject_process64_so_wrapper(unsigned int root_key, pid_t target_pid, const char *p_target_so_path, const char* p_target_so_func_name);
//fork��ȫ�汾�������ڰ�׿APPֱ�ӵ��ã�
ssize_t safe_inject_process64_so_wrapper(unsigned int root_key, pid_t target_pid, const char *p_target_so_path, const char* p_target_so_func_name);
#endif /* _PROCESS64_INJECT_H_ */
