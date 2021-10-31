#ifndef ADB_HELPER_H_
#define ADB_HELPER_H_
#include <unistd.h>
#include "process64_inject.h"

//ע��adbd64����Զ��ִ�������ע����������Զ���Ȩ��ROOT�����ҹر�SELinux���������к�ɸ����Լ�����Ҫ�����Ƿ��ֶ����´�SELinux
ssize_t inject_adbd64_run_cmd_wrapper(
	unsigned int root_key,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0,
	bool afert_kill_adb = true,
	bool user_root_auth = true,
	bool after_recovery_last_uid = true,
	bool after_recovery_last_gid = true,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL);

//fork��ȫ�汾�������ڰ�׿APPֱ�ӵ��ã�
ssize_t safe_inject_adbd64_run_cmd_wrapper(
	unsigned int root_key,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0,
	bool afert_kill_adb = true,
	bool user_root_auth = true,
	bool after_recovery_last_uid = true,
	bool after_recovery_last_gid = true,
	const char * chdir_path = NULL,
	bool clear_env = false,
	std::vector<process64_env> *set_env = NULL);

#endif /* ADB_HELPER_H_ */
