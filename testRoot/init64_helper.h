#ifndef INIT64_HELPER_H_
#define INIT64_HELPER_H_
#include <unistd.h>
#include "process64_inject.h"

//ע��init64����Զ��ִ�������ע����������Զ���Ȩ��ROOT�����ҹر�SELinux���������к�ɸ����Լ�����Ҫ�����Ƿ��ֶ����´�SELinux
ssize_t inject_init64_run_cmd_wrapper(
	unsigned int root_key,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0) {
	return inject_process64_run_cmd_wrapper(root_key, 1, cmd, p_out_result_buf, out_result_buf_size, false, false, false, NULL, false, NULL);
}

//fork��ȫ�汾�������ڰ�׿APPֱ�ӵ��ã�
ssize_t safe_inject_init64_run_cmd_wrapper(
	unsigned int root_key,
	const char *cmd,
	const char* p_out_result_buf = NULL,
	size_t out_result_buf_size = 0) {
	return safe_inject_process64_run_cmd_wrapper(root_key, 1, cmd, p_out_result_buf, out_result_buf_size, false, false, false, NULL, false, NULL);
}
#endif /* INIT64_HELPER_H_ */
