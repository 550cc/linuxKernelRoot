#ifndef _SU_INSTALL_HELPER_H_
#define _SU_INSTALL_HELPER_H_
#include <iostream>

std::string get_child_su_hidden_path(const char* myself_path);

int install_su_tools(unsigned int root_key, const char* base_path, std::string & su_hidden_path);
//fork��ȫ�汾�������ڰ�׿APPֱ�ӵ��ã�
int safe_install_su_tools(unsigned int root_key, const char* base_path, std::string & su_hidden_path);


int uninstall_su_tools(unsigned int root_key, const char* base_path);
//fork��ȫ�汾�������ڰ�׿APPֱ�ӵ��ã�
int safe_uninstall_su_tools(unsigned int root_key, const char* base_path);

#endif /* _SU_INSTALL_HELPER_H_ */
