#ifndef _SU_INSTALL_HELPER_H_
#define _SU_INSTALL_HELPER_H_
#include <iostream>

std::string get_child_su_hidden_path(const char* myself_path, const char* su_hidden_folder_head_flag = "su");

int install_su_tools(unsigned int root_key, const char* base_path, std::string & su_hidden_path, const char* su_hidden_folder_head_flag = "su");
//fork安全版本（可用于安卓APP直接调用）
int safe_install_su_tools(unsigned int root_key, const char* base_path, std::string & su_hidden_path, const char* su_hidden_folder_head_flag = "su");


int uninstall_su_tools(unsigned int root_key, const char* base_path, const char* su_hidden_folder_head_flag = "su");
//fork安全版本（可用于安卓APP直接调用）
int safe_uninstall_su_tools(unsigned int root_key, const char* base_path, const char* su_hidden_folder_head_flag = "su");

#endif /* _SU_INSTALL_HELPER_H_ */
