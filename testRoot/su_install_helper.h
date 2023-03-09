#ifndef _SU_INSTALL_HELPER_H_
#define _SU_INSTALL_HELPER_H_
#include <iostream>
int install_su(const char* str_root_key, const char* base_path, std::string & su_hide_folder_path, const char* su_hide_folder_head_flag = "su");
//fork安全版本
int safe_install_su(const char* str_root_key, const char* base_path, std::string & su_hide_folder_path, const char* su_hide_folder_head_flag = "su");

int uninstall_su(const char* str_root_key, const char* base_path, const char* su_hide_folder_head_flag = "su" );
//fork安全版本
int safe_uninstall_su(const char* str_root_key, const char* base_path, const char* su_hide_folder_head_flag = "su");

#endif /* _SU_INSTALL_HELPER_H_ */
