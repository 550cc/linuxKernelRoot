#include "su_install_helper.h"
#include "kernel_root_helper.h"
#include "init64_helper.h"
#include "testRoot.h"
#include "../su/su_hide_path_utils.h"
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <sys/stat.h> 
#include <sys/types.h>
#include <sys/xattr.h>

/*
 * xattr name for SELinux attributes.
 * This may have been exported via Kernel uapi header.
 */
#ifndef XATTR_NAME_SELINUX
#define XATTR_NAME_SELINUX "security.selinux"
#endif
const char* selinux_file_flag = "u:object_r:system_file:s0";
const char* check_file_list[] = {
	"su",
};

bool check_su_file_exist(const char* path) {

	std::string str_path = path;
	for (size_t i = 0; i < sizeof(check_file_list) / sizeof(check_file_list[0]); i++) {
		if (access(std::string(str_path + "/" + check_file_list[i]).c_str(), F_OK)) {
			TRACE("check_su_file_exist could not found %s.\n", check_file_list[i]);
			return false;
		}
	}
	return true;
}

bool set_su_file_access_mode(const char* path) {

	std::string str_path = path;
	if (setxattr(str_path.c_str(), XATTR_NAME_SELINUX, selinux_file_flag, strlen(selinux_file_flag) + 1, 0)) {
		TRACE("setxattr error %s.\n", str_target_file_path.c_str());
		return false;
	}
	for (size_t i = 0; i < sizeof(check_file_list) / sizeof(check_file_list[0]); i++) {
		std::string str_target_file_path = std::string(str_path + "/" + check_file_list[i]);
		if (chmod(str_target_file_path.c_str(), 0777)) {
			TRACE("set_su_file_access_mode could not found %s.\n", check_file_list[i]);
			return false;
		}
		if (setxattr(str_target_file_path.c_str(), XATTR_NAME_SELINUX, selinux_file_flag, strlen(selinux_file_flag) + 1, 0)) {
			TRACE("setxattr error %s.\n", str_target_file_path.c_str());
			return false;
		}

	}
	return true;
}

bool move_su_file_to_su_hide_path(const char* source_path, const char* target_path) {

	std::string str_source_path = source_path;
	std::string str_target_path = target_path;
	for (size_t i = 0; i < sizeof(check_file_list) / sizeof(check_file_list[0]); i++) {

		std::string old_file_path = std::string(str_source_path + "/" + check_file_list[i]);
		std::string new_file_path = std::string(str_target_path + "/" + check_file_list[i]);
		if (access(old_file_path.c_str(), F_OK)) {
			TRACE("move_su_file_to_su_hide_path could not found %s.\n", old_file_path.c_str());
			return false;
		}
		std::fstream file1;
		file1.open(old_file_path.c_str(), std::ios::binary | std::ios::in | std::ios::ate); //打开时指针在文件尾
		if (!file1.is_open()) {
			TRACE("Could not open file %s.\n", old_file_path.c_str());
			return false;
		}
		size_t length = file1.tellg();
		std::unique_ptr<char[]> up_new_file_data = std::make_unique<char[]>(length);
		file1.seekg(0);
		file1.read(up_new_file_data.get(), length); //二进制只能用这个读
		file1.close();


		std::fstream file2;
		file2.open(new_file_path.c_str(), std::ios::binary | std::ios::out);
		if (!file2.is_open()) {
			TRACE("Could not open file %s.\n", new_file_path.c_str());
			return false;
		}
		file2.write(up_new_file_data.get(), length);   //二进制只能用这个写
		file2.close();

		if (chmod(new_file_path.c_str(), 0777)) {
			TRACE("Could not chmod file %s.\n", new_file_path.c_str());
			return false;
		}
	}
	return true;
}

bool del_su_file(const char* path) {
	std::string str_path = path;
	for (size_t i = 0; i < sizeof(check_file_list) / sizeof(check_file_list[0]); i++) {
		std::string file_path = std::string(str_path + "/" + check_file_list[i]);
		TRACE("del_su_file:%s\n", file_path.c_str());
		remove(file_path.c_str());
	}
	return true;
}

int install_su(const char* str_root_key, const char* base_path, std::string & su_hide_folder_path, const char* su_hide_folder_head_flag/* = "su"*/) {

	if (kernel_root::get_root(str_root_key) != 0) {
		return -501;
	}

	std::string _su_hide_folder_head_flag = su_hide_folder_head_flag;
	_su_hide_folder_head_flag += "_";

	//1.获取su_xxx隐藏目录
	std::string _su_hide_folder_path = find_su_hide_folder_path(base_path, _su_hide_folder_head_flag.c_str()); //没有再看看子目录
	if (_su_hide_folder_path.empty()) {
		//2.取不到，那就创建一个
        _su_hide_folder_path = create_su_hide_folder(str_root_key, base_path, _su_hide_folder_head_flag.c_str());
	}
	if (_su_hide_folder_path.empty()) {
		TRACE("su hide folder path empty error\n");
		return -503;
	}
    su_hide_folder_path = _su_hide_folder_path + "/";

	//3.检查su_xxx目录下的文件是否齐全
	if (!check_su_file_exist(_su_hide_folder_path.c_str())) {
		//4.不齐全则开始补齐
		if (!check_su_file_exist(base_path)) {
			//自身目录都没有，怎么补过去
			TRACE("base_path su file not exist:%s\n", base_path);
			return -504;
		}
		//5.开始移动文件补齐到su_xxx目录
		if (!move_su_file_to_su_hide_path(base_path, _su_hide_folder_path.c_str())) {
			TRACE("move_su_file_to_su_hide_folder_path error:%s -> %s\n", base_path, _su_hide_path.c_str());
			return -505;
		}
	}
	//6.赋值文件运行权限
	if(!set_su_file_access_mode(_su_hide_folder_path.c_str())) {
		TRACE("set_su_file_access_mode error:%s\n", _su_hide_folder_path.c_str());
		return -506;
	}
	//7.从自身路径中删除文件，移除痕迹，防止被检测
	del_su_file(base_path);
	return 0;
}

int safe_install_su(const char* str_root_key, const char* base_path, std::string & su_hide_folder_path, const char* su_hide_folder_head_flag) {
	
	int fd[2];
	if (pipe(fd)) {
		return -432;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -433;
	}
	else if (pid == 0) { // child process
		close(fd[0]); //close read pipe
		pid_t ret = install_su(str_root_key, base_path, su_hide_folder_path, su_hide_folder_head_flag);
		write(fd[1], &ret, sizeof(ret));
		char buf[4096] = { 0 };
		strcpy(buf, su_hide_folder_path.c_str());
		write(fd[1], &buf, sizeof(buf));
		close(fd[1]); //close write pipe
		_exit(0);
	}
	else { // father process

		close(fd[1]); //close write pipe

		int status;
		
		if (waitpid(pid, &status, WUNTRACED) < 0 && errno != EACCES) {
			return -434;
		}

		pid_t ret = -435;
		read(fd[0], (void*)&ret, sizeof(ret));
		char buf[4096] = { 0 };
		read(fd[0], (void*)&buf, sizeof(buf));
		su_hide_folder_path = buf;
		
		close(fd[0]); //close read pipe
		return ret;
	}
	return -436;
}

int uninstall_su(const char* str_root_key, const char* base_path, const char* su_hide_folder_head_flag) {

	if (kernel_root::get_root(str_root_key) != 0) {
		return -511;
	}

	std::string _su_hide_folder_head_flag = su_hide_folder_head_flag;
	_su_hide_folder_head_flag += "_";


	//从自身路径中删除文件，移除痕迹，防止被检测
	del_su_file(base_path);

	do {
		//获取su_xxx隐藏目录
		std::string _su_hide_path = find_su_hide_folder_path(base_path, _su_hide_folder_head_flag.c_str()); //没有再看看子目录
		if (_su_hide_path.empty()) {
			break;
		}
		//取到了，再删
		del_su_file(_su_hide_path.c_str());

		//文件夹也删掉
		std::string del_dir_cmd = "rm -rf ";
		del_dir_cmd += _su_hide_path;
		int err = kernel_root::run_root_cmd(str_root_key, del_dir_cmd.c_str(), NULL, 0);
		if (err) {
			return err;
		}
		return access(_su_hide_path.c_str(), F_OK) == -1 ? 0 : -512;

	} while (1);
	return 0;
}

int safe_uninstall_su(const char* str_root_key, const char* base_path, const char* su_hide_folder_head_flag) {
	int fd[2];
	if (pipe(fd)) {
		return -521;
	}

	pid_t pid;
	if ((pid = fork()) < 0) {
		//fork error
		return -522;
	}
	else if (pid == 0) { // child process
		close(fd[0]); //close read pipe
		int ret = uninstall_su(str_root_key, base_path, su_hide_folder_head_flag);
		write(fd[1], &ret, sizeof(ret));
		close(fd[1]); //close write pipe
		_exit(0);
	}
	else { // father process

		close(fd[1]); //close write pipe

		int status;
		
		if (waitpid(pid, &status, WUNTRACED) < 0 && errno != EACCES) {
			return -523;
		}

		int ret = -524;
		read(fd[0], (void*)&ret, sizeof(ret));
		
		close(fd[0]); //close read pipe
		return ret;
	}
	return -525;
}



