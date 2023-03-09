#include <jni.h>
#include <string>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <thread>
#include <sys/capability.h>

#include "../../../../../testRoot/testRoot.h"
#include "../../../../../testRoot/kernel_root_helper.h"
#include "../../../../../testRoot/process64_inject.h"
#include "../../../../../testRoot/adb64_helper.h"
#include "../../../../../testRoot/init64_helper.h"
#include "../../../../../testRoot/su_install_helper.h"

using namespace std;

std::string g_last_su_full_path;

string getCapabilityInfo()
{
    __uid_t now_uid, now_euid, now_suid;
    if (getresuid(&now_uid, &now_euid, &now_suid)) {
        return "FAILED getresuid()";
    }


    __gid_t now_gid, now_egid, now_sgid;
    if (getresgid(&now_gid, &now_egid, &now_sgid)) {
        return "FAILED getresgid()";
    }

    stringstream sstrCapInfo;
    sstrCapInfo<< "now_uid="<<now_uid <<", now_euid="<< now_euid <<", now_suid="<< now_suid <<", now_gid="<< now_gid <<", now_egid="<< now_egid << ", now_sgid="<< now_sgid <<"\n";

    struct __user_cap_header_struct cap_header_data;
    cap_user_header_t cap_header = &cap_header_data;

    struct __user_cap_data_struct cap_data_data;
    cap_user_data_t cap_data = &cap_data_data;

    cap_header->pid = getpid();
    cap_header->version = _LINUX_CAPABILITY_VERSION_3; //_1、_2、_3

    if (capget(cap_header, cap_data) < 0) {
        return "FAILED capget()";
        // perror("FAILED capget()");
        //exit(1);
    }
    sstrCapInfo << "Cap data effective:"<<(uint64_t *) cap_data->effective<<", permitted:"<<(uint64_t *) cap_data->permitted<<", inheritable:"<<(uint64_t *) cap_data->inheritable<<"\n";
    sstrCapInfo << "My native check SELinux: "<< (kernel_root::is_disable_selinux_status() ? "0" : "1") <<"\n";

    FILE * fp = popen("getenforce", "r");
    if (fp)
    {
        char cmd[512] = { 0 };
        fread(cmd, 1, sizeof(cmd), fp);
        pclose(fp);

        sstrCapInfo<< "Read system SELinux: "<< cmd;
    }

    return sstrCapInfo.str();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_getCapabilityInfo(
        JNIEnv* env,
        jobject /* this */) {

    return env->NewStringUTF(getCapabilityInfo().c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_linux_permissionmanager_MainActivity_getRoot(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    return kernel_root::get_root(strRootKey.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_runRootCmd(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring cmd) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(cmd, 0);
    string strCmd= str1;
    env->ReleaseStringUTFChars(cmd, str1);

    char szResult[0x1000] = {0};
    ssize_t  ret = kernel_root::safe_run_root_cmd(strRootKey.c_str(), strCmd.c_str(), szResult, sizeof(szResult));
    stringstream sstr;
    sstr << "runRootCmd ret val:" << ret << ", result:" << szResult;
    return env->NewStringUTF(sstr.str().c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_runInit64ProcessCmd(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring cmd) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(cmd, 0);
    string strCmd= str1;
    env->ReleaseStringUTFChars(cmd, str1);

    stringstream sstr;
    char szResult[0x1000] = {0};
    ssize_t  inject = safe_inject_init64_run_cmd_wrapper(strRootKey.c_str(), strCmd.c_str(), szResult, sizeof(szResult));
    sstr << "runRootCmd ret val:" << inject << ", result:" << szResult;
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_linux_permissionmanager_MainActivity_disableSElinux(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);
    return kernel_root::safe_disable_selinux(strRootKey.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_linux_permissionmanager_MainActivity_enableSElinux(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);
    return kernel_root::safe_enable_selinux(strRootKey.c_str());
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_adbRoot(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);
    stringstream sstr;
    ssize_t  inject = safe_inject_adbd64_run_cmd_wrapper(strRootKey.c_str(), "id", NULL, 0, false, true ,false, false);
    sstr << "adbRoot ret val:" << inject;
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_installSu(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring basePath,
        jstring suFilePath) {

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(basePath, 0);
    string strBasePath= str1;
    env->ReleaseStringUTFChars(basePath, str1);

    str1 = env->GetStringUTFChars(suFilePath, 0);
    string strSuFilePath= str1;
    env->ReleaseStringUTFChars(suFilePath, str1);
    stringstream sstr;

    //安装su工具套件
    std::string su_hide_folder_path;
    int install_su_ret = safe_install_su(strRootKey.c_str(), strBasePath.c_str(), su_hide_folder_path);
    sstr << "install_su ret val:" << install_su_ret<<", su_hide_folder_path:" << su_hide_folder_path << std::endl;

    if (install_su_ret == -504) {
        //需要补一下su文件的释放
        std::string tmpCmd = "cp "+strSuFilePath + " " + su_hide_folder_path+"/su";
        int cp_ret = kernel_root::safe_run_root_cmd(strRootKey.c_str(), tmpCmd.c_str(), NULL, 0);
        if(cp_ret != 0) {
            sstr << "safe_run_normal_cmd cp_ret val:" <<cp_ret;
            return env->NewStringUTF(sstr.str().c_str());
        }
        install_su_ret = safe_install_su(strRootKey.c_str(), strBasePath.c_str(), su_hide_folder_path);
        sstr << "install_su ret val:" << install_su_ret<<", su_hide_folder_path:" << su_hide_folder_path << std::endl;
    }
    if (install_su_ret != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }

   g_last_su_full_path = su_hide_folder_path + "su";
    sstr << "installSu done."<< std::endl;
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_getLastInstallSuFullPath(
        JNIEnv* env,
        jobject /* this */) {
    return env->NewStringUTF(g_last_su_full_path.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_uninstallSu(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring basePath) {

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(basePath, 0);
    string strBasePath= str1;
    env->ReleaseStringUTFChars(basePath, str1);

    stringstream sstr;

    int uninstall_su_ret = safe_uninstall_su(strRootKey.c_str(), strBasePath.c_str());
    sstr << "uninstallSu ret val:" << uninstall_su_ret << std::endl;
    if (uninstall_su_ret != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    sstr << "uninstallSu done.";
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_autoSuEnvInject(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring targetProcessCmdline,
        jstring basePath) {

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(targetProcessCmdline, 0);
    string strTargetProcessCmdline = str1;
    env->ReleaseStringUTFChars(targetProcessCmdline, str1);

    str1 = env->GetStringUTFChars(basePath, 0);
    string strBasePath= str1;
    env->ReleaseStringUTFChars(basePath, str1);

    stringstream sstr;

    //杀光所有历史进程
    std::vector<pid_t> vOut;
    int find_all_cmdline_process_ret = safe_find_all_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), vOut);
    sstr << "find_all_cmdline_process ret val:"<< find_all_cmdline_process_ret<<", cnt:"<<vOut.size() << std::endl;
    if (find_all_cmdline_process_ret != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    std::string kill_cmd;
    for (pid_t t : vOut) {
        kill_cmd += "kill -9 ";
        kill_cmd += std::to_string(t);
        kill_cmd += ";";
    }
    int kill_ret = kernel_root::safe_run_root_cmd(strRootKey.c_str(), kill_cmd.c_str());
    sstr << "kill_ret ret val:"<< kill_ret << std::endl;
    if (kill_ret != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }

    //注入su环境变量到指定进程
    std::string su_hide_path;
    int install_su_ret = safe_install_su(strRootKey.c_str(), strBasePath.c_str(), su_hide_path);
    sstr << "install_su ret val:" << install_su_ret<<", su_hide_path:" << su_hide_path << std::endl;
    if (install_su_ret != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }

    int pid = safe_wait_and_find_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str());

    sstr << "autoSuEnvInject("<< pid<<", " <<  su_hide_path<<")" << std::endl;
    ssize_t ret = safe_inject_process_env64_PATH_wrapper(strRootKey.c_str(), pid, su_hide_path.c_str());
    sstr << "autoSuEnvInject ret val:" << ret << std::endl;

    if (ret != 0) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    sstr << "autoSuEnvInject done.";
    return env->NewStringUTF(sstr.str().c_str());
}
