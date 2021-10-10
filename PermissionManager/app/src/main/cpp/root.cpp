#include <jni.h>
#include <string>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <sys/capability.h>

#include "../../../../../testRoot/super_root.h"
#include "../../../../../testRoot/adb_inject.h"

using namespace std;
string getCapabilityInfo()
{
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
    stringstream sstrCapInfo;
    sstrCapInfo << "Cap data effective:"<<(uint64_t *) cap_data->effective<<", permitted:"<<(uint64_t *) cap_data->permitted<<", inheritable:"<<(uint64_t *) cap_data->inheritable<<"\n";
    sstrCapInfo << "now getuid()="<< getuid() <<",geteuid()="<< geteuid() <<",getgid()="<< getgid() <<",getegid()="<< getegid() << "\n";

    FILE * fp = popen("getenforce", "r");
    if (fp)
    {
        char cmd[512] = { 0 };
        fread(cmd, 1, sizeof(cmd), fp);
        pclose(fp);

        sstrCapInfo<< "SELinux status: "<< cmd;
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
        jlong rootKey) {
    return get_root(rootKey);
}
extern "C" JNIEXPORT jint JNICALL
Java_com_linux_permissionmanager_MainActivity_disableSElinux(
        JNIEnv* env,
        jobject /* this */,
        jlong rootKey) {
    return safe_disable_selinux(rootKey);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_linux_permissionmanager_MainActivity_enableSElinux(
        JNIEnv* env,
        jobject /* this */,
        jlong rootKey) {
    return safe_enable_selinux(rootKey);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_runRootCmd(
        JNIEnv* env,
        jobject /* this */,
        jlong rootKey,
        jstring cmd) {

    const char *str1 = env->GetStringUTFChars(cmd, 0);
    string strCmd= str1;
    env->ReleaseStringUTFChars(cmd, str1);

    char szResult[0x1000] = {0};
    ssize_t  ret = safe_run_root_cmd(rootKey, strCmd.c_str(), szResult, sizeof(szResult));
    stringstream sstr;
    sstr << "runRootCmd ret val:" << ret << ", result:" << szResult;
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_runAdbShell(
        JNIEnv* env,
        jobject /* this */,
        jlong rootKey,
        jstring shell,
        jboolean keepAdbRoot) {

    const char *str1 = env->GetStringUTFChars(shell, 0);
    string strShell= str1;
    env->ReleaseStringUTFChars(shell, str1);

    char szResult[0x1000] = {0};
    ssize_t  inject = safe_inject_adb_process_run_shell_wrapper(rootKey, strShell.c_str(), keepAdbRoot, szResult, sizeof(szResult));
    //ssize_t  inject = safe_inject_adb_process_run_shell_wrapper(rootKey, strShell.c_str(), NULL, 0);
    stringstream sstr;
    sstr << "runAdbShell ret val:" << inject << ", result:" << szResult;
    return env->NewStringUTF(sstr.str().c_str());
}
