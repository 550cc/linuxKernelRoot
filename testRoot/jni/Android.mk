LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS += -std=c++17
LOCAL_CFLAGS += -fPIE
LOCAL_CFLAGS += -fvisibility=hidden
LOCAL_LDFLAGS += -fPIE -pie
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
LOCAL_MODULE    := testRoot.out
LOCAL_SRC_FILES :=  ../testRoot.cpp ../process64_inject.cpp ../adb64_helper.cpp ../ptrace_arm64_utils.cpp ../su_install_helper.cpp ../base64.cpp
include $(BUILD_EXECUTABLE)
