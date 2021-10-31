LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS += -std=c++17
LOCAL_CFLAGS += -fPIE
LOCAL_CFLAGS += -fvisibility=hidden
LOCAL_LDFLAGS += -fPIE -pie
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
LOCAL_MODULE    := su
LOCAL_SRC_FILES :=  ../su.cpp ../base64.cpp ../../testRoot/adb64_helper.cpp ../../testRoot/process64_inject.cpp ../../testRoot/ptrace_arm64_utils.cpp
include $(BUILD_EXECUTABLE)
