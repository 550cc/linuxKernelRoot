LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS += -std=c++1y
LOCAL_CFLAGS += -fPIE
LOCAL_CFLAGS += -fvisibility=hidden
LOCAL_LDFLAGS += -fPIE -pie
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
LOCAL_MODULE    := testRoot.out
LOCAL_SRC_FILES :=  ../testRoot.cpp ../adb64_inject.cpp  ../env64_inject.cpp ../ptrace_arm64_utils.cpp ../maps_helper.cpp
include $(BUILD_EXECUTABLE)
