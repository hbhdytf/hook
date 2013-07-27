# Copyright (C) 2009 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(call my-dir)

#include $(CLEAR_VARS)

#LOCAL_MODULE    := hello-jni
#LOCAL_SRC_FILES := \
                   hello-jni.c\
                   shellcode.s

##added 注意添加代码的位置                   
#LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog 

#include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
LOCAL_LDLIBS+= -lcutils 
LOCAL_ARM_MODE := arm
LOCAL_MODULE    := hello
LOCAL_SRC_FILES := hello.c\
					shellcode.s
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE    := inject
LOCAL_SRC_FILES := \
                   inject.c\
                   shellcode.s

##added 注意添加代码的位置                   
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog 

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_C_INCLUDES:= \
					$(SYSROOT)/system/core/include
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -lcrypto
LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -lssl
LOCAL_LDLIBS+= -lcutils  
LOCAL_ARM_MODE := arm
LOCAL_MODULE    := hook_open
LOCAL_SRC_FILES := newhook_open.c

include $(BUILD_SHARED_LIBRARY)
