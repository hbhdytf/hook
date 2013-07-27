#include <properties.h>
#include <unistd.h>
#include <sys/types.h>
#include <android/log.h>
//#include <kernel/include/linux/binder.h>
#include <sys/ioctl.h>
#include <asm/ioctl.h>
#include <linux/binder.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/ptrace.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <jni.h>
//#include <utils/Log.h>
#include <android/log.h>
#include <sys/system_properties.h>


//#define PROPERTY_VALUE_MAX 65535
#define PROP_IOCTL_CALL_COUNT "persist.sys.ioctl.callcount"
#define PROP_OLD_IOCTL_ADDR "persist.sys.ioctl.old"
#define PROP_NEW_IOCTL_ADDR "persist.sys.ioctl.new"

//#include "../../../libhook/hook.h"

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "hook-ioctl", __VA_ARGS__))
//#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "hook-ioctl", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "hook-ioctl", __VA_ARGS__))
#define LOG_TAG "inject"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
/****
 void _init(char *args)
 {
 LOGI("lib loaded ...");
 }

 int (*orig_ioctl)(int, int, ...);

 int hooked_ioctl(int fd, int cmd, void *data)
 {
 LOGI("ioctl is invoked ...");
 // do something here

 return (*orig_ioctl)(fd, cmd, data);
 }

 void so_entry(char *p)
 {
 char *sym = "ioctl";

 // servicemanager does not use /system/lib/libbinder.so
 // therefore, if you want to hook ioctl of servicemanager
 // please change module_path to /system/bin/servicemanager
 char *module_path = "/system/lib/libbinder.so";

 orig_ioctl = do_hook(module_path, hooked_ioctl, sym);

 if ( orig_ioctl == 0 )
 {
 LOGE("[+] hook %s failed", sym);
 return ;
 }

 LOGI("orignal ioctl: 0x%x", orig_ioctl);
 }
 */
/*
 // 将新旧ioctl地址写入Andorid的Property供外界使用
 int do_hook(void * param)
 {
 old_ioctl = ioctl;
 printf("Ioctl addr: %p. New addr %p\n", ioctl, new_ioctl);

 char value[PROPERTY_VALUE_MAX] = {'\0'};
 snprintf(value, PROPERTY_VALUE_MAX, "%u", ioctl);
 property_set(PROP_OLD_IOCTL_ADDR, value);

 snprintf(value, PROPERTY_VALUE_MAX, "%u", new_ioctl);
 property_set(PROP_NEW_IOCTL_ADDR, value);

 return 0;
 }

 // 全局变量用以保存旧的ioctl地址，其实也可直接使用ioctl
 int (*old_ioctl) (int __fd, unsigned long int __request, void * arg) = 0;

 // 欲接替ioctl的新函数地址，其中内部调用了老的ioctl
 int new_ioctl (int __fd, unsigned long int __request, void * arg)
 {
 if ( __request == BINDER_WRITE_READ )
 {
 call_count++;

 char value[PROPERTY_VALUE_MAX] = {'\0'};
 snprintf(value, PROPERTY_VALUE_MAX, "%d", call_count);
 property_set(PROP_IOCTL_CALL_COUNT, value);
 }

 int res = (*old_ioctl)(__fd, __request, arg);
 return res;
 }*/
int (*old_ioctl)(int __fd, unsigned long int __request, void * arg) = 0;
int call_count=0;
// 欲接替ioctl的新函数地址，其中内部调用了老的ioctl
int new_ioctl(int __fd, unsigned long int __request, void * arg) {

	LOGD("[+] The NewIoctl count %d",call_count);
	if (__request == BINDER_WRITE_READ) {
		call_count++;

		char value[PROPERTY_VALUE_MAX] = { '\0' };
		snprintf(value, PROPERTY_VALUE_MAX, "%d", call_count);
		property_set(PROP_IOCTL_CALL_COUNT, value);
		LOGD("[+] The NewIoctl count %d",call_count);

	}
	int res = (*old_ioctl)(__fd, __request, arg);
	return res;

}
int do_hook(void * param) {
	LOGD("[+] old ioctl1 is invoked ...");
	old_ioctl = ioctl;
	LOGD("[+] Ioctl addr: %p. New addr %p\n", ioctl, new_ioctl);


	char value[PROPERTY_VALUE_MAX] = { '\0' };
	snprintf(value, PROPERTY_VALUE_MAX, "%u", ioctl);
	property_set(PROP_OLD_IOCTL_ADDR, value);

	snprintf(value, PROPERTY_VALUE_MAX, "%u", new_ioctl);
	property_set(PROP_NEW_IOCTL_ADDR, value);

	return 0;
}

