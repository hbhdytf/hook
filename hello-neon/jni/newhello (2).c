#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
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
#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
//#include <utils/Log.h>
#include <android/log.h>
#include <inject.h>
#include <inject.c>
#include <properties.h>
//#define LOG_TAG "debug"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
#define PROP_IOCTL_CALL_COUNT "persist.sys.ioctl.callcount"
#define PROP_OLD_IOCTL_ADDR "persist.sys.ioctl.old"
#define PROP_NEW_IOCTL_ADDR "persist.sys.ioctl.new"

//extern int ptrace_readdata( pid_t pid,  uint8_t *src, uint8_t *buf, size_t size );
//extern int ptrace_writedata( pid_t pid, uint8_t *dest, uint8_t *data, size_t size );
/*--
 void* get_module_base(pid_t pid, const char* module_name) {
 FILE *fp;
 long addr = 0;
 char *pch;
 char filename[32];
 char line[1024];

 if (pid < 0) {
 // self process
 snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
 } else {
 snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
 }

 fp = fopen(filename, "r");

 if (fp != NULL) {
 while (fgets(line, sizeof(line), fp)) {
 if (strstr(line, module_name)) {
 pch = strtok(line, "-");
 addr = strtoul(pch, NULL, 16);

 if (addr == 0x8000)
 addr = 0;

 break;
 }
 }

 fclose(fp);
 }

 return (void *) addr;
 }
 */
int hook_entry(char * a) {
	LOGD("Hello ARM! %s pid:%d\n", a, getpid());
	void *handle;
	int (*fcn)(void *param);
	int target_pid = getpid();
	void *helper;
	//helper= dlopen("/system/lib/libnativehelper.so", RTLD_NOW);
	if (helper != NULL) {
		LOGD("Open libnativehelper success: %s\n");
	}
	handle = dlopen("/dev/libhook_ioctl.so", RTLD_NOW);
	LOGD("The Handle of libhookioctl: %x\n",handle);

	if (handle == NULL) {
		LOGD("Failed to load libsthc.so: %s\n", dlerror());
		//fprintf(stderr, "Failed to load libsthc.so: %s\n", dlerror());
		return 1;
	}
	// void * binder_addr = get_module_base(getpid(), "/dev/libhook_ioctl.so");
	//  LOGD("Ioctl path %x\n",binder_addr);
	LOGD("find it pre1 %x\n", fcn);
	fcn = dlsym(handle, "do_hook");
	if (fcn != NULL)
		LOGD("find it1 %x\n", fcn);
	fcn(a);
	//取old_ioctl_addr地址
	char value[PROPERTY_VALUE_MAX] = { '\0' };
	do {
		LOGD("test\n");
		sleep(1);
		property_get(PROP_OLD_IOCTL_ADDR, value, "0");
	} while (strcmp(value, "0") == 0);
	unsigned long old_ioctl_addr = atoi(value);
	LOGD("[+] Get old address property  %x\n", old_ioctl_addr);
	//取new_ioctl_addr地址
	do {
		LOGD("test\n");
		sleep(1);
		property_get(PROP_NEW_IOCTL_ADDR, value, "0");
	} while (strcmp(value, "0") == 0);
	unsigned long new_ioctl_addr = atoi(value);
	LOGD("[+] Get new address property  %x\n", new_ioctl_addr);
	//动态打开libbinder.so库
	void * binder_addr = get_module_base(target_pid,
			"/system/lib/libbinder.so");
	LOGD("[+] binder path %x\n", binder_addr);
	if (binder_addr == NULL) {
		LOGD("Failed to get module base!\n");
		return 1;
	}

	//以文件形式打开libbinder.so
	int fp = 0;
	if ((fp = open("/system/lib/libbinder.so", O_RDONLY)) == 0) {
		LOGD("can not open file\n");
		exit(0);
	}
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *) malloc(sizeof(Elf32_Ehdr));
	read(fp, ehdr, sizeof(Elf32_Ehdr));
	if (ehdr == NULL) {
		LOGD("Failed to read ehdr!\n");
		return 1;
	}
	//读入Elf头格式，并输出
	unsigned long shdr_addr = ehdr->e_shoff;
	LOGD("[+] Section header table file offset %x\n", ehdr->e_shoff);
	int shnum = ehdr->e_shnum;
	LOGD("[+] Section header table entry count %x\n", shnum);
	int shent_size = ehdr->e_shentsize;
	LOGD("[+] Section header table entry size %x\n", shent_size);
	unsigned long stridx = ehdr->e_shstrndx;
	LOGD("[+] Section header string table index %x\n", stridx);
	int type = ehdr->e_type;
	LOGD("[+] Object file type %x\n", type);
	int version = ehdr->e_version;
	LOGD("[+] Object file version %x\n", version);
	int fd = fp;
	// 读取Section Header中关于字符串表的描述，得到其尺寸和位置
	lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
	Elf32_Shdr *shdr = (Elf32_Shdr *) malloc(sizeof(Elf32_Shdr));
	read(fd, shdr, shent_size);
	// 根据尺寸分配内存
	char * string_table = (char *) malloc(shdr->sh_size);
	lseek(fd, shdr->sh_offset, SEEK_SET);

	// 将字符串表内容读入
	read(fd, string_table, shdr->sh_size);
	//再重新遍历Section Header，找名为.got表的Section：
	int *out_addr;
	unsigned int out_size;
	LOGD("[+] Out_addr in GOT table before %x\n", out_addr);
	LOGD("[+] Out_size of func in GOT table before %x\n", out_size);
	lseek(fd, shdr_addr, SEEK_SET);
	int i;
	for (i = 0; i < shnum; i++) {
		read(fd, shdr, shent_size);

		if (shdr->sh_type == SHT_PROGBITS) {
			int name_idx = shdr->sh_name;
			if (strcmp(&(string_table[name_idx]), ".got") == 0) {
				/* 就是 GOT 表！ */

				out_addr = binder_addr + shdr->sh_offset;
				out_size = shdr->sh_size;
				LOGD("[+] Out_addr in GOT table %x\n", out_addr);
				LOGD("[+] Out_size of func in GOT table %x\n", out_size);
				break;
			}
		}
	}
	LOGD("[+] Out_addr in GOT table %x\n", out_addr);
	LOGD("[+] Out_size of func in GOT table %x\n", out_size);
	int b = *out_addr;
	LOGD("[+] Out_addr in GOT %x\n", b);
	long word = ptrace(PTRACE_PEEKTEXT, target_pid, out_addr, NULL);
	LOGD("[+] word %x\n", word);
	long elfword = ptrace(PTRACE_PEEKTEXT, target_pid, binder_addr, NULL);
	LOGD("[+] wordelf %x\n", elfword);
	int v = *(int *) binder_addr;
	LOGD("[+] Out_addr in GOT %x\n", v);
	//搜索与Hook就好办了：
	uint8_t got_item = 0;
	LOGD("[+] target pid %x\n", target_pid);
	ptrace_readdata(target_pid, out_addr, &got_item, 4);
	LOGD("[+] Find got_item %x \n", got_item);



	for (i = 0; i < out_size; i++) {
		int got_item = *out_addr;
		//LOGD("[+] Out_addr in GOT %x\n", b);
		LOGD("[+] Find got item %x \n", got_item);
		LOGD("[+] old open address   %x \n", old_ioctl_addr);
		if (got_item == old_ioctl_addr) {
			/* !!! 拿到了 ioctl 地址 !!! 改成我们的。 */
			LOGD("[+] Find ioctl and replace \n");
			//ptrace_writedata(target_pid, out_addr, &new_ioctl_addr,
			//	sizeof(new_ioctl_addr));
			(*out_addr) = new_ioctl_addr ;
			//
			break;
		} else if (got_item == new_ioctl_addr) {
			/* 已经是我们的了，不重复Hook。 */
			break;
		}
		out_addr++;
	}
	return 0;
}
