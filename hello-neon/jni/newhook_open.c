#include <properties.h>
#include <unistd.h>
#include <sys/types.h>
#include <android/log.h>
//#include <kernel/include/linux/binder.h>
//#include <sys/ioctl.h>
//#include <asm/ioctl.h>
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
#include <openssl/evp.h>
#include <fcntl.h>
#include <errno.h>

//#define PROPERTY_VALUE_MAX 65535
#define PROP_OPEN_CALL_COUNT   "persist.sys.open.callcount"
#define PROP_OLD_OPEN_ADDR     "persist.sys.open.old"
#define PROP_NEW_OPEN_ADDR     "persist.sys.open.new"
#define AES_BLOCK_SIZE  16;
#define CIPHER_BUFFER_SIZE 256

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "hook-open", __VA_ARGS__))

#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "hook-open", __VA_ARGS__))
#define LOG_TAG "inject"
#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, fmt, ##args)
//added
#define BUFFER_SIZE 256
//AES初始化加密
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt,
		EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx) {
	int i, nrounds = 5;
	unsigned char key[32], iv[32];

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	 * nrounds is the number of times the we hash the material. More rounds are more secure but
	 * slower.
	 */
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data,
			key_data_len, nrounds, key, iv);
	if (i != 32) {
		printf("Key size is %d bits - should be 256 bits\n", i);
		return -1;
	}

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	return 0;
}
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext,
		int *len) {
	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int p_len = *len;
	int f_len = 0;
	int templen = p_len + AES_BLOCK_SIZE;
	unsigned char *plaintext = malloc(templen);
	// unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);
	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}


extern int  __open(const char*, int, int);
int (*old_open)(const char*  path, int  mode, ...) = 0;
int (*old_close)(int fd)=0;
int call_count=0;
// 欲接替open的新函数地址，其中内部调用了老的open
int new_open(const char*  path, int  mode, ...) {


	//for test
	LOGD("[+]-----------open test txt file-----------");
	LOGD("[+] The New open path %s",path);
	call_count++;
	LOGD("[+] The New open count %d",call_count);
	// 检测path是否为检测列表中的地址
	const char* testpath = "/mnt/sdcard/documents/test.txt";
	const char* new_path = "/mnt/sdcard/documents/testcopy1.txt";
	int j = 0;
	int from_fd, to_fd;
	int bytes_read, bytes_write;
	char buffer[BUFFER_SIZE];
	char *ptr;
	if (strcmp(testpath, path) == 0) {

		LOGD("[+] test copy file");
		from_fd = (*old_open)(testpath, O_RDONLY, 0);
		to_fd = (*old_open)(new_path, O_WRONLY | O_CREAT | O_TRUNC);

		//初始化密码
		EVP_CIPHER_CTX en, de;
		unsigned int salt[] = { 12345, 54321 };
		unsigned char *key_data;
		int key_data_len, i;
		unsigned char * key = "123456";
		key_data = key;
		key_data_len = strlen(key_data);
		if (aes_init(key_data, key_data_len, (unsigned char *) &salt, &en, &de)) {
				LOGD("Couldn't initialize AES cipher\n");
				return -1;
			}

		int len = CIPHER_BUFFER_SIZE;
		int c_len = len + AES_BLOCK_SIZE;
		int templen = len + AES_BLOCK_SIZE;
		char *ptr2 = malloc(templen);
		char outbuffer[CIPHER_BUFFER_SIZE + 16];
		LOGD("-------------------------------------------");
		while (bytes_read = read(from_fd, outbuffer, c_len)) {
			printf("bytes_read:%d\n", bytes_read);
			if ((bytes_read == -1) && (errno != EINTR))
				break;
			else if (bytes_read > 0) {
				len = CIPHER_BUFFER_SIZE+16;
				LOGD("buffer:\t%s\n", outbuffer);
				ptr2 = (char *) aes_decrypt(&de, outbuffer, &len);
				LOGD("the len is %d",len);
				LOGD("ptr:%s\n", ptr2);
				LOGD("len:%d\n", strlen(ptr2));
				bytes_write = write(to_fd,ptr2,len);
			}
			for (j = 0; j < CIPHER_BUFFER_SIZE + 16; j++)
				outbuffer[j] = '\0';
		}
		EVP_CIPHER_CTX_cleanup(&en);
		EVP_CIPHER_CTX_cleanup(&de);





		/** 明文拷贝
		    while (bytes_read = read(from_fd, buffer, BUFFER_SIZE)) {
		        if ((bytes_read == -1) && (errno != EINTR)) break;
		        else if (bytes_read > 0) {
		            ptr = buffer;
		            while (bytes_write = write(to_fd, ptr, bytes_read)) {
		                if ((bytes_write == -1) && (errno != EINTR))break;
		                else if (bytes_write == bytes_read) break;
		                else if (bytes_write > 0) {
		                    ptr += bytes_write;
		                    bytes_read -= bytes_write;
		                }
		            }
		            if (bytes_write == -1)break;
		        }
		    }
		    */
            //在拷贝文件后面追加标记
			//char* mark ="END!\0";
			//bytes_write = write(to_fd, mark, 4);
		    LOGD("[+] The old file fd %d",from_fd);
		    LOGD("[+] The copy file fd %d",to_fd);
		    (*old_close)(from_fd);
            (*old_close)(to_fd);
         //  return to_fd; // 会报io异常的错误

		int res = (*old_open)(new_path, mode);//
		LOGD("[+] The New open file fd %d",res); //打印的结果是from_fd 不是to_fd????

		char s[256], name[256];
			snprintf(s, 255, "/proc/%d/fd/%d", getpid(), res);
			memset(name, 0, sizeof(name)); // readlink在name后面不会加'\0'，加上清buf
			readlink(s, name, 255);
			LOGD("[+] The Name of fd %s",name);
			LOGD("[+] The S of fd %s",s);

		return res;
	}

	//4. invoke old function
	int res = (*old_open)(path,mode);//?????
	LOGD("[+] The old openfile fd %d",res);
	return res;

}

int new_close(int fd)
{
	LOGD("[+]-----------close test txt file-----------");
	//1.find the file of fd
	char s[256], name[256];
	snprintf(s, 255, "/proc/%d/fd/%d", getpid(), fd);
	memset(name, 0, sizeof(name)); // readlink在name后面不会加'\0'，加上清buf
	readlink(s, name, 255);
	LOGD("[+] The Name of fd %s",name);
	LOGD("[+] The S of fd %s",s);
	//2.
	const  char* new_path =  "/mnt/sdcard/documents/testcopy1.txt";
	const  char* testpath = "/mnt/sdcard/documents/test.txt";
	int rel_fd,to_fd;
	int bytes_read, bytes_write;
	char buffer[BUFFER_SIZE]={'\0'};
	char *ptr;
	int j=0;
	if(strcmp(new_path,name)==0)
	{
		LOGD("[+] open pre test copy file");
		rel_fd 	=  (*old_open)(new_path,O_RDONLY,0);
		to_fd   = (*old_open)(testpath, O_WRONLY|O_CREAT|O_TRUNC);
		//初始化密码
		EVP_CIPHER_CTX en, de;
		unsigned int salt[] = { 12345, 54321 };
		unsigned char *key_data;
		int key_data_len, i;
		unsigned char * key = "123456";
		key_data = key;
		key_data_len = strlen(key_data);
		if (aes_init(key_data, key_data_len, (unsigned char *) &salt, &en,
				&de)) {
			LOGD("Couldn't initialize AES cipher\n");
			return -1;
		}
		int len = BUFFER_SIZE;
		int c_len = len + AES_BLOCK_SIZE;
		char *ptr1 = malloc(c_len);
		while (bytes_read = read(rel_fd, buffer, BUFFER_SIZE)) {
			if ((bytes_read == -1) && (errno != EINTR))
				break;
			else if (bytes_read > 0) {
				int tmplen;
				LOGD("buffer:\t%s\n", buffer);
				LOGD("c_len:%d\n", c_len);
				EVP_EncryptInit_ex(&en, NULL, NULL, NULL, NULL);
				EVP_EncryptUpdate(&en, ptr1, &c_len, buffer, len);
				EVP_EncryptFinal_ex(&en, ptr1 + c_len, &tmplen);
				c_len += tmplen;
				LOGD("ptr:%s\n", ptr1);
				LOGD("len:%d\n", strlen(ptr1));
				LOGD("c_len:%d\n", c_len);
				//EVP_CipherUpdate(&en, ptr, &outlen, inbuf, inlen)
				bytes_write = write(to_fd, ptr1, c_len);
				LOGD("bytes_write:%d\n", bytes_write);
				for (j = 0; j < BUFFER_SIZE; j++)
					buffer[j] = '\0';
				if (bytes_write == -1)
					break;
			}
		}


		//read bytes from the copyed file
/*	    while (bytes_read = read(rel_fd, buffer, BUFFER_SIZE)) {
	         一个致命的错误发生了
	    	 LOGD("[+] String of byte_read %d",bytes_read);
	        if ((bytes_read == -1) && (errno != EINTR)) break;
	        else if (bytes_read > 0) {
	            ptr = buffer;
	            LOGD("[+] String of ptr %s",ptr);
	            while (bytes_write = write(to_fd, ptr, bytes_read)) {
	                 一个致命错误发生了
	                if ((bytes_write == -1) && (errno != EINTR))break;
	                     写完了所有读的字节
	                else if (bytes_write == bytes_read) break;
	                     只写了一部分,继续写
	                else if (bytes_write > 0) {
	                    ptr += bytes_write;
	                    bytes_read -= bytes_write;
	                }
	            }
	             写的时候发生的致命错误
	            if (bytes_write == -1)break;
	        }
	    }*/

	    //在拷贝文件后面追加标记
	  //  char* mark ="From copy to test!\0";
	  // 	bytes_write = write(to_fd, mark, strlen(mark));
	   	(*old_close)(rel_fd);
	   	(*old_close)(to_fd);

	   	int res=(*old_close)(fd);
	   	LOGD("[+] The new close file return %d.",res);
	//	int removefd=remove(new_path);
	//	LOGD("[+] The temp file has been removed %d.",removefd);
	   	return res;
	}
	//4.invoke old function
	int res = (*old_close)(fd);
	LOGD("[+] The old close file return %d.",res);
	return res;
}


int do_hook(unsigned long * old_open_addr,unsigned long * new_open_addr,unsigned long * old_close_addr,unsigned long * new_close_addr) {

	LOGD("[+] aaaaaaa do_hook function is invoked ");
	old_open = open;
	old_close = close;
	LOGD("[+] open addr: %p. New addr %p\n", open, new_open);
    // get existed property ok,but can not set property???
	//--------------test property set---------------------
	LOGD("[+] just for test info ");
	property_set("persist.sys.test", "bbbbbbbb");
	LOGD("[+] set ok ");
	char value2[PROPERTY_VALUE_MAX] = { '\0' };
	property_get("persist.sys.test", value2, "0");
	LOGD("[+] Get the persist.sys.test  %s\n", value2);
	//------------------------------------------------------------

	//get open function address
	char value[PROPERTY_VALUE_MAX] = { '\0' };
	snprintf(value, PROPERTY_VALUE_MAX, "%u", old_open);
	*old_open_addr=old_open;
	LOGD("[+] just for test print old_open address %p\n", *old_open_addr);
	property_set(PROP_OLD_OPEN_ADDR, value);

	snprintf(value, PROPERTY_VALUE_MAX, "%u", new_open);
	*new_open_addr=new_open;
	LOGD("[+] just for test print new_open address %p\n", *new_open_addr);
	property_set(PROP_NEW_OPEN_ADDR, value);

	//get close function address
	*old_close_addr=old_close;
	LOGD("[+] just for test print old_close address %p\n", *old_close_addr);
	*new_close_addr=new_close;
	LOGD("[+] just for test print new_close address %p\n", *new_close_addr);

	return 0;
}
