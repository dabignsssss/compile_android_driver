# MIUI13 Android12 内核4.14.186 虚拟摄像头 Makefile
# 修复语法错误，简化编译流程

obj-m := miui13_kernel414_virtual_camera.o

# 目标架构
ARCH := arm64

# 自动检测交叉编译器
ifeq ($(CROSS_COMPILE),)
    COMPILERS := aarch64-linux-android21- aarch64-linux-android- aarch64-linux-gnu-
    
    define find_compiler
        $(shell which $(1)gcc 2>/dev/null | sed 's/gcc$$//')
    endef
    
    CROSS_COMPILE := $(foreach comp,$(COMPILERS),$(call find_compiler,$(comp)))
    CROSS_COMPILE := $(firstword $(CROSS_COMPILE))
    
    ifeq ($(CROSS_COMPILE),)
        $(error 未找到交叉编译器，请运行 ./fix_ndk_compiler.sh)
    endif
endif

# 编译器设置
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

# 编译标志
CFLAGS_MODULE := -DMODULE -D__KERNEL__
CFLAGS_MODULE += -DCONFIG_MIUI13_VCAM=1
CFLAGS_MODULE += -DCONFIG_ANDROID_KERNEL_4_14=1
CFLAGS_MODULE += -Wall -Wno-unused-function -Wno-unused-variable
CFLAGS_MODULE += -fno-strict-aliasing -fno-common
CFLAGS_MODULE += -fno-pic -fno-pie

# 默认目标
all: miui13_kernel414_virtual_camera.ko

# 编译规则
miui13_kernel414_virtual_camera.ko: miui13_kernel414_virtual_camera.c
	@echo "编译MIUI13虚拟摄像头模块..."
	$(CC) $(CFLAGS_MODULE) -c -o miui13_kernel414_virtual_camera.o miui13_kernel414_virtual_camera.c
	$(LD) -r -o $@ miui13_kernel414_virtual_camera.o
	@echo "编译完成: $@"

# 清理
clean:
	@echo "清理编译文件..."
	rm -f *.o *.ko *.mod.c .*.cmd
	rm -rf .tmp_versions/

# 安装到设备
install: miui13_kernel414_virtual_camera.ko
	@echo "推送模块到设备..."
	adb push miui13_kernel414_virtual_camera.ko /data/local/tmp/
	adb shell su -c "cp /data/local/tmp/miui13_kernel414_virtual_camera.ko /vendor/lib/modules/"
	adb shell su -c "chmod 644 /vendor/lib/modules/miui13_kernel414_virtual_camera.ko"
	@echo "模块安装完成"

# 加载模块
load: install
	@echo "加载内核模块..."
	adb shell su -c "insmod /vendor/lib/modules/miui13_kernel414_virtual_camera.ko server_ip=192.168.1.6 server_port=8080 debug=1 replace_all=1 stealth_mode=1 auto_request=1"
	@echo "模块加载完成"

# 卸载模块
unload:
	@echo "卸载内核模块..."
	adb shell su -c "rmmod miui13_kernel414_virtual_camera"
	@echo "模块卸载完成"

# 查看状态
status:
	@echo "检查模块状态..."
	adb shell su -c "lsmod | grep miui13"
	adb shell su -c "cat /proc/miui13_vcam" 2>/dev/null || echo "无法读取模块状态"

# 查看日志
log:
	@echo "显示内核日志..."
	adb shell su -c "dmesg | grep MIUI13VCam | tail -20"

# 测试
test: load
	@echo "测试虚拟摄像头..."
	adb shell su -c "ls -la /dev/video*"
	adb shell su -c "cat /proc/miui13_vcam" 2>/dev/null || echo "模块状态文件不存在"

.PHONY: all clean install load unload status log test
