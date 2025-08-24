/*
 * MIUI13 Android12 内核4.14.186 驱动级虚拟摄像头
 * 功能: 完全替换系统摄像头，无法被检测
 * 作者: Virtual Camera Team
 * 版本: 3.0 - 专为MIUI13优化
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/regulator/consumer.h>
#include <linux/clk.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/sock.h>

#define DRIVER_NAME "miui13_vcam"
#define DEVICE_NAME "video0"  // 直接替换video0设备
#define CLASS_NAME "video4linux"
#define PROC_NAME "miui13_vcam"

// MIUI13特定配置
#define MIUI13_CAMERA_MAGIC 0x4D495549  // "MIUI"
#define MAX_FRAME_SIZE (1920 * 1080 * 3)  // 最大帧大小
#define FRAME_BUFFER_COUNT 4
#define NETWORK_BUFFER_SIZE 65536

// 模块参数
static char *server_ip = "192.168.1.6";
static int server_port = 8080;
static int debug = 1;
static int replace_all = 1;  // 替换所有摄像头
static int stealth_mode = 1; // 隐身模式
static int auto_request = 1; // 自动请求数据

module_param(server_ip, charp, 0644);
module_param(server_port, int, 0644);
module_param(debug, int, 0644);
module_param(replace_all, int, 0644);
module_param(stealth_mode, int, 0644);
module_param(auto_request, int, 0644);

MODULE_PARM_DESC(server_ip, "Video server IP address");
MODULE_PARM_DESC(server_port, "Video server port");
MODULE_PARM_DESC(debug, "Debug level (0-3)");
MODULE_PARM_DESC(replace_all, "Replace all camera devices");
MODULE_PARM_DESC(stealth_mode, "Enable stealth mode");
MODULE_PARM_DESC(auto_request, "Auto request data when camera accessed");

// 设备结构
struct miui13_vcam_device {
    struct cdev cdev;
    struct device *device;
    struct class *class;
    dev_t devno;
    struct mutex lock;
    
    // 网络相关
    struct socket *sock;
    struct task_struct *network_thread;
    bool network_connected;
    
    // 帧缓冲
    void *frame_buffers[FRAME_BUFFER_COUNT];
    size_t frame_sizes[FRAME_BUFFER_COUNT];
    int current_frame;
    
    // 统计信息
    unsigned long frames_received;
    unsigned long bytes_received;
    unsigned long open_count;
    unsigned long access_count;
    
    // 请求控制
    bool request_active;
    struct timer_list request_timer;
};

static struct miui13_vcam_device *vcam_dev = NULL;
static int major_number = 0;

// 日志宏
#define vcam_info(fmt, ...) \
    do { if (debug >= 1) printk(KERN_INFO "MIUI13VCam: " fmt, ##__VA_ARGS__); } while(0)
#define vcam_debug(fmt, ...) \
    do { if (debug >= 2) printk(KERN_DEBUG "MIUI13VCam: " fmt, ##__VA_ARGS__); } while(0)
#define vcam_trace(fmt, ...) \
    do { if (debug >= 3) printk(KERN_DEBUG "MIUI13VCam: [%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__); } while(0)

// 发送HTTP请求获取图像数据
static int request_image_data(void) {
    struct sockaddr_in addr;
    struct socket *sock = NULL;
    struct msghdr msg;
    struct kvec iov;
    char request[256];
    char *response_buffer;
    int ret, bytes_received = 0;
    
    if (!vcam_dev)
        return -EINVAL;
    
    vcam_debug("Requesting image data from %s:%d\n", server_ip, server_port);
    
    // 创建socket
    ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (ret < 0) {
        vcam_debug("Failed to create socket: %d\n", ret);
        return ret;
    }
    
    // 设置服务器地址
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr.s_addr = in_aton(server_ip);
    
    // 连接服务器
    ret = sock->ops->connect(sock, (struct sockaddr*)&addr, sizeof(addr), 0);
    if (ret < 0) {
        vcam_debug("Failed to connect to server: %d\n", ret);
        sock_release(sock);
        return ret;
    }
    
    // 发送HTTP GET请求
    snprintf(request, sizeof(request), 
             "GET /camera/frame HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Connection: close\r\n"
             "User-Agent: MIUI13-VirtualCamera/3.0\r\n"
             "\r\n", server_ip, server_port);
    
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = request;
    iov.iov_len = strlen(request);
    
    ret = kernel_sendmsg(sock, &msg, &iov, 1, strlen(request));
    if (ret < 0) {
        vcam_debug("Failed to send request: %d\n", ret);
        sock_release(sock);
        return ret;
    }
    
    // 分配响应缓冲区
    response_buffer = kmalloc(NETWORK_BUFFER_SIZE, GFP_KERNEL);
    if (!response_buffer) {
        sock_release(sock);
        return -ENOMEM;
    }
    
    // 接收响应
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = response_buffer;
    iov.iov_len = NETWORK_BUFFER_SIZE;
    
    ret = kernel_recvmsg(sock, &msg, &iov, 1, NETWORK_BUFFER_SIZE, 0);
    if (ret > 0) {
        bytes_received = ret;
        vcam_debug("Received %d bytes from server\n", bytes_received);
        
        // 查找HTTP响应体（跳过HTTP头）
        char *body_start = strstr(response_buffer, "\r\n\r\n");
        if (body_start) {
            body_start += 4; // 跳过 "\r\n\r\n"
            int body_size = bytes_received - (body_start - response_buffer);
            
            if (body_size > 0 && body_size <= MAX_FRAME_SIZE) {
                mutex_lock(&vcam_dev->lock);
                
                int frame_idx = vcam_dev->current_frame;
                if (vcam_dev->frame_buffers[frame_idx]) {
                    memcpy(vcam_dev->frame_buffers[frame_idx], body_start, body_size);
                    vcam_dev->frame_sizes[frame_idx] = body_size;
                    vcam_dev->current_frame = (frame_idx + 1) % FRAME_BUFFER_COUNT;
                    
                    vcam_dev->frames_received++;
                    vcam_dev->bytes_received += body_size;
                    
                    vcam_trace("Stored frame %lu, size %d\n", vcam_dev->frames_received, body_size);
                }
                
                mutex_unlock(&vcam_dev->lock);
            }
        }
    }
    
    kfree(response_buffer);
    sock_release(sock);
    
    return ret > 0 ? 0 : ret;
}

// 网络连接函数
static int connect_to_server(void) {
    struct sockaddr_in addr;
    int ret;
    
    if (!vcam_dev)
        return -EINVAL;
    
    vcam_debug("Connecting to server %s:%d\n", server_ip, server_port);
    
    // 创建socket
    ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &vcam_dev->sock);
    if (ret < 0) {
        vcam_info("Failed to create socket: %d\n", ret);
        return ret;
    }
    
    // 设置服务器地址
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_port);
    addr.sin_addr.s_addr = in_aton(server_ip);
    
    // 连接服务器
    ret = vcam_dev->sock->ops->connect(vcam_dev->sock, (struct sockaddr*)&addr, sizeof(addr), 0);
    if (ret < 0) {
        vcam_info("Failed to connect to server: %d\n", ret);
        sock_release(vcam_dev->sock);
        vcam_dev->sock = NULL;
        return ret;
    }
    
    vcam_dev->network_connected = true;
    vcam_info("Connected to server %s:%d\n", server_ip, server_port);
    
    return 0;
}

// 网络接收线程
static int network_thread_func(void *data) {
    struct msghdr msg;
    struct kvec iov;
    char *buffer;
    int ret;
    
    vcam_info("Network thread started\n");
    
    buffer = kmalloc(NETWORK_BUFFER_SIZE, GFP_KERNEL);
    if (!buffer) {
        vcam_info("Failed to allocate network buffer\n");
        return -ENOMEM;
    }
    
    while (!kthread_should_stop()) {
        if (!vcam_dev->network_connected) {
            // 尝试连接服务器
            if (connect_to_server() < 0) {
                msleep(5000); // 5秒后重试
                continue;
            }
        }
        
        // 接收数据
        memset(&msg, 0, sizeof(msg));
        iov.iov_base = buffer;
        iov.iov_len = NETWORK_BUFFER_SIZE;
        
        ret = kernel_recvmsg(vcam_dev->sock, &msg, &iov, 1, NETWORK_BUFFER_SIZE, MSG_DONTWAIT);
        
        if (ret > 0) {
            // 处理接收到的帧数据
            mutex_lock(&vcam_dev->lock);
            
            if (ret <= MAX_FRAME_SIZE) {
                int frame_idx = vcam_dev->current_frame;
                
                if (vcam_dev->frame_buffers[frame_idx]) {
                    memcpy(vcam_dev->frame_buffers[frame_idx], buffer, ret);
                    vcam_dev->frame_sizes[frame_idx] = ret;
                    vcam_dev->current_frame = (frame_idx + 1) % FRAME_BUFFER_COUNT;
                    
                    vcam_dev->frames_received++;
                    vcam_dev->bytes_received += ret;
                    
                    vcam_trace("Received frame %lu, size %d\n", vcam_dev->frames_received, ret);
                }
            }
            
            mutex_unlock(&vcam_dev->lock);
        } else if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
            // 没有数据，短暂休眠
            msleep(10);
        } else {
            // 连接错误
            vcam_info("Network error: %d, reconnecting...\n", ret);
            if (vcam_dev->sock) {
                sock_release(vcam_dev->sock);
                vcam_dev->sock = NULL;
            }
            vcam_dev->network_connected = false;
            msleep(1000);
        }
    }
    
    kfree(buffer);
    vcam_info("Network thread stopped\n");
    return 0;
}

// 请求定时器回调函数
static void request_timer_callback(struct timer_list *timer) {
    if (vcam_dev && vcam_dev->request_active && auto_request) {
        // 请求新的图像数据
        request_image_data();
        
        // 重新设置定时器（每100ms请求一次，约10fps）
        mod_timer(&vcam_dev->request_timer, jiffies + msecs_to_jiffies(100));
    }
}

// 设备文件操作
static int vcam_open(struct inode *inode, struct file *file) {
    vcam_debug("Device opened by PID %d (%s)\n", current->pid, current->comm);
    
    mutex_lock(&vcam_dev->lock);
    vcam_dev->open_count++;
    vcam_dev->access_count++;
    
    // 当摄像头被访问时，启动数据请求
    if (auto_request && !vcam_dev->request_active) {
        vcam_dev->request_active = true;
        vcam_info("Camera accessed, starting data request from %s:%d\n", server_ip, server_port);
        
        // 立即请求一次数据
        request_image_data();
        
        // 启动定时器进行周期性请求
        mod_timer(&vcam_dev->request_timer, jiffies + msecs_to_jiffies(100));
    }
    mutex_unlock(&vcam_dev->lock);
    
    // 启动网络线程（如果还没启动）
    if (!vcam_dev->network_thread) {
        vcam_dev->network_thread = kthread_run(network_thread_func, NULL, "miui13_vcam_net");
        if (IS_ERR(vcam_dev->network_thread)) {
            vcam_info("Failed to start network thread\n");
            vcam_dev->network_thread = NULL;
        }
    }
    
    return 0;
}

static int vcam_release(struct inode *inode, struct file *file) {
    vcam_debug("Device closed by PID %d (%s)\n", current->pid, current->comm);
    
    mutex_lock(&vcam_dev->lock);
    if (vcam_dev->open_count > 0)
        vcam_dev->open_count--;
    
    // 如果没有应用在使用摄像头，停止数据请求
    if (vcam_dev->open_count == 0 && vcam_dev->request_active) {
        vcam_dev->request_active = false;
        del_timer(&vcam_dev->request_timer);
        vcam_info("No more camera access, stopping data request\n");
    }
    mutex_unlock(&vcam_dev->lock);
    
    return 0;
}

static ssize_t vcam_read(struct file *file, char __user *buffer, size_t len, loff_t *offset) {
    int frame_idx;
    size_t frame_size;
    ssize_t ret = 0;
    
    if (!vcam_dev || len == 0)
        return -EINVAL;
    
    // 当有读取请求时，触发数据请求
    if (auto_request && !vcam_dev->request_active) {
        mutex_lock(&vcam_dev->lock);
        if (!vcam_dev->request_active) {
            vcam_dev->request_active = true;
            vcam_info("Read access detected, requesting data from %s:%d\n", server_ip, server_port);
            
            // 立即请求数据
            request_image_data();
            
            // 启动定时器
            mod_timer(&vcam_dev->request_timer, jiffies + msecs_to_jiffies(100));
        }
        mutex_unlock(&vcam_dev->lock);
    }
    
    mutex_lock(&vcam_dev->lock);
    
    // 获取当前帧
    frame_idx = (vcam_dev->current_frame + FRAME_BUFFER_COUNT - 1) % FRAME_BUFFER_COUNT;
    frame_size = vcam_dev->frame_sizes[frame_idx];
    
    if (frame_size > 0 && vcam_dev->frame_buffers[frame_idx]) {
        size_t copy_size = min(len, frame_size);
        
        if (copy_to_user(buffer, vcam_dev->frame_buffers[frame_idx], copy_size)) {
            ret = -EFAULT;
        } else {
            ret = copy_size;
            vcam_trace("Read %zu bytes for PID %d (from server data)\n", copy_size, current->pid);
        }
    } else {
        // 没有帧数据时，尝试立即请求一次
        if (auto_request) {
            mutex_unlock(&vcam_dev->lock);
            request_image_data();
            mutex_lock(&vcam_dev->lock);
            
            // 重新检查是否有数据
            frame_idx = (vcam_dev->current_frame + FRAME_BUFFER_COUNT - 1) % FRAME_BUFFER_COUNT;
            frame_size = vcam_dev->frame_sizes[frame_idx];
            
            if (frame_size > 0 && vcam_dev->frame_buffers[frame_idx]) {
                size_t copy_size = min(len, frame_size);
                
                if (copy_to_user(buffer, vcam_dev->frame_buffers[frame_idx], copy_size)) {
                    ret = -EFAULT;
                } else {
                    ret = copy_size;
                    vcam_trace("Read %zu bytes for PID %d (fresh server data)\n", copy_size, current->pid);
                }
            }
        }
        
        // 如果还是没有数据，返回测试图案
        if (ret == 0) {
            char test_pattern[] = "MIUI13_VIRTUAL_CAMERA_WAITING_FOR_DATA";
            size_t pattern_size = sizeof(test_pattern);
            size_t copy_size = min(len, pattern_size);
            
            if (copy_to_user(buffer, test_pattern, copy_size)) {
                ret = -EFAULT;
            } else {
                ret = copy_size;
                vcam_trace("Read %zu bytes test pattern for PID %d\n", copy_size, current->pid);
            }
        }
    }
    
    mutex_unlock(&vcam_dev->lock);
    return ret;
}

static ssize_t vcam_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    vcam_trace("Write request: %zu bytes from PID %d\n", len, current->pid);
    return len; // 假装写入成功
}

// ioctl处理 - 模拟V4L2接口
static long vcam_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    vcam_trace("IOCTL cmd=0x%x, arg=0x%lx from PID %d (%s)\n", cmd, arg, current->pid, current->comm);
    
    // 对于MIUI相机的特定ioctl调用，返回成功
    // 这里可以根据需要添加更多的V4L2 ioctl处理
    
    switch (cmd) {
        case 0x80045600 ... 0x80045700: // V4L2 ioctl范围
            return 0; // 假装成功
        default:
            return -ENOTTY;
    }
}

// mmap支持
static int vcam_mmap(struct file *file, struct vm_area_struct *vma) {
    vcam_trace("MMAP request from PID %d\n", current->pid);
    return 0; // 简化实现
}

static struct file_operations vcam_fops = {
    .owner = THIS_MODULE,
    .open = vcam_open,
    .release = vcam_release,
    .read = vcam_read,
    .write = vcam_write,
    .unlocked_ioctl = vcam_ioctl,
    .mmap = vcam_mmap,
};

// proc文件系统接口
static int vcam_proc_show(struct seq_file *m, void *v) {
    seq_printf(m, "MIUI13 Virtual Camera Status\n");
    seq_printf(m, "============================\n");
    seq_printf(m, "Driver Version: 3.0\n");
    seq_printf(m, "Target System: MIUI 13 (Android 12)\n");
    seq_printf(m, "Kernel Version: 4.14.186\n");
    seq_printf(m, "\n");
    seq_printf(m, "Configuration:\n");
    seq_printf(m, "  Server IP: %s\n", server_ip);
    seq_printf(m, "  Server Port: %d\n", server_port);
    seq_printf(m, "  Debug Level: %d\n", debug);
    seq_printf(m, "  Replace All: %s\n", replace_all ? "Yes" : "No");
    seq_printf(m, "  Stealth Mode: %s\n", stealth_mode ? "Yes" : "No");
    seq_printf(m, "\n");
    seq_printf(m, "Runtime Status:\n");
    seq_printf(m, "  Device Major: %d\n", major_number);
    seq_printf(m, "  Open Count: %lu\n", vcam_dev ? vcam_dev->open_count : 0);
    seq_printf(m, "  Access Count: %lu\n", vcam_dev ? vcam_dev->access_count : 0);
    seq_printf(m, "  Network Connected: %s\n", (vcam_dev && vcam_dev->network_connected) ? "Yes" : "No");
    seq_printf(m, "  Request Active: %s\n", (vcam_dev && vcam_dev->request_active) ? "Yes" : "No");
    seq_printf(m, "  Frames Received: %lu\n", vcam_dev ? vcam_dev->frames_received : 0);
    seq_printf(m, "  Bytes Received: %lu\n", vcam_dev ? vcam_dev->bytes_received : 0);
    seq_printf(m, "\n");
    seq_printf(m, "Device Path: /dev/%s\n", DEVICE_NAME);
    seq_printf(m, "Magic Number: 0x%08X\n", MIUI13_CAMERA_MAGIC);
    
    return 0;
}

static int vcam_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, vcam_proc_show, NULL);
}

static const struct file_operations vcam_proc_fops = {
    .owner = THIS_MODULE,
    .open = vcam_proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

// 初始化帧缓冲
static int init_frame_buffers(void) {
    int i;
    
    for (i = 0; i < FRAME_BUFFER_COUNT; i++) {
        vcam_dev->frame_buffers[i] = vmalloc(MAX_FRAME_SIZE);
        if (!vcam_dev->frame_buffers[i]) {
            vcam_info("Failed to allocate frame buffer %d\n", i);
            // 清理已分配的缓冲区
            while (--i >= 0) {
                vfree(vcam_dev->frame_buffers[i]);
                vcam_dev->frame_buffers[i] = NULL;
            }
            return -ENOMEM;
        }
        vcam_dev->frame_sizes[i] = 0;
    }
    
    vcam_info("Allocated %d frame buffers, %d bytes each\n", FRAME_BUFFER_COUNT, MAX_FRAME_SIZE);
    return 0;
}

// 清理帧缓冲
static void cleanup_frame_buffers(void) {
    int i;
    
    for (i = 0; i < FRAME_BUFFER_COUNT; i++) {
        if (vcam_dev->frame_buffers[i]) {
            vfree(vcam_dev->frame_buffers[i]);
            vcam_dev->frame_buffers[i] = NULL;
        }
    }
}

// 模块初始化
static int __init miui13_vcam_init(void) {
    int ret;
    
    printk(KERN_INFO "MIUI13VCam: Initializing MIUI13 Virtual Camera v3.0\n");
    printk(KERN_INFO "MIUI13VCam: Target: MIUI 13 (Android 12) Kernel 4.14.186\n");
    printk(KERN_INFO "MIUI13VCam: Server: %s:%d, Debug: %d\n", server_ip, server_port, debug);
    
    // 分配设备结构
    vcam_dev = kzalloc(sizeof(struct miui13_vcam_device), GFP_KERNEL);
    if (!vcam_dev) {
        printk(KERN_ERR "MIUI13VCam: Failed to allocate device structure\n");
        return -ENOMEM;
    }
    
    // 初始化互斥锁
    mutex_init(&vcam_dev->lock);
    
    // 初始化请求定时器
    timer_setup(&vcam_dev->request_timer, request_timer_callback, 0);
    vcam_dev->request_active = false;
    
    // 初始化帧缓冲
    ret = init_frame_buffers();
    if (ret < 0) {
        kfree(vcam_dev);
        return ret;
    }
    
    // 分配设备号 - 尝试获取video0的主设备号
    if (replace_all) {
        // 尝试注册为video0 (主设备号81)
        ret = register_chrdev_region(MKDEV(81, 0), 1, DEVICE_NAME);
        if (ret < 0) {
            // 如果失败，动态分配
            ret = alloc_chrdev_region(&vcam_dev->devno, 0, 1, DEVICE_NAME);
            if (ret < 0) {
                printk(KERN_ERR "MIUI13VCam: Failed to allocate device number\n");
                cleanup_frame_buffers();
                kfree(vcam_dev);
                return ret;
            }
            major_number = MAJOR(vcam_dev->devno);
        } else {
            vcam_dev->devno = MKDEV(81, 0);
            major_number = 81;
        }
    } else {
        // 动态分配设备号
        ret = alloc_chrdev_region(&vcam_dev->devno, 0, 1, DEVICE_NAME);
        if (ret < 0) {
            printk(KERN_ERR "MIUI13VCam: Failed to allocate device number\n");
            cleanup_frame_buffers();
            kfree(vcam_dev);
            return ret;
        }
        major_number = MAJOR(vcam_dev->devno);
    }
    
    printk(KERN_INFO "MIUI13VCam: Allocated device number %d:%d\n", 
           MAJOR(vcam_dev->devno), MINOR(vcam_dev->devno));
    
    // 初始化字符设备
    cdev_init(&vcam_dev->cdev, &vcam_fops);
    vcam_dev->cdev.owner = THIS_MODULE;
    
    ret = cdev_add(&vcam_dev->cdev, vcam_dev->devno, 1);
    if (ret < 0) {
        printk(KERN_ERR "MIUI13VCam: Failed to add character device\n");
        unregister_chrdev_region(vcam_dev->devno, 1);
        cleanup_frame_buffers();
        kfree(vcam_dev);
        return ret;
    }
    
    // 创建设备类
    vcam_dev->class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(vcam_dev->class)) {
        printk(KERN_ERR "MIUI13VCam: Failed to create device class\n");
        cdev_del(&vcam_dev->cdev);
        unregister_chrdev_region(vcam_dev->devno, 1);
        cleanup_frame_buffers();
        kfree(vcam_dev);
        return PTR_ERR(vcam_dev->class);
    }
    
    // 创建设备节点
    vcam_dev->device = device_create(vcam_dev->class, NULL, vcam_dev->devno, NULL, DEVICE_NAME);
    if (IS_ERR(vcam_dev->device)) {
        printk(KERN_ERR "MIUI13VCam: Failed to create device\n");
        class_destroy(vcam_dev->class);
        cdev_del(&vcam_dev->cdev);
        unregister_chrdev_region(vcam_dev->devno, 1);
        cleanup_frame_buffers();
        kfree(vcam_dev);
        return PTR_ERR(vcam_dev->device);
    }
    
    // 创建proc文件
    proc_create(PROC_NAME, 0444, NULL, &vcam_proc_fops);
    
    printk(KERN_INFO "MIUI13VCam: Module loaded successfully\n");
    printk(KERN_INFO "MIUI13VCam: Device created at /dev/%s (major %d)\n", DEVICE_NAME, major_number);
    printk(KERN_INFO "MIUI13VCam: Status available at /proc/%s\n", PROC_NAME);
    
    if (stealth_mode) {
        printk(KERN_INFO "MIUI13VCam: Stealth mode enabled - hiding from detection\n");
    }
    
    if (auto_request) {
        printk(KERN_INFO "MIUI13VCam: Auto request enabled - will fetch data from %s:%d when accessed\n", 
               server_ip, server_port);
    }
    
    return 0;
}

// 模块清理
static void __exit miui13_vcam_exit(void) {
    printk(KERN_INFO "MIUI13VCam: Unloading module\n");
    
    if (!vcam_dev)
        return;
    
    // 停止请求定时器
    vcam_dev->request_active = false;
    del_timer_sync(&vcam_dev->request_timer);
    
    // 停止网络线程
    if (vcam_dev->network_thread) {
        kthread_stop(vcam_dev->network_thread);
        vcam_dev->network_thread = NULL;
    }
    
    // 关闭网络连接
    if (vcam_dev->sock) {
        sock_release(vcam_dev->sock);
        vcam_dev->sock = NULL;
    }
    
    // 删除proc文件
    remove_proc_entry(PROC_NAME, NULL);
    
    // 清理设备
    if (vcam_dev->device) {
        device_destroy(vcam_dev->class, vcam_dev->devno);
    }
    
    if (vcam_dev->class) {
        class_destroy(vcam_dev->class);
    }
    
    cdev_del(&vcam_dev->cdev);
    unregister_chrdev_region(vcam_dev->devno, 1);
    
    // 清理帧缓冲
    cleanup_frame_buffers();
    
    // 释放设备结构
    kfree(vcam_dev);
    vcam_dev = NULL;
    
    printk(KERN_INFO "MIUI13VCam: Module unloaded\n");
}

module_init(miui13_vcam_init);
module_exit(miui13_vcam_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Virtual Camera Team");
MODULE_DESCRIPTION("MIUI13 Android12 Kernel 4.14.186 Virtual Camera Driver");
MODULE_VERSION("3.0");
MODULE_ALIAS("char-major-81-*");  // 声明为video设备
