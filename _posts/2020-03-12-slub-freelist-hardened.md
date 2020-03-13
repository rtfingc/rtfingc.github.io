linux 内核默认使用slub分配器来做内存管理，在这篇文章里，我们首先简要交代了slub分配器内存分配的基本流程，然后对其上面的两种安全加固做了分析。


### slub 分配器简述

slub 的实现具体可以参考[这篇文章](https://my.oschina.net/fileoptions/blog/1630346),这里我们简要说明一下。

slub 是针对内核的小内存分配，和用户态堆一开始会brk分一大块内存，然后再慢慢切割一样

伙伴系统给内存，然后slub分配器把内存切割成特定大小的块，后续的分配就可以用了。

具体来说，内核会预先定义一些`kmem_cache` 结构体，它保存着要如何分割使用内存页的信息，可以通过`cat /proc/slabinfo` 查看系统当前可用的`kmem_cache`。

![1](https://p0.ssl.qhimg.com/t017b264d1701c9d401.jpg)

内核很多的结构体会频繁的申请和释放内存，用`kmem_cache` 来管理特定的结构体所需要申请的内存效率上就会比较高，也比较节省内存。默认会创建`kmalloc-8k,kmalloc-4k,... ,kmalloc-16,kmalloc-8` 这样的cache，这样内核调用kmalloc函数时就可以根据申请的内存大小找到对应的`kmalloc-xx`，然后在里面找可可用的内存块。
内核全局有一个 `slab_caches` 变量，它是一个链表，系统所有的 `kmem_cache` 都接在这个链表上。

slab 以页为基本单位切割，然后用单向链表(fd指针)串起来，类似用户态堆的 fastbin，每一个小块我们叫它`object`

`kmem_cache` 内部比较重要的结构如下:

```
kmem_cache
	- kmem_cache_cpu 
		- freelist
		- partial
	- kmem_cache_node
		- partial
```

因为现在的计算机大多是多个cpu的，`kmem_cache_cpu`相当于一个缓存，kmalloc的时候会现在这里找free的slab, 找不到再到`kmem_cache_node` 找。`partial` 保存着之前申请过的没用完的slab

#### 内存分配与释放

slab 其实就类似一个fastbin, 所有的分配都会在`kmem_cache_cpu` 结构体的 `freelist` 上找。

刚开始什么都没有，伙伴系统会根据`kmem_cache`的配置信息给出一块内存，分配好后类似` freelist ==> [x]->[x]->[x]->...->0` 这样，后面每次分配就到`freelist`链表上找 ，它指向第一个可用的free object。

然后可能申请太多，free object 用完了，那就会再向伙伴系统要。

已经用满的slab不用去管它，等它里面有object被free之后，它就会被挂到`kmem_cache_cpu` 的`partial`链表上。

等下一次 `freelist`上的slab又用完了，就可以看看`partial`还有没有可用的，直接拿过来换上，就不用去麻烦伙伴系统了。

`kmem_cache_cpu` 上的`partial` 可能挂了很多未满的slab, 超过一个阈值的时候，就会把整个链表拿到`kmem_cache_node`的`partial` 链表上，然后再有就又可以放了。

那可能又用多了，`kmem_cache_cpu` 上的 freelist 和 partial 的slab都用满了，这时就可以到 `kmem_cache_node`的partial 上拿。

object 的free 是 FIFO的，也就是都会接在freelist 链表头，free 的object 超过一个设定好的阈值时会触发内存回收。

okay， slub 分配器大概就是这样，我们接下来分析一下slub上的两个安全加固是什么样的。

### 环境配置

[linux-5.4 版本](https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.4.tar.xz)

### 模块编写

为了方便调试，我们写个模块来帮助我们操作内核的 kmalloc 以及kfree, 可以随便kmalloc和kfree任意地址

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include<linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/delay.h>
//msleep


MODULE_LICENSE("Dual BSD/GPL");

#define ADD_ANY   0xbeef
#define DEL_ANY   0x2333


struct in_args{
    uint64_t addr;
    uint64_t size;
    char __user *buf;
};

uint64_t g_val = 0;

static long add_any(struct in_args *args){
    long ret = 0;
    char *buffer = kmalloc(args->size,GFP_KERNEL);
    if(buffer == NULL){
        return -ENOMEM;
    }
    if(copy_to_user(args->buf,(void *)&buffer,0x8)){
        return -EINVAL;
    }
    
    return ret;
}
static long del_any(struct in_args *args){
    long ret = 0;
    kfree((void *)args->addr);
    return ret;
}
static long kpwn_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    long ret = -EINVAL;
    struct in_args in;
    if(copy_from_user(&in,(void *)arg,sizeof(in))){
        return ret;
    }
    switch(cmd){
        case DEL_ANY:
            ret = del_any(&in);
            break;
        case ADD_ANY:
            ret = add_any(&in);
            break;
        default:
            ret = -1;
    }
    return ret;
}
static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open =      NULL,
    .release =   NULL,
    .read =      NULL,
    .write =     NULL,
    .unlocked_ioctl = kpwn_ioctl
};

static struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "kpwn",
    .fops = &fops
};

int kpwn_init(void)
{
    misc_register(&misc);
    return 0;
}

void kpwn_exit(void)
{
    printk(KERN_INFO "Goodbye hacker\n");
    misc_deregister(&misc);
}
module_init(kpwn_init);
module_exit(kpwn_exit);

```

然后写个交互脚本

```c
#define _GNU_SOURCE
#include "exp.h"

#define ADD_ANY 0xbeef
#define DEL_ANY 0x2333

struct in_args{
    u64 addr;
    u64 size;
    char *buf;
};

void init(){
    save_status();
    setbuf(stdin,0);
    setbuf(stdout,0);
    signal(SIGSEGV, sh);
}
int main(int argc,char **argv){
    init();
    char *buf=malloc(0x1000);
    u64 *buf64 =(u64 *)buf;
    struct in_args *p = malloc(sizeof(struct in_args));

    int op=0;
    u32 addsize=1024;

    int fd = open("/dev/kpwn",O_RDWR);
    logx("fd",fd);
    u64 freeaddr=0;

    while(1){
        printf("1.malloc\n");
        printf("2.free\n");
        printf("3.exit\n");
        printf(">> ");
        scanf("%d",&op);
        switch(op){
            case 1:
                p->addr=0;
                p->size=addsize;
                p->buf=buf;
                ioctl(fd,ADD_ANY,p);
                loglx("kmalloc: ",buf64[0]);
                break;
            case 2:
                printf("free addr: ");
                scanf("%lx",&freeaddr);
                loglx("read ",freeaddr);
                p->addr=freeaddr;
                ioctl(fd,DEL_ANY,p);
                break;
            case 3:
                exit(0);
                break;
        }
        
    }


    close(fd);

    logs("wtf","aaaaa");

    return 0;
}
```



### CONFIG_SLAB_FREELIST_HARDENED 配置下

okay，我们先看第一个，需要在内核的`.config` 文件中添加`CONFIG_SLAB_FREELIST_HARDENED=y` 编译选项

在这个配置下, `kmem_cache` 增加了一个unsigned long类型的变量random.

```c
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	unsigned long random;
#endif
```

在[mm/slub.c](https://elixir.bootlin.com/linux/v5.4/source/mm/slub.c) 文件, `kmem_cache_open`的时候给random字段一个随机数

```c
static int kmem_cache_open(struct kmem_cache *s, slab_flags_t flags)
{
	s->flags = kmem_cache_flags(s->size, flags, s->name, s->ctor);
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	s->random = get_random_long();
#endif
```

`set_freepointer` 函数中加了一个`BUG_ON`的检查，这里是检查double free的，当前free 的object 的内存地址和 `freelist` 指向的第一个object 的地址不能一样,这和glibc类似。

```c
static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
{
	unsigned long freeptr_addr = (unsigned long)object + s->offset;

#ifdef CONFIG_SLAB_FREELIST_HARDENED
	BUG_ON(object == fp); /* naive detection of double free or corruption */
#endif

	*(void **)freeptr_addr = freelist_ptr(s, fp, freeptr_addr);
}
```

接着是`freelist_ptr`, 它会返回当前object 的下一个 free object 的地址， 加上hardened 之后会和之前初始化的random值做异或。

```c
static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
				 unsigned long ptr_addr)
{
#ifdef CONFIG_SLAB_FREELIST_HARDENED

	return (void *)((unsigned long)ptr ^ s->random ^
			(unsigned long)kasan_reset_tag((void *)ptr_addr));
#else
	return ptr;
#endif
}
```

我们实际调试看看，我们只用一个CPU, 然后kmalloc的大小是 1k,启动exp之后的内存状态如下
![2](https://p5.ssl.qhimg.com/t0123d9f55476560fb4.jpg)


`random` 的值为 `0xed74254a6ccbe301` free object 上保存不再是下一个free object 的地址，而是一个看起来乱七八糟的数字，参考前面的`(void *)((unsigned long)ptr ^ s->random ^(unsigned long)kasan_reset_tag((void *)ptr_addr))`

加上hardened 之后

`下一个free object的地址` = `random` ^ `当前free object的地址` ^ `当前free object 原本fd处的值`

计算一下`hex(0xed74254a6ccbe301^0xed74254a6ccbef01^0xffff88800d7ce400)` 

可以得到`0xffff88800d7ce800` 也就是下一个free object 的地址。

也就是说`CONFIG_SLAB_FREELIST_HARDENED ` 就是加了个给 `fd` 指针异或加了个密，这样如果有溢出就读不到内存地址，要溢出覆盖因为不知道`random`的值也很难继续利用。

我们继续看另外一个安全加固

### CONFIG_SLAB_FREELIST_RANDOM 配置下

同样，这里需要改`.config`文件，加上`CONFIG_SLAB_FREELIST_RANDOM=y`, 简单期间，我们加上`CONFIG_SLAB_FREELIST_HARDENED=n`

这个配置下，`kmem_cache` 会添加一个 unsigned int 类型的数组

```c
#ifdef CONFIG_SLAB_FREELIST_RANDOM
	unsigned int *random_seq;
#endif
```

具体代码实现在[mm/slab_common.c](https://elixir.bootlin.com/linux/v5.4/source/mm/slub_common.c) 以及[mm/slab.c](https://elixir.bootlin.com/linux/v5.4/source/mm/slub.c)里，首先是初始化

```c
static int init_cache_random_seq(struct kmem_cache *s)
{
	unsigned int count = oo_objects(s->oo);
	int err;
...
	if (s->random_seq)
		return 0;

	err = cache_random_seq_create(s, count, GFP_KERNEL);
...
	if (s->random_seq) {
		unsigned int i;

		for (i = 0; i < count; i++)
			s->random_seq[i] *= s->size;
	}
	return 0;
}

/* Initialize each random sequence freelist per cache */
static void __init init_freelist_randomization(void)
{
	struct kmem_cache *s;

	mutex_lock(&slab_mutex);

	list_for_each_entry(s, &slab_caches, list)// 对每个kmem_cache
		init_cache_random_seq(s);

	mutex_unlock(&slab_mutex);
}


```

`init_cache_random_seq`函数先找出当前`kmem_cache`一个slab 里会有多少object(`oo&0xffff`) , `cache_random_seq_create`会根据object的数量给`random_seq` 数组分配内存，初始化为`random_seq[index]=index`, 然后把顺序打乱再乘object的大小

```c
/* Create a random sequence per cache */
int cache_random_seq_create(struct kmem_cache *cachep, unsigned int count,
				    gfp_t gfp)
{
	struct rnd_state state;

	if (count < 2 || cachep->random_seq)
		return 0;

	cachep->random_seq = kcalloc(count, sizeof(unsigned int), gfp);
	if (!cachep->random_seq)
		return -ENOMEM;

	/* Get best entropy at this stage of boot */
	prandom_seed_state(&state, get_random_long());

	freelist_randomize(&state, cachep->random_seq, count);
}
static void freelist_randomize(struct rnd_state *state, unsigned int *list,
			       unsigned int count)
{
	unsigned int rand;
	unsigned int i;

	for (i = 0; i < count; i++)
		list[i] = i;

	/* Fisher-Yates shuffle */
	for (i = count - 1; i > 0; i--) {
		rand = prandom_u32_state(state);
		rand %= (i + 1);
		swap(list[i], list[rand]);
	}
}

```

然后在每次申请新的slab 的时候，会调用`shuffle_freelist` 函数，根据`random_seq` 来把 `freelist` 链表的顺序打乱，这样内存申请的object 后，下一个可以申请的object的地址也就变的不可预测。

```c
	cur = next_freelist_entry(s, page, &pos, start, page_limit,
				freelist_count);
	cur = setup_object(s, page, cur);
	page->freelist = cur;

	for (idx = 1; idx < page->objects; idx++) {
		next = next_freelist_entry(s, page, &pos, start, page_limit,
			freelist_count);
		next = setup_object(s, page, next);
		set_freepointer(s, cur, next);
		cur = next;
	}
	set_freepointer(s, cur, NULL);

```

同样的，我们调试一下看看实际的运行效果, 程序运行 后的slab状态如下，7个free object 以及一个在partial 链表上
![3](https://p5.ssl.qhimg.com/t01fcee0a1ba53be7e0.jpg)

不断调kmalloc 把 free object 消耗完, 再次kmalloc 就会重新分配一个 slab

![4](https://p3.ssl.qhimg.com/t0151655e6ed3e91580.jpg)

可以看到我们kmalloc得到的是`0xffff88800d7df800` 这个地址， 接着下一个是`0xffff88800d7dfc00`, 然后就变成了`0xffff88800d7de000`,并不是连续的，仔细看我们还可以发现其实`0xffff88800d7df800-0x1800` 和`0xffff88800d7dfc00-0x1c00`结果是一样的, 和`random_seq` 的取值关联上了。

![5](https://p3.ssl.qhimg.com/t0183b5a77233ef4a2c.jpg)
### 小结

我们主要分析了Linux slub分配器上的两种安全加固，默认情况下这两个机制都会开启。虽然两个机制都不是很复杂，但是加上之后，内核slab溢出等内存相关的漏洞利用难度就会加大很多，对系统的安全防护还是有很大作用的。



首发[安全客](https://www.anquanke.com/post/id/200161)

### reference

[https://my.oschina.net/fileoptions/blog/1630346](https://my.oschina.net/fileoptions/blog/1630346)
