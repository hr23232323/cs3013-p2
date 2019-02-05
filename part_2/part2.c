#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/list.h>


unsigned long **sys_call_table;

// References for the OG sys call- Remember no parameters on OG sys call
asmlinkage long (*ref_sys_cs3013_syscall2)(void);


// Struct given in the problem to hold ancestry
typedef struct ancestry{
  pid_t ancestors[10];
  pid_t siblings[100];
  pid_t children[100];
} ancestry;

// task_struct
typedef struct task_struct task_struct;



// New Syscall 
asmlinkage long new_sys_cs3013_syscall2(unsigned short *target_pid, struct ancestry *response) {
  // Struct to store self
  task_struct* self;
  // Copy of PID for checking validity
  unsigned short pid_copy;

  // Pointer for iterating through siblings and children
  task_struct* iter;

  // pointers to children
  pid_t* child_ptr;

  // pointer to siblings
  pid_t* sibling_ptr;

  // pointer to ancestry holder
  ancestry new_vals;
  ancestry* new_vals_ptr = &new_vals;
  struct list_head *i;

  //printk(KERN_INFO "New Sys call running----------------------"); 

  // Make sure PID is valid
  if(copy_from_user(&pid_copy, target_pid, sizeof(unsigned short))){
    printk(KERN_INFO "INVALID PID----------------------"); 
    return EFAULT;
  }

  if(copy_from_user(new_vals_ptr, response, sizeof(ancestry))){
    printk(KERN_INFO "INVALID PID----------------------"); 
    return EFAULT;
  }

  child_ptr = new_vals_ptr->children;

  self = pid_task(find_vpid(pid_copy), PIDTYPE_PID);

  list_for_each(i, &(self->children)){
    iter = list_entry(i, task_struct, sibling);
    *child_ptr++ = iter->pid;
    printk(KERN_INFO "---------%d's child is %d--------\n", self->pid, iter->pid);
  }

  // Find and store PID's of all siblings
  list_for_each(i, &(self->sibling)){
    iter = list_entry(i, task_struct, sibling);
    if(iter->pid == 0){
      return;
    }
    *sibling_ptr++ = iter->pid;
    printk(KERN_INFO "---------%d's sibling is %d--------\n", self->pid, iter->pid);
  }

  // Traverse through parents using recursion


  printk("-------------------------%d---------------------\n", self->pid);
  return self->pid;

}


static unsigned long **find_sys_call_table(void) {
  unsigned long int offset = PAGE_OFFSET;
  unsigned long **sct;
  
  while (offset < ULLONG_MAX) {
    sct = (unsigned long **)offset;

    if (sct[__NR_close] == (unsigned long *) sys_close) {
      printk(KERN_INFO "Interceptor: Found syscall table at address: 0x%02lX",
       (unsigned long) sct);
      return sct;
    }
    
    offset += sizeof(void *);
  }
  
  return NULL;
}

static void disable_page_protection(void) {
  /*
    Control Register 0 (cr0) governs how the CPU operates.

    Bit #16, if set, prevents the CPU from writing to memory marked as
    read only. Well, our system call table meets that description.
    But, we can simply turn off this bit in cr0 to allow us to make
    changes. We read in the current value of the register (32 or 64
    bits wide), and AND that with a value where all bits are 0 except
    the 16th bit (using a negation operation), causing the write_cr0
    value to have the 16th bit cleared (with all other bits staying
    the same. We will thus be able to write to the protected memory.

    It's good to be the kernel!
  */
  write_cr0 (read_cr0 () & (~ 0x10000));
}

static void enable_page_protection(void) {
  /*
   See the above description for cr0. Here, we use an OR to set the 
   16th bit to re-enable write protection on the CPU.
  */
  write_cr0 (read_cr0 () | 0x10000);
}

static int __init interceptor_start(void) {
  /* Find the system call table */
  if(!(sys_call_table = find_sys_call_table())) {
    /* Well, that didn't work. 
       Cancel the module loading step. */
    printk("Something failed");
    return -1;
  }
  
  /* Store a copy of all the existing functions */
  ref_sys_cs3013_syscall2 = (void *)sys_call_table[__NR_cs3013_syscall2];

  /* Replace the existing system calls */
  disable_page_protection();

  sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)new_sys_cs3013_syscall2;
  
  enable_page_protection();
  
  /* And indicate the load was successful */
  printk(KERN_INFO "Loaded interceptor!");

  return 0;
}

static void __exit interceptor_end(void) {
  /* If we don't know what the syscall table is, don't bother. */
  if(!sys_call_table)
    return;
  
  /* Revert all system calls to what they were before we began. */
  disable_page_protection();

  sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)ref_sys_cs3013_syscall2;

  enable_page_protection();

  printk(KERN_INFO "Unloaded interceptor!");
}

MODULE_LICENSE("GPL");
module_init(interceptor_start);
module_exit(interceptor_end);
