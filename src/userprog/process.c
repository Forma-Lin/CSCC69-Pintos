#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static struct thread *get_thread (tid_t tid);
static bool setup_stack (void **esp, const char *cmd_line);

/* Helper struct and function for get_thread */
struct get_thread_aux {
    tid_t tid;
    struct thread *t;
};

static void 
get_thread_action (struct thread *t, void *aux) {
    struct get_thread_aux *gta = aux;
    if (gta != NULL && t->tid == gta->tid) {
        gta->t = t;
    }
}

/* Finds a thread by its TID. */
static struct thread *
get_thread (tid_t tid)
{
  struct get_thread_aux gta;
  gta.tid = tid;
  gta.t = NULL;

  enum intr_level old_level = intr_disable ();
  thread_foreach (get_thread_action, &gta);
  intr_set_level (old_level);
  
  return gta.t;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  char *process_name = palloc_get_page(0);
  if (process_name == NULL) {
      palloc_free_page(fn_copy);
      return TID_ERROR;
  }
  strlcpy(process_name, file_name, PGSIZE);
  char *save_ptr;
  process_name = strtok_r(process_name, " ", &save_ptr);

  tid = thread_create (process_name, PRI_DEFAULT, start_process, fn_copy);
  
  palloc_free_page(process_name);

  if (tid == TID_ERROR) {
    palloc_free_page (fn_copy); 
    return TID_ERROR;
  }

  struct thread *child = get_thread(tid);
  if (child) {
    sema_down(&child->load_sema);
    
    /* The load_success flag should be set in the child's child_info structure
       which is managed by the parent and won't disappear when child exits. */
    struct thread *cur = thread_current();
    struct list_elem *e;
    bool load_success = false;
    
    /* Find the child_info for this TID and read the load result from there */
    for (e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e)) {
        struct child_info *child_info = list_entry(e, struct child_info, elem);
        if (child_info->tid == tid) {
            load_success = child_info->load_success;
            break;
        }
    }
    
    if (!load_success) {
      return TID_ERROR;
    }
  } else {
    return TID_ERROR;
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  struct thread *t = thread_current();
  
  t->child_info = malloc(sizeof(struct child_info));
  if (t->child_info) {
    t->child_info->tid = t->tid;
    t->child_info->exit_status = 0;  /* Initialize exit status */
    t->child_info->has_waited_on = false;
    t->child_info->load_success = false;  /* Initialize load success flag */
    sema_init(&t->child_info->wait_sema, 0);
    list_push_back(&t->parent->children, &t->child_info->elem);
  }

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  t->load_success = success;
  
  /* Also store the load result in child_info so parent can access it safely */
  if (t->child_info) {
    t->child_info->load_success = success;
  }
  
  sema_up(&t->load_sema);

  /* If load failed, quit. */
  if (!success) {
    /* Set exit status to -1 for load failure */
    if (t->child_info) {
      t->child_info->exit_status = -1;
    }
    palloc_free_page (file_name);
    thread_exit ();
  }
  
  palloc_free_page (file_name);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *cur = thread_current();
  struct list_elem *e;

  for (e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e)) {
      struct child_info *child = list_entry(e, struct child_info, elem);
      if (child->tid == child_tid) {
          if (child->has_waited_on) {
              return -1;
          }
          child->has_waited_on = true;
          sema_down(&child->wait_sema);
          int status = child->exit_status;
          list_remove(&child->elem);
          free(child);
          return status;
      }
  }
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  
  /* Print exit status in the required format: "process_name: exit(status)" */
  printf ("%s: exit(%d)\n", cur->name, 
          cur->child_info ? cur->child_info->exit_status : 0);
  
  while (!list_empty(&cur->files)) {
      struct list_elem *e = list_pop_front(&cur->files);
      struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);
      file_close(fd_struct->file);
      free(fd_struct);
  }

  if (cur->executable) {
      file_allow_write(cur->executable);
      file_close(cur->executable);
  }

   while (!list_empty(&cur->children)) {
      struct list_elem *e = list_pop_front(&cur->children);
      struct child_info *child = list_entry(e, struct child_info, elem);
      /* The child may still be running, so we just free our tracking struct. */
      free(child);
  }

  /* Signal the parent that we're done and provide our exit status.
     The parent should have the exit status in its child_info structure. */
  if (cur->child_info) {
      sema_up(&cur->child_info->wait_sema);
  }
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}
/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Extract program name from command line for file opening */
  char *prog_name = palloc_get_page(0);
  if (prog_name == NULL)
    goto done;
  strlcpy(prog_name, file_name, PGSIZE);
  
  char *save_ptr;
  char *just_prog_name = strtok_r(prog_name, " ", &save_ptr);

  /* Open executable file. */
  file = filesys_open (just_prog_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", just_prog_name);
      palloc_free_page(prog_name);
      goto done; 
    }

  /* Deny writes to the executable. */
  file_deny_write(file);
  t->executable = file;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", just_prog_name);
      palloc_free_page(prog_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        {
          palloc_free_page(prog_name);
          goto done;
        }
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        {
          palloc_free_page(prog_name);
          goto done;
        }
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          palloc_free_page(prog_name);
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                {
                  palloc_free_page(prog_name);
                  goto done;
                }
            }
          else
            {
              palloc_free_page(prog_name);
              goto done;
            }
          break;
        }
    }

  /* Set up stack with original command line (file_name) */
  if (!setup_stack (esp, file_name))
    {
      palloc_free_page(prog_name);
      goto done;
    }

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  palloc_free_page(prog_name);

 done:
  /* We arrive here whether the load is successful or not. */
  if (file != NULL && !success) {
    file_close (file);
    /* Clear the executable pointer since we closed the file */
    t->executable = NULL;
  }
  return success;
}
/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char *cmd_line) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) {
        *esp = PHYS_BASE;
        
        /* Calculate stack boundaries for overflow detection. */
        void *stack_bottom = PHYS_BASE - PGSIZE;
        
        char *cmd_copy = palloc_get_page(0);
        if (cmd_copy == NULL) {
            palloc_free_page(kpage);
            return false;
        }
        strlcpy(cmd_copy, cmd_line, PGSIZE);

        char *token, *save_ptr;
        char *argv[128];
        int argc = 0;

        // Push argument strings onto stack
        for (token = strtok_r(cmd_copy, " ", &save_ptr); token != NULL; 
             token = strtok_r(NULL, " ", &save_ptr)) {
          int len = strlen(token) + 1;
          /* Check for stack overflow before pushing string. */
          if ((char *)*esp - len < (char *)stack_bottom) {
            palloc_free_page(cmd_copy);
            return false;
          }
          *esp -= len;
          strlcpy(*esp, token, len);
          argv[argc++] = *esp;
        }

        // Word-align stack pointer
        while ((uintptr_t)*esp % 4 != 0) {
          /* Check for stack overflow before decrementing. */
          if ((char *)*esp - 1 < (char *)stack_bottom) {
            palloc_free_page(cmd_copy);
            return false;
          }
          (*esp)--;
          *(char*)*esp = 0;
        }

        /* Estimate space needed for pointers and metadata. */
        int metadata_size = sizeof(char *) +              /* null sentinel */
                           argc * sizeof(char *) +        /* argv pointers */
                           sizeof(char **) +               /* argv */
                           sizeof(int) +                   /* argc */
                           sizeof(void *);                 /* return address */
        
        /* Check if we have enough space for all metadata. */
        if ((char *)*esp - metadata_size < (char *)stack_bottom) {
          palloc_free_page(cmd_copy);
          return false;
        }

        // Push null pointer sentinel (argv[argc])
        *esp -= sizeof(char *);
        *(char **)*esp = NULL;

        // Push argv pointers in reverse order
        for (int i = argc - 1; i >= 0; i--) {
          *esp -= sizeof(char *);
          *(char **)*esp = argv[i];
        }

        // Push argv (pointer to argv[0])
        char **argv_ptr = *esp;
        *esp -= sizeof(char **);
        *(char ***)*esp = argv_ptr;

        // Push argc
        *esp -= sizeof(int);
        *(int *)*esp = argc;
        
        // Push fake return address
        *esp -= sizeof(void *);
        *(void **)*esp = NULL;

        palloc_free_page(cmd_copy);
      }
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
