#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);
static struct lock filesys_lock;

static bool is_valid_ptr (const void *uaddr);
static bool is_valid_buffer (const void *buffer, unsigned size);
static bool is_valid_string (const char *str);
static void get_args (struct intr_frame *f, int *args, int count);
static void sys_exit (int status) NO_RETURN;
static tid_t sys_exec (const char *cmd_line);
static int sys_wait (tid_t tid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);
struct file_descriptor* get_file_descriptor(int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  // Basic pointer validation - let hardware handle boundary violations
  if (!is_valid_ptr(f->esp)) {
    sys_exit(-1);
  }

  // Read system call number - page fault will be caught if memory is invalid
  int syscall_num = *(int *)f->esp;
  int args[3];

  switch (syscall_num)
  {
    case SYS_HALT:
      shutdown_power_off();
      break;

    case SYS_EXIT:
      get_args(f, args, 1);
      sys_exit(args[0]);
      break;

    case SYS_EXEC:
      get_args(f, args, 1);
      if (!is_valid_string((const char *)args[0])) sys_exit(-1);
      f->eax = sys_exec((const char *)args[0]);
      break;
    
    case SYS_WAIT:
      get_args(f, args, 1);
      f->eax = sys_wait((tid_t)args[0]);
      break;

    case SYS_CREATE:
      get_args(f, args, 2);
      if (!is_valid_string((const char *)args[0])) sys_exit(-1);
      f->eax = sys_create((const char *)args[0], (unsigned)args[1]);
      break;

    case SYS_REMOVE:
      get_args(f, args, 1);
      if (!is_valid_string((const char *)args[0])) sys_exit(-1);
      f->eax = sys_remove((const char *)args[0]);
      break;

    case SYS_OPEN:
      get_args(f, args, 1);
      if (!is_valid_string((const char *)args[0])) sys_exit(-1);
      f->eax = sys_open((const char *)args[0]);
      break;

    case SYS_FILESIZE:
      get_args(f, args, 1);
      f->eax = sys_filesize(args[0]);
      break;

    case SYS_READ:
      get_args(f, args, 3);
      if (!is_valid_buffer((void *)args[1], (unsigned)args[2])) sys_exit(-1);
      f->eax = sys_read(args[0], (void *)args[1], (unsigned)args[2]);
      break;
    
    case SYS_WRITE:
      get_args(f, args, 3);
      if (!is_valid_buffer((const void *)args[1], (unsigned)args[2])) sys_exit(-1);
      f->eax = sys_write(args[0], (const void *)args[1], (unsigned)args[2]);
      break;

    case SYS_SEEK:
      get_args(f, args, 2);
      sys_seek(args[0], (unsigned)args[1]);
      break;

    case SYS_TELL:
      get_args(f, args, 1);
      f->eax = sys_tell(args[0]);
      break;

    case SYS_CLOSE:
      get_args(f, args, 1);
      sys_close(args[0]);
      break;
    
    default:
      sys_exit(-1);
  }
}

static bool
is_valid_ptr (const void *uaddr) {
    struct thread *t = thread_current();
    if (uaddr == NULL || !is_user_vaddr(uaddr) || pagedir_get_page(t->pagedir, uaddr) == NULL) {
        return false;
    }
    return true;
}

static bool
is_valid_buffer(const void *buffer, unsigned size) {
    if (size == 0) return true;
    
    // Check every page boundary in the buffer
    char *start = (char*)buffer;
    char *end = start + size - 1;
    
    // Check first byte
    if (!is_valid_ptr(start)) return false;
    
    // Check each page boundary
    uintptr_t current_page = ((uintptr_t)start) & ~(PGSIZE - 1);
    uintptr_t end_page = ((uintptr_t)end) & ~(PGSIZE - 1);
    
    while (current_page <= end_page) {
        if (!is_valid_ptr((void*)current_page)) return false;
        current_page += PGSIZE;
    }
    
    // Check last byte
    return is_valid_ptr(end);
}

static bool
is_valid_string(const char *str) {
    if (!is_valid_ptr(str)) return false;
    
    while (true) {
        if (!is_valid_ptr(str)) return false;
        if (*str == '\0') break;
        str++;
    }
    return true;
}

static void
get_args(struct intr_frame *f, int *args, int count) {
    int *user_arg_ptr = (int *)f->esp + 1;
    for (int i = 0; i < count; i++) {
        if (!is_valid_ptr(user_arg_ptr + i) || 
            !is_valid_ptr((char*)(user_arg_ptr + i) + sizeof(int) - 1)) {
            sys_exit(-1);
        }
        args[i] = user_arg_ptr[i];
    }
}

static void
sys_exit (int status)
{
    struct thread *cur = thread_current();
    if (cur->child_info) {
        cur->child_info->exit_status = status;
    }
    thread_exit();
}

static tid_t
sys_exec (const char *cmd_line)
{
    return process_execute(cmd_line);
}

static int
sys_wait (tid_t tid)
{
    return process_wait(tid);
}

static bool
sys_create (const char *file, unsigned initial_size)
{
    lock_acquire(&filesys_lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return success;
}

static bool
sys_remove (const char *file)
{
    lock_acquire(&filesys_lock);
    bool success = filesys_remove(file);
    lock_release(&filesys_lock);
    return success;
}

static int
sys_open (const char *file)
{
    lock_acquire(&filesys_lock);
    struct file *f = filesys_open(file);
    lock_release(&filesys_lock);

    if (f == NULL) {
        return -1;
    }

    struct file_descriptor *fd_struct = malloc(sizeof(struct file_descriptor));
    if (fd_struct == NULL) {
        file_close(f);
        return -1;
    }

    struct thread *cur = thread_current();
    fd_struct->fd = cur->next_fd++;
    fd_struct->file = f;
    list_push_back(&cur->files, &fd_struct->elem);

    return fd_struct->fd;
}

static int
sys_filesize (int fd)
{
    struct file_descriptor *fd_struct = get_file_descriptor(fd);
    if (fd_struct == NULL) return -1;
    
    lock_acquire(&filesys_lock);
    int size = file_length(fd_struct->file);
    lock_release(&filesys_lock);
    return size;
}

static int
sys_read (int fd, void *buffer, unsigned size)
{
    if (fd == 0) { // STDIN
        unsigned i;
        for (i = 0; i < size; i++) {
            ((uint8_t *)buffer)[i] = input_getc();
        }
        return i;
    }

    struct file_descriptor *fd_struct = get_file_descriptor(fd);
    if (fd_struct == NULL) return -1;

    lock_acquire(&filesys_lock);
    int bytes_read = file_read(fd_struct->file, buffer, size);
    lock_release(&filesys_lock);
    return bytes_read;
}

static int
sys_write (int fd, const void *buffer, unsigned size)
{
    if (fd == 1) { // STDOUT
        putbuf(buffer, size);
        return size;
    }

    struct file_descriptor *fd_struct = get_file_descriptor(fd);
    if (fd_struct == NULL) return -1;

    lock_acquire(&filesys_lock);
    int bytes_written = file_write(fd_struct->file, buffer, size);
    lock_release(&filesys_lock);
    return bytes_written;
}

static void
sys_seek (int fd, unsigned position)
{
    struct file_descriptor *fd_struct = get_file_descriptor(fd);
    if (fd_struct == NULL) return;
    
    lock_acquire(&filesys_lock);
    file_seek(fd_struct->file, position);
    lock_release(&filesys_lock);
}

static unsigned
sys_tell (int fd)
{
    struct file_descriptor *fd_struct = get_file_descriptor(fd);
    if (fd_struct == NULL) return 0; // Or some error indicator

    lock_acquire(&filesys_lock);
    unsigned pos = file_tell(fd_struct->file);
    lock_release(&filesys_lock);
    return pos;
}

static void
sys_close (int fd)
{
    struct file_descriptor *fd_struct = get_file_descriptor(fd);
    if (fd_struct == NULL) return;

    lock_acquire(&filesys_lock);
    file_close(fd_struct->file);
    lock_release(&filesys_lock);

    list_remove(&fd_struct->elem);
    free(fd_struct);
}

struct file_descriptor*
get_file_descriptor(int fd)
{
    struct thread *cur = thread_current();
    struct list_elem *e;

    for (e = list_begin(&cur->files); e != list_end(&cur->files); e = list_next(e)) {
        struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);
        if (fd_struct->fd == fd) {
            return fd_struct;
        }
    }
    return NULL;
}
