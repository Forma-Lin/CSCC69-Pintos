#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    /* For alarm clock implementation. */
    struct semaphore sleep_sema;        /* Semaphore for sleeping. */
    int64_t wake_time;                  /* Tick when thread should wake up. */
    struct list_elem sleep_elem;        /* List element for sleeping list. */

    /* For priority scheduling and donation. */
    int base_priority;                  /* Original priority before donation. */
    int effective_priority;             /* Current effective priority. */
    struct list donors;                 /* List of threads donating to this thread. */
    struct list_elem donor_elem;        /* Element for donor lists. */
    struct lock *waiting_for;           /* Lock this thread is waiting for. */
    struct list held_locks;             /* List of locks held by this thread. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    
    /* For project 2: User Programs */
    struct thread *parent;              /* Parent process. */
    struct list children;               /* List of child processes' info. */
    struct child_info *child_info;      /* Info for waiting parent. */

    struct list files;                  /* List of open files (file_descriptor). */
    int next_fd;                        /* Next available file descriptor. */
    struct file *executable;            /* The process's executable file. */

    bool load_success;                  /* For exec: whether child loaded successfully. */
    struct semaphore load_sema;         /* For exec: parent blocks until child loads. */
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* Project 2: Structure definitions. */
#ifdef USERPROG
/* Structure to hold information about a child process for the parent. */
struct child_info {
    tid_t tid;                      /* Child's thread ID. */
    int exit_status;                /* Child's exit status. */
    bool has_waited_on;             /* True if parent has already waited. */
    bool load_success;              /* True if child loaded successfully. */
    struct list_elem elem;          /* List element for parent's children list. */
    struct semaphore wait_sema;     /* Semaphore for parent to wait on child. */
};

/* Structure to map a file descriptor to a file. */
struct file_descriptor {
    int fd;
    struct file *file;
    struct list_elem elem;
};
#endif

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

bool thread_priority_less_func (const struct list_elem *a,
                                const struct list_elem *b, void *aux);
void thread_donate_priority (struct thread *t, int priority);
void thread_update_effective_priority (struct thread *t);
void thread_check_preemption (void);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */
