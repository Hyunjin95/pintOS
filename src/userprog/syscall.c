#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
static struct lock lock_sys;
static void syscall_init(void);

static int syscall_exit(int);
static unsigned syscall_tell(int);
static bool syscall_remove(const char*);
static int syscall_open(char*);
static void syscall_close(int);
static int syscall_filesize(int);
static bool syscall_create(const char*, unsigned);
static void syscall_seek(int, unsigned);
static int syscall_read(int, char*, unsigned);
static int syscall_write(int, const char*, unsigned);


static bool is_valid(void *p) {
	if(p != NULL && p < PHYS_BASE && pagedir_get_pages(thread_current()->pagedir, p) != NULL)
		return true;
	return false;
}


static void
syscall_handler (struct intr_frame *f) 
{
	int nsyscall, argc, i;
	int *esp = (int *)f -> esp;

	if(!is_valid((void*)esp))
		thread_exit();
	
	int *arg_int[3];
	void **arg_ptr[3];

	nsyscall = *(esp++);

	switch(nsyscall) {
		case SYS_HALT:
			argc = 0;
			break;
		case SYS_EXIT:
		case SYS_EXEC:
		case SYS_WAIT:
		case SYS_TELL:
		case SYS_REMOVE:
		case SYS_OPEN:
		case SYS_CLOSE:
		case SYS_FILESIZE:
			argc = 1;
			break;
		case SYS_CREATE:
		case SYS_SEEK:
			argc = 2;
			break;
		case SYS_READ:
		case SYS_WRITE:
			argc = 3;
			break;

		deafult:
			thread_exit();
	}

	for(i = 0; i < argc; i++) {
		if(is_valid((void*)(esp+i))) {
			arg_int[i] = esp + i;
			arg_ptr[i] = (void **)(esp + i);
		}
		else {
			break;
		}
	}

	if( i < argc )
		thread_exit();

	switch(nsyscall) {
		case SYS_HALT:
			shutdown_power_off();
			break;
		case SYS_EXIT:
	    syscall_exit(*arg_int[0]);
	    break;
	  case SYS_EXEC:
	    if (!is_valid(*arg_ptr[0]))
	      thread_exit();
			lock_acquire (&lock_sys);
			f->eax = process_execute(*arg_ptr[0]);
			lock_release (&lock_sys);
			break;
		case SYS_WAIT:
			f->eax = process_wait(*arg_int[0]);
			break;
		case SYS_TELL:
		  lock_acquire (&lock_sys);
			f->eax = syscall_tell(*arg_int[0]);
		  lock_release (&lock_sys);
	    break;
		case SYS_REMOVE:
			if (!is_valid(*arg_ptr[0]))
				thread_exit();
			lock_acquire (&lock_sys);
			f->eax = syscall_remove(*arg_ptr[0]);
			lock_release (&lock_sys);
			break;
		case SYS_OPEN:
			if (!is_valid(*arg_ptr[0]))
				thread_exit();
			lock_acquire (&lock_sys);
			f->eax = syscall_open(*arg_ptr[0]);
			lock_release (&lock_sys);
			break;
		case SYS_CLOSE:
			lock_acquire (&lock_sys);
			syscall_close(*arg_int[0]);
			lock_release (&lock_sys);
			break;
		case SYS_FILESIZE:			
			lock_acquire (&lock_sys);
			f->eax = syscall_filesize(*arg_int[0]);
			lock_release (&lock_sys);
			break;
		case SYS_CREATE:
			if (!is_valid(*arg_ptr[0]))
				thread_exit();
			lock_acquire (&lock_sys);
			f->eax = syscall_create(*arg_ptr[0], *arg_int[1]);
			lock_release (&lock_sys);	
			break;
		case SYS_SEEK:
			lock_acquire(&lock_sys);
			f->eax = syscall_seek(*arg_int[0], *arg_int[1]);
			lock_release(&lock_sys);
			break;
		case SYS_READ:
			if(!is_valid(*arg_ptr[1]))
				thread_exit();
			lock_acquire(&lock_sys);
			f->eax = syscall_read(*arg_int[0], *arg_ptr[1], *arg_int[2]);
			lock_release(&lock_sys);
			break;
		case SYS_WRITE:
			if(!is_valid(*arg_ptr[1]))
				thread_exit();
			lock_acquire(&lock_sys);
			f->eax = syscall_write(*arg_int[0], *arg_ptr[1], *arg_int[2]);
			lock_release(&lock_sys);
			break;

		default:
			thread_exit();
	}
}


void
syscall_init (void) 
{
	lock_init(&lock_sys);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static int syscall_exit(int status) {
	thread_current()->exit_status = status;
	thread_exit(); // thread_exit -> process_exit
}

/* syscall read and write - Taeho */
static int syscall_read(int fd, char* content, unsigned content_size){
	if(fd == STDIN_FILENO){//standard input stream
		int i=0;
		for(;i<content_size;i++){
			content[i] = input_getc();
		}
		return i;
	}else{
		struct file* f = file_find(fd);
		if(f != NULL) return file_read(f, content, content_size);
		else return -1;
	}
}


static int syscall_write(int fd, const char* content, unsigned content_size){
	if(fd == STDOUT_FILENO){//standard output stream
		const int buf_size = 256;
		unsigned remains = content_size;

		while(remains > buf_size){
			putbuf(content, buf_size);
			content += buf_size;
			remains -= buf_size;
		}
		putbuf(content, remains);
		return content_size;
	}else{
		struct file* f = file_find(fd);
		if(f == NULL) return -1;
		return file_write(f, content, content_size);
	}
}
/* syscall read and write - Taeho */
