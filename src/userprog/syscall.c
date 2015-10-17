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
void syscall_init(void);

static int syscall_exit(int);
static unsigned syscall_tell(int);
static int syscall_open(char*);
static void syscall_close(int);
static int syscall_filesize(int);
static void syscall_seek(int, unsigned);
static int syscall_read(int, char*, unsigned);
static int syscall_write(int, const char*, unsigned);
static struct file * file_find(int fd);

static bool is_valid(void *p) {
	if(p != NULL && p < PHYS_BASE && pagedir_get_page(thread_current()->pagedir, p) != NULL)
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

		default:
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
			f->eax = filesys_remove(*arg_ptr[0]);
		
			//f->eax = syscall_remove(*arg_ptr[0]);
			
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
			f->eax = filesys_create(*arg_ptr[0], *arg_int[1]);
			//f->eax = syscall_create(*arg_ptr[0], *arg_int[1]);
			lock_release (&lock_sys);	
			break;
		case SYS_SEEK:
			lock_acquire(&lock_sys);
			syscall_seek(*arg_int[0], *arg_int[1]);
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


static struct file * file_find(int fd)
{
		struct thread *t = thread_current();
		struct file_elem *fe;
		struct list_elem *e;

		
		for(e = list_begin(&t->open_files); e!=list_end(&t->open_files);
						e = list_next(e))
		{
				fe = list_entry(e, struct file_elem, elem);
				if(fe->fd == fd) return fe->file;
		}
			return NULL;
}

void syscall_close(int fd)
{
		struct thread *t = thread_current();
		struct file_elem *fe;
		struct list_elem *e;
		
		for(e = list_begin(&t->open_files); e!=list_end(&t->open_files);
						e = list_next(e))
		{		
				fe = list_entry(e, struct file_elem, elem);
				if(fe->fd == fd)
						break;
		}
		if (fe == NULL) 
				return;
	
		file_close(fe->file);
		file_allow_write(fe->file);
		list_remove(&fe->elem);
		free((void*)fe);
		return;
						
}
static void syscall_seek(int fd, unsigned position)
{
		struct file *f = file_find(fd);
		if (f == NULL) 
				return;
		file_seek(f, (off_t)position);

}

static int syscall_filesize(int fd)
{
		struct file *f = file_find(fd);
		if(f == NULL) 
				return -1;
		else
				return (int)file_length(f);
}

static unsigned syscall_tell(int fd)
{
		struct file *f = file_find(fd);
		if( f== NULL)
				return -1;
		else
				return (unsigned) file_tell(f);
}
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

static int syscall_open(char *filename){
	struct thread *cur = thread_current ();
	struct file_elem *fe, *fe_prev;
	struct list_elem *le;
	int fd;

	struct file *file = filesys_open(filename);
	if(file == NULL) {
		/* Error occured while opening file */
		return -1;
	}

	if(!list_empty(&cur->open_files)) {
		le = list_back(&cur->open_files);
		fe_prev = list_entry(le, struct file_elem, elem);
		fd = fe_prev->fd + 1;
	} else {
		fd = 3;
	}

	fe = (struct file_elem*)calloc(1, sizeof(struct thread));
	if(fe == NULL) {
		/* Error occured while allocating thread */
		return -1;
	}

	/* Add information for the opend file */
	fe->fd = fd;
	fe->file = file;
	list_push_back(&cur->open_files, &fe->elem);

	return fd;
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
