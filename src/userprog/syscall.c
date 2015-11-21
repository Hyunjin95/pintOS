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
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

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
static bool syscall_chdir(const char *);
static bool syscall_mkdir(const char *);
static bool syscall_readdir(int, char *);
static bool syscall_isdir(int);
static int syscall_inumber(int);
static struct file * file_find(int fd);
static struct file_elem * file_elem_find(int fd);

// Verify if a requested pointer is valid.
static bool is_valid(void *p) {
	// Check pointer isn't NULL, below PHYS_BASE, and page directory is not null.
	if(p != NULL && p < PHYS_BASE && pagedir_get_page(thread_current()->pagedir, p) != NULL)
		return true;
	return false;
}


static void
syscall_handler (struct intr_frame *f) 
{
	int nsyscall, i;
	int *esp = (int *)f -> esp;

	if(!is_valid(esp))
		thread_exit();
	
	int *arg_int[3];
	void **arg_ptr[3];

	// Get system call number.
	nsyscall = *(esp++);

	/* argc number
		0:
			SYS_HALT 
		1:
			SYS_EXIT, SYS_EXEC, SYS_WAIT, SYS_TELL, SYS_REMOVE, SYS_OPEN, SYS_CLOSE, SYS_FILESIZE
		2:
			SYS_CREATE, SYS_SEEK
		3:
			SYS_READ, SYS_WRITE
	*/
	if(nsyscall == SYS_HALT) {
		shutdown_power_off();
	}
	else if(nsyscall == SYS_EXIT) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
			}
			else thread_exit();
		}

		syscall_exit(*arg_int[0]);
	}
	else if(nsyscall == SYS_EXEC) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_ptr[i] = (void **)(esp + i);
			}
			else thread_exit();
		}

		if(!is_valid(*arg_ptr[0]))
			thread_exit();
	
		lock_acquire(&lock_sys);
		f->eax = process_execute(*arg_ptr[0]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_WAIT) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
			}
			else thread_exit();
		}

		f->eax = process_wait(*arg_int[0]);
	}
	else if(nsyscall == SYS_TELL) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
			}
			else thread_exit();
		}

		lock_acquire(&lock_sys);
		f->eax = syscall_tell(*arg_int[0]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_REMOVE) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_ptr[i] = (void **)(esp + i);
			}
			else thread_exit();
		}
		
		if(!is_valid(*arg_ptr[0]))
			thread_exit();

		lock_acquire(&lock_sys);
		f->eax = filesys_remove(*arg_ptr[0]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_OPEN) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_ptr[i] = (void **)(esp + i);
			}
			else thread_exit();
		}
		
		if(!is_valid(*arg_ptr[0]))
			thread_exit();

		lock_acquire(&lock_sys);
		f->eax = syscall_open(*arg_ptr[0]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_CLOSE) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
			}
			else thread_exit();
		}

		lock_acquire(&lock_sys);
		syscall_close(*arg_int[0]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_FILESIZE) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
			}
			else thread_exit();
		}

		lock_acquire(&lock_sys);
		f->eax = syscall_filesize(*arg_int[0]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_CREATE) {
		for(i = 0; i < 2; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
				arg_ptr[i] = (void **)(esp + i);
			}
			else thread_exit();
		}

		if(!is_valid(*arg_ptr[0]))
			thread_exit();

		lock_acquire(&lock_sys);
		f->eax = filesys_create(*arg_ptr[0], *arg_int[1]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_SEEK) {
		for(i = 0; i < 2; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
			}
			else thread_exit();
		}

		lock_acquire(&lock_sys);
		syscall_seek(*arg_int[0], *arg_int[1]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_READ) {
		for(i = 0; i < 3; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
				arg_ptr[i] = (void **)(esp + i);
			}
			else thread_exit();
		}

		if(!is_valid(*arg_ptr[1]))
			thread_exit();

		lock_acquire(&lock_sys);
		f->eax = syscall_read(*arg_int[0], *arg_ptr[1], *arg_int[2]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_WRITE) {
		for(i = 0; i < 3; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
				arg_ptr[i] = (void **)(esp + i);
			}
			else thread_exit();
		}

		if(!is_valid(*arg_ptr[1]))
			thread_exit();

		lock_acquire(&lock_sys);
		f->eax = syscall_write(*arg_int[0], *arg_ptr[1], *arg_int[2]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_CHDIR) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_ptr[i] = (void **)(esp + i);
			}
			else thread_exit();
		}
		
		if(!is_valid(*arg_ptr[0]))
			thread_exit();

		lock_acquire(&lock_sys);
		f->eax = syscall_chdir(*arg_ptr[0]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_MKDIR) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_ptr[i] = (void **)(esp + i);
			}
			else thread_exit();
		}
		
		if(!is_valid(*arg_ptr[0]))
			thread_exit();

		lock_acquire(&lock_sys);
		f->eax = syscall_mkdir(*arg_ptr[0]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_READDIR) {
		for(i = 0; i < 2; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
				arg_ptr[i] = (void **)(esp + i);
			}
			else thread_exit();
		}

		if(!is_valid(*arg_ptr[1]))
			thread_exit();

		lock_acquire(&lock_sys);
		f->eax = syscall_readdir(*arg_int[0], *arg_ptr[1]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_ISDIR) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
			}
			else thread_exit();
		}

		lock_acquire(&lock_sys);
		f->eax = syscall_isdir(*arg_int[0]);
		lock_release(&lock_sys);
	}
	else if(nsyscall == SYS_INUMBER) {
		for(i = 0; i < 1; i++) {
			if(is_valid((esp+i))) {
				arg_int[i] = esp + i;
			}
			else thread_exit();
		}

		lock_acquire(&lock_sys);
		f->eax = syscall_inumber(*arg_int[0]);
		lock_release(&lock_sys);
	}
	else
		thread_exit();
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

// Find a file with file descriptor.
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
// Find a file element with file descriptor.
static struct file_elem *file_elem_find(int fd)
{
		struct thread *t = thread_current();
		struct file_elem *fe;
		struct list_elem *e;
		
		for(e = list_begin(&t->open_files); e!=list_end(&t->open_files);
						e = list_next(e))
		{
				fe = list_entry(e, struct file_elem, elem);
				if(fe->fd == fd) return fe;
		}
			return NULL;
}


void syscall_close(int fd)
{
		struct file_elem *fe = file_elem_find(fd);
	
		if (fe == NULL || fe->fd != fd)
				return;
	
		if(fe->file != NULL)
			file_close(fe->file); // In file close, file_allow_write() and free(fe->file) will be executed.
		else
			dir_close(fe->dir);

		list_remove(&fe->elem);
		free(fe); // free 'file struct'
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
		unsigned i=0;
		for(;i<content_size;i++){
			content[i] = input_getc(); // Read command line by using input_getc();
		}
		return (int)i;
	}else{
		struct file* f = file_find(fd);
		if(f != NULL) return file_read(f, content, content_size);
		else return -1;
	}
}

static int syscall_open(char *filename){
	if(filename == NULL || strlen(filename) == 0)
		return -1;

	struct thread *cur = thread_current ();
	struct file_elem *fe, *fe_prev;
	struct list_elem *le;
	int fd;

	fe = filesys_open_file(filename);

	if(fe == NULL)
		return -1;

	if(fe->file == NULL && fe->dir == NULL) {
		/* Error occured while opening file */
		return -1;
	}

	// If some files are opened already, fd will be fd of last opened file + 1.
	if(!list_empty(&cur->open_files)) {
		le = list_back(&cur->open_files);
		fe_prev = list_entry(le, struct file_elem, elem);
		fd = fe_prev->fd + 1;
	}
	else {
		// 0 = stdin, 1 = stdout
		fd = 2;
	}

	/* Add information for the opened file */
	fe->fd = fd;
	fe->pos = 0;
	list_push_back(&cur->open_files, &fe->elem);

	return fd;
}



static int syscall_write(int fd, const char* content, unsigned content_size){
	if(fd == STDOUT_FILENO){//standard output stream
		const unsigned buf_size = 200;
		unsigned remains = content_size;

		while(remains > buf_size){
			putbuf(content, buf_size); // Write to stdout by using putbuf()
			content += buf_size;
			remains -= buf_size;
		}
		putbuf(content, remains);
		return (int)content_size;
	}
	else{
		struct file* f = file_find(fd);
		if(f == NULL) return -1;
		return file_write(f, content, content_size);
	}
}

/* syscall read and write - Taeho */

// Chnage current working directory.
static bool syscall_chdir(const char *dir_path) {
	char *token, *ptr;
	struct inode *inode = NULL;
	bool success = true;
	struct thread *curr = thread_current();


	// Absolute path.
	if(dir_path[0] == '/') {
		dir_close(curr->dir);
		curr->dir = dir_open_root();
	}

	// Parse the 'path'
	for(token = strtok_r(dir_path, "/", &ptr); token != NULL; token = strtok_r(NULL, "/", &ptr)) {
		if(!dir_lookup(curr->dir, token, &inode)) {
			success = false;
			break;
		}
		dir_close(curr->dir);
		curr->dir = dir_open(inode);
	}

	return success;
}

// Make new directory.
static bool syscall_mkdir(const char *dir_path) {
	struct thread *curr = thread_current();
	char name[NAME_MAX + 1];
	char dir_name[strlen(dir_path) + 1];
	strlcpy(dir_name, dir_path, strlen(dir_path)+1);
	struct dir *open_dir;
	char *token, *token2, *ptr;
	bool success = true;

	// Absolute path
	if(dir_name[0] == '/')
		open_dir = dir_open_root();
	else // Relative path
		open_dir = dir_reopen(curr->dir);

	token = strtok_r(dir_name, "/", &ptr);

	// Parse the 'path'
	for(token2 = strtok_r(NULL, "/", &ptr); token2 != NULL; token2 = strtok_r(NULL, "/", &ptr)) {
		struct inode *inode = NULL;
		success = dir_lookup(open_dir, token, &inode);
		if(!success)
			return false;
		dir_close(open_dir);
		open_dir = dir_open(inode);
		token = token2;
	}

	if(token == NULL)
		return false;

	strlcpy(name, token, sizeof name);

	// create new directory. Simliar to 'filesys_create'
	block_sector_t sector = 0;
	success = (open_dir != NULL
						&& free_map_allocate(1, &sector)
						&& dir_create(sector, inode_get_inumber(dir_get_inode(open_dir)), 20)
						&& dir_add(open_dir, name, sector));

	dir_close(open_dir);
	if(!success && sector != 0)
		free_map_release(sector, 1);

	return success;
}

// Read one directory entry and save its name to NAME.
static bool syscall_readdir(int fd, char *name) {
	if(fd != 0 && fd != 1) {
		struct thread *curr = thread_current();
		struct file_elem *fe = file_elem_find(fd);

		if(fe->dir == NULL)
			return false;
		else
			return dir_readdir(fe->dir, name);
	}
	else
		return false;
}

// Return true if directory, false if file.
static bool syscall_isdir(int fd) {
	if(fd < 2)
		return false;

	struct file_elem *fe = file_elem_find(fd);

	if(fe == NULL)
		return false;

	if(fe->file == NULL && fe->dir != NULL)
		return true;
	else
		return false;
}

// Return inode sector number of (file or directory).
static int syscall_inumber(int fd) {
	struct file_elem *fe = file_elem_find(fd);

	if(fe->file != NULL) {
		return inode_get_inumber(file_get_inode(fe->file));
	}
	else if(fe->dir != NULL) {
		return inode_get_inumber(dir_get_inode(fe->dir));
	}
	else {
		PANIC("File & Directory are boyh empty\n");
	}
}
