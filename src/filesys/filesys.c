#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/thread.h"
#include "filesys/directory.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name_, off_t initial_size) 
{
	if(name_ == NULL || strlen(name_) == 0)
		return false;

	char name[strlen(name_) + 1];
	strlcpy(name, name_, strlen(name_) + 1);

	struct thread *curr = thread_current();
	struct dir *dir;

	// Absolute path
	if(name[0] == '/' || curr->dir == NULL) {
		dir = dir_open_root();
	} // Relative path
	else {
		dir = dir_reopen(curr->dir);
	}

	lock_acquire(dir_lock(dir));

	char *token, *token2, *ptr;
	struct inode *inode = NULL;
	bool success = true;

	// Parse the path
	token = strtok_r(name, "/", &ptr);
	for(token2 = strtok_r(NULL, "/", &ptr); token2 != NULL; token2 = strtok_r(NULL, "/", &ptr)) {
		success = dir_lookup(dir, token, &inode);
		lock_release(dir_lock(dir));
		dir_close(dir);

		if(!success)
			return false;

		dir = dir_open(inode);
		lock_acquire(dir_lock(dir));
		token = token2;
	}

	if(strlen(token) > NAME_MAX) {
		lock_release(dir_lock(dir));
		dir_close(dir);
		return false;
	}

  block_sector_t inode_sector = 0;
  success = (dir != NULL
             && free_map_allocate (1, &inode_sector)
             && inode_create (inode_sector, initial_size, false)
             && dir_add (dir, token, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);

	lock_release(dir_lock(dir));
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct dir *dir = dir_open_root ();
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, name, &inode);
  dir_close (dir);

  return file_open (inode);
}

// Open 'file' if not isdir, otherwise open 'directory'.
struct file_elem *
filesys_open_file(const char *name_) {
	char name[strlen(name_) + 1];
	strlcpy(name, name_, strlen(name_)+1);

	struct thread *curr = thread_current();
	struct dir *dir;

	// Absolute path
	if(name[0] == '/')
		dir = dir_open_root();
	else // Relative path
		dir = dir_reopen(curr->dir);

	// Parse name
	struct inode *inode = NULL;
	char *token, *token2, *ptr;
	bool success = true;

	token = strtok_r(name, "/", &ptr);
	for(token2 = strtok_r(NULL, "/", &ptr); token2 != NULL; token2 = strtok_r(NULL, "/", &ptr)) {
		success = dir_lookup(dir, token, &inode);
		dir_close(dir);
		if(!success) {
			return NULL;
		}
		dir = dir_open(inode);
		token = token2;
	}

	// Root directory case.
	if(token == NULL) {
		inode = inode_open (ROOT_DIR_SECTOR);
	}
	else {
		if(!dir_lookup(dir, token, &inode))
			return NULL;
	}
	dir_close(dir);

	struct file_elem *fe = (struct file_elem *)malloc(sizeof(struct file_elem));
	if(inode_isdir(inode)) {
		fe->dir = dir_open(inode);
		fe->file = NULL;
	}
	else {
		fe->file = file_open(inode);
		fe->dir = NULL;
	}

	return fe;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name_) 
{
	char name[strlen(name_) + 1];
	strlcpy(name, name_, strlen(name_)+1);

	struct thread *curr = thread_current();
	struct dir *dir;

	// Absolute path
	if(name[0] == '/')
		dir = dir_open_root();
	else // Relative path
		dir = dir_reopen(curr->dir);

	bool success = false;
	char *token, *token2, *ptr;
	struct inode *inode = NULL;

	// Parse name
	token = strtok_r(name, "/", &ptr);
	for(token2 = strtok_r(NULL, "/", &ptr); token2 != NULL; token2 = strtok_r(NULL, "/", &ptr)) {
		success = dir_lookup(dir, token, &inode);
		dir_close(dir);
		if(!success)
			return false;
		dir = dir_open(inode);
		token = token2;
	}

	if(token != NULL)
		success = dir_remove(dir, token);

	dir_close(dir);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR, 20))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
