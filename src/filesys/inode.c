#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Maximum sector number: 8MB / 512B */
#define MAX_SECTOR 16384

/* Maximum size of byte: 8MB == 8388608bytes) */
#define MAX_BYTE 8388608

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t sectors_of_data[14];	/* Sectors of Data blocks.
																					 First 12 sectors for direct data blocks,
																					 next 1 sector for single indirect block,
																					 last 1 sector for double indirect block */
		off_t length;              			    /* File size in bytes. */
		size_t number_of_sectors;						/* The number of allocated sectors */
		bool isdir;													/* directory or file */
    unsigned magic;                     /* Magic number. */
		uint32_t unused[110];               /* Not used. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock dir_lock;								/* lock for direcotry synch */
		struct lock expand_lock;						/* lock for file size expand synch */
		struct inode_disk data;             /* Inode content. */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length) {
		off_t offset = pos / BLOCK_SECTOR_SIZE;

		if(offset < 12) { // direct.
			return inode->data.sectors_of_data[offset];	
		}
		else if(offset < 140) { // Single Indirect
			block_sector_t single_indirect_sector = inode->data.sectors_of_data[12];
			off_t index = offset - 12;
			block_sector_t ret;
			block_sector_t *buf = calloc(1, BLOCK_SECTOR_SIZE);

			block_read(fs_device, single_indirect_sector, (void *)buf);
			ret = buf[index];
			free(buf);

			return ret;
		}
		else { // double indirect
			block_sector_t fst_double_indirect_sector = inode->data.sectors_of_data[13];
			block_sector_t snd_double_indirect_sector;
			block_sector_t ret;
			
			offset -= 140;
			off_t fst_index = offset / 128;
			off_t snd_index = offset % 128;
			
			block_sector_t *buf = calloc(1, BLOCK_SECTOR_SIZE);
			
			block_read(fs_device, fst_double_indirect_sector, (void *)buf);
			snd_double_indirect_sector = buf[fst_index];
			free(buf);
	
			block_sector_t *buf2 = calloc(1, BLOCK_SECTOR_SIZE);
			
			block_read(fs_device, snd_double_indirect_sector, (void *)buf2);
			ret = buf2[snd_index];
			free(buf2);

			return ret;
		}
	}
  else {
    return -1;
	}
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

static void
dealloc_function (block_sector_t *list, block_sector_t cnt) {
	block_sector_t i;
	for(i = 0; i < cnt; i++) {
		free_map_release(list[i], 1);
	}
	free(list);
}

static bool
allocate_sectors(size_t sectors, struct inode_disk *disk_inode) {
	size_t allocated_sectors = disk_inode->number_of_sectors;
	block_sector_t cnt = 0;
	// + 1 for single indirect block. (1 + 128) for 1 double indirect block and its single indirect blocks.
	block_sector_t *list = malloc(sizeof(block_sector_t)*(sectors + 1 + (1 + 128)));

	if(allocated_sectors + sectors > MAX_SECTOR)
		return false;

	while(sectors > 0) {
		// Direct
		if(allocated_sectors < 12) {
			block_sector_t *s = &(disk_inode->sectors_of_data[allocated_sectors]);
			
			if(!free_map_allocate(1, s)) {
				dealloc_function(list, cnt);
				return false;
			}

			list[cnt++] = *s;
		}
		// Single indirect
		else if(allocated_sectors < 140) {
			int index = allocated_sectors - 12;

			if(allocated_sectors == 12) {
				if(!free_map_allocate(1, &disk_inode->sectors_of_data[12])) {
					dealloc_function(list, cnt);
					return false;
				}
				list[cnt++] = disk_inode->sectors_of_data[12];
			}

			block_sector_t *buf = calloc(1, BLOCK_SECTOR_SIZE);
			block_read(fs_device, disk_inode -> sectors_of_data[12], (void *)buf);
			block_sector_t *s = &buf[index];

			if(!free_map_allocate(1, s)) {
				free(buf);
				dealloc_function(list, cnt);
				return false;
			}
			block_write(fs_device, disk_inode -> sectors_of_data[12], (const void *)buf);
			list[cnt++] = *s;
			free(buf);
		}
		// Double indirect
		else {
			size_t _index = allocated_sectors - 140;
			size_t fst_index = _index / 128;
			size_t snd_index = _index % 128;

			if(allocated_sectors == 140) {
				if(!free_map_allocate(1, &disk_inode -> sectors_of_data[13])) {
					dealloc_function(list, cnt);
					return false;
				}
				list[cnt++] = disk_inode -> sectors_of_data[13];
			}
			
			if(snd_index == 0) {
				block_sector_t *buf = calloc(1, BLOCK_SECTOR_SIZE);
				block_read(fs_device, disk_inode -> sectors_of_data[13], (void *)buf);
				if(!free_map_allocate(1, &buf[fst_index])) {
					free(buf);
					dealloc_function(list, cnt);
					return false;
				}
				block_write(fs_device, disk_inode->sectors_of_data[13], (const void *)buf);
				list[cnt++] = buf[fst_index];
				free(buf);
			}

			block_sector_t *buf1 = calloc(1, BLOCK_SECTOR_SIZE);
			block_read(fs_device, disk_inode -> sectors_of_data[13], (void *)buf1);
			block_sector_t *buf2 = calloc(1, BLOCK_SECTOR_SIZE);
			block_read(fs_device, buf1[fst_index], (void *)buf2);
			
			block_sector_t *s = &buf2[snd_index];
			if(!free_map_allocate(1, s)) {
				free(buf1);
				free(buf2);
				dealloc_function(list, cnt);
				return false;
			}

			block_write(fs_device, buf1[fst_index], (const void *)buf2);
			list[cnt++] = buf2[snd_index];
			free(buf1);
			free(buf2);
		}
		
		sectors--;
		allocated_sectors++;
	}

	free(list);
	disk_inode -> number_of_sectors = allocated_sectors;
	return true;
}

static void
deallocate_sectors(struct inode_disk *disk_inode) {
	size_t allocated_sectors = disk_inode -> number_of_sectors;

	while(allocated_sectors > 0) {
		// Direct
		if(allocated_sectors <= 12) {
			size_t index = allocated_sectors - 1;
			free_map_release(disk_inode -> sectors_of_data[index], 1);
		}
		// Single indirect
		else if(allocated_sectors <= 140) {
			size_t index = allocated_sectors - 13; 
			block_sector_t *buf = calloc(1, BLOCK_SECTOR_SIZE);
			block_read(fs_device, disk_inode -> sectors_of_data[12], (void *)buf);

			free_map_release(buf[index], 1);
			free(buf);
			
			if(allocated_sectors == 13) {
				free_map_release(disk_inode -> sectors_of_data[12], 1);
			}
		}
		// Dobule indirect
		else {
			size_t index = allocated_sectors - 141;
			size_t fst_index = index / 128;
			size_t snd_index = index % 128;
			block_sector_t *buf = calloc(1, BLOCK_SECTOR_SIZE);
			block_read(fs_device, disk_inode -> sectors_of_data[13], (void *)buf);
			block_sector_t *buf2 = calloc(1, BLOCK_SECTOR_SIZE);
			block_read(fs_device, buf[fst_index], (void *)buf2);
			
			free_map_release(buf2[snd_index], 1);
			free(buf2);

			if(snd_index == 0) {
				free_map_release(buf[fst_index], 1);
			}
			free(buf);

			if(allocated_sectors == 141) {
				free_map_release(disk_inode -> sectors_of_data[13], 1);
			}
		}
		allocated_sectors--;
	}

	disk_inode -> number_of_sectors = allocated_sectors;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool isdir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
  		disk_inode->number_of_sectors = 0;
			disk_inode->isdir = isdir;

			if (allocate_sectors(sectors, disk_inode))
				{
          block_write (fs_device, sector, disk_inode);
          success = true; 
        } 
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
	lock_init(&inode->dir_lock);
	lock_init(&inode->expand_lock);
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
					deallocate_sectors (&inode->data);
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
	
			if(sector_idx == -1)
				break;

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      
			if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

	if(byte_to_sector(inode, offset+size-1) == -1 && offset+size <= MAX_BYTE) {
		if(!inode_isdir(inode))
			lock_acquire(&inode->expand_lock);

		size_t total = bytes_to_sectors(size+offset);
		size_t allocated = inode->data.number_of_sectors;
		size_t need = total - allocated;

		if(!allocate_sectors(need, &inode->data))
			return 0;

		inode->data.length = size + offset;
		block_write(fs_device, inode->sector, &inode->data);

		if(!inode_isdir(inode))
			lock_release(&inode->expand_lock);
	}

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
     
			if(sector_idx == -1)
				break;

			int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
	struct inode_disk *disk_inode = calloc(1, BLOCK_SECTOR_SIZE);
	if(disk_inode == NULL)
		return -1;

	block_read(fs_device, inode->sector, disk_inode);

	off_t length = disk_inode-> length;
	free(disk_inode);

  return length;
}

// Return true if directory, false if file.
bool
inode_isdir(const struct inode *inode) {
	struct inode_disk *disk_inode = calloc(1, BLOCK_SECTOR_SIZE);
	if(disk_inode == NULL)
		return -1;

	block_read(fs_device, inode->sector, disk_inode);

	bool result = disk_inode-> isdir;
	free(disk_inode);
	return result;
}

// Return open count of inode.
int
inode_open_cnt(const struct inode *inode) {
	return inode->open_cnt;
}

// Return dir_lock of inode.
struct lock *
inode_lock(const struct inode *inode) {
	return &inode->dir_lock;
}
