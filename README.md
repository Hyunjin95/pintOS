# PintOS
Pintos is computer software, a simple instructional operating system framework for the x86 instruction set architecture. It supports kernel threads, loading and running user programs, and a file system, but it implements all of these in a very simple way. It was created at Stanford University by Ben Pfaff in 2004. (https://en.wikipedia.org/wiki/Pintos)

# Projects
There were three projects in this class.

## 1. Scheduling
* Implement wait queue
  * When a thread goes to sleep state, make Pintos use wait queue (instead of busy wait)
* Applying priority
  * The thread that has higher priority should run first (sort a ready queue according to the priority)
* Priority inversion prevension
  * Solve priority-inversion problem by priority-donation

## 2. Process & File Descriptor
* Use File System
  * Use a simple file system (built in PintOS).
* Load User Program <br>
  * Modify 'start_process (void *file_name_)' so as to be able to pass not only 'file_name_', but also command line arguments (argc and argv)
* System Call
  * Make a system call handler, process system calls, and file system calls.

## 3. File System
* Extensible Files
  * Modify the file system so file sizes could be increased bigger than 8MB. Expand the file every time a write is made off the end of the file.
* Subdirectories
  * Modify the directory system in order for directories to have their subdirectories.
