# PintOS
Pintos is computer software, a simple instructional operating system framework for the x86 instruction set architecture. It supports kernel threads, loading and running user programs, and a file system, but it implements all of these in a very simple way. It was created at Stanford University by Ben Pfaff in 2004. (https://en.wikipedia.org/wiki/Pintos)
<br>
# Project
There were three projects in this class. <br>
## Scheduling <br>
* Implement wait queue <br>
When a thread goes to sleep state, make Pintos use wait queue (instead of busy wait) <br>
* Applying priority <br>
The thread that has higher priority should run first (sort a ready queue according to the priority) <br>
* Priority inversion prevension <br>
Solve priority-inversion problem by priority-donation <br>
## Process & File Descriptor <br>
* Use File System <br>
Use a simple file system (built in PintOS). <br>
* Load User Program <br>
Modify 'start_process (void *file_name_)' so as to be able to pass not only 'file_name_', but also command line arguments (argc and argv) <br>
* System Call <br>
Make a system call handler, process system calls, and file system calls. <br>
## File System <br>
* Extensible Files <br>
Modify the file system so file sizes could be increased bigger than 8MB. Expand the file every time a write is made off the end of the file. <br>
* Subdirectories <br>
Modify the directory system in order for directories to have their subdirectories.

