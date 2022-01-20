#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "threads/malloc.h"

void exit (int status);
void chk_addr(const void *ptr);
int write(int fd, const void *buffer, unsigned size);
int read(int fd, const void *buffer, unsigned size);
int filesize(int fd);
void close(int fd);
int findFileAdd(int fd, int type);

typedef int pid_t;

static void halt();
static void syscall_handler (struct intr_frame *);
bool create(const char *file, unsigned size);
bool remove(const char *file);
unsigned tell(int fd);
static pid_t exec(const char *file);

int exit_status =-1;

static struct lock file_lock;

struct file_desc{
	int fd;
	struct list_elem file_elem;
	struct file *file_add;
};

void
syscall_init (void) 
{
	// printf("%d\n", exit_status );
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{ 
	
	chk_addr((const void *)f->esp);

	switch(*(int*)f->esp){

		case SYS_HALT:
			goto next1;
			next1: ;
			halt();
			break;

		case SYS_EXIT:

			goto next2;
			next2: ;

			int *ptr;
			ptr = (int *) f->esp +1;

			chk_addr(ptr);

			exit(*ptr);
			break;

		case SYS_READ:
			
			goto next3;
			next3:;

			// printf("Read case\n");
			int read_args[3];
			int *rd;

			for (int i = 0; i < 3; i++){
				rd = (int *) f->esp + i + 1;
				chk_addr((const void *) rd);
				read_args[i] = *rd;
			}

			char *rbf  = (char * )read_args[1];
			for (unsigned i = 0; i < read_args[2]; i++)
			   {
			    	chk_addr((const void *) rbf);
			     	rbf++;
			    }

			f->eax = read(read_args[0], (const void*)read_args[1], (unsigned) read_args[2]);
			break;

		case SYS_WRITE:

			goto next4;
			next4:;

			int args[3];
			int *t;

			for (int i = 0; i < 3; i++){
				t = (int *) f->esp + i + 1;
				chk_addr((const void *) t);
				args[i] = *t;
			}
			
			char *pt  = (char * )args[1];
			for (unsigned i = 0; i < args[2]; i++)
			   {
			    	chk_addr((const void *) pt);
			     	pt++;
			    }

			f->eax = write(args[0],(const void*)args[1],(unsigned)args[2]);
			break;

		case SYS_WAIT:
		// printf("Wait caught\n");
			goto next5;
			next5:;

			int arg[3];
			int *x;

			for (int i = 0; i < 3; i++){
				x = (int *) f->esp + i + 1;
				chk_addr((const void *) x);
				arg[i] = *x;
			}
			// printf("Arg 0: %d\n", arg[0]);
			f->eax = wait((pid_t)arg[0]);
			break;

		case SYS_CREATE:
			goto next6;
			next6:;

			int sarg[3];
			int *y;

			for (int i = 0; i < 3; i++){
				y = (int *) f->esp + i + 1;
				chk_addr((const void *) y);
				sarg[i] = *y;
			}

			char *bf_ptr  = (char * )sarg[0];
			for (unsigned i = 0; i < sarg[1]; i++)
			   {
			    	chk_addr((const void *) bf_ptr);
			     	bf_ptr++;
			    }
			void *phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) sarg[0]);
	        if (phys_page_ptr == NULL)
	        {
	          exit(-1);
	        }
	        sarg[0] = (int) phys_page_ptr;
			f->eax = create((const char*)sarg[0],
							(unsigned)sarg[1]);
			break;

		case SYS_REMOVE:
			goto next7;
			next7:;

			int st_arg[3];
			int *z;

			for (int i = 0; i < 3; i++){
				z = (int *) f->esp + i + 1;
				chk_addr((const void *) z);
				st_arg[i] = *z;
			}

			char *bf_pt  = (char * )st_arg[0];
			for (unsigned i = 0; i < st_arg[1]; i++)
			   {
			    	chk_addr((const void *) bf_pt);
			     	bf_pt++;
			    }
			void *phys_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) st_arg[0]);
        if (phys_ptr == NULL)
        {
          exit(-1);
        }
        st_arg[0] = (int) phys_ptr;

        f->eax = remove((const char*)st_arg[0]);
        break;

        case SYS_EXEC:
        	goto next8;
			next8:;

			int st_args[3];
			int *a;

			for (int i = 0; i < 3; i++){
				a = (int *) f->esp + i + 1;
				chk_addr((const void *) a);
				st_args[i] = *a;
			}
			void *page_ptr = (void *) pagedir_get_page(thread_current()->pagedir, (const void *) st_args[0]);
        	if (page_ptr == NULL)
        	{
          		exit(-1);
        	}
        	st_args[0] = (int)page_ptr;

        	f->eax = exec((const char *)st_args[0]);
        	break;

        case SYS_OPEN:
        	goto next9;
			next9:;

			int stck_args[3];
			int *b;

			for (int i = 0; i < 3; i++){
				b = (int *) f->esp + i + 1;
				chk_addr((const void *) b);
				stck_args[i] = *b;
			}

			void *page_pt = (void *) pagedir_get_page(thread_current()->pagedir, (const void *) stck_args[0]);
        	if (page_pt == NULL)
        	{
          		exit(-1);
        	}
        	stck_args[0] = (int)page_pt;

        	f->eax = open((const char *)stck_args[0]);
        	break;

        case SYS_SEEK:
        	goto next10;
			next10:;

			int seek_args[3];
			int *s;

			for (int i = 0; i < 3; i++){
				s = (int *) f->esp + i + 1;
				chk_addr((const void *) s);
				seek_args[i] = *s;
			}

			seek(seek_args[0], (unsigned) seek_args[1]);
			break;

		case SYS_TELL:
			goto next11;
			next11:;

			int tell_args[3];
			int *tl;

			for (int i = 0; i < 3; i++){
				tl = (int *) f->esp + i + 1;
				chk_addr((const void *) tl);
				tell_args[i] = *tl;
			}

			f->eax = tell(tell_args[0]);
			break;

		case SYS_CLOSE:
			goto next12;
			next12:;

			int close_args[3];
			int *cl;

			for (int i = 0; i < 3; i++){
				cl = (int *) f->esp + i + 1;
				chk_addr((const void *) cl);
				close_args[i] = *cl;
			}

			close(close_args[0]);
			break;

		case SYS_FILESIZE:
			goto next13;
			next13:;

			int file_args[3];
			int *fl;

			for (int i = 0; i < 3; i++){
				fl = (int *) f->esp + i + 1;
				chk_addr((const void *) fl);
				file_args[i] = *fl;
			}

			f->eax = filesize(file_args[0]);
			break;
		default:
			// printf("Direct exit\n");
			exit(-1);
			break;
		}
	}


void
exit (int status)
{	

	// printf("In EXIT: status is %d \n", status);
	exit_status = status;
	printf("%s: exit(%d)\n", thread_current()->name,exit_status);
	thread_exit(); 
}

void chk_addr(const void *ptr)
{
 	if(ptr == NULL || !is_user_vaddr(ptr)|| pagedir_get_page(thread_current()->pagedir,ptr)==NULL)
		{
		    exit(-1);
		}

}

void seek(int fd, unsigned pos){
	lock_acquire(&file_lock);

	int *file_addr = findFileAdd(fd, 0);
	if(file_addr == NULL){
		return;
	}
	file_seek(file_addr, pos);
	lock_release(&file_lock);
	return;

}

unsigned tell(int fd){
	lock_acquire(&file_lock);

	int *file_addr = findFileAdd(fd, 0);
	if(file_addr == NULL){
		return;
	}
	unsigned pos = (unsigned) file_tell(file_addr);
	lock_release(&file_lock);
	return pos;
}

int findFileAdd(int fd, int type){

	if(list_empty(&thread_current() -> open_files)){
		lock_release(&file_lock);
		return -1;
	}
	for (struct list_elem *temp = list_front(&thread_current()->open_files); temp != NULL; temp = temp->next)
  {
      struct file_desc *t = list_entry (temp, struct file_desc, file_elem);
      if (fd == t->fd)
      {
      	if(type)
      		list_remove(&t->file_elem);
        return t->file_add;
      }
  }
}
static void halt(){
	shutdown_power_off();
}

int open(const char *file){

	lock_acquire(&file_lock);

	struct file *file_struct = filesys_open(file);
	if(file_struct!=NULL){
		struct file_desc *t = malloc(sizeof(struct file_desc));
	  	t->file_add = file_struct;
	  	
	  	int fd = thread_current ()->cfd;
	 	thread_current ()->cfd++;
	  	
	  	t->fd = fd;
	  	
	  	list_push_front(&thread_current ()->open_files, &t->file_elem);
	  	lock_release(&file_lock);
		return fd;
	}
	
		lock_release(&file_lock);
		return -1;
}

int read(int fd, const void *buffer, unsigned size){
	// printf("Called read\n");
	lock_acquire(&file_lock);

	if(fd == 0){
		lock_release(&file_lock);
		return (int) input_getc();
	}
	if(fd == 1 || list_empty(&thread_current() -> open_files)){
		lock_release(&file_lock);
		return 0;
	}

	int file_addr = findFileAdd(fd, 0);
	if(file_addr){
		int bytes = (int) file_read(file_addr, buffer, size);
		lock_release(&file_lock);
		return bytes;
	}
	return -1;
}

int write(int fd, const void *buffer, unsigned size){
	
	lock_acquire(&file_lock);

	if(fd == 1){
		putbuf(buffer, size);
		lock_release(&file_lock);
		return size;
	}
	if(fd == 0 || list_empty(&thread_current() -> open_files)){
		lock_release(&file_lock);
		return 0;
	}

	int file_addr = findFileAdd(fd, 0);
	if(file_addr){
		int bytes = (int) file_write(file_addr, buffer, size);
		lock_release(&file_lock);
		return bytes;
	}

	return 0;
}

int wait(pid_t process_id){
	// printf("Recived id: %d\n",process_id);
	return process_wait(process_id);
}

static pid_t exec(const char *file_name){
	// printf("Recieved %c \n", file_name);
	if(!file_name){
		return -1;
	}
	lock_acquire(&file_lock);
	const pid_t tid = process_execute(file_name);
	lock_release(&file_lock);

	return tid;
}

int filesize(int fd){
	lock_acquire(&file_lock);

	int file_addr = findFileAdd(fd, 0);
	if(file_addr){
		int len = (int)file_length(file_addr);
		lock_release(&file_lock);
		return len;
	}

	lock_release(&file_lock);
	return -1;
}

bool create(const char *file, unsigned size){
	if(file == NULL){
		exit(-1);
	}
	lock_acquire(&file_lock);
	bool status = filesys_create(file, size);
	lock_release(&file_lock);

	return status;
}

bool remove(const char *file){
	lock_acquire(&file_lock);
	bool remove_status = filesys_remove(file);
	lock_release(&file_lock);
	return remove_status;
}

void close(int fd){
	lock_acquire(&file_lock);

	int file_addr = findFileAdd(fd, 1);
	if(file_addr){
		file_close(file_addr);
		lock_release(&file_lock);
		return ;
	}

	lock_release(&file_lock);
	return;
}