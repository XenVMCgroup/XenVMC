/*******************************************************************************
*
*  COPYRIGHT (c) 2007- ELECTRONICS AND TELECOMMUNICATIONS RESEARCH INSTITUTE,
*  P.O. Box 106, YOUSONG, TAEJON, KOREA
*  All rights are reserved, No part of this work covered by the copyright
*  hereon may be reproduced, stored in retrieval systems, in any form or by
*  any means, electronic, mechanical, photocopying, recording or otherwise,
*  without the prior permission of ETRI.
*
*  DATE        : 2007.3.
*
*  This file is maintained by:
*        Kim, Kang-ho   <khk@etri.re.kr>
*        Kim, Chei-yol  <gauri@etri.re.kr>
*        Shin, Hyun-sup <superstarsup@etri.re.kr>
********************************************************************************/

//#define DEBUG

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/in.h>

#include <linux/proc_fs.h>
#include <linux/syscalls.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/semaphore.h>

#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/xway_proto.h>		// xway_tcp_sendmsg, xway_tcp_recvmsg
#include <net/xd.h>				// ring_info, conn_info
#include <net/xd_db.h>

#define procfs_name "xway"
#define PROCFS_MAX_SIZE 1024

#define ADD_IP	(-100)
#define DEL_IP	(-200)

MODULE_LICENSE("Dual BSD/GPL");

extern int xway_enabled; // defined in net/ipv4/af_inet.c
struct proc_dir_entry *xway_proc_file;
static char procfs_buffer[1024];
static unsigned long procfs_buffer_size = 0 ;

extern rwlock_t accept_list_lock;
extern struct list_head accept_list;
extern wait_queue_head_t wait_accept;

// defined at net/ipv4/xway_proto.c
extern int (*xway_setup)(struct sock *sk, unsigned short port);
extern void handler(void *p);

// defined at net/ipv4/xd.c
extern int xd_reg_callback(xp_callback_t callback);

extern rwlock_t xwayip_lock;
extern struct list_head xwayip_list;

static int xwaya_major = 0;
static int xwaya_minor = 0;
static struct cdev xwaya_cdev;
static LIST_HEAD(accept_sock_list);
static DEFINE_SPINLOCK(accept_sock_lock);

static struct workqueue_struct *accept_sock_wq;
static void accept_sock_routine(void *);
static DECLARE_WORK(accept_sock_work, accept_sock_routine, NULL);

static struct semaphore sem;
static int domid;

static int add_xwayip(int ip_addr) {
	struct ip_chain *ic;
	dprintk("adding ip_addr = 0x%x", ip_addr);

	ic = (struct ip_chain*) kmalloc(sizeof(struct ip_chain), GFP_KERNEL);

	if(!ic) {
		ERROR("kmalloc error");
		return -1;
	}

	ic->addr = ip_addr;

	write_lock(&xwayip_lock);
	list_add(&ic->list, &xwayip_list);
	write_unlock(&xwayip_lock);

	return 0;
}

static int del_xwayip(int ip_addr) {
	int done=0;
	struct ip_chain *ic;
	struct list_head *tmp;

	dprintk("deleting ip_addr = 0x%x", ip_addr);

	write_lock(&xwayip_lock);
	list_for_each(tmp, &xwayip_list) {
		ic = list_entry(tmp, struct ip_chain, list);
		if(ic->addr == ip_addr) {
			list_del(&ic->list);
			dprintk("find matching ip : 0x%x", ip_addr);
			done = 1;

			if(ic)
				kfree(ic);

			break;
		}
	}
	write_unlock(&xwayip_lock);

	if(done)
		return 0;
	else
		return -1;	
}

static void free_ipchain() {
	struct ip_chain *ic;
	struct list_head *tmp;

	write_lock(&xwayip_lock);
	list_for_each(tmp, &xwayip_list) {
		ic = list_entry(tmp, struct ip_chain, list);
		list_del(&ic->list);
//		if(ic)
//			kfree(ic);
	}
	write_unlock(&xwayip_lock);
	return;
}


int procfile_read(char *buffer,
	      char **buffer_location,
	      off_t offset, int buffer_length, int *eof, void *data) {
	int ret;

        /* fill the buffer, return the buffer size */
	ret = sprintf(buffer, "%d", xway_enabled);
	*eof = 1;

	return ret;
}

int procfile_write(struct file *file, const char *buffer, unsigned long  count,  void *data)
{
	/* get buffer size */
	procfs_buffer_size = count;

	if (procfs_buffer_size > PROCFS_MAX_SIZE ) {
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}
	
	/* write data to the buffer */
	if ( copy_from_user(procfs_buffer, buffer, procfs_buffer_size))	
	{
		return -EFAULT;
	}

	sscanf(procfs_buffer,"%d",&xway_enabled);
	
	return procfs_buffer_size;
}


static int readn(struct socket *sock, char *ptr, int nbytes)
{
     int nleft, nread;

     nleft = nbytes;
     while (nleft > 0) {
         nread = xway_tcp_recvmsg(sock, ptr, nleft, 0);
         if (nread < 0)
             return nread;
         else if (nread == 0)
             break;   // EOF
         nleft -= nread;
         ptr += nread;
     }
     return (nbytes - nleft);
}

static int writen(struct socket *sock, char *ptr, int nbytes)
{
     int nleft, nwritten;

     nleft = nbytes;
     while (nleft > 0) {
         nwritten = xway_tcp_sendmsg(sock, ptr, nleft);
         if (nwritten <= 0)
             return nwritten;
         nleft -= nwritten;
         ptr += nwritten;
     }

     return (nbytes - nleft);
}

/************************* xway connect  part *************************************/
static int _xway_setup(struct sock *sk, unsigned short port) {
	void   *ptr;
	struct xway_sock *xsock;
	struct sockaddr_in saddr;
	struct socket *sock = NULL;
	struct inet_sock *inet = inet_sk(sk);
	struct conn_info *ci;
	struct ring_info ri;
	int    ret, ack, remoteid;
	struct xwayring *xring=NULL;

	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(4444);
	saddr.sin_addr.s_addr = inet->daddr; 

	ret = sock->ops->connect(sock, (struct sockaddr *) &saddr, 
										sizeof(saddr), O_RDWR);

	ci = (struct conn_info*) kmalloc(sizeof(struct conn_info) + sizeof(int), GFP_KERNEL);
	if(!ci) {
		ERROR("kmalloc() memory space lack error");
		return -1;
	}

	ci->saddr = inet->saddr;
	ci->daddr = inet->daddr;
	ci->sport = inet->sport;
	ci->dport = inet->dport;

	ptr = (void *)ci;
	
	ptr += sizeof(struct conn_info);
	memcpy(ptr, &domid, sizeof(int));

	ret = writen(sock, (char *)ci, sizeof(struct conn_info)+sizeof(int));
	dprintk("1. write ret=%d\n", ret);
	ret = readn(sock, (char *)&remoteid, sizeof(int));
	dprintk("2. read ret=%d\n", ret);


	xring = xd_setup_sendring(sk, remoteid, RING_PAGE, 0, ri.ref, &ri.ev_port);
	if(!xring) {
		printk("xd_setup_sendring error\n");
		sock_release(sock);
		kfree(ci);
		return -1;
	}

	ret = writen(sock, (char *)&ri, sizeof(ri));
	dprintk("3. write ret=%d\n", ret);

	ret = readn(sock, (char *)&ri, sizeof(ri.ref));
	dprintk("4. read ret=%d\n", ret);

	if( xd_setup_recvring(sk, xring, RING_PAGE, ri.ref, 0) < 0)
	{
		printk("xd_setup_recvring error\n");
		sock_release(sock);
		kfree(ci);
		return -1;
	}

	ack = 1;
	ret = writen(sock, (char *)&ack, sizeof(int));
	dprintk("5. write ret=%d\n", ret);

	sock_release(sock);
	xsock = (struct xway_sock *)sk;
	xsock->p_desc = xring;

	kfree(ci);
	return 0;
}
	
static int xwayc_xway_setup(struct sock *sk, unsigned short port) {
	int ret;

	down(&sem);
	ret = _xway_setup(sk, port);
	up(&sem);

	return ret;
}
/*******************************************************************************/

/********************** xway accept part ***************************************/
static void accept_sock_routine(void *data) {
	void *ptr;
	struct xwayring *xring; 
	struct accept_sock *as;
	struct conn_info *remote_ci, ci;
	struct ring_info ri;
	int ref_array[MAX_RING_PAGE];
	int ret, ack=1, *remoteid;

	remote_ci = (struct conn_info *) kmalloc(sizeof(struct conn_info)+sizeof(int), GFP_KERNEL);
	if(!remote_ci) {
		ERROR("kmalloc() memory space lack error");
		return;
	}
	ptr = (void *)remote_ci;
	ptr += sizeof(struct conn_info);
	remoteid = (int *)ptr;

	spin_lock(&accept_sock_lock);
	dprintk("accept_sock_routine called\n");

	while (!list_empty(&accept_sock_list)) {
		as = list_entry(accept_sock_list.next, struct accept_sock, list);
		dprintk("accept_sock_routine: as=0x%X\n", (unsigned int) as);
		list_del_init(&as->list);
		spin_unlock(&accept_sock_lock);

		//=========================================================
		ret = readn(as->s, (char *)remote_ci, sizeof(struct conn_info)+sizeof(int));
		dprintk("%s:%i: 1. sock=0x%x, read=%d\n", __FUNCTION__, 
								__LINE__, (unsigned int)as->s, ret);
		ret = writen(as->s, (char *)&domid, sizeof(int));
		dprintk("%s:%i: 2. sock=0x%x, write=%d\n", __FUNCTION__, 
								__LINE__, (unsigned int)as->s, ret);
		ret = readn(as->s, (char *)&ri, sizeof(ri));
		dprintk("%s:%i: 3. sock=0x%x, read=%d\n", __FUNCTION__, 
								__LINE__, (unsigned int)as->s, ret);
	
		ci.saddr = remote_ci->daddr;
		ci.daddr = remote_ci->saddr;
		ci.sport = remote_ci->dport;
		ci.dport = remote_ci->sport;
		
		xring = xd_setup_sendring(0, *remoteid, RING_PAGE, &ci, ref_array, 0);
		if(!xring) {
			ERROR("xd_setup_sendring()");
			kfree(remote_ci);
			xd_put_failed_xway(&ci);
			return;
		}

		if(xd_setup_recvring(0, xring, RING_PAGE, ri.ref, ri.ev_port)) {
			ERROR("xd_setup_recvring()");
			xd_put_failed_xway(&ci);
			kfree(remote_ci);
			kfree(xring->xring_send);
			kfree(xring);
			return;
		}

		ret = writen(as->s, (char *)ref_array, sizeof(ref_array));
		dprintk("%s:%i: 4. sock=0x%x, write=%d\n", __FUNCTION__, 
								__LINE__, (unsigned int)as->s, ret);

		ret = readn(as->s, (char *)&ack, sizeof(int));
		dprintk("%s:%i: 5. sock=0x%x, read=%d\n", __FUNCTION__, 
								__LINE__, (unsigned int)as->s, ret);

		write_lock(&accept_list_lock);
		list_add(&xring->list, &accept_list);
		write_unlock(&accept_list_lock);

		wake_up_interruptible(&wait_accept);

		dprintk("%s:%i: sock=0x%x, successfuly, we made waiting bind xring(0x%x) !!!\n",
					__FUNCTION__, __LINE__, (unsigned int)as->s, (unsigned int)xring);

		fput(as->f);
		//===========================================================================

		kfree(as);
		spin_lock(&accept_sock_lock);
	}

	kfree(remote_ci);
	spin_unlock(&accept_sock_lock);
}

static int xwaya_open(struct inode *inode, struct file *filp)
{
	dprintk("xwaya_open called\n");

	return 0;
}

static int xwaya_release(struct inode *inode, struct file *filp)
{
    return 0;
}


static ssize_t xwaya_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
	int err;
	unsigned int i=0;
	unsigned int addr[100];
	struct ip_chain *ic;
	struct list_head *tmp;
	
	memset(addr, 0x0, sizeof(int)*100);
	
	read_lock(xwayip_lock);
	list_for_each(tmp, &xwayip_list) {
		ic = list_entry(tmp, struct ip_chain, list);
		i++;
		addr[i] = ic->addr;
		dprintk("addr = 0x%x", addr[i]);
	}
	addr[0] = i;	// total number of the IPs
	dprintk("total num of ip =%d", i);

	if((sizeof(int)*(i+1)) > count)
		err = copy_to_user(buf, addr, count);
	else
		err = copy_to_user(buf, addr, sizeof(int)*(i+1));

	if(err)
		return -EFAULT;

	return ((i+1)*4);
}

static ssize_t xwaya_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
	struct accept_sock *as;
	struct file *filep;
	struct inode *inode;
	int    sock_fd;
	int		cmd_ip[2];
	int    err;

	dprintk("xwaya_write called");
	dprintk("count = %d", count);
	
	if(count != sizeof(int)) {
		err = copy_from_user((char *)cmd_ip, buf, sizeof(int)*2);
		if(err)
			return -EFAULT;

		dprintk("cmd_ip[0] = %d", cmd_ip[0]);
		dprintk("add or del ip addr(0x%x) operations", cmd_ip[1]);

		if(cmd_ip[0] == ADD_IP)
			err = add_xwayip(cmd_ip[1]);
		else if(cmd_ip[0] == DEL_IP)
			err = del_xwayip(cmd_ip[1]);
		else
			return -EFAULT;

		return err;
	}

	err = copy_from_user((char *)&sock_fd, buf, sizeof(int));
	if (err)
		return -EFAULT;

	filep = fget(sock_fd);
	if (!filep)
		return -EINVAL;

	inode = filep->f_dentry->d_inode;
	if (S_ISSOCK(inode->i_mode)) {
		as = (struct accept_sock *) kmalloc(sizeof(struct accept_sock), 
						GFP_KERNEL);
		if (as == NULL) 
			return -ENOMEM;
		dprintk("xwaya_write: as=0x%X\n", (unsigned int)as);
		as->f = filep;
		as->s = SOCKET_I(inode);
	} else {
		fput(filep);
		return -EINVAL;
    }
			
	spin_lock(&accept_sock_lock);
	list_add(&as->list, &accept_sock_list);
	spin_unlock(&accept_sock_lock);

	queue_work(accept_sock_wq, &accept_sock_work);

	return 0;
}


static struct file_operations xwaya_fops = {
    .owner =    THIS_MODULE,
    .read =     xwaya_read,
    .write =    xwaya_write,
    .open =     xwaya_open,
    .release =  xwaya_release,
};

static int xwaya_init(void) {
	int result;
	int err;
	dev_t dev = 0;

	if (xwaya_major) {
		dev = MKDEV(xwaya_major, xwaya_minor);
		result = register_chrdev_region(dev, 1, "xwaya");
	} else {
		result = alloc_chrdev_region(&dev, xwaya_minor, 1, "xwaya");
		xwaya_major = MAJOR(dev);
	}

    cdev_init(&xwaya_cdev, &xwaya_fops);
	xwaya_cdev.owner = THIS_MODULE;
	err = cdev_add(&xwaya_cdev, dev, 1);

	if (err)
		printk(KERN_INFO "Error %d adding xwaya_cdev", err);

	// for accept code
	accept_sock_wq = create_workqueue("accept_sock_wq");

	// for connect code
	init_MUTEX(&sem);
	xway_setup = xwayc_xway_setup;

	// register event channel callback function
	xd_reg_callback(handler);

	domid = (int)HYPERVISOR_get_domid();
	
	// proc file system
	xway_proc_file = create_proc_entry(procfs_name, 0644, NULL);
	
	if (xway_proc_file == NULL) {
		remove_proc_entry(procfs_name, &proc_root);
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
		       procfs_name);
		return -ENOMEM;
	}

	xway_proc_file->read_proc = procfile_read;
	xway_proc_file->write_proc = procfile_write;
	xway_proc_file->owner 	 = THIS_MODULE;
	xway_proc_file->mode 	 = S_IFREG | S_IRUGO | S_IWUSR;
	xway_proc_file->uid 	 = 0;
	xway_proc_file->gid 	 = 0;
	xway_proc_file->size	 = 37;

	dprintk("/proc/%s created", procfs_name);	

	dprintk("xwaya module loaded: xwaya_major=%d, domid=%d\n", 

							xwaya_major, domid);
		struct vm_struct * vm_area;
	vm_area = alloc_vm_area(PAGE_SIZE*4,NULL);
	if(!vm_area) {
		printk("xwaya.c,line 626::alloc_vm_area()");
		return 0;
	}
	dprintk("vm_area=0x%lx", (unsigned long)vm_area->addr);
	return 0;
}

static void xwaya_exit(void) {
	dev_t devno = MKDEV(xwaya_major, 0);

	cdev_del(&xwaya_cdev);
	unregister_chrdev_region(devno, 1);

	cancel_delayed_work(&accept_sock_work);
	flush_workqueue(accept_sock_wq);
	destroy_workqueue(accept_sock_wq);

	xway_setup = NULL;

	// proc file system
	remove_proc_entry(procfs_name, &proc_root);
	free_ipchain();

	dprintk(KERN_INFO "xwaya module unloaded\n");
}

module_init(xwaya_init);
module_exit(xwaya_exit);
