/*
 *  XenVMC -- A High Performance Inter-VM Network Communication Mechanism
 *
 *  Authors:
 *  	Liu Renshi(newcent) - National University of Defense Technology (liurenshi_1989@163.com)
 *  	Ren Yi - National University of Defense Technology
 *  	You Ziqi - National University of Defense Technology
 *
 *  Copyright (C) 2013-2015 Liu Renshi, Ren Yi, You Ziqi
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <asm/cacheflush.h>
#include <asm/paravirt.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>  //include __NR_close,sys_close
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/genhd.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <linux/mm.h>
#include <linux/time.h>
#include <linux/genhd.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/irqflags.h>
#include <linux/inetdevice.h>
#include <linux/file.h>
#include <uapi/linux/in.h>
#include <uapi/linux/socket.h>

#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/protocol.h>
#include <net/dst.h>
#include <net/inet_common.h>
#include <net/neighbour.h>
#include <net/inet6_hashtables.h>
#include <net/tcp.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/page.h>
#include <xen/xen.h>
#include <xen/grant_table.h>
#include <xen/evtchn.h>
#include <xen/xenbus.h>
#include <xen/events.h>

#include "config.h"
#include "debug.h"
#include "xenfifo.h"
#include "maptable.h"
#include "bififo.h"
#include "xenvmc_frontend.h"

#define DEBUG_EVT				1
#define DEBUG_SENDTO			0
#define DEBUG_RECVFROM			0
#define DEBUG_CLOSE				0
#define DEBUG_MSG				0
#define DEBUG_MSG_CREATE		0
#define DEBUG_ACCEPT_CONNECT	0

#if DEBUG_EVTCHN_REPONSE
extern int tcs_response_times;
extern int recv_response_times;
extern int nospace_response_times;
int wait_for_tcs = 0;
int wait_tcs_success = 0;
int wait_for_nospace = 0;
int wait_nospace_susccess = 0;
#endif

typedef void (*sys_call_ptr_t)(void);

static sys_call_ptr_t *syscall_table_preception = NULL;

vm_infor my_infor;
struct net_device *NIC = NULL;

asmlinkage long (*ref_sys_sendto)(int, void __user *, size_t, unsigned, struct sockaddr __user *, int);
asmlinkage long (*ref_sys_recvfrom)(int, void __user *, size_t, unsigned, struct sockaddr __user *, int __user *);
asmlinkage long (*ref_sys_shutdown)(int , int);
asmlinkage long (*ref_sys_close)(int);

#define NET_PERF_TEST_PORT			12865

static struct timer_list *join_timer = NULL;
static int join_retry_count = 0;

static struct timer_list *migrating_timer = NULL;
static int migrating_msg_retry_count = 0;
DECLARE_WAIT_QUEUE_HEAD(migrate_wq);
static u8 pre_migrating = false;

static u8 dom0_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


//event process
static DECLARE_WAIT_QUEUE_HEAD(vmc_event_wq);
static LIST_HEAD(vmc_event_list);
static DEFINE_SPINLOCK(vmc_event_lock);


static DECLARE_WAIT_QUEUE_HEAD(freeze_wait_head);

static void enter_freeze(u32 ip_addr, co_located_vm *vm)
{
	set_bit(WAIT_FOR_VM_CONNECT_OR_DELETE, &vm->vm_flags);
	wait_event_interruptible(freeze_wait_head, ((vm = lookup_vm_by_ip(ip_addr)) == NULL) || vm->status == E_VMC_VM_STATUS_CONNECTED);
}

static void freeze_wake(void)
{
	wake_up(&freeze_wait_head);
}

#define MAC 0xff&msg->mac[i]
#if DEBUG_MSG
void inline debug_msg(message_t *msg)
{
	int i;
	printk("msg type: %d\n", msg->type);
	printk("vm_num:%d\n", msg->vm_num);
	if (msg->vm_num >= 0 && msg->vm_num <= MAX_VM_NUM)
	{
		for (i = 0; i < msg->vm_num; i++)
		{
			printk("domid:%d ip:%x mac:%x:%x:%x:%x:%x:%x\n", msg->domid[i], msg->ip_addr[i], MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
		}
	}
	printk("gref_in:%d gref_out:%d \n", msg->gref_in, msg->gref_out);
	printk("rx:%d tx_ns:%d tx_tsc:%d", msg->remote_rx_evtchn, msg->remote_tx_evtchn_ns, msg->remote_tx_evtchn_tsc);
	printk("src_port:%x peer_port:%x\n", msg->src_port, msg->peer_port);
	printk("snd_nxt:%d\n", msg->snd_nxt);
}
#endif

static void construct_vmc_event(u8 type, domid_t domid, u32	ip_addr, u8 *mac)
{
	vmc_event *evt = kmalloc(sizeof(*evt), GFP_NOIO | __GFP_HIGH);
	evt->type = type;
	evt->infor.domid = domid;
	evt->infor.ip_addr = ip_addr;
	memcpy(evt->infor.mac, mac, ETH_ALEN);
	spin_lock(&vmc_event_lock);
	list_add_tail(&evt->list, &vmc_event_list);
	spin_unlock(&vmc_event_lock);
}

static void respond_for_self_join(void)
{
	construct_vmc_event(E_VMC_EVT_REGISGER, my_infor.domid, my_infor.ip_addr, my_infor.mac);
	wake_up(&vmc_event_wq);
}

static void respond_for_self_migrating(void)
{
	construct_vmc_event(E_VMC_EVT_SELF_PREPARE_TO_MIGRATE, my_infor.domid, my_infor.ip_addr, my_infor.mac);
	wake_up(&vmc_event_wq);
}

void do_pre_migrating(void)
{
	pre_migrating = true;
	respond_for_self_migrating();
	wait_event_interruptible(migrate_wq, is_empty_vm_set());
	pre_migrating = false;
}

void do_post_migrating(void)
{
	respond_for_self_join();
}

static void suspend_resume_handler(struct xenbus_watch *watch, const char **vec, unsigned int len)
{
	char *str;
	static int migrating = false;

	str = (char *)xenbus_read(XBT_NIL, "control", "shutdown", NULL);
	if (IS_ERR(str))
	{
		EPRINTK("ERROR\n");
		return;
	}
	if (strcmp(str, "suspend") == 0)
	{
		migrating = true;
		do_pre_migrating();
	}
	else if (strcmp(str, "") == 0 && migrating)
	{
		migrating = false;
		do_post_migrating();
	}
	kfree(str);
}

static struct xenbus_watch suspend_resume_watch = {
        .node = "control/shutdown",
        .callback = suspend_resume_handler
};

static void re_insert_origin_suspend_watch(void)
{
	struct xenbus_watch *origin_suspend_watch = NULL;
	struct list_head *x;
	static bool first_re_insert = true;

	if (first_re_insert)
	{
		list_for_each(x, &suspend_resume_watch.list)
		{
			origin_suspend_watch = list_entry(x, struct xenbus_watch, list);
			if (origin_suspend_watch && strcmp(origin_suspend_watch->node, "control/shutdown") == 0)
			{
				unregister_xenbus_watch(origin_suspend_watch);
				register_xenbus_watch(origin_suspend_watch);
				first_re_insert = false;
				return;
			}
		}
	}
	else
	{
		list_for_each_prev(x, &suspend_resume_watch.list)
		{
			origin_suspend_watch = list_entry(x, struct xenbus_watch, list);
			if (origin_suspend_watch && strcmp(origin_suspend_watch->node, "control/shutdown") == 0)
			{
				unregister_xenbus_watch(origin_suspend_watch);
				register_xenbus_watch(origin_suspend_watch);
				return;
			}
		}
	}
	DPRINTK("can not find previous shutdown watch!\n");
}

static bool msg_need_extra_para(int type)
{
	if (type == E_VMC_MSG_CHANNEL_CONNECT || (type >= E_VMC_MSG_VMC_TCP_SOCK_CONNECT && type <= E_VMC_MSG_VMC_TCP_SOCK_CLOSE ))
		return true;
	return false;
}

static struct sk_buff *vmc_msg_create(int type, struct net_device *dev, const unsigned char *dest_hw)
{
	struct sk_buff *skb = NULL;
	message_t *msg;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;

	/*
	 *	Allocate a buffer
	 */

	if (msg_need_extra_para(type))
	{
		EPRINTK("error para:%d\n", type);
		goto out;
	}
	skb = alloc_skb(sizeof(message_t) + hlen + tlen, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	msg = (message_t *) skb_put(skb, sizeof(message_t));
	skb->dev = dev;
	skb->protocol = htons(ETH_P_VMC);
	if (dest_hw == NULL)
		dest_hw = dev->broadcast;

	/*
	 *	Fill the device header for the ARP frame
	 */
	if (dev_hard_header(skb, dev, ETH_P_VMC, dest_hw, dev->dev_addr, skb->len) < 0)
		goto out;

	msg->type = type;
	msg->vm_num = 1;
	msg->domid[0] = my_infor.domid;
	msg->ip_addr[0] = my_infor.ip_addr;
	memcpy(msg->mac[0], my_infor.mac, ETH_ALEN);
//	dump(msg, sizeof(message_t));
#if DEBUG_MSG_CREATE
	debug_msg(msg);
#endif
	return skb;

out:
	kfree_skb(skb);
	return NULL;
}

#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
static struct sk_buff *vmc_channel_connect_msg_create(struct net_device *dev,
		const unsigned char *dest_hw, int gref_in, int gref_out, int *remote_rx_evtchn,
		int remote_tx_evtchn_ns, int remote_tx_evtchn_tsc)
#else
static struct sk_buff *vmc_channel_connect_msg_create(struct net_device *dev,
		const unsigned char *dest_hw, int gref_in, int gref_out, int remote_rx_evtchn,
		int remote_tx_evtchn_ns, int remote_tx_evtchn_tsc)
#endif
{
	struct sk_buff *skb;
	message_t *msg;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	int i;
#endif

	/*
	 *	Allocate a buffer
	 */

	skb = alloc_skb(sizeof(message_t) + hlen + tlen, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	msg = (message_t *) skb_put(skb, sizeof(message_t));
	skb->dev = dev;
	skb->protocol = htons(ETH_P_VMC);
	if (dest_hw == NULL)
		dest_hw = dev->broadcast;

	/*
	 *	Fill the device header for the ARP frame
	 */
	if (dev_hard_header(skb, dev, ETH_P_VMC, dest_hw, dev->dev_addr, skb->len) < 0)
		goto out;

	msg->type = E_VMC_MSG_CHANNEL_CONNECT;
	msg->vm_num = 1;
	msg->domid[0] = my_infor.domid;
	msg->ip_addr[0] = my_infor.ip_addr;
	memcpy(msg->mac[0], my_infor.mac, ETH_ALEN);
	//	dump(msg, sizeof(message_t));
	msg->gref_in = gref_in;
	msg->gref_out = gref_out;
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	for (i = 0; i < RX_EVTCHN_NUM; i++)
	{
		msg->remote_rx_evtchn[i] = remote_rx_evtchn[i];
	}
#else
	msg->remote_rx_evtchn = remote_rx_evtchn;
#endif
	msg->remote_tx_evtchn_ns = remote_tx_evtchn_ns;
	msg->remote_tx_evtchn_tsc = remote_tx_evtchn_tsc;
#if DEBUG_MSG_CREATE
	debug_msg(msg);
#endif
	return skb;

out:
	kfree_skb(skb);
	return NULL;
}

static struct sk_buff *vmc_tcp_sock_msg_create(int type, struct net_device *dev,
		const unsigned char *dest_hw, u16 my_port, u16 dst_port, u32 write_seq)
{
	struct sk_buff *skb = NULL;
	message_t *msg;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;

	/*
	 *	Allocate a buffer
	 */

	if (type < E_VMC_MSG_VMC_TCP_SOCK_CONNECT || type > E_VMC_MSG_VMC_TCP_SOCK_CLOSE)
	{
		EPRINTK("error type:%d\n", type);
		goto out;
	}
	skb = alloc_skb(sizeof(message_t) + hlen + tlen, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	skb_reserve(skb, hlen);
	skb_reset_network_header(skb);
	msg = (message_t *) skb_put(skb, sizeof(message_t));
	skb->dev = dev;
	skb->protocol = htons(ETH_P_VMC);
	if (dest_hw == NULL)
		dest_hw = dev->broadcast;

	/*
	 *	Fill the device header for the ARP frame
	 */
	if (dev_hard_header(skb, dev, ETH_P_VMC, dest_hw, dev->dev_addr, skb->len) < 0)
		goto out;

	msg->type = type;
	msg->vm_num = 1;
	msg->domid[0] = my_infor.domid;
	msg->ip_addr[0] = my_infor.ip_addr;
	memcpy(msg->mac[0], my_infor.mac, ETH_ALEN);
	msg->src_port = my_port;
	msg->peer_port = dst_port;
	if (type == E_VMC_MSG_VMC_TCP_SOCK_ACCEPT)
	{
		msg->write_seq = write_seq;
	}
#if DEBUG_MSG_CREATE
	debug_msg(msg);
#endif
	return skb;

out:
	kfree_skb(skb);
	return NULL;
}



inline void  net_send(struct sk_buff * skb, u8 * dest)
{
	struct ethhdr * eth;
	int ret;

	skb->data_len = 0;
	skb_shinfo(skb)->nr_frags 	= 0;
	skb_shinfo(skb)->frag_list 	= NULL;
	skb_put(skb, headers);
	skb->dev 	= NIC;
	eth 		= (struct ethhdr *) skb->data;
	eth->h_proto = htons(ETH_P_VMC);
	memcpy(eth->h_dest, dest, ETH_ALEN);
	memcpy(eth->h_source, NIC->dev_addr, ETH_ALEN);

	if ((skb_shinfo(skb) == NULL))
	{
		WARN_ON(1);
		TRACE_ERROR;
	}
	SKB_LINEAR_ASSERT(skb);
	if ((ret = dev_queue_xmit(skb)))
	{
		EPRINTK("Non-zero return code: %d %s", ret,	skb_shinfo(skb) ? "good" : "bad");
	}
}

void dump(u8 *data, int data_len)
{
	int i;
	for(i = 0; i < data_len; i++)
	{
		if ((i&0xff) == 0)
		{
			printk(KERN_DEBUG "\n");
		}
		printk(KERN_DEBUG "%02x ", data[i]&0xff);
	}
}

#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
void send_channel_connect_msg(int gref_in, int gref_out, int *remote_rx_evtchn, int remote_tx_evtchn_ns, int remote_tx_evtchn_tsc, u8 *dest_mac)
#else
void send_channel_connect_msg(int gref_in, int gref_out, int remote_rx_evtchn, int remote_tx_evtchn_ns, int remote_tx_evtchn_tsc, u8 *dest_mac)
#endif
{
	int ret;
	struct sk_buff *skb = vmc_channel_connect_msg_create(NIC, dest_mac, gref_in, gref_out, remote_rx_evtchn, remote_tx_evtchn_ns, remote_tx_evtchn_tsc);
	BUG_ON(!skb);

	ret = dev_queue_xmit(skb);
	if(ret)
	{
		EPRINTK("xmit error:%d\n", ret);
	}
}

void send_vmc_tcp_connect_msg(u8 *dest_mac, u16 my_port, u16 peer_port)
{
	int ret;
	struct sk_buff *skb = vmc_tcp_sock_msg_create(E_VMC_MSG_VMC_TCP_SOCK_CONNECT, NIC, dest_mac, my_port, peer_port, 0);

	BUG_ON(!skb);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("xmit error:%d!\n", ret);
	}
}

void send_vmc_tcp_accept_msg(u8 *dest_mac, u16 my_port, u16 peer_port, u32	snd_nxt)
{
	int ret;
	struct sk_buff *skb = vmc_tcp_sock_msg_create(E_VMC_MSG_VMC_TCP_SOCK_ACCEPT, NIC, dest_mac, my_port, peer_port, snd_nxt);

	BUG_ON(!skb);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("xmit error:%d!\n", ret);
	}
}

void send_vmc_tcp_close_msg(u8 *dest_mac, u16 my_port, u16 peer_port)
{
	int ret;
	struct sk_buff *skb = vmc_tcp_sock_msg_create(E_VMC_MSG_VMC_TCP_SOCK_CLOSE, NIC, dest_mac, my_port, peer_port, 0);

	BUG_ON(!skb);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("xmit error:%d!\n", ret);
	}
}

void send_channel_accept_msg(u8 *dest_mac)
{
	int ret;
	struct sk_buff *skb = vmc_msg_create(E_VMC_MSG_CHANNEL_ACCEPT, NIC, dest_mac);

	BUG_ON(skb == NULL);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("xmit error:%d\n", ret);
	}
}

void send_channel_release_msg(u8 *dest_mac)
{
	int ret;
	struct sk_buff *skb = vmc_msg_create(E_VMC_MSG_CHANNEL_RELEASE, NIC, dest_mac);

	BUG_ON(skb == NULL);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("xmit error:%d\n", ret);
	}
}

void send_channel_release_ack_msg(u8 *dest_mac)
{
	int ret;
	struct sk_buff *skb = vmc_msg_create(E_VMC_MSG_CHANNEL_RELEASE_ACK, NIC, dest_mac);

	BUG_ON(skb == NULL);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("xmit error:%d\n", ret);
	}
}


void broadcast_register_msg(void)
{
	int ret;
	struct sk_buff *skb = vmc_msg_create(E_VMC_MSG_REGISTER, NIC, NULL);

	BUG_ON(skb == NULL);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("xmit error:%d\n", ret);
	}
}

void send_vm_add_ack(u8 *dest)
{
	int ret;
	struct sk_buff *skb = vmc_msg_create(E_VMC_MSG_VM_ADD_ACK, NIC, dest);

	BUG_ON(skb == NULL);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("xmit error:%d\n", ret);
	}
}

void send_self_migrating_msg(u8 *dest)
{
	int ret;
	struct sk_buff *skb = vmc_msg_create(E_VMC_MSG_DOMU_MIGRATING, NIC, dest);

	BUG_ON(skb == NULL);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("xmit error:%d\n", ret);
	}
}

void send_vm_migrating_ack(u8 *dest)
{
	int ret;
	struct sk_buff *skb = vmc_msg_create(E_VMC_MSG_VM_MIGRATING_ACK, NIC, dest);

	BUG_ON(skb == NULL);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("xmit error:%d\n", ret);
	}
}

void send_vm_delete_ack(u8 *dest)
{
	int ret;
	struct sk_buff *skb = vmc_msg_create(E_VMC_MSG_VM_DELETE_ACK, NIC, dest);

	BUG_ON(skb == NULL);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("xmit error:%d\n", ret);
	}
}

static void register_timeout(ulong nouse_data)
{
	vmc_event *evt = NULL;
	if (join_retry_count < MAX_RETRY_COUNT)
	{
		broadcast_register_msg();
		join_retry_count++;
		mod_timer(join_timer, jiffies + XENSYSCALL_ACK_TIMEOUT * HZ);
	}
	else
	{
		join_retry_count = 0;
		evt = kmalloc(sizeof(*evt), GFP_NOIO | __GFP_HIGH);
		evt->type = E_VMC_EVT_REGISTER_FAILED;
		spin_lock(&vmc_event_lock);
		list_add_tail(&evt->list, &vmc_event_list);
		spin_unlock(&vmc_event_lock);
		wake_up(&vmc_event_wq);
	}
}

static void migrate_timeout(ulong nouse_data)
{
	if (migrating_msg_retry_count < MAX_RETRY_COUNT)
	{
		send_self_migrating_msg(dom0_mac);
		migrating_msg_retry_count++;
		mod_timer(migrating_timer, jiffies + XENSYSCALL_ACK_TIMEOUT*HZ);
	}
	else
	{
		BUG();
	}
}

static domid_t get_my_domid(void)
{
	char *domidstr;
	domid_t domid;

	domidstr = xenbus_read(XBT_NIL, "domid", "", NULL);
	if ( IS_ERR(domidstr) ) {
		return PTR_ERR(domidstr);
	}

	domid = (domid_t) simple_strtoul(domidstr, NULL, 10);
	kfree(domidstr);
	return domid;
}

static u32 get_my_ip_addr(void)
{
	char *net_dev_name = "eth0";
	struct in_device *ip_ptr = NULL;
	struct in_ifaddr *if_addr = NULL;
	struct net_device *net_dev = NULL;

	net_dev = dev_get_by_name(&init_net, net_dev_name);
	if (!net_dev)
	{
		EPRINTK("net device not found!\n");
		return -1;
	}

	rcu_read_lock();
	ip_ptr = rcu_dereference(net_dev->ip_ptr);
	rcu_read_unlock();
	if (!ip_ptr)
	{
		return -1;
	}
	if_addr = ip_ptr->ifa_list;
	if (!ip_ptr)
	{
		return -1;
	}
	return ntohl(if_addr->ifa_address);
}

static void get_my_infor(void)
{
	my_infor.domid = get_my_domid();
	my_infor.ip_addr = get_my_ip_addr();
	memcpy(my_infor.mac, NIC->dev_addr, ETH_ALEN);
}

void register_vmc(void)
{
	memset(dom0_mac, 0xff, sizeof(dom0_mac));
	get_my_infor();
	re_insert_origin_suspend_watch();
	broadcast_register_msg();
	join_timer = kmalloc(sizeof(struct timer_list), GFP_ATOMIC);
	init_timer(join_timer);
	join_timer->function = register_timeout;
	join_timer->expires = jiffies + XENSYSCALL_ACK_TIMEOUT * HZ;
	join_timer->data = 0;
	add_timer(join_timer);
}

static void ack_timeout(ulong data)
{
	co_located_vm *vm = (void *) data;

	BUG_ON(!vm);
	BUG_ON(!vm->listen_flag);
	if (vm->status == E_VMC_VM_STATUS_CONNECTED)
		return;
	BUG_ON(vm->status != E_VMC_VM_STATUS_LISTEN);
	if (vm->retry_count < MAX_RETRY_COUNT)
	{
		send_channel_connect_msg(VM_RX_GREF(vm), VM_TX_GREF(vm), VM_RX_EVT(vm), VM_TX_EVT_NS(vm),
				VM_TX_EVT_TSC(vm), vm->mac);
		vm->retry_count++;
		mod_timer(vm->ack_timer, jiffies + XENSYSCALL_ACK_TIMEOUT * HZ);
	}
	else
	{
		vmc_event *evt = kmalloc(sizeof(*evt), GFP_NOIO | __GFP_HIGH);
		evt->type = E_VMC_EVT_VM_DELETE;
		memcpy(&evt->infor, &vm->infor, sizeof(vm_infor));
		spin_lock(&vmc_event_lock);
		list_add_tail(&evt->list, &vmc_event_list);
		spin_unlock(&vmc_event_lock);
		wake_up(&vmc_event_wq);
	}
}

static int xen_vmc_channel_connect(co_located_vm *vm)
{
	static DEFINE_SPINLOCK(listen_lock);
	unsigned long flag;
	int ret = 0;
#if ENABLE_MULTI_RING_READER
	int i;
#endif

	spin_lock_irqsave(&listen_lock, flag);
	if (vm->status != E_VMC_VM_STATUS_INIT)
	{
		spin_unlock_irqrestore(&listen_lock, flag);
		return 0;
	}
	vm->status = E_VMC_VM_STATUS_LISTEN;
	spin_unlock_irqrestore(&listen_lock, flag);
	ret = bf_create(vm);
	if (ret)
	{
		vm->status = E_VMC_VM_STATUS_INIT;
		EPRINTK("bf_creat failed\n");
		return -1;
	}
	vm->listen_flag = 1;
#if ENABLE_MULTI_RING_READER
	for (i = 0; i < READER_NUM; i++)
	{
		napi_enable(&vm->napi[i]);
	}
#else
	napi_enable(&vm->napi);
#endif
	send_channel_connect_msg(VM_RX_GREF(vm), VM_TX_GREF(vm), VM_RX_EVT(vm), VM_TX_EVT_NS(vm), VM_TX_EVT_TSC(vm), vm->mac);
	vm->ack_timer = kmalloc(sizeof(struct timer_list), GFP_ATOMIC);
	BUG_ON(!vm->ack_timer);
	init_timer(vm->ack_timer);
	vm->ack_timer->function = ack_timeout;
	vm->ack_timer->expires = jiffies + XENSYSCALL_ACK_TIMEOUT * HZ;
	vm->ack_timer->data = (unsigned long) vm;
	add_timer(vm->ack_timer);
	return 0;
}

static int xen_vmc_channel_accept(vmc_event *evt, co_located_vm *vm)
{
	int ret;
#if ENABLE_MULTI_RING_READER
	int i;
#endif

	if (vm->status == E_VMC_VM_STATUS_CONNECTED)
	{
		send_channel_accept_msg(vm->mac);
		return 0;
	}
	if (evt->gref_in <= 0 || evt->gref_out <= 0)
	{
		EPRINTK("gref_in %d gref_out %d \n", evt->gref_in, evt->gref_out);
		goto err;
	}
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	for(i = 0; i < RX_EVTCHN_NUM; i++)
	{
		if (evt->remote_rx_evtchn[i] <= 0)
		{
			EPRINTK("rx_evtchn %d:%d \n", i, evt->remote_rx_evtchn[i]);
			goto err;
		}
	}
#else
	if (evt->remote_rx_evtchn <= 0)
	{
		if (evt->remote_rx_evtchn <= 0)
		{
			EPRINTK("rx_evtchn:%d \n", evt->remote_rx_evtchn);
			goto err;
		}
	}
#endif
	if (evt->remote_tx_evtchn_ns <= 0 || evt->remote_tx_evtchn_tsc <= 0)
	{
		EPRINTK("tx_evtchn_ns:%d tx_evtchn_tsc:%d\n", evt->remote_tx_evtchn_ns, evt->remote_tx_evtchn_tsc);
		goto err;
	}

	ret = bf_connect(vm, evt->gref_out, evt->gref_in, evt->remote_rx_evtchn, evt->remote_tx_evtchn_ns, evt->remote_tx_evtchn_tsc);
	if (ret)
	{
		EPRINTK("bf_connect failed\n");
		goto err;
	}
#if ENABLE_MULTI_RING_READER
	for(i = 0; i < READER_NUM; i++)
	{
		napi_enable(&vm->napi[i]);
	}
#else
	napi_enable(&vm->napi);
#endif
	vm->listen_flag = 0;
	vm->status = E_VMC_VM_STATUS_CONNECTED;
	if (test_bit(WAIT_FOR_VM_CONNECT_OR_DELETE, &vm->vm_flags))
		freeze_wake();
	send_channel_accept_msg(vm->mac);
	return 0;
err:
	TRACE_ERROR;
	return -1;
}

static void set_vmc_sock_peeready(vmc_tcp_sock *vmc_sock)
{
	lock_vmc_sock(vmc_sock);
	vmc_sock->peer_ready = true;
	release_vmc_sock(vmc_sock);
}

static void set_vmc_sock_imready(vmc_tcp_sock *vmc_sock)
{
	lock_vmc_sock(vmc_sock);
	vmc_sock->first_recv = true;
	vmc_sock->im_ready = true;
	release_vmc_sock(vmc_sock);
}

static void update_vmc_sock_status(vmc_tcp_sock *vmc_sock, u8 vmc_sock_status)
{
	vmc_sock->vmc_sock_status = vmc_sock_status;
}

static int xen_vmc_tcp_session_accept(co_located_vm *vm, u16 peer_port, u16 my_port)
{
	vmc_tcp_sock *vmc_sock = NULL;
	struct sock *sk = inet_lookup(dev_net(NIC), &tcp_hashinfo, htonl(vm->infor.ip_addr), htons(peer_port),
			htonl(my_infor.ip_addr), htons(my_port), NIC->ifindex);

	if (sk == NULL || ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_SYN_RECV | TCPF_SYN_SENT | TCPF_LISTEN)))
		return -1;
	vmc_sock = lookup_vmc_tcp_sock_by_port_in_vm(vm, my_port, peer_port);
	if (vmc_sock == NULL)
	{
		vmc_sock = init_vmc_tcp_sock(my_port, peer_port, sk);
		set_vmc_sock_peeready(vmc_sock);
		insert_vmc_tcp_sock_to_vm(vm, vmc_sock);
	}
	else
	{
		set_vmc_sock_peeready(vmc_sock);
	}
	return 0;
}

static vmc_tcp_sock *xen_vmc_tcp_session_connect(co_located_vm *vm, u16 my_port, u16 peer_port)
{
	vmc_tcp_sock *vmc_sock = NULL;
	struct tcp_sock *tp = NULL;
	struct sock *sk = inet_lookup(dev_net(NIC), &tcp_hashinfo, htonl(vm->infor.ip_addr), htons(peer_port),
			htonl(my_infor.ip_addr), htons(my_port), NIC->ifindex);

	if (sk == NULL || ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_SYN_RECV | TCPF_SYN_SENT | TCPF_LISTEN)))
		return NULL;
	BUG_ON(vm->status != E_VMC_VM_STATUS_CONNECTED);
	vmc_sock = lookup_vmc_tcp_sock_by_port_in_vm(vm, my_port, peer_port);
	if (vmc_sock == NULL)
	{
		vmc_sock = init_vmc_tcp_sock(my_port, peer_port, sk);
		set_vmc_sock_imready(vmc_sock);
		insert_vmc_tcp_sock_to_vm(vm, vmc_sock);
	}
	else
	{
		set_vmc_sock_imready(vmc_sock);
	}
	tp = tcp_sk(sk);
	send_vmc_tcp_connect_msg(vm->mac, my_port, peer_port);
	return vmc_sock;
}

static int close_vmc_tcp_sock(vmc_tcp_sock *vmc_sock)
{
	BUG_ON(vmc_sock == NULL);
	lock_vmc_sock(vmc_sock);
	update_vmc_sock_status(vmc_sock, E_VMC_TCP_CONN_CLOSE);
	vmc_sock->sk_shutdown |= RCV_SHUTDOWN;
	release_vmc_sock(vmc_sock);
	if (test_bit(VMC_SOCK_WAITING_FOR_DATA, &vmc_sock->vmc_sock_flags))
	{
		wake_up_interruptible(&vmc_sock->wait_queue);
	}
	return 0;
}

static int is_empty(vmc_tcp_sock *vmc_sock)
{
	return (vmc_sock->head == NULL);
}

static void destroy_vmc_sock(vmc_tcp_sock *vmc_sock, co_located_vm *vm)
{
	receive_buf *buf_read;

	lock_vmc_sock(vmc_sock);
	while(!is_empty(vmc_sock))
	{
		buf_read = vmc_sock->head;
		vmc_sock->head = buf_read->next;
		atomic_sub(buf_read->len, &vm->rx_ring->descriptor->tcp_buf_size);
		if (vm->rx_ring->descriptor->wait_for_peer)
		{
			tell_remote_to_wakeup_xmit_tsc(vm);
		}
		kfree(buf_read);
		if (vmc_sock->head == NULL)
		{
			vmc_sock->tail = NULL;
		}
	}
	release_vmc_sock(vmc_sock);
	kfree(vmc_sock);
}


static int remove_vmc_tcp_sock(co_located_vm *vm, vmc_tcp_sock *vmc_sock)
{
	close_vmc_tcp_sock(vmc_sock);
	write_lock_irq(&vm->lock);
	list_del(&vmc_sock->vm_list);
	write_unlock_irq(&vm->lock);
	destroy_vmc_sock(vmc_sock, vm);
	return 0;
}

static int xen_vmc_tcp_close(co_located_vm *vm, u16 peer_port, u16 my_port)
{
	vmc_tcp_sock *vmc_sock = NULL;

	vmc_sock = lookup_vmc_tcp_sock_by_port_in_vm(vm, my_port, peer_port);
	if (vmc_sock == NULL)
	{
		pr_warn("vmc_sock not exist!port:%d peer_port:%d", my_port, peer_port);
	}
	else
	{
		lock_vmc_sock(vmc_sock);
		update_vmc_sock_status(vmc_sock, E_VMC_TCP_CONN_CLOSE);
		vmc_sock->sk_shutdown |= RCV_SHUTDOWN;
		release_vmc_sock(vmc_sock);
		if (test_bit(VMC_SOCK_WAITING_FOR_DATA, &vmc_sock->vmc_sock_flags))
		{
			wake_up_interruptible(&vmc_sock->wait_queue);
		}
	}
	return 0;
}

static void wait_for_all_vmc_tcp_sock_empty_and_remove(co_located_vm *vm)
{
	struct list_head *x, *y;
	vmc_tcp_sock *vmc_sock;
	int i;

	for (i = 0; i < VMC_TCP_SOCK_HASH_SIZE; i++)
	{
		list_for_each_safe(x, y, &vm->vmc_tcp_sock[i])
		{
			vmc_sock = list_entry(x, vmc_tcp_sock, vm_list);
			set_bit(VMC_SOCK_WAITING_FOR_EMPTY, &vmc_sock->vmc_sock_flags);
			wait_event_interruptible(vmc_sock->wait_queue, is_empty(vmc_sock));
			clear_bit(VMC_SOCK_WAITING_FOR_EMPTY, &vmc_sock->vmc_sock_flags);
			if (test_bit(VMC_SOCK_WAITING_FOR_DATA, &vmc_sock->vmc_sock_flags))
			{
				close_vmc_tcp_sock(vmc_sock);
				set_bit(WAIT_FOR_VMC_TCP_SOCK_REMOVED, &vm->vm_flags);
				wait_event_interruptible(vm->wait_queue, list_empty(&vm->vmc_tcp_sock[i]));
				clear_bit(WAIT_FOR_VMC_TCP_SOCK_REMOVED, &vm->vm_flags);
			}
			else
			{
				remove_vmc_tcp_sock(vm, vmc_sock);
			}
		}
	}
}

static void debug_evt(vmc_event *evt)
{
#if	DEBUG_EVT
#define EVT_MAC  0xff&evt->infor.mac
	printk("evt type:%d\n", evt->type);
	printk("vm: domid:%d ip:%x mac:%x:%x:%x:%x:%x:%x\n", evt->infor.domid, evt->infor.ip_addr, EVT_MAC[0], EVT_MAC[1], EVT_MAC[2], EVT_MAC[3], EVT_MAC[4], EVT_MAC[5]);
	printk("gref_in:%d gref_out:%d\n", evt->gref_in, evt->gref_out);
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	{
		int i;
		for(i = 0; i < RX_EVTCHN_NUM; i++)
		{
			printk("rx_evtchn_%d:%d\n", i, evt->remote_rx_evtchn[i]);
		}
	}
#else
	printk("rx_evtchn:%d\n", evt->remote_rx_evtchn);
#endif

	printk("tx_ns:%d tx_tsc:%d\n", evt->remote_tx_evtchn_ns, evt->remote_tx_evtchn_tsc);
	printk("src_port:%x peer_port:%x\n", evt->src_port, evt->peer_port);
	printk("write_seq:%d\n", evt->write_seq);
#endif
}

static int kthread_vmc_event_process(void *noused)
{
	struct list_head *ent;
	vmc_event *event;
	co_located_vm * vm;
	bool need_wake_up_send = false;
	bool need_send_release_ack = false;
	u8 mac[ETH_ALEN];

	for(;;)
	{
		wait_event_interruptible(vmc_event_wq, !list_empty(&vmc_event_list) || kthread_should_stop());

		if(kthread_should_stop())
			break;

		ent = vmc_event_list.next;
		spin_lock_irq(&vmc_event_lock);
		if (ent != &vmc_event_list)
		{
			list_del(ent);
		}
		spin_unlock_irq(&vmc_event_lock);

		if (ent != &vmc_event_list)
		{
			event = list_entry(ent, vmc_event, list);
			debug_evt(event);
			switch(event->type)
			{
			case E_VMC_EVT_REGISGER:
				register_vmc();
				break;
			case E_VMC_EVT_REGISTER_FAILED:
				if (join_timer)
				{
					del_timer_sync(join_timer);
					join_timer = NULL;
				}
				EPRINTK("Join failed!Please check dom0 backend module!\n");
				break;
			case E_VMC_EVT_VM_ADD:
				WARN_ON(lookup_vm_by_ip(event->infor.ip_addr));
				vm = insert_vm_to_table(event->infor.ip_addr, event->infor.domid, event->infor.mac);
				BUG_ON(vm == NULL);
				BUG_ON(!(vm = lookup_vm_by_ip(event->infor.ip_addr)));
				EPRINTK("add vm:domid %d ip:%x\n", vm->infor.domid, vm->infor.ip_addr);
				if(vm->infor.domid > my_infor.domid)
				{
					xen_vmc_channel_connect(vm);
				}
				break;
			case E_VMC_EVT_VM_DELETE:
				vm = lookup_vm_by_ip(event->infor.ip_addr);
				BUG_ON(vm == NULL);
				need_wake_up_send = need_wake_send_remove_vm(vm);
				if (need_wake_up_send)
				{
					freeze_wake();
				}
				break;
			case E_VMC_EVT_VM_MIGRATING:
				if (my_infor.domid == event->infor.domid)
				{
					DPRINTK("slef migrate!\n");
					break;
				}
				vm = lookup_vm_by_ip(event->infor.ip_addr);
				BUG_ON(vm == NULL);
				update_vm_status(vm, E_VMC_VM_STATUS_SUSPEND);
				tell_remote_to_receive(vm);
				//wating for channel empty
				set_bit(WAIT_FOR_RX_CHANNEL_EMPTY, &vm->vm_flags);
				wait_event_interruptible(vm->wait_queue, xf_empty(vm->rx_ring));
				clear_bit(WAIT_FOR_RX_CHANNEL_EMPTY, &vm->vm_flags);
				//wating for vmc_tcp_sock empty and removed
				wait_for_all_vmc_tcp_sock_empty_and_remove(vm);
				send_channel_release_msg(event->infor.mac);

				//if listen_flag ,should wait for peer vm release share-mem channel firstly
				if (!vm->listen_flag)
				{
					EPRINTK("release channel!\n");
					need_wake_send_remove_vm(vm);
				}
				break;
			case E_VMC_EVT_CHANNEL_RELEASE_ACK:
				vm = lookup_vm_by_ip(event->infor.ip_addr);
				BUG_ON(vm == NULL);
				BUG_ON(vm->listen_flag == 0);
				DPRINTK("release channel!\n");
//				need_wake_up_send = need_wake_send_remove_vm(vm);
				need_wake_send_remove_vm(vm);
//				if (need_wake_up_send)
//				{
//					freeze_send_wake();
//				}
				if (is_empty_vm_set() && pre_migrating)
				{
					wake_up(&migrate_wq);
				}
				break;
			case E_VMC_EVT_SELF_PREPARE_TO_MIGRATE:
				if (*(int64_t*)(dom0_mac) != 0xffffffffffff)
					send_self_migrating_msg(dom0_mac);
				//mark all vm suspended!
				mark_all_vm_suspend();
				break;

//channel and vmc_tcp_sock
			case E_VMC_EVT_CHANNEL_CONNECT:
				vm = lookup_vm_by_ip(event->infor.ip_addr);
				BUG_ON(vm == NULL);
				xen_vmc_channel_accept(event, vm);
				break;
			case E_VMC_EVT_CHANNEL_ACCEPT:
				vm = lookup_vm_by_ip(event->infor.ip_addr);
				BUG_ON(vm == NULL);
				if (vm->ack_timer)
				{
					del_timer_sync(vm->ack_timer);
					vm->ack_timer = NULL;
				}
				update_vm_status(vm, E_VMC_VM_STATUS_CONNECTED);
				if (test_bit(WAIT_FOR_VM_CONNECT_OR_DELETE, &vm->vm_flags))
					freeze_wake();
				break;
			case E_VMC_EVT_CHANNEL_RELEASE:
				vm = lookup_vm_by_ip(event->infor.ip_addr);
				BUG_ON(vm == NULL);
				BUG_ON(vm->status != E_VMC_VM_STATUS_SUSPEND);
				//wating for channel empty
				set_bit(WAIT_FOR_RX_CHANNEL_EMPTY, &vm->vm_flags);
				wait_event_interruptible(vm->wait_queue, xf_empty(vm->rx_ring));
				clear_bit(WAIT_FOR_RX_CHANNEL_EMPTY, &vm->vm_flags);
				//wating for vmc_tcp_sock empty and removed
				wait_for_all_vmc_tcp_sock_empty_and_remove(vm);
				if (!vm->listen_flag)
				{
					need_send_release_ack = true;
					memcpy(mac, vm->infor.mac, ETH_ALEN);
				}
				else
				{
					need_send_release_ack = false;
				}
				need_wake_send_remove_vm(vm);
				if (need_send_release_ack)
				{
					send_channel_release_ack_msg(mac);
				}
				if (is_empty_vm_set() && pre_migrating)
				{
					wake_up(&migrate_wq);
				}
				break;
			case E_VMC_EVT_VMC_TCP_SOCK_CONNECT:
				vm = lookup_vm_by_ip(event->infor.ip_addr);
				xen_vmc_tcp_session_accept(vm, event->src_port, event->peer_port);
				break;
			case E_VMC_EVT_VMC_TCP_SOCK_ACCEPT:
				vm = lookup_vm_by_ip(event->infor.ip_addr);
				BUG_ON(vm == NULL);
				{
					vmc_tcp_sock *vmc_sock = lookup_vmc_tcp_sock_by_port_in_vm(vm, event->peer_port, event->src_port);
					BUG_ON(vmc_sock == NULL);
					vmc_sock->peer_accept = true;
					vmc_sock->peer_write_seq = event->write_seq;
					if (test_bit(VMC_SOCK_WAITING_FOR_PEER_ACCEPT, &vmc_sock->vmc_sock_flags))
					{
						wake_up_interruptible(&vmc_sock->wait_queue);
					}
				}
				break;
			case E_VMC_EVT_VMC_TCP_SOCK_SHUTDOWN:
				vm = lookup_vm_by_ip(event->infor.ip_addr);
				BUG_ON(vm == NULL);
				xen_vmc_tcp_close(vm, event->src_port, event->peer_port);
				break;
			}
			kfree(event);
		}
	}
	return 0;
}

static void construct_vmc_tcp_sock_event(u8 type, u32 ip_addr, u16 src_port,
		u16 peer_port)
{
	vmc_event *evt = kmalloc(sizeof(*evt), GFP_NOIO | __GFP_HIGH);
	evt->type = type;
	evt->infor.ip_addr = ip_addr;
	evt->src_port = src_port;
	evt->peer_port = peer_port;
	spin_lock(&vmc_event_lock);
	list_add_tail(&evt->list, &vmc_event_list);
	spin_unlock(&vmc_event_lock);
}

static void construct_vmc_tcp_sock_accept_event(u8 type, u32 ip_addr, u16 src_port,
		u16 peer_port, u32 write_seq)
{
	vmc_event *evt = kmalloc(sizeof(*evt), GFP_NOIO | __GFP_HIGH);
	evt->type = type;
	evt->infor.ip_addr = ip_addr;
	evt->src_port = src_port;
	evt->peer_port = peer_port;
	evt->write_seq = write_seq;
	spin_lock(&vmc_event_lock);
	list_add_tail(&evt->list, &vmc_event_list);
	spin_unlock(&vmc_event_lock);
}

int session_recv(struct sk_buff * skb, struct net_device * dev, struct packet_type * pt, struct net_device * d)
{
	int ret = NET_RX_SUCCESS;
	message_t * msg = NULL;
	vmc_event *evt;
	int i = 0;

	BUG_ON(!skb);
	msg = (message_t *)skb->data;
	BUG_ON(!msg);
	skb_linearize(skb);
#if DEBUG_MSG
	debug_msg(msg);
#endif
	switch(msg->type) {
		case E_VMC_MSG_REGISTER_ACK:
			if (*(int64_t*)(dom0_mac) != 0xffffffffffff)//this means this domu have joined vmc co-located vms set
			{
				break;
			}
			if (join_timer)
			{
				del_timer_sync(join_timer);
				join_timer = NULL;
			}
			memcpy(dom0_mac, eth_hdr(skb)->h_source, ETH_ALEN);
			BUG_ON(msg->vm_num > MAX_VM_NUM);
			DPRINTK("register successfully!\n");
			for(i = 0; i < msg->vm_num; i++)
			{
				if (msg->domid[i] != my_infor.domid)
					construct_vmc_event(E_VMC_EVT_VM_ADD, msg->domid[i], msg->ip_addr[i], msg->mac[i]);
			}
			wake_up(&vmc_event_wq);
			break;
		case E_VMC_MSG_VM_ADD:
		case E_VMC_MSG_VM_DELETE:
		case E_VMC_MSG_VM_MIGRATING:
			if (memcmp(dom0_mac, eth_hdr(skb)->h_source, ETH_ALEN) != 0)
			{
				WARN(1, "Not send to me!\n");
				break;
			}
			if (msg->domid[0] != my_infor.domid)
			{
				construct_vmc_event(((msg->type - E_VMC_MSG_VM_ADD) + E_VMC_EVT_VM_ADD), msg->domid[0], msg->ip_addr[0], msg->mac[0]);
				wake_up(&vmc_event_wq);
			}
			break;
		case E_VMC_MSG_CHANNEL_CONNECT:
			evt = kmalloc(sizeof(*evt), GFP_NOIO | __GFP_HIGH);
			evt->type = E_VMC_EVT_CHANNEL_CONNECT;
			evt->infor.domid = msg->domid[0];
			evt->infor.ip_addr = msg->ip_addr[0];
			memcpy(evt->infor.mac, msg->mac[0], ETH_ALEN);
			evt->gref_in = msg->gref_in;
			evt->gref_out = msg->gref_out;
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
			for (i = 0; i < RX_EVTCHN_NUM; i++)
			{
				evt->remote_rx_evtchn[i] = msg->remote_rx_evtchn[i];
			}
#else
			evt->remote_rx_evtchn = msg->remote_rx_evtchn;
#endif
			evt->remote_tx_evtchn_ns = msg->remote_tx_evtchn_ns;
			evt->remote_tx_evtchn_tsc = msg->remote_tx_evtchn_tsc;
			spin_lock(&vmc_event_lock);
			list_add_tail(&evt->list, &vmc_event_list);
			spin_unlock(&vmc_event_lock);
			wake_up(&vmc_event_wq);
			break;
		case E_VMC_MSG_CHANNEL_ACCEPT:
		case E_VMC_MSG_CHANNEL_RELEASE:
		case E_VMC_MSG_CHANNEL_RELEASE_ACK:
			construct_vmc_event((E_VMC_EVT_CHANNEL_ACCEPT + (msg->type - E_VMC_MSG_CHANNEL_ACCEPT)), msg->domid[0], msg->ip_addr[0], msg->mac[0]);
			wake_up(&vmc_event_wq);
			break;
		case E_VMC_MSG_VMC_TCP_SOCK_CONNECT:
			construct_vmc_tcp_sock_event(E_VMC_EVT_VMC_TCP_SOCK_CONNECT, msg->ip_addr[0], msg->src_port, msg->peer_port);
			wake_up(&vmc_event_wq);
			break;
		case E_VMC_MSG_VMC_TCP_SOCK_ACCEPT:
			construct_vmc_tcp_sock_accept_event(E_VMC_EVT_VMC_TCP_SOCK_ACCEPT, msg->ip_addr[0], msg->src_port, msg->peer_port, msg->write_seq);
			wake_up(&vmc_event_wq);
			break;
		case E_VMC_MSG_VMC_TCP_SOCK_CLOSE:
			construct_vmc_tcp_sock_event(E_VMC_EVT_VMC_TCP_SOCK_SHUTDOWN, msg->ip_addr[0], msg->src_port, msg->peer_port);
			wake_up(&vmc_event_wq);
			break;
	}
	kfree_skb(skb);
	return ret;
}

static struct packet_type xensyscall_ptype = {
	.type		= __constant_htons(ETH_P_VMC),
	.func 		= session_recv,
	.dev 		= NULL,
	.af_packet_priv = NULL,
};

static int xmit_large_pkt(struct iovec *iov, XMIT_TYPE type, u_short src_port, u_short dst_port, co_located_vm *vm)
{
	bf_data_t *mdata;
	bool success = false;
	char *pback, *pfront, *pfifo, *pend;
	int ret;
	xf_handle_t *xfh = vm->tx_ring;
	xf_descriptor_t *des = xfh->descriptor;


	BUG_ON(!iov);
	BUG_ON(!xfh);
	BUG_ON(!des);
	do{
#if DEBUG_SENDTO
		DPRINTK("front:%x back:%x ring_size:%x index_mask:%x len:%d\n", des->front, des->back, des->ring_size, des->index_mask, iov->iov_len);
#endif
#if ENABLE_TWO_STAGE_RDWR
		BUG_ON(before(des->back, des->front_w));
#else
		BUG_ON(before(des->back, des->front));
#endif
		spin_lock(&des->tail_lock);
		if (iov->iov_len + sizeof(bf_data_t) > xf_free(xfh))
		{
#if DEBUG_EVTCHN_REPONSE
			wait_for_nospace++;
#endif
			set_bit(WAIT_FOR_SPACE, &vm->vm_flags);
			vm->need_space_size = iov->iov_len + sizeof(bf_data_t);
			des->wait_for_space = true;
			spin_unlock(&des->tail_lock);
			tell_remote_to_receive(vm);
			wait_event_interruptible(vm->wait_queue, (iov->iov_len + sizeof(bf_data_t) <= xf_free(xfh)));
			if (signal_pending(current))
			{
				EPRINTK("signal pending!\n");
				return -EINTR;
			}
#if DEBUG_EVTCHN_REPONSE
			wait_nospace_susccess++;
#endif
			des->wait_for_space = false;
			clear_bit(WAIT_FOR_SPACE, &vm->vm_flags);
			continue;
		}
		if (type == XMIT_TCP && (VM_TX_TCP_BUF_SIZE(vm) >= DEFAULT_MAX_TCP_BUF_SIZE))
		{
#if DEBUG_EVTCHN_REPONSE
			wait_for_tcs++;
#endif
			set_bit(WAIT_FOR_PEER, &vm->vm_flags);
			des->wait_for_peer = true;
			spin_unlock(&des->tail_lock);
			wait_event_interruptible(vm->wait_queue, (VM_TX_TCP_BUF_SIZE(vm) < (DEFAULT_MAX_TCP_BUF_SIZE - TCP_TX_WIN_SIZE) ));
			if (signal_pending(current))
			{
				EPRINTK("signal pending");
				return -EINTR;
			}
#if DEBUG_EVTCHN_REPONSE
			wait_tcs_success++;
#endif
			des->wait_for_peer = false;
			clear_bit(WAIT_FOR_PEER, &vm->vm_flags);
			continue;
		}
		pfifo = (char *) xfh->fifo;

		mdata = (bf_data_t *)&pfifo[des->back&des->index_mask];
		BUG_ON(!mdata);
		mdata->type = type;
		mdata->src_port = src_port;
		mdata->dst_port = dst_port;
		mdata->pkt_len = iov->iov_len;
		ret = mdata->pkt_len;

		pfront = &pfifo[(des->back + (1 << MDATA_ORDER)) & des->index_mask];
		pback = &pfifo[(des->back + ((1 + (mdata->pkt_len>>MDATA_ORDER) + !!(iov->iov_len & MDATA_SHIFT))<<MDATA_ORDER))&des->index_mask];
		pend = &pfifo[des->ring_size];

#if ENABLE_TWO_STAGE_RDWR
		mdata->complete = false;
		des->back += (1 + (mdata->pkt_len>>MDATA_ORDER) + !!(mdata->pkt_len & MDATA_SHIFT)) << MDATA_ORDER;
		spin_unlock(&des->tail_lock);
#endif

		BUG_ON(!pfifo);
		BUG_ON(!pfront);
		BUG_ON(!pback);

#if ENABLE_TWO_STAGE_RDWR
#if ENABLE_AREA_LOCK
		writer_area_lock(des, des->back);
#endif
#endif

		if (pfront <= pback || pback == pfifo)
		{
			BUG_ON(memcpy_fromiovec(pfront, iov, iov->iov_len));
		}
		else
		{
			BUG_ON(memcpy_fromiovec(pfront, iov, pend - pfront));
			BUG_ON(memcpy_fromiovec(pfifo, iov, iov->iov_len));
		}
		success = true;
#if ENABLE_TWO_STAGE_RDWR
		mdata->complete = true;
#else
		des->back += (1 + (mdata->pkt_len>>MDATA_ORDER) + !!(mdata->pkt_len & MDATA_SHIFT)) << MDATA_ORDER;
		spin_unlock(&des->tail_lock);
#endif
	}while (!success);

	return ret;
}

inline int xmit_packets(struct iovec *iov, XMIT_TYPE type, __be16 src_port, __be16 dst_port,
		co_located_vm *vm)
{
	int ret = 0;

	BUG_ON( in_irq() );

	ret = xmit_large_pkt(iov, type, src_port, dst_port, vm);

	if (ret > 0)
		tell_remote_to_receive(vm);
	return ret;
}

int net_init(void)
{
	int ret = 0, i;
	char nic[5];

	for ( i=0; i<5; i++) {
		sprintf(nic, "eth%d", i);
		NIC = dev_get_by_name(&init_net, nic);
		if(NIC) break;
	}
	if(!NIC) {
		EPRINTK("Could not find network card %s\n", nic);
		ret = -ENODEV;
		goto out;
	}

	dev_add_pack(&xensyscall_ptype);
out:
	return ret;
}

void net_exit(void)
{
	dev_remove_pack(&xensyscall_ptype);
	if(NIC) dev_put(NIC);
}

//added by newcent@Jun 26, 2014
//just for remove the warning when compile this module
static void xenvmc_unregister(void) {
	unregister_xenbus_watch(&suspend_resume_watch);
	net_exit();
	destroy_hash_table();
#if DEBUG_EVTCHN_REPONSE
	DPRINTK("tcs_response_times:%d recv_response_times:%d nospace_response_times:%d\n", tcs_response_times, recv_response_times, nospace_response_times);
	DPRINTK("wait_for_tcs:%d wait_tcs_success:%d wait_for_nospace:%d wait_nospace_susccess:%d\n", wait_for_tcs, wait_tcs_success, wait_for_nospace, wait_nospace_susccess);
#endif
}

static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct file *file;
	struct socket *sock;

	*err = -EBADF;
	file = fget_light(fd, fput_needed);
	if (file) {
		sock = sock_from_file(file, err);
		if (sock)
			return sock;
		fput_light(file, *fput_needed);
	}
	return NULL;
}

int get_sock_info(struct socket *sock, short *type, uint32_t *dst_addr, uint16_t *peer_port, uint16_t *my_port)
{
	struct inet_sock *inet = NULL;
	struct sock *sk = sock->sk;

	if (sock->ops->family != AF_INET)
	{
		return -1;
	}
	*type = sock->type;
	inet = inet_sk(sk);
	*dst_addr = ntohl(inet->inet_daddr);
	*peer_port = ntohs(inet->inet_dport);
	*my_port = ntohs(inet->inet_sport);
	return 0;
}

short get_sock_type_by_fd(int sockfd)
{
	struct socket *sock;
	int err;

	sock = sockfd_lookup(sockfd, &err);
	if (!sock)
	{
		return -1;
	}
	if(sock->ops->family != AF_INET)
	{
		return -1;
	}
	return sock->type;
}

struct sock *get_sk_by_sockfd(int sockfd)
{
	struct socket *sock;
	struct sock *sk;
	int err;

	sock = sockfd_lookup(sockfd, &err);
	if (!sock) {
		return NULL;
	}

	if (sock->ops->family != PF_INET) {
		return NULL;
	}

	if (sock->type != SOCK_STREAM && sock->type != SOCK_DGRAM) {
		return NULL;
	}
	sk = sock->sk;
	return sk;
}

int get_peer_ip_port_by_sockfd(int sockfd, u32 *dst_addr, u16 *peer_port, u16 *my_port)
{
	struct sock *sk = NULL;
	struct inet_sock *inet;

	if (!dst_addr || !peer_port || !my_port)
	{
		DPRINTK("parameter error!\n");
		return -1;
	}
	sk = get_sk_by_sockfd(sockfd);
	if (!sk)
	{
		DPRINTK("Can not get sk by socket fd!\n");
		return -1;
	}
	inet = inet_sk(sk);
	*dst_addr = ntohl(inet->inet_daddr);
	*peer_port = ntohs(inet->inet_dport);
	*my_port = ntohs(inet->inet_sport);
	return 0;
}

asmlinkage long new_sys_sendto(int fd, void __user *buff, size_t len, unsigned int flags,
		struct sockaddr __user *addr, int addrlen)
{
	co_located_vm *vm;
	struct iovec iov;
	uint16_t type;
	u32 ip_addr;
	struct socket *sk = NULL;
	vmc_tcp_sock *vmc_sock = NULL;
	u16 my_port = -1, peer_port = -1;
	int err, fput_needed;

	sk = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sk)
		goto send_traditionally;
	get_sock_info(sk, &type, &ip_addr, &peer_port, &my_port);
	if (type != SOCK_STREAM && type != SOCK_DGRAM)
	{
		goto put_fd;
	}
	if (peer_port == NET_PERF_TEST_PORT || my_port == NET_PERF_TEST_PORT)
	{
		goto put_fd;
	}
	if (type == SOCK_DGRAM && addr != NULL)
	{
		ip_addr = ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr);
		peer_port = ntohs(((struct sockaddr_in *)addr)->sin_port);
	}
	vm = lookup_vm_by_ip(ip_addr);
	if (vm == NULL)
	{
#if DEBUG_SENDTO
		DPRINTK("vm NULL!\n");
#endif
		goto put_fd;
	}
	if (vm->status == E_VMC_VM_STATUS_CONNECTED)
	{
		iov.iov_base = buff;
		iov.iov_len = len;
		if (type == SOCK_DGRAM)
		{
			err = xmit_packets(&iov, XMIT_UDP, my_port, peer_port, vm);
			fput_light(sk->file, fput_needed);
			return err;
		}
		else
		{
			vmc_sock = lookup_vmc_tcp_sock_by_port_in_vm(vm, my_port, peer_port);
			if (vmc_sock == NULL || !vmc_sock->peer_ready)
			{
#if DEBUG_SENDTO
				DPRINTK("vmc_sock NULL or peer not ready!\n");
#endif
				goto put_fd;
			}
			BUG_ON(!vmc_sock->peer_ready);
			if (!vmc_sock->sent_write_seq)
			{
				//xmit data in socket sent but not recved
				struct tcp_sock *tp = tcp_sk(vmc_sock->refer_sock);
				BUG_ON(tp == NULL);
#if DEBUG_SENDTO
				DPRINTK("send accept msg[myport:%x peer_port:%x write_seq:%d]\n", my_port, peer_port, tp->write_seq);
#endif
				send_vmc_tcp_accept_msg(vm->mac, my_port, peer_port, tp->write_seq);
				vmc_sock->sent_write_seq = true;
			}
			err = xmit_packets(&iov, XMIT_TCP, my_port, peer_port, vm);
			fput_light(sk->file, fput_needed);
			return err;
		}
	}
put_fd:
	fput_light(sk->file, fput_needed);
send_traditionally:
	return ref_sys_sendto(fd, buff, len, flags, addr, addrlen);
}

asmlinkage long new_sys_shutdown(int fd, int how)
{
	int err, fput_needed;
	co_located_vm *vm = NULL;
	vmc_tcp_sock *vmc_sock = NULL;
	struct socket *sock = NULL;
	uint16_t type;
	u32 ip_addr;
	u16 my_port = -1, peer_port = -1;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		return ref_sys_close(fd);
	get_sock_info(sock, &type, &ip_addr, &peer_port, &my_port);
	if (type == SOCK_STREAM)
	{
		vm = lookup_vm_by_ip(ip_addr);
		if (vm != NULL)
		{
			vmc_sock = lookup_vmc_tcp_sock_by_port_in_vm(vm, my_port, peer_port);
			if (vmc_sock != NULL)
			{
				int how_2 = how + 1;// in inet_shutdown, it will
				if (!((how_2 & ~SHUTDOWN_MASK) || !how_2)) /* MAXINT->0 */
				{
					lock_vmc_sock(vmc_sock);
					vmc_sock->sk_shutdown |= how_2;
					release_vmc_sock(vmc_sock);
					send_vmc_tcp_close_msg(vm->mac, my_port, peer_port);
				}
			}
		}
	}
	fput_light(sock->file, fput_needed);
	return ref_sys_shutdown(fd, how);
}

asmlinkage long new_sys_close(int fd)
{
	int err = 0, fput_needed;
	struct socket *sock = NULL;
	co_located_vm *vm = NULL;
	vmc_tcp_sock *vmc_sock = NULL;
	uint16_t type;
	u32 ip_addr = 0;
	u16 my_port = -1, peer_port = -1;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		return ref_sys_close(fd);
	get_sock_info(sock, &type, &ip_addr, &peer_port, &my_port);
	if (type == SOCK_STREAM)
	{
		vm = lookup_vm_by_ip(ip_addr);
#if DEBUG_CLOSE
		DPRINTK("ip_addr:%x peer_port:%d my_port:%d\n", ip_addr, peer_port, my_port);
#endif
		if (vm != NULL)
		{
			vmc_sock = lookup_vmc_tcp_sock_by_port_in_vm(vm, my_port, peer_port);
			if (vmc_sock != NULL)
			{
				remove_vmc_tcp_sock_from_vm(vm, vmc_sock);
				lock_vmc_sock(vmc_sock);
				update_vmc_sock_status(vmc_sock, E_VMC_TCP_CONN_CLOSE);
				send_vmc_tcp_close_msg(vm->mac, my_port, peer_port);
				release_vmc_sock(vmc_sock);
				destroy_vmc_sock(vmc_sock, vm);
			}
		}
	}
	fput_light(sock->file, fput_needed);
	return ref_sys_close(fd);
}

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define vmc_sock_wait_event(__sk, __timeo, __condition)			\
	({	int __rc;						\
		release_vmc_sock(__sk);					\
		__rc = __condition;					\
		if (!__rc) {						\
			*(__timeo) = schedule_timeout(*(__timeo));	\
		}							\
		lock_vmc_sock(__sk);					\
		__rc = __condition;					\
		__rc;							\
	})

int vmc_sock_wait_data_or_shutdown(vmc_tcp_sock *vmc_sock, long *timeo)
{
	int rc = 0;
#if 0
	DEFINE_WAIT(wait);

	prepare_to_wait(&vmc_sock->wait_queue, &wait, TASK_INTERRUPTIBLE);
//	prepare_to_wait(sk_sleep(vmc_sock->refer_sock), &wait, TASK_INTERRUPTIBLE);
	set_bit(VMC_SOCK_WAITINGF_FOR_DATA, &vmc_sock->vmc_sock_flags);
	rc = vmc_sock_wait_event(vmc_sock, timeo,
				(!is_empty(vmc_sock) || (vmc_sock->sk_shutdown & RCV_SHUTDOWN) || (vmc_sock->vmc_sock_status == E_VMC_TCP_CONN_CLOSE)));
	clear_bit(VMC_SOCK_WAITINGF_FOR_DATA, &vmc_sock->vmc_sock_flags);
	finish_wait(&vmc_sock->wait_queue, &wait);
//	finish_wait(sk_sleep(vmc_sock->refer_sock), &wait);
	return rc;
#else
	release_vmc_sock(vmc_sock);
	if (is_empty(vmc_sock) && test_bit(VMC_SOCK_WAITING_FOR_EMPTY, &vmc_sock->vmc_sock_flags))
	{
#if DEBUG_RECVFROM
		DPRINTK("wait data!\n");
#endif
		wake_up_interruptible(&vmc_sock->wait_queue);
	}
	set_bit(VMC_SOCK_WAITING_FOR_DATA, &vmc_sock->vmc_sock_flags);
	wait_event_interruptible(vmc_sock->wait_queue, (!is_empty(vmc_sock) || (vmc_sock->sk_shutdown & RCV_SHUTDOWN) || (vmc_sock->vmc_sock_status == E_VMC_TCP_CONN_CLOSE)));
	clear_bit(VMC_SOCK_WAITING_FOR_DATA, &vmc_sock->vmc_sock_flags);
	lock_vmc_sock(vmc_sock);
	return rc;
#endif
}

static size_t do_fast_recv_from_vmc_sock(co_located_vm *vm, vmc_tcp_sock *vmc_sock, void __user *buff, unsigned int flags, size_t len)
{
	size_t read_len = 0/*, read_left = len*/;
	receive_buf *buf_read;
	long timeo;
	int copied = 0;
	int target;/* Read at least this many bytes */
	int err = -1;

	lock_vmc_sock(vmc_sock);
	timeo = sock_rcvtimeo(vmc_sock->refer_sock, flags & MSG_DONTWAIT);
	target = sock_rcvlowat(vmc_sock->refer_sock, flags & MSG_WAITALL, len);

	do
	{
		if (!is_empty(vmc_sock))
		{
			goto found_data;
		}

		if (copied >= target)
		{
			break;
		}
		if (signal_pending(current))
		{
			copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
			break;
		}
		if (copied)
		{
			if (vmc_sock->vmc_sock_status == E_VMC_TCP_CONN_CLOSE || (vmc_sock->sk_shutdown & RCV_SHUTDOWN)
					|| !timeo || signal_pending(current))
				break;
		}
		else
		{
			if ((vmc_sock->sk_shutdown & RCV_SHUTDOWN) || (vmc_sock->vmc_sock_flags == E_VMC_TCP_CONN_CLOSE))
				break;

			if (!timeo)
			{
				copied = -EAGAIN;
				break;
			}
			if (signal_pending(current))
			{
				copied = sock_intr_errno(timeo);
				break;
			}
		}
		if (copied < target)
		{
			vmc_sock_wait_data_or_shutdown(vmc_sock, &timeo);
		}
		continue;

found_data:
		buf_read = vmc_sock->head;
		release_vmc_sock(vmc_sock);
		read_len = MIN(len, buf_read->len - buf_read->read_start_point);
		BUG_ON(read_len < 0);
		if (copy_to_user(buff, buf_read->data + buf_read->read_start_point, read_len))
		{
			err = -EFAULT;
			break;
		}
		copied += read_len;
		buff += read_len;
		len -= read_len;
		buf_read->read_start_point += read_len;
		BUG_ON(buf_read->read_start_point > buf_read->len);
		if (buf_read->read_start_point == buf_read->len)
		{
			lock_vmc_sock(vmc_sock);
			vmc_sock->head = buf_read->next;
			if (vmc_sock->head == NULL)
			{
				vmc_sock->tail = NULL;
			}
			release_vmc_sock(vmc_sock);
			atomic_sub(buf_read->len, &vm->rx_ring->descriptor->tcp_buf_size);
			kfree(buf_read);
		}
		lock_vmc_sock(vmc_sock);
	}while (len > 0);
//	if (vm->rx_ring->descriptor->wait_for_peer/* && (VM_RX_TCP_BUF_SIZE(vm) < DEFAULT_MAX_TCP_BUF_SIZE - TCP_WIN_SIZE)*/)
	if (vm->rx_ring->descriptor->wait_for_peer && (VM_RX_TCP_BUF_SIZE(vm) < DEFAULT_MAX_TCP_BUF_SIZE - TCP_RX_WIN_SIZE))
	{
//		notify_remote_via_irq(VM_TX_IRQ_TSC(vm));
		tell_remote_to_wakeup_xmit_tsc(vm);
	}
	release_vmc_sock(vmc_sock);
	return copied;
}

asmlinkage long new_sys_recvfrom(int fd, void __user *buff, size_t len, unsigned int flags,
		struct sockaddr __user *addr, int __user *addr_len)
{
	int err, fput_needed;
	__be32 ip_addr;
	u16 my_port = -1, peer_port = -1;
	co_located_vm *vm;
	vmc_tcp_sock *vmc_sock = NULL;
	struct socket *sock = NULL;
	struct tcp_sock *tp = NULL;
	uint16_t type = 0;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto recv_traditionally;
	get_sock_info(sock, &type, &ip_addr, &peer_port, &my_port);
	if (type != SOCK_STREAM)
		goto put_fd;
	vm = lookup_vm_by_ip(ip_addr);
	if (peer_port == NET_PERF_TEST_PORT || my_port == NET_PERF_TEST_PORT)
	{
#if DEBUG_RECVFROM
		EPRINTK("recv related to netperf!\n");
#endif
		vm = NULL;
	}
	if (vm == NULL)
	{
#if DEBUG_RECVFROM
		DPRINTK("vm NULL!\n");
#endif
		goto put_fd;
	}
	else if (vm->status == E_VMC_VM_STATUS_INIT || vm->status == E_VMC_VM_STATUS_LISTEN)
	{
#if DEBUG_RECVFROM
		DPRINTK("enter freeze,vm status:%d!\n", vm->status);
#endif
		enter_freeze(ip_addr, vm);
		if ((vm = lookup_vm_by_ip(ip_addr)) == NULL)
			goto put_fd;
	}
#if DEBUG_RECVFROM
	DPRINTK("type:%d addr:%x peer_port:%d my_port:%d!\n", type, ip_addr, peer_port, my_port);
#endif
	vmc_sock = lookup_vmc_tcp_sock_by_port_in_vm(vm, my_port, peer_port);
	if (vm->status == E_VMC_VM_STATUS_CONNECTED && (vmc_sock == NULL || !vmc_sock->im_ready))
	{
#if DEBUG_RECVFROM
		DPRINTK("connect vmc_sock[my_port:%d peer_port:%d]!\n", my_port, peer_port);
#endif
		vmc_sock = xen_vmc_tcp_session_connect(vm, my_port, peer_port);
	}
	if (!vmc_sock || !vmc_sock->im_ready)
		goto put_fd;

	if (vmc_sock->first_recv)
	{
		//recv data from TCP/IP
		tp = tcp_sk(vmc_sock->refer_sock);
		BUG_ON(tp == NULL);
		if (!vmc_sock->sent_write_seq)
		{
#if DEBUG_RECVFROM
			DPRINTK("send write seq![my_port:%d peer_port:%d write_seq:%d]\n", my_port, peer_port, tp->write_seq);
#endif
			send_vmc_tcp_accept_msg(vm->mac, my_port, peer_port, tp->write_seq);
			vmc_sock->sent_write_seq = true;
		}
		set_bit(VMC_SOCK_WAITING_FOR_PEER_ACCEPT, &vmc_sock->vmc_sock_flags);
		wait_event_interruptible(vmc_sock->wait_queue, vmc_sock->peer_accept == true);
		clear_bit(VMC_SOCK_WAITING_FOR_PEER_ACCEPT, &vmc_sock->vmc_sock_flags);
		if (signal_pending(current))
			return -EINTR;
#if DEBUG_RECVFROM
		DPRINTK("tcp_sk: rcv_nxt:%d copied_seq:%d peer_snd_nxt:%d", tp->rcv_nxt, tp->copied_seq, vmc_sock->peer_write_seq);
#endif
		BUG_ON(before(vmc_sock->peer_write_seq, tp->copied_seq));
		if (after(vmc_sock->peer_write_seq, tp->copied_seq))
		{
			fput_light(sock->file, fput_needed);
			return ref_sys_recvfrom(fd, buff, min(len, (size_t)(vmc_sock->peer_write_seq - tp->copied_seq)), flags, addr, addr_len);
		}
		else
		{
			vmc_sock->first_recv = false;
		}
	}
	BUG_ON(!vmc_sock->im_ready);
#if DEBUG_RECVFROM
	DPRINTK("recv from shared mem!\n");
#endif
	err = do_fast_recv_from_vmc_sock(vm, vmc_sock, buff, flags, len);
	if (err == 0 && vm->status == E_VMC_VM_STATUS_SUSPEND && vmc_sock->vmc_sock_status == E_VMC_TCP_CONN_CLOSE)
	{
#if DEBUG_RECVFROM
		DPRINTK("remove vmc_tcp_sock!\n");
#endif
		remove_vmc_tcp_sock(vm, vmc_sock);
		if (test_bit(WAIT_FOR_VMC_TCP_SOCK_REMOVED, &vm->vm_flags))
			wake_up_interruptible(&vm->wait_queue);
		err = -EINTR;
	}
	fput_light(sock->file, fput_needed);
	return err;
put_fd:
	fput_light(sock->file, fput_needed);
recv_traditionally:
	return ref_sys_recvfrom(fd, buff, len, flags, addr, addr_len);
}

asmlinkage long new_sys_recv(int fd, void __user *buff, size_t len, unsigned int flags)
{
	return new_sys_recvfrom(fd, buff, len, flags, NULL, 0);
}


//just an implementation of make_lowmem_page_readwrite
//add by newcent@Nov 19, 2014
static void my_make_lowmem_page_readwrite(void *vaddr)
{
	pte_t *pte, ptev;
	unsigned long address = (unsigned long) vaddr;
	unsigned int level;

	pte = lookup_address(address, &level);
	if (pte == NULL)
		return; /* vaddr missing */

	ptev = pte_mkwrite(*pte);
	if (HYPERVISOR_update_va_mapping(address, ptev, 0))
		BUG();
}

//a implementation of make_lowmem_page_readonly
//add by newcent@Nov 19, 2014, because this function is not a symbol
static void my_make_lowmem_page_readonly(void *vaddr)
{
    pte_t *pte, ptev;
    unsigned long address = (unsigned long)vaddr;
    unsigned int level;

    pte = lookup_address(address, &level);
    if (pte == NULL)
        return;     /* vaddr missing */
    ptev = pte_wrprotect(*pte);

    if (HYPERVISOR_update_va_mapping(address, ptev, 0))
        BUG();
}


static sys_call_ptr_t *aquire_sys_call_table(void)
{
  unsigned long int offset = PAGE_OFFSET;
  sys_call_ptr_t *sct;

  while (offset < ULLONG_MAX) {
    sct = (sys_call_ptr_t *)offset;

    if (sct[__NR_close] == (sys_call_ptr_t )sys_close)
      return sct;

    offset += sizeof(void *);
  }
  printk("Getting syscall table failed. :(");
  return NULL;
}

static int syscall_hook(void)
{
	unsigned int ret = -1;
	unsigned long cr0 = 0;
	unsigned long start = 0, end = 0;
	xmaddr_t addr;

	if (!(syscall_table_preception = (sys_call_ptr_t *)aquire_sys_call_table()))
	{
		printk("wrong init syscall_table_perception!\n");
		return -1;
	}
	if (xen_pv_domain())
	{
		my_make_lowmem_page_readwrite((void *) &syscall_table_preception[__NR_close]);
		my_make_lowmem_page_readwrite((void *) &syscall_table_preception[__NR_sendto]);
		my_make_lowmem_page_readwrite((void *) &syscall_table_preception[__NR_recvfrom]);
		my_make_lowmem_page_readwrite((void *) &syscall_table_preception[__NR_shutdown]);
	}
	else
	{
		cr0 = read_cr0();//disable write protection
		write_cr0(cr0 & ~X86_CR0_WP);
		start = ((unsigned long) syscall_table_preception & PAGE_MASK);
		end = (unsigned long) (syscall_table_preception + __NR_open);
		addr = virt_to_machine(start);
		ret = set_memory_rw(addr.maddr, (end - start) >> PAGE_SHIFT);//set page attribution to read-write
		if (ret)
		{
			printk("set memory start:%lx end:%lx rw error,code = %d\n", start, end, ret);
			return -1;
		}
	}
	ref_sys_close = (asmlinkage long (*)(int))syscall_table_preception[__NR_close];
	ref_sys_sendto = (asmlinkage long (*)(int, void __user *, size_t, unsigned, struct sockaddr __user *, int))syscall_table_preception[__NR_sendto];
	ref_sys_recvfrom = (asmlinkage long (*)(int, void __user *, size_t, unsigned, struct sockaddr __user *, int __user *))syscall_table_preception[__NR_recvfrom];
	ref_sys_shutdown = (asmlinkage long (*)(int , int))syscall_table_preception[__NR_shutdown];
	syscall_table_preception[__NR_close] = (sys_call_ptr_t)new_sys_close;
	syscall_table_preception[__NR_sendto] = (sys_call_ptr_t)new_sys_sendto;
	syscall_table_preception[__NR_recvfrom] = (sys_call_ptr_t)new_sys_recvfrom;
	syscall_table_preception[__NR_shutdown] = (sys_call_ptr_t)new_sys_shutdown;

	if (xen_pv_domain())
	{
		my_make_lowmem_page_readonly((void *) &syscall_table_preception[__NR_close]);
		my_make_lowmem_page_readonly((void *) &syscall_table_preception[__NR_sendto]);
		my_make_lowmem_page_readonly((void *) &syscall_table_preception[__NR_recvfrom]);
		my_make_lowmem_page_readonly((void *) &syscall_table_preception[__NR_shutdown]);
	}
	else
	{
		ret = set_memory_ro(start, (end - start) >> PAGE_SHIFT);//reset page attribution to read-only
		if (ret)
		{
			printk("set memory start:%lx end:%lx ro error,code = %d\n", start, end, ret);
			return -1;
		}
		write_cr0(cr0 | X86_CR0_WP);//enable page protection
	}
	return 0;
}

struct task_struct *event_process_task = NULL;

static int __init xenvmc_frontend_init(void)
{
	int rc = 0;

	int i;
	for_each_possible_cpu(i)
		DPRINTK("cpu:%d\n", i);

	if (init_hash_table() != 0)
	{
		rc = -ENOMEM;
		goto out;
	}

	if ((rc = net_init()) < 0) {
		EPRINTK("session_init(): net_init failed\n");
		goto out;
	}
	rc = register_xenbus_watch(&suspend_resume_watch);
	//need system respond our watch first!
	if (rc)
	{
		EPRINTK("Failed to set shutdown watcher\n");
	}
	syscall_hook();
	event_process_task = kthread_run(kthread_vmc_event_process, NULL, "evt_process");
	if (!event_process_task)
	{
		DPRINTK("error!\n");
		xenvmc_unregister();
		rc = -1;
		goto out;
	}
	respond_for_self_join();
	DPRINTK("XENVMC successfully initialized!\n");
out:
	return rc;
}


static void syscall_restore(void)
{
	unsigned long start = 0, end = 0;
	int ret = -1;

	if (!syscall_table_preception)
	{
		return;
	}
	if (xen_pv_domain())
	{
		my_make_lowmem_page_readwrite((void *) &syscall_table_preception[__NR_close]);
		my_make_lowmem_page_readwrite((void *) &syscall_table_preception[__NR_sendto]);
		my_make_lowmem_page_readwrite((void *) &syscall_table_preception[__NR_recvfrom]);
		my_make_lowmem_page_readwrite((void *) &syscall_table_preception[__NR_shutdown]);
	}
	else
	{
		write_cr0(read_cr0() & (~X86_CR0_WP)); //disable write protection
		start = ((unsigned long) syscall_table_preception & PAGE_MASK);
		end = (unsigned long) (syscall_table_preception + __NR_open);
		ret = set_memory_rw(start, (end - start) >> PAGE_SHIFT);//set page attribution to read-write
		if (ret)
		{
			printk("set memory start:%lx end:%lx rw error,code = %d\n", start, end, ret);
			return;
		}
	}

	syscall_table_preception[__NR_close] = (sys_call_ptr_t)ref_sys_close;
	syscall_table_preception[__NR_sendto] = (sys_call_ptr_t)ref_sys_sendto;
	syscall_table_preception[__NR_recvfrom] = (sys_call_ptr_t)ref_sys_recvfrom;
	syscall_table_preception[__NR_shutdown] = (sys_call_ptr_t)ref_sys_shutdown;

	if (xen_pv_domain())
	{
		my_make_lowmem_page_readonly((void *) &syscall_table_preception[__NR_close]);
		my_make_lowmem_page_readonly((void *) &syscall_table_preception[__NR_sendto]);
		my_make_lowmem_page_readonly((void *) &syscall_table_preception[__NR_recvfrom]);
		my_make_lowmem_page_readonly((void *) &syscall_table_preception[__NR_shutdown]);
	}
	else
	{
		ret = set_memory_ro(start, (end - start) >> PAGE_SHIFT);//reset page attribution to read-only
		if (ret)
		{
			printk("set memory start:%lx end:%lx ro error,code = %d\n", start, end, ret);
			return;
		}
		write_cr0(read_cr0() | X86_CR0_WP);//enable page protection
	}
	syscall_table_preception = NULL;
}

static void __exit xenvmc_frontend_exit(void)
{
//	respond_for_self_migrating();
	int i;

	for_each_possible_cpu(i)
		DPRINTK("cpu:%d\n", i);
	do_pre_migrating();
	syscall_restore();
	xenvmc_unregister();
	DPRINTK("exit xenvmc-frontend");
}

module_init(xenvmc_frontend_init);
module_exit(xenvmc_frontend_exit);

MODULE_LICENSE("GPL");

