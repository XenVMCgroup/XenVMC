/*
 * xenvmc_backend.c
 *
 *  Created on: Nov 30, 2015
 *      Author: newcent
 */
/*
 *  XenVMC -- A High Performance Inter-VM Network Communication Mechanism
 *
 *  Installation and Usage instructions
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


#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/genhd.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/printk.h>
#include <linux/list.h>

#include <xen/evtchn.h>
#include <xen/xenbus.h>

//#include "discovery.h"
#include "config.h"
#include "xenvmc_backend.h"
#include "debug.h"

#define DEBUG_MSG			1
#define DEBUG_MSG_CREATE	0

static char *nic = "xenbr0\0";
struct net_device *NIC = NULL;

#define MAC 0xff&msg->mac[i]
#if DEBUG_MSG
void inline debug_msg(message_t *msg)
{
	int i;
	printk("type: %d\n", msg->type);
	printk("vm_num:%d\n", msg->vm_num);
	if (msg->vm_num >= 0 && msg->vm_num <= MAX_VM_NUM)
	{
		for (i = 0; i < msg->vm_num; i++)
		{
			printk("domid:%d ip:%x mac:%x:%x:%x:%x:%x:%x\n", msg->domid[i], msg->ip_addr[i], MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
		}
	}
#if 0
	printk("gref_in:%d gref_out:%d \n", msg->gref_in, msg->gref_out);
	printk("rx:%d tx_ns:%d tx_tsc:%d", msg->remote_rx_evtchn, msg->remote_tx_evtchn_ns, msg->remote_tx_evtchn_tsc);
	printk("src_port:%x peer_port:%x\n", msg->src_port, msg->peer_port);
	printk("write_seq:%d\n", msg->write_seq);
#endif
}
#endif

Dom0_HashTable vm_hash_table;

int __init_hash_table(Dom0_HashTable * ht, char * name)
{
	int i;

	ht->completed = true;
	ht->count 	= 0;
	ht->entries = kmem_cache_create(name, sizeof(vm_in_node), 0, 0, NULL);
	rwlock_init(&ht->lock);

	if(!ht->entries) {
		EPRINTK("hashtable(): slab caches failed.\n");
		return -ENOMEM;
	}

	for(i = 0; i < HASH_SIZE; i++) {
		INIT_LIST_HEAD(&(ht->domid_table[i].bucket));
	}
	return 0;
}

int __destroy_hash_table(Dom0_HashTable *ht)
{
	if (ht->entries)
		kmem_cache_destroy(ht->entries);
	return 0;
}

static ulong hash_domid(domid_t domid)
{
	return (domid % HASH_SIZE);
}

int init_hash_table(void)
{
	return __init_hash_table(&vm_hash_table, "VM_HASH_TABLE");
}

int destroy_hash_table(void)
{
	return __destroy_hash_table(&vm_hash_table);
}

static Dom0_HashTable *get_hash_table(void)
{
	return &vm_hash_table;
}

static void __construct_vm_set_from_hash_table(message_t *msg, Dom0_HashTable *ht)
{
	struct list_head *x, *y;
	Bucket * table = ht->domid_table;
	vm_in_node *vm;
	int i;

	msg->vm_num = 0;
	read_lock(&ht->lock);
	for (i = 0; i < HASH_SIZE; i++)
	{
		list_for_each_safe(x, y, &(table[i].bucket))
		{
			vm = list_entry(x, vm_in_node, domid_list);
			msg->domid[msg->vm_num] = vm->infor.domid;
			msg->ip_addr[msg->vm_num] = vm->infor.ip_addr;
			memcpy(msg->mac[msg->vm_num], vm->infor.mac, ETH_ALEN);
			msg->vm_num++;
			BUG_ON(msg->vm_num > MAX_VM_NUM);
		}
	}
	read_unlock(&ht->lock);
}

static void construct_vm_set(message_t *msg)
{
	Dom0_HashTable *vm_hash_table = get_hash_table();
	return __construct_vm_set_from_hash_table(msg, vm_hash_table);
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

struct sk_buff *vmc_msg_create(int type, vm_infor *infor, struct net_device *dev, const unsigned char *dest_hw)
{
	struct sk_buff *skb;
	message_t *msg;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;

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

	msg->type = type;
	if (type == E_VMC_MSG_REGISTER_ACK)
		construct_vm_set(msg);
	else
	{
		msg->domid[0] = infor->domid;
		msg->ip_addr[0] = infor->ip_addr;
		memcpy(msg->mac[0], infor->mac, ETH_ALEN);
		msg->vm_num = 1;
	}
#if DEBUG_MSG_CREATE
	debug_msg(msg);
#endif
	return skb;

out:
	kfree_skb(skb);
	return NULL;
}

//event process
DECLARE_WAIT_QUEUE_HEAD(vmc_event_wq);
static LIST_HEAD(vmc_event_list);
static DEFINE_SPINLOCK(vmc_event_lock);

static void respond_for_vm_destroy(struct xenbus_watch *watch, const char **vec, unsigned int len)
{
	char **dir;
	int dir_n;
	domid_t domid;
	evt_dom0 *evt;
	char *p = NULL;

	dir = xenbus_directory(XBT_NIL, watch->node, "", &dir_n);

	if (IS_ERR(dir))
	{
		p = (char *)(watch->node + strlen("/local/domain/"));
		domid = simple_strtoul(p, NULL, 10);
		evt = kmalloc(sizeof(*evt), GFP_NOIO | __GFP_HIGH);
		evt->type = E_EVT_VMC_DOMU_DELETE;
		evt->infor.domid = domid;
		spin_lock(&vmc_event_lock);
		list_add_tail(&evt->list, &vmc_event_list);
		spin_unlock(&vmc_event_lock);
		wake_up(&vmc_event_wq);
		return;
	}
	kfree(dir);
}

static void init_vm_xenbus_watch(struct xenbus_watch *watch, domid_t domid)
{
	char *str = kasprintf(GFP_KERNEL, "/local/domain/%d", domid);
	watch->node = str;
	watch->callback = respond_for_vm_destroy;
}

static vm_in_node *_insert_vm_to_hash_table(Dom0_HashTable *ht, u32 ip, domid_t domid, u8 *mac)
{
	Bucket *domid_bucket = &ht->domid_table[hash_domid(domid)];
	vm_in_node * vm;

	vm = kmem_cache_zalloc(ht->entries, GFP_ATOMIC);
	vm->infor.domid = domid;
	vm->infor.ip_addr = ip;
	memcpy(vm->infor.mac, mac, ETH_ALEN);
	init_vm_xenbus_watch(&vm->watch, domid);
	register_xenbus_watch(&vm->watch);
	write_lock(&ht->lock);
	list_add(&vm->domid_list, &(domid_bucket->bucket));
	ht->count++;
	write_unlock(&ht->lock);
	return vm;
}

static vm_in_node *insert_vm_to_hash_table(u32 ip, domid_t domid, u8 *mac)
{
	Dom0_HashTable *vm_hash_table = get_hash_table();

	return _insert_vm_to_hash_table(vm_hash_table, ip, domid, mac);
}

static vm_in_node *_lookup_vm_by_domid(Dom0_HashTable *ht, domid_t domid)
{
	vm_in_node *vm;
	Bucket *domid_bucket = &ht->domid_table[hash_domid(domid)];
	struct list_head *x;

	read_lock(&ht->lock);
	if (!list_empty(&domid_bucket->bucket))
	{
		list_for_each(x, &(domid_bucket->bucket))
		{
			vm = list_entry(x, vm_in_node, domid_list);
			if (domid == vm->infor.domid)
			{
				read_unlock(&ht->lock);
				return vm;
			}
		}
	}
	read_unlock(&ht->lock);
	return NULL;
}

static vm_in_node *lookup_vm_by_domid(domid_t domid)
{
	Dom0_HashTable *vm_hash_table = get_hash_table();

	return _lookup_vm_by_domid(vm_hash_table, domid);
}

static void __remove_vm_from_hash_table(Dom0_HashTable *ht, domid_t domid)
{
	vm_in_node *vm = _lookup_vm_by_domid(ht, domid);

	BUG_ON(vm == NULL);
	write_lock(&ht->lock);
	list_del(&vm->domid_list);
	ht->count--;
	write_unlock(&ht->lock);
	unregister_xenbus_watch(&vm->watch);
	kfree(vm->watch.node);
	kmem_cache_free(ht->entries, vm);
}

static void remove_vm_from_hash_table(domid_t domid)
{
	Dom0_HashTable *vm_hash_table = get_hash_table();

	return __remove_vm_from_hash_table(vm_hash_table, domid);
}

void send_register_ack_msg(u8 *dst_addr)
{
	int ret = -1;
	struct sk_buff *skb = NULL;

	skb = vmc_msg_create(E_VMC_MSG_REGISTER_ACK, NULL, NIC, dst_addr);
	WARN_ON(!skb);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("Non-zero return code: %d %s", ret,	skb_shinfo(skb) ? "good" : "bad");
	}
}

void broadcast_vm_add_msg(vm_infor *infor)
{
	int ret = -1;
	struct sk_buff *skb = NULL;

	skb = vmc_msg_create(E_VMC_MSG_VM_ADD, infor, NIC, NULL);
	WARN_ON(!skb);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("Non-zero return code: %d %s", ret, skb_shinfo(skb) ? "good" : "bad");
	}
}

void broadcast_vm_delete_msg(vm_infor *infor)
{
	int ret = -1;
	struct sk_buff *skb = NULL;

	skb = vmc_msg_create(E_VMC_MSG_VM_DELETE, infor, NIC, NULL);
	WARN_ON(!skb);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("Non-zero return code: %d %s", ret, skb_shinfo(skb) ? "good" : "bad");
	}
}

void broadcast_vm_migrating_msg(vm_infor *infor)
{
	int ret = -1;
	struct sk_buff *skb = NULL;

	skb = vmc_msg_create(E_VMC_MSG_VM_MIGRATING, infor, NIC, NULL);
	WARN_ON(!skb);
	ret = dev_queue_xmit(skb);
	if (ret)
	{
		EPRINTK("Non-zero return code: %d %s", ret, skb_shinfo(skb) ? "good" : "bad");
	}
}

bool is_my_domu(u8 *mac, domid_t domid)
{
	char *path = kasprintf(GFP_KERNEL, "/local/domain/%d/device/vif", domid);
	char **dir;
	char *guest_mac_path;
	char *guest_mac_str;
	u8 guest_mac[ETH_ALEN];
	int num, i;

	dir = xenbus_directory(XBT_NIL, path, "", &num);
	if (IS_ERR(dir))
	{
		EPRINTK("error!\n");
		kfree(path);
		return false;
	}
	for (i = 0; i < num; i++)
	{
		guest_mac_path = kasprintf(GFP_KERNEL, "%s/%s/mac", path, dir[i]);
		guest_mac_str = xenbus_read(XBT_NIL, guest_mac_path, "", NULL);
		if (!IS_ERR(guest_mac_str))
		{
			int j;
			char *pEnd = guest_mac_str;
			for(j = 0; j < ETH_ALEN - 1; j++)
			{
				guest_mac[j] = simple_strtol(pEnd, &pEnd, 16);
				pEnd++;
			}
			guest_mac[ETH_ALEN - 1] = simple_strtol(pEnd, &pEnd, 16);
			if(memcmp(mac, guest_mac, ETH_ALEN) == 0)
			{
				kfree(guest_mac_str);
				kfree(guest_mac_path);
				kfree(dir);
				kfree(path);
				return true;
			}
			kfree(guest_mac_str);
		}
		kfree(guest_mac_path);
	}
	kfree(dir);
	kfree(path);
	return false;
}

static int kthread_vmc_event_process(void *noused)
{
	struct list_head *ent;
	evt_dom0 *event;
	vm_in_node *vm;


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
			event = list_entry(ent, evt_dom0, list);
			switch(event->type)
			{
			case E_EVT_VMC_DOMU_REGISTER:
				if (is_my_domu(event->infor.mac, event->infor.domid))
				{
					vm = lookup_vm_by_domid(event->infor.domid);
					BUG_ON(vm != NULL);
					insert_vm_to_hash_table(event->infor.ip_addr, event->infor.domid,
							event->infor.mac);
					send_register_ack_msg(event->infor.mac);
					broadcast_vm_add_msg(&event->infor);
				}
				else
				{
					DPRINTK("not my domu!\n");
				}
				break;
			case E_EVT_VMC_DOMU_MIGRATING:
				vm = lookup_vm_by_domid(event->infor.domid);
				WARN_ON(vm == NULL);
				if (vm)
				{
					broadcast_vm_migrating_msg(&vm->infor);
					remove_vm_from_hash_table(event->infor.domid);
				}
				break;
			case E_EVT_VMC_DOMU_DELETE:
				vm = lookup_vm_by_domid(event->infor.domid);
				BUG_ON(vm == NULL);
				broadcast_vm_delete_msg(&vm->infor);
				remove_vm_from_hash_table(event->infor.domid);
				break;
			}
			kfree(event);
		}
	}
	return 0;
}

int discovery_session_recv(struct sk_buff * skb, struct net_device * dev, struct packet_type * pt, struct net_device * d)
{
	int ret = NET_RX_SUCCESS;
	message_t * msg = NULL;
	evt_dom0 *evt;

	BUG_ON(!skb);
//	DPRINTK("skb_len:%d data_len:%d true_size:%d\n", skb->len, skb->data_len, skb->truesize);
	msg = (message_t *) skb->data;
	BUG_ON(!msg);
	skb_linearize(skb);
//	dump(msg, sizeof(message_t));
#if DEBUG_MSG
	debug_msg(msg);
#endif
	switch (msg->type)
	{
		case E_VMC_MSG_REGISTER:
			evt = kmalloc(sizeof(*evt), GFP_NOIO | __GFP_HIGH);
			evt->type = E_EVT_VMC_DOMU_REGISTER;
			evt->infor.domid = msg->domid[0];
			evt->infor.ip_addr = msg->ip_addr[0];
			memcpy(evt->infor.mac, msg->mac[0], ETH_ALEN);
			spin_lock(&vmc_event_lock);
			list_add_tail(&evt->list, &vmc_event_list);
			spin_unlock(&vmc_event_lock);
			wake_up(&vmc_event_wq);
			break;
		case E_VMC_MSG_DOMU_MIGRATING:
			evt = kmalloc(sizeof(*evt), GFP_NOIO | __GFP_HIGH);
			evt->type = E_EVT_VMC_DOMU_MIGRATING;
			evt->infor.domid = msg->domid[0];
			evt->infor.ip_addr = msg->ip_addr[0];
			memcpy(evt->infor.mac, msg->mac[0], ETH_ALEN);
			spin_lock(&vmc_event_lock);
			list_add_tail(&evt->list, &vmc_event_list);
			spin_unlock(&vmc_event_lock);
			wake_up(&vmc_event_wq);
			break;
		default:
			EPRINTK("session_recv(): unknown msg type %d\n", msg->type);
	}
	kfree_skb(skb);
	return ret;
}

static struct packet_type discovery_ptype = {
	.type		= __constant_htons(ETH_P_VMC),
	.func 		= discovery_session_recv,
	.dev 		= NULL,
	.af_packet_priv = NULL,
};

struct task_struct *task = NULL;
static int __init xenvmc_backend_init(void)
{
	int ret = 0;
	int i;

	for_each_possible_cpu(i)
		DPRINTK("cpu:%d\n", i);

	init_hash_table();
	NIC = dev_get_by_name(&init_net, nic);
	if (!NIC)
	{
		DB("discovery_init(): Could not find network card %s\n", nic);
		ret = -ENODEV;
		goto out;
	}
	dev_add_pack(&discovery_ptype);
	task = kthread_run(kthread_vmc_event_process, NULL, "evt_process");
	if (task == NULL)
	{
		EPRINTK("evt_process run failed!\n");
	}
	DPRINTK("xenvmc-backend insmod!\n");
out:
	return ret;
}

static void __exit xenvmc_backend_exit(void)
{
	dev_remove_pack(&discovery_ptype);
	if (NIC)
		dev_put(NIC);
	if (task != NULL)
	{
		kthread_stop(task);
		task = NULL;
	}
	destroy_hash_table();
	DPRINTK("xenvmc-backend removed!\n");
}

module_init(xenvmc_backend_init);
module_exit(xenvmc_backend_exit);

MODULE_LICENSE("GPL");




