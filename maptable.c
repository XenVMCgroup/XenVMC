/*
 *  XenVMC -- A Residency Aware Transparent Inter-VM Network Communication Accelerator
 *
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

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/kernel.h>
#include <linux/if_ether.h>
#include <net/sock.h>
#include <asm-generic/bug.h>

#include <xen/interface/event_channel.h>

#include "xenfifo.h"
#include "maptable.h"
#include "debug.h"

HashTable ip_domid_map;

ulong hash_ip(u32 ip)
{
	return (ip % HASH_SIZE);
}

ulong hash_domid(domid_t dom_id)
{
	return (dom_id % HASH_SIZE);
}

int equal_ip(void *key1, void *key2)
{
	if (memcmp(key1, key2, sizeof(__be32)) == 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

//socket is used to re-send data when vm migrating
vmc_tcp_sock *init_vmc_tcp_sock(u16 my_port, u16 peer_port, struct sock* sk)
{
	vmc_tcp_sock *vmc_sock = NULL;
	vmc_sock = kzalloc(sizeof(struct vmc_tcp_sock), GFP_KERNEL);

	if (vmc_sock == NULL)
	{
		EPRINTK("memory not enough!\n");
		return NULL;
	}
	vmc_sock->vmc_sock_status = E_VMC_TCP_CONN_INIT;
	vmc_sock->my_port = my_port;
	vmc_sock->peer_port = peer_port;
	INIT_LIST_HEAD(&vmc_sock->vm_list);
	vmc_sock->refer_sock = sk;
	vmc_sock->head = NULL;
	vmc_sock->tail = NULL;
	spin_lock_init(&vmc_sock->lock);
	init_waitqueue_head(&vmc_sock->wait_queue);
	return vmc_sock;
}

static ulong hash_port(u16 my_port, u16 dst_port)
{
	return ((my_port + dst_port)%VMC_TCP_SOCK_HASH_SIZE);
}

vmc_tcp_sock *insert_vmc_tcp_sock_to_vm(co_located_vm *vm, vmc_tcp_sock *vmc_sock)
{
	vmc_tcp_sock *vmc_sock_found = NULL;
	struct list_head *vmc_sock_list_head = NULL;
	struct list_head *x;
	int found = 0;

	write_lock_irq(&vm->lock);
	vmc_sock_list_head = &(vm->vmc_tcp_sock[hash_port(vmc_sock->my_port, vmc_sock->peer_port)]);
	list_for_each(x, vmc_sock_list_head)
	{
		vmc_sock_found = list_entry(x, vmc_tcp_sock, vm_list);
		if (vmc_sock_found->my_port == vmc_sock->my_port && vmc_sock_found->peer_port == vmc_sock->peer_port)
		{
			found = 1;
			break;
		}
	}
	if (!found)
	{
		list_add(&(vmc_sock->vm_list), &(vm->vmc_tcp_sock[hash_port(vmc_sock->my_port, vmc_sock->peer_port)]));
	}
	write_unlock_irq(&vm->lock);
	WARN_ON(found == 1);
	return vmc_sock;
}

void remove_vmc_tcp_sock_from_vm(co_located_vm *vm, vmc_tcp_sock *vmc_sock)
{
	vmc_tcp_sock *vmc_sock_found = NULL;
	struct list_head *vmc_sock_list_head = NULL;
	struct list_head *x;
	int found = 0;

	write_lock_irq(&vm->lock);
	vmc_sock_list_head = &(vm->vmc_tcp_sock[hash_port(vmc_sock->my_port, vmc_sock->peer_port)]);
	list_for_each(x, vmc_sock_list_head)
	{
		vmc_sock_found = list_entry(x, vmc_tcp_sock, vm_list);
		if (vmc_sock_found == vmc_sock)
		{
			list_del(&vmc_sock->vm_list);
			found = 1;
			break;
		}
	}
	write_unlock_irq(&vm->lock);
	WARN_ON(found != 1);
}

vmc_tcp_sock *lookup_vmc_tcp_sock_by_port_in_vm(co_located_vm *vm, u16 my_port, u16 peer_port)
{
	vmc_tcp_sock *vmc_sock = NULL;
	struct list_head *vmc_sock_list_head = NULL;
	struct list_head *x;
	int found = 0;

	read_lock_irq(&vm->lock);
	vmc_sock_list_head = &(vm->vmc_tcp_sock[hash_port(my_port, peer_port)]);
	list_for_each(x, vmc_sock_list_head)
	{
		vmc_sock = list_entry(x, vmc_tcp_sock, vm_list);
		if (vmc_sock->my_port == my_port && vmc_sock->peer_port == peer_port)
		{
			found = 1;
			break;
		}
	}
	if (!found)
		vmc_sock = NULL;
	read_unlock_irq(&vm->lock);
	return vmc_sock;
}

static co_located_vm * __lookup_vm_by_ip(HashTable * ht, u32 ip)
{
	co_located_vm *vm = NULL;
	Bucket * b = &ht->ip_table[hash_ip(ip)];
	struct list_head *x;

	read_lock(&ht->lock);
	if (!list_empty(&b->bucket))
	{
		list_for_each(x, &(b->bucket))
		{
			vm = list_entry(x, co_located_vm, ip_list);
			if (ip == vm->infor.ip_addr)
			{
				read_unlock(&ht->lock);
				return vm;
			}
		}
	}
	read_unlock(&ht->lock);
	return NULL;
}

co_located_vm *lookup_vm_by_ip(u32 ip)
{
	return __lookup_vm_by_ip(&ip_domid_map, ip);
}


int __init_hash_table(HashTable * ht, char * name)
{
	int i;

	ht->count 	= 0;
	ht->entries = kmem_cache_create(name, sizeof(co_located_vm), 0, 0, NULL);
	rwlock_init(&ht->lock);

	if(!ht->entries) {
		EPRINTK("hashtable(): slab caches failed.\n");
		return -ENOMEM;
	}

	for(i = 0; i < HASH_SIZE; i++) {
		INIT_LIST_HEAD(&(ht->ip_table[i].bucket));
	}
	return 0;
}

int init_hash_table(void)
{
	return __init_hash_table(&ip_domid_map, "IP_DOMID_TABLE");
}

static int __destroy_hash_table(HashTable  *ht)
{
	if (ht->entries)
		kmem_cache_destroy(ht->entries);
	return 0;
}

int destroy_hash_table(void)
{
	return __destroy_hash_table(&ip_domid_map);
}

HashTable *get_hash_table(void)
{
	return &ip_domid_map;
}
