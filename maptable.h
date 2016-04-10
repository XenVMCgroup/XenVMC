/*
 *  XenLoop -- A High Performance Inter-VM Network Loopback 
 *
 *  Installation and Usage instructions
 *
 *  Authors: 
 *  	Jian Wang - Binghamton University (jianwang@cs.binghamton.edu)
 *  	Kartik Gopalan - Binghamton University (kartik@cs.binghamton.edu)
 *
 *  Copyright (C) 2007-2009 Kartik Gopalan, Jian Wang
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


#ifndef _MAPTABLE_H
#define _MAPTABLE_H

#define XENSYSCALL_ACK_TIMEOUT 		5
#define DISCOVER_TIMEOUT 			1


#define HASH_SIZE 16
#include "config.h"
#include "xenvmc_msg.h"

ulong  hash(u8 *);

typedef struct Bucket
{
	struct list_head bucket;
} Bucket;

typedef struct HashTable
{
	ulong 		count;
	Bucket 		ip_table[HASH_SIZE];
	rwlock_t 	lock;
	struct kmem_cache *entries;
} HashTable;

typedef struct vmc_event
{
	struct list_head	list;
	u8					type;
	vm_infor 			infor;
	int 				gref_in;
	int					gref_out;
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	int					remote_rx_evtchn[READER_NUM];
#else
	int					remote_rx_evtchn;
#endif
	int					remote_tx_evtchn_ns;
	int					remote_tx_evtchn_tsc;
	u16					src_port;
	u16					peer_port;
	u32					write_seq;
}vmc_event;

enum E_VMC_VM_STAUTS{
	E_VMC_VM_STATUS_INIT = 0,
	E_VMC_VM_STATUS_LISTEN,
	E_VMC_VM_STATUS_CONNECTED,
	E_VMC_VM_STATUS_SUSPEND
};

#define VMC_TCP_SOCK_HASH_SIZE			(20)

//this struct shoud be 2^n
struct bf_data{
	uint32_t type				:8;
#if ENABLE_TWO_STAGE_RDWR
	uint32_t complete			:1;
	uint32_t reserve1			:23;
#else
	uint32_t reserve1			:24;
#endif
	uint32_t src_port			:16;
	uint32_t dst_port			:16;
	uint32_t pkt_len			;
	uint32_t reserve2			;
};
#define MDATA_SHIFT				0x0f
#define MDATA_ORDER				4
typedef struct bf_data bf_data_t;

#define VM_RX_GREF(vm) 				(vm->rx_ring->descriptor->dgref)
#define VM_TX_GREF(vm) 				(vm->tx_ring->descriptor->dgref)
#define VM_RX_EVT(vm) 				(vm->rx_evtchn)
#define VM_TX_EVT_NS(vm) 			(vm->tx_evtchn_ns)
#define VM_TX_EVT_TSC(vm) 			(vm->tx_evtchn_tsc)
#define VM_RX_IRQ(vm) 				(vm->rx_irq)
#define VM_TX_IRQ_NS(vm) 			(vm->tx_irq_ns)
#define VM_TX_IRQ_TSC(vm) 			(vm->tx_irq_tsc)
#define VM_RX_TCP_BUF_SIZE(vm)		(atomic_read(&vm->rx_ring->descriptor->tcp_buf_size))
#define VM_TX_TCP_BUF_SIZE(vm)		(atomic_read(&vm->tx_ring->descriptor->tcp_buf_size))

typedef struct receive_buf
{
	struct receive_buf *next;
	int  	read_start_point;
	int  	len;
	u16	 	my_port;
	u16  	peer_port;
#if ENABLE_TWO_STAGE_RDWR
	int		complete;
#endif
	unsigned char *data;
}receive_buf;

typedef struct vmc_tcp_sock
{
	struct list_head vm_list;
	u16 my_port, peer_port;
	struct sock *refer_sock;//for data clean
	spinlock_t 	lock;
	u32			peer_write_seq;
	receive_buf *head;
	receive_buf *tail;
	u8	vmc_sock_status;
	u8 	peer_ready: 	1;
	u8	im_ready:		1;
	u8	peer_accept:	1;
	u8	first_recv:		1;
	u8	sent_write_seq:	1;
	u8  sk_shutdown:	2;
	u8	reserved:		1;
	unsigned long vmc_sock_flags;
	long sk_rcvtimeo;
	wait_queue_head_t wait_queue;
}vmc_tcp_sock;

typedef struct co_located_vm {
	u8				    mac[ETH_ALEN];
	u8				    status;
	u8				    listen_flag;
	u8				    retry_count;
	vm_infor			infor;
	rwlock_t 		    lock;
	xf_handle_t 	    *tx_ring;
	xf_handle_t 	    *rx_ring;
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	unsigned int		rx_irq[RX_EVTCHN_NUM];
#else
	unsigned int	    rx_irq;
#endif
	unsigned int	    tx_irq_ns;
	unsigned int	    tx_irq_tsc;
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	evtchn_port_t	    rx_evtchn[RX_EVTCHN_NUM];
#else
	evtchn_port_t	    rx_evtchn;													//to notify peer vm recv pakcets
#endif
#if  TEST_RX_IPI_EVTCHN
	evtchn_port_t		rx_evtchn_ipi;
	evtchn_port_t		rx_irq_ipi;
#endif
	evtchn_port_t	    tx_evtchn_ns;												//used for rate control when xmit too fast but peer vm can not receiving buf in time, in this condition, no space to xmit by
	evtchn_port_t	    tx_evtchn_tsc;												//used for tcp stream controll, user layer can not receive data as soon as possible
	unsigned long 	    vm_flags;
	unsigned long	    need_space_size;
	struct list_head 	ip_list;
	struct list_head 	vmc_tcp_sock[VMC_TCP_SOCK_HASH_SIZE];
#ifdef USE_NAPI_STRUCT
#if ENABLE_MULTI_RING_READER
	struct napi_struct 	napi[READER_NUM];
#else
	struct napi_struct 	napi;
#endif
#endif
	struct timer_list* 	ack_timer;
	wait_queue_head_t 	wait_queue;
} co_located_vm;

typedef enum
{
	XMIT_UDP = 0,
	XMIT_TCP,
	XMIT_MAX
}XMIT_TYPE;

enum
{
	E_VMC_TCP_CONN_INIT,
	E_VMC_TCP_CONN_LISTEN,
	E_VMC_TCP_CONN_ESTABLISHED,
	E_VMC_TCP_CONN_CLOSE,
};

#define WAIT_FOR_SPACE					(1)
#define WAIT_FOR_PEER					(2)
#define WAIT_FOR_RX_CHANNEL_EMPTY		(3)
#define WAIT_FOR_VM_REMOVE				(4)
#define WAIT_FOR_VM_CONNECT_OR_DELETE	(5)
#define WAIT_FOR_VMC_TCP_SOCK_REMOVED	(6)

#define VMC_SOCK_WAITING_FOR_DATA			(0)
#define VMC_SOCK_WAITING_FOR_EMPTY			(1)
#define VMC_SOCK_WAITING_FOR_PEER_ACCEPT	(2)

#define check_descriptor(vm) (vm && vm->rx_ring && vm->tx_ring && vm->rx_ring->descriptor && vm->tx_ring->descriptor)
#define IP_HLEN			sizeof(struct iphdr)
#define UDP_HLEN		sizeof(struct udphdr)

ulong hash_domid(domid_t dom_id);
ulong hash_ip(u32 ip);

//co_located_vm *lookup_vm_by_domid(HashTable *ht, domid_t key);
//__be32 get_ip_by_domid(domid_t domid);

co_located_vm * lookup_vm_by_ip(u32 ip);
co_located_vm *insert_vm_to_table(u32 ip, u8 domid, char *mac);
vmc_tcp_sock *init_vmc_tcp_sock(u16 my_port, u16 peer_port, struct sock *sk);
vmc_tcp_sock *insert_vmc_tcp_sock_to_vm(co_located_vm *vm, vmc_tcp_sock *vmc_sock);
void remove_vmc_tcp_sock_from_vm(co_located_vm *vm, vmc_tcp_sock *vmc_sock);
vmc_tcp_sock *lookup_vmc_tcp_sock_by_port_in_vm(co_located_vm *vm, u16 my_port, u16 peer_port);

static inline void lock_vmc_sock(vmc_tcp_sock *vmc_sock)
{
	spin_lock_irq(&vmc_sock->lock);
//	lock_sock(vmc_sock->refer_sock);
}

static inline void release_vmc_sock(vmc_tcp_sock *vmc_sock)
{
	spin_unlock_irq(&vmc_sock->lock);
//	release_sock(vmc_sock->refer_sock);
}

int init_hash_table(void);
HashTable *get_hash_table(void);
int destroy_hash_table(void);

#endif /* _MAPTABLE_H_*/ 
