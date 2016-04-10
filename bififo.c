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
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/irqdesc.h>
#include <linux/irq.h>
#include <net/udp.h>
#include <net/xfrm.h>
#include <linux/uio.h>

#include <xen/interface/event_channel.h>
#include <xen/evtchn.h>
#include <asm/xen/hypercall.h>
#include <xen/events.h>
#include <linux/udp.h>
#include <net/udp.h>
#include <trace/events/udp.h>
#include <net/busy_poll.h>

#include "debug.h"
#include "xenfifo.h"
#include "maptable.h"
#include "bififo.h"

extern HashTable ip_domid_map;
extern struct net_device *NIC;
extern vm_infor my_infor;

#if DEBUG_EVTCHN_REPONSE
int tcs_response_times = 0;
int recv_response_times = 0;
int nospace_response_times = 0;
#endif

static void insert_receiv_buf_to_vmc_sock(receive_buf *buf, vmc_tcp_sock *vmc_sock)
{
	if (vmc_sock->tail == NULL)
	{
		BUG_ON(vmc_sock->head != NULL);
		vmc_sock->head = vmc_sock->tail = buf;
	}
	else
	{
		BUG_ON(vmc_sock->tail->next != NULL);
		vmc_sock->tail->next = buf;
		vmc_sock->tail = buf;
	}
}

irqreturn_t xenvmc_virq_interrupt(int irq, void *dev_id)
{
	DPRINTK("cpu:%d\n", smp_processor_id());
	return IRQ_HANDLED;
}


irqreturn_t xenvmc_rx_interrupt(int irq, void *dev_id)
{
	co_located_vm *vm = dev_id;
	unsigned long flags;
	static DEFINE_SPINLOCK(rx_lock);

#if DEBUG_EVTCHN_REPONSE
	recv_response_times++;
#endif
//	DPRINTK("cpu:%d\n", smp_processor_id());
	spin_lock_irqsave(&rx_lock, flags);

#if TEST_RX_IPI_EVTCHN
	if (vm->rx_irq_ipi)
	{
		DPRINTK("\n");
		notify_remote_via_irq(vm->rx_irq_ipi);
	}
#else
	if (!xf_empty(vm->rx_ring))
	{
#if ENABLE_MULTI_RING_READER
		napi_schedule(&vm->napi[smp_processor_id()%READER_NUM]);
#else
		napi_schedule(&vm->napi);
#endif
	}
#endif
	spin_unlock_irqrestore(&rx_lock, flags);
	return IRQ_HANDLED;
}

irqreturn_t xenvmc_tx_ns_interrupt(int irq, void *dev_id)
{
	co_located_vm *vm = (co_located_vm *)dev_id;
	static DEFINE_SPINLOCK(tx_ns_lock);
	unsigned long flags;
#if DEBUG_EVTCHN_REPONSE
	nospace_response_times++;
#endif

	spin_lock_irqsave(&tx_ns_lock, flags);
	if(test_bit(WAIT_FOR_SPACE, &vm->vm_flags)/* && (xf_free(vm->tx_ring) >= vm->need_space_size)*/)
	{
		wake_up_interruptible(&vm->wait_queue);
	}
	spin_unlock_irqrestore(&tx_ns_lock, flags);
	return IRQ_HANDLED;
}

irqreturn_t xenvmc_tx_tsc_interrupt(int irq, void *dev_id)
{
	co_located_vm *vm = (co_located_vm *)dev_id;
	static DEFINE_SPINLOCK(tx_tsc_lock);
	unsigned long flags;

#if DEBUG_EVTCHN_REPONSE
	tcs_response_times++;
#endif
	spin_lock_irqsave(&tx_tsc_lock, flags);
	if (test_bit(WAIT_FOR_PEER, &vm->vm_flags)/* && (VM_TX_TCP_BUF_SIZE(vm) < (DEFAULT_MAX_TCP_BUF_SIZE - TCP_WIN_SIZE))*/)
	{
		wake_up_interruptible(&vm->wait_queue);
	}
	spin_unlock_irqrestore(&tx_tsc_lock, flags);
	return IRQ_HANDLED;
}
//int create_evtch(domid_t rdomid, int *port, int *irq, int *port_space, int *irq_space, int *port_peer, int *irq_peer, void *arg)
//para vcpu is designed for multi-reader multi-writer ring-buf algorithm,
//as for xen's evtchn can not handled by different vcpu, so it is not useful by now
//add by newcent@Mar 29, 2016 liurenshi_1989@163.mail
static inline int vmc_alloc_evtchn(domid_t domid, int *port, int vcpu)
{
	int err;
	struct evtchn_alloc_unbound op;
	struct evtchn_bind_vcpu bind_vcpu;
	struct evtchn_status status;

	memset(&op, 0, sizeof(op));
	op.dom = DOMID_SELF;
	op.remote_dom = domid;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);
	if (err)
	{
		EPRINTK("alloc evthn failed!\n");
		return err;
	}
	else
	{
		*port = op.port;
	}
	//not used now ,add by newcent@Mar 29, 2016
	if (vcpu != 0)
	{
		bind_vcpu.port = op.port;
		bind_vcpu.vcpu = vcpu;
		err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_vcpu, &bind_vcpu);
		if (err)
		{
			DPRINTK("bind vcpu err:%d vcpu:%d\n", err, vcpu);
		}
	}
	status.dom = DOMID_SELF;
	status.port = *port;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_status, &status);
	if (err != 0)
	{
		DPRINTK("err:%d", err);
	}
	else
	{
		DPRINTK("status:%d vcpu:%d\n", status.status, status.vcpu);
		if (status.status == EVTCHNSTAT_interdomain)
		{
			DPRINTK("remote_domid:%d remote_port:%d\n", status.u.interdomain.dom, status.u.interdomain.port);
		}
	}

	return err;
}

static inline int close_evtchn(evtchn_port_t port)
{
	struct evtchn_close op;

	op.port = port;
	return HYPERVISOR_event_channel_op(EVTCHNOP_close, &op);
}

void free_evtchn(int port, int irq, void *dev_id)
{
	if (irq)
	{
		unbind_from_irqhandler(irq, dev_id);
	}
	else if (port)
	{
		close_evtchn(port);
	}
}

static int create_evtchn_bind_vcpu_and_irqhandler(domid_t domid, int vcpu, evtchn_port_t *evtchn,
		unsigned int *port, irq_handler_t handler, char *name, void *dev_id)
{
	int err = 0;

	err = vmc_alloc_evtchn(domid, evtchn, vcpu);
	if(err)
	{
		EPRINTK("alloc evthn failed[name:%s]!\n", name);
		goto failed;
	}
	err = bind_evtchn_to_irqhandler(*evtchn, handler, 0, name, dev_id);
	if (err < 0)
	{
		EPRINTK("bind evtchn failed[name:%s]!\n", name);
		goto failed;
	}
	*port = err;
	return 0;
failed:
	return -1;
}

#if TEST_RX_IPI_EVTCHN
static irqreturn_t ipi_rx_irq(int irq, void *dev_id)
{
	DPRINTK("cpu:%d\n", smp_processor_id());
	return IRQ_HANDLED;
}
#endif

int create_evtchn(co_located_vm *vm)
{
	int err;
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	int i;
	char rx_name[16];
#endif

#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	for (i = 0; i < RX_EVTCHN_NUM; i++)
	{
		sprintf(rx_name, "rx_interrupt_%d", i);
		err = create_evtchn_bind_vcpu_and_irqhandler(vm->infor.domid, i, &vm->rx_evtchn[i], &vm->rx_irq[i], xenvmc_rx_interrupt, rx_name, vm);
		if (err)
		{
			EPRINTK("create and bind evtchn failed name[%s]!\n", rx_name);
			goto failed;
		}
	}
#else
	err = create_evtchn_bind_vcpu_and_irqhandler(vm->infor.domid, 0, &vm->rx_evtchn, &vm->rx_irq, xenvmc_rx_interrupt, "rx_interrupt", vm);
	if (err)
	{
		EPRINTK("create and bind evtchn failed name[rx_interrupt]!\n");
		goto failed;
	}
#endif
	err = create_evtchn_bind_vcpu_and_irqhandler(vm->infor.domid, 0, &vm->tx_evtchn_ns, &vm->tx_irq_ns, xenvmc_tx_ns_interrupt, "tx_ns_interrupt", vm);
	if (err)
	{
		EPRINTK("create and bind evtchn failed name[tx_ns_interrupt]!\n");
		goto failed;
	}
	err = create_evtchn_bind_vcpu_and_irqhandler(vm->infor.domid, 0, &vm->tx_evtchn_tsc, &vm->tx_irq_tsc, xenvmc_tx_tsc_interrupt, "tx_tsc_interrupt", vm);
	if (err)
	{
		EPRINTK("create and bind evtchn failed name[tx_tsc_interrupt]!\n");
		goto failed;
	}
#if TEST_RX_IPI_EVTCHN
	{
		struct evtchn_alloc_unbound op;
		op.dom = DOMID_SELF;
		op.remote_dom = DOMID_SELF;

		err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);
		if (err)
		{
			EPRINTK("err:%d \n", err);
		}
		else
		{
			struct evtchn_bind_ipi ipi_op;
			vm->rx_evtchn_ipi = op.port;
			ipi_op.port = op.port;
			//ipi_op.vcpu = 1;
			ipi_op.vcpu = 0;
			err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_ipi, &ipi_op);
			if (err)
			{
				EPRINTK("err:%d\n", err);
			}
			else
			{
				err = bind_evtchn_to_irqhandler(op.port, ipi_rx_irq, 0, "vmc_ipi", vm);
				if (err <= 0)
				{
					EPRINTK("err:%d\n", err);
				}
				else
				{
					vm->rx_irq_ipi = err;
					DPRINTK("rx_ipi_rx:%d\n", err);
				}
			}
		}

	}
#endif
	return 0;
failed:
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	for(i = 0; i < RX_EVTCHN_NUM; i++)
		free_evtchn(vm->rx_evtchn[i], vm->rx_irq[i], vm);
#else
	free_evtchn(vm->rx_evtchn, vm->rx_irq, vm);
#endif
	free_evtchn(vm->tx_evtchn_ns, vm->tx_irq_ns, vm);
	free_evtchn(vm->tx_evtchn_tsc, vm->tx_irq_tsc, vm);
	return -1;
}

//void bf_destroy(bf_handle_t *bfl)
void bf_destroy(co_located_vm *vm)
{
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	int i;
#endif

	xf_destroy(vm->rx_ring);
	xf_destroy(vm->tx_ring);
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	for (i = 0; i < RX_EVTCHN_NUM; i++)
	{
		free_evtchn(vm->rx_evtchn[i], vm->rx_irq[i], vm);
		vm->rx_evtchn[i] = 0;
		vm->rx_irq[i] = 0;
	}
#else
	free_evtchn(vm->rx_evtchn, vm->rx_irq, vm);
	vm->rx_evtchn = 0;
	vm->rx_irq = 0;
#endif
	free_evtchn(vm->tx_evtchn_ns, vm->tx_irq_ns, vm);
	free_evtchn(vm->tx_evtchn_tsc, vm->tx_irq_tsc, vm);
	return;
}

int bf_create(co_located_vm *vm)
{
	int err = 0;

	vm->tx_ring = xf_create(vm->infor.domid, RING_BUF_SIZE);
	vm->rx_ring = xf_create(vm->infor.domid, RING_BUF_SIZE);
	if(!vm->tx_ring || !vm->rx_ring) {
		EPRINTK("Can't allocate bfl->in %p or bfl->out %p\n", vm->rx_ring, vm->tx_ring);
		goto failed;
	}
	err = create_evtchn(vm);
	if(err < 0) {
		EPRINTK("Can't allocate event channel\n");
		goto failed;
	}
	return 0;
failed:
	bf_destroy(vm);
	return -1;
}

static int vmc_bind_interdomain_evthn(domid_t domid, evtchn_port_t remote_evthn, int vcpu, evtchn_port_t *local_evthn)
{
	int err;
	struct evtchn_bind_interdomain bind_interdomain;
	struct evtchn_bind_vcpu bind_vcpu;
	struct evtchn_status status;

	bind_interdomain.remote_dom = domid;
	bind_interdomain.remote_port = remote_evthn;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_interdomain, &bind_interdomain);
	if (err)
	{
		EPRINTK("bind evtchn failed!\n");
	}
	else
	{
		*local_evthn = bind_interdomain.local_port;
	}
	if (vcpu > 0)
	{
		bind_vcpu.port = *local_evthn;
		bind_vcpu.vcpu = vcpu;
		err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_vcpu, &bind_vcpu);
		if (err)
		{
			EPRINTK("bind evtchn:%d vcpu error:%d\n", *local_evthn, err);
		}
	}
	DPRINTK("remote_port:%d\n", remote_evthn);
	status.dom = DOMID_SELF;
	status.port = *local_evthn;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_status, &status);
	if (err != 0)
	{
		DPRINTK("err:%d", err);
	}
	else
	{
		DPRINTK("status:%d vcpu:%d\n", status.status, status.vcpu);
		if (status.status == EVTCHNSTAT_interdomain)
		{
			DPRINTK("remote_domid:%d remote_port:%d\n", status.u.interdomain.dom, status.u.interdomain.port);
		}
	}
	return err;
}

static int vmc_bind_interdomain_evtchn_and_irq_handler(domid_t domid, evtchn_port_t remote_evtchn, int vcpu,
		evtchn_port_t *local_evtchn, unsigned int *local_irq, irq_handler_t handler,char *name,
		void *dev_id)
{
	int err;
	err = vmc_bind_interdomain_evthn(domid, remote_evtchn, vcpu, local_evtchn);
	if (err)
	{
		EPRINTK("err:%d remote_domain:%d remote_port:%d\n", err, domid, remote_evtchn);
		goto failed;
	}

	err = bind_evtchn_to_irqhandler(*local_evtchn, handler, 0, name, dev_id);
	if (err <= 0)
	{
		EPRINTK("err:%d remote_port:%d local_port:%d\n", err, remote_evtchn, *local_evtchn);
		goto failed;
	}
	*local_irq = err;
	return 0;
failed:
	return -1;
}

//static int bind_evtch(domid_t rdomid, int rport, int rport_space,int *local_port, int *local_irq, int *local_port_space, int *local_irq_space, void *arg)
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
static int bind_evtchn(co_located_vm *vm, evtchn_port_t *remote_rx_evtchn, evtchn_port_t remote_tx_evtchn_ns, evtchn_port_t remote_tx_evtchn_tsc)
#else
static int bind_evtchn(co_located_vm *vm, evtchn_port_t remote_rx_evtchn, evtchn_port_t remote_tx_evtchn_ns, evtchn_port_t remote_tx_evtchn_tsc)
#endif
{
	int err;
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	int i;
	char rx_name[16];
#endif


#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	for (i = 0; i < RX_EVTCHN_NUM; i++)
	{
		sprintf(rx_name, "rx_interrupt_%d", i);
		err = vmc_bind_interdomain_evtchn_and_irq_handler(vm->infor.domid, remote_rx_evtchn[i], i,
				&vm->rx_evtchn[i], &vm->rx_irq[i], xenvmc_rx_interrupt, rx_name, vm);
		if (err)
		{
			EPRINTK("vmc bind evtchn failed[rx_interrupt%d]\n", i);
			goto failed;
		}
	}
#else
	err = vmc_bind_interdomain_evtchn_and_irq_handler(vm->infor.domid, remote_rx_evtchn, 0,
			&vm->rx_evtchn, &vm->rx_irq, xenvmc_rx_interrupt, "rx_inetrrupt", vm);
	if (err)
	{
		EPRINTK("vmc bind evtchn failed[rx_interrupt]!\n");
		goto failed;
	}
#endif
	err = vmc_bind_interdomain_evtchn_and_irq_handler(vm->infor.domid, remote_tx_evtchn_ns, 0,
			&vm->tx_evtchn_ns, &vm->tx_irq_ns, xenvmc_tx_ns_interrupt, "tx_ns_interrupt", vm);
	if (err)
	{
		EPRINTK("vmc bind evtchn failed[tx_ns_interrupt]!\n");
		goto failed;
	}
	err = vmc_bind_interdomain_evtchn_and_irq_handler(vm->infor.domid, remote_tx_evtchn_tsc, 0,
			&vm->tx_evtchn_ns, &vm->tx_irq_ns, xenvmc_tx_tsc_interrupt, "tx_tsc_interrupt", vm);
	if (err)
	{
		EPRINTK("vmc bind evtchn failed[tx_tsc_interrupt]!\n");
		goto failed;
	}
#if TEST_RX_IPI_EVTCHN
	{
		struct evtchn_alloc_unbound op;
		op.dom = DOMID_SELF;
		op.remote_dom = DOMID_SELF;

		err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &op);
		if (err)
		{
			EPRINTK("err:%d \n", err);
		}
		else
		{
			struct evtchn_bind_ipi ipi_op;
			vm->rx_evtchn_ipi = op.port;
			ipi_op.port = op.port;
			//ipi_op.vcpu = 1;  //we can't bind event-channel to vcpu1?
			ipi_op.vcpu = 0;
			err = HYPERVISOR_event_channel_op(EVTCHNOP_bind_ipi, &ipi_op);
			if (err)
			{
				EPRINTK("err:%d\n", err); }
			else
			{
				err = bind_evtchn_to_irqhandler(vm->rx_evtchn_ipi, ipi_rx_irq, 0, "vmc_ipi", vm);
				if (err < 0)
				{
					EPRINTK("err:%d\n", err);
				}
				else
				{
					vm->rx_irq_ipi = err;
					notify_remote_via_evtchn(vm->rx_evtchn_ipi);
				}
			}
		}

	}
#endif
	return 0;
failed:
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	for(i = 0; i < RX_EVTCHN_NUM; i++)
		free_evtchn(vm->rx_evtchn[i], vm->rx_irq[i], vm);
#else
	free_evtchn(vm->rx_evtchn, vm->rx_irq, vm);
#endif
	free_evtchn(vm->tx_evtchn_ns, vm->tx_irq_ns, vm);
	free_evtchn(vm->tx_evtchn_tsc, vm->tx_irq_tsc, vm);
	return -1;
}

void bf_disconnect(co_located_vm *vm)
{
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	int i;
#endif

	xf_disconnect(vm->rx_ring);
	xf_disconnect(vm->tx_ring);
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	for (i = 0; i < RX_EVTCHN_NUM; i++)
		free_evtchn(vm->rx_evtchn[i], vm->rx_irq[i], vm);
#else
	free_evtchn(vm->rx_evtchn, vm->rx_irq, vm);
#endif
	free_evtchn(vm->tx_evtchn_ns, vm->tx_irq_ns, vm);
	free_evtchn(vm->tx_evtchn_tsc, vm->tx_irq_tsc, vm);
	return;
}


#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
int bf_connect(co_located_vm *vm, int rgref_in, int rgref_out, int *remote_rx_evtchn, int remote_tx_evtchn_ns, int remote_tx_evtchn_tsc)
#else
int bf_connect(co_located_vm *vm, int rgref_in, int rgref_out, int remote_rx_evtchn, int remote_tx_evtchn_ns, int remote_tx_evtchn_tsc)
#endif
{
	int err;

	vm->tx_ring = xf_connect(vm->infor.domid, rgref_out);
	vm->rx_ring = xf_connect(vm->infor.domid, rgref_in);
	if (!vm->tx_ring || !vm->rx_ring)
	{
		EPRINTK("Can't allocate bfc->in %p or bfc->out %p\n", vm->rx_ring, vm->tx_ring);
		goto failed;
	}
	err = bind_evtchn(vm, remote_rx_evtchn, remote_tx_evtchn_ns, remote_tx_evtchn_tsc);
	if (err < 0)
	{
		EPRINTK("Can't allocate bfc->in %p or bfc->out %p\n", vm->rx_ring, vm->tx_ring);
		goto failed;
	}
	return 0;
failed:
	bf_disconnect(vm);
	return -1;
}


void tell_remote_to_receive(co_located_vm *vm)
{
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	int i;
#endif
#if ENABLE_SEND_RX_EVT_ON_DEMAND
	xf_descriptor_t *des = vm->tx_ring->descriptor;
	BUG_ON(des == NULL);
#endif

#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	for(i = 0; i < RX_EVTCHN_NUM; i++)
	{
#if ENABLE_SEND_RX_EVT_ON_DEMAND
		if(!des->napi_scheduled[i])
#endif
			notify_remote_via_irq(vm->rx_irq[i]);
	}
#else
#if ENABLE_SEND_RX_EVT_ON_DEMAND
		if(!des->napi_scheduled)
#endif
			notify_remote_via_irq(vm->rx_irq);

#endif
}

void tell_remote_to_wakeup_xmit_ns(co_located_vm *vm)
{
	notify_remote_via_irq(vm->tx_irq_ns);
}

void tell_remote_to_wakeup_xmit_tsc(co_located_vm *vm)
{
	notify_remote_via_irq(vm->tx_irq_tsc);
}


static int vmc_tcp_rcv(receive_buf *buf, co_located_vm *vm)
{
	vmc_tcp_sock *vmc_sock = lookup_vmc_tcp_sock_by_port_in_vm(vm, buf->my_port, buf->peer_port);
	WARN_ON(!vmc_sock);
	if (!vmc_sock)
	{
		kfree(buf);
		return -1;
	}
#if ENABLE_TWO_STAGE_RDWR
	lock_vmc_sock(vmc_sock);
	insert_receiv_buf_to_vmc_sock(buf, vmc_sock);
	release_vmc_sock(vmc_sock);
	atomic_add(((receive_buf *)buf)->len, &vm->rx_ring->descriptor->tcp_buf_size);
	return 0;
#else
	lock_vmc_sock(vmc_sock);
	insert_receiv_buf_to_vmc_sock(buf, vmc_sock);
	release_vmc_sock(vmc_sock);
	atomic_add(((receive_buf *)buf)->len, &vm->rx_ring->descriptor->tcp_buf_size);
	if (test_bit(VMC_SOCK_WAITING_FOR_DATA, &vmc_sock->vmc_sock_flags))
	{
		wake_up_interruptible(&vmc_sock->wait_queue);
	}
	return 0;
#endif
}

#if ENABLE_TWO_STAGE_RDWR
static int wake_up_vmc_tcp_sock(co_located_vm *vm, u16 my_port, u16 peer_port)
{
	vmc_tcp_sock *vmc_sock = lookup_vmc_tcp_sock_by_port_in_vm(vm, my_port, peer_port);

	if (test_bit(VMC_SOCK_WAITING_FOR_DATA, &vmc_sock->vmc_sock_flags))
	{
		wake_up_interruptible(&vmc_sock->wait_queue);
	}
	return 0;
}
#endif

/* returns:
 *  -1: error
 *   0: success
 *  >0: "udp encap" protocol resubmission
 *
 * Note that in the success and error cases, the skb is assumed to
 * have either been requeued or freed.
 */
#if 1
static int __udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int rc;

	if (inet_sk(sk)->inet_daddr) {
		sock_rps_save_rxhash(sk, skb);
		sk_mark_napi_id(sk, skb);
	}

	rc = sock_queue_rcv_skb(sk, skb);
	if (rc < 0) {
		int is_udplite = IS_UDPLITE(sk);

		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM)
			UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_RCVBUFERRORS,
					 is_udplite);
		UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
		kfree_skb(skb);
//		trace_udp_fail_queue_rcv_skb(rc, sk);
		return -1;
	}

	return 0;

}

int my_own_udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	int rc;
	int is_udplite = IS_UDPLITE(sk);

	/*
	 *	Charge it to the socket, dropping if the queue is full.
	 */
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset(skb);

//	if (static_key_false(&udp_encap_needed) && up->encap_type) {
//		int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);
//
//		/*
//		 * This is an encapsulation socket so pass the skb to
//		 * the socket's udp_encap_rcv() hook. Otherwise, just
//		 * fall through and pass this up the UDP socket.
//		 * up->encap_rcv() returns the following value:
//		 * =0 if skb was successfully passed to the encap
//		 *    handler or was discarded by it.
//		 * >0 if skb should be passed on to UDP.
//		 * <0 if skb should be resubmitted as proto -N
//		 */
//
//		/* if we're overly short, let UDP handle it */
//		encap_rcv = ACCESS_ONCE(up->encap_rcv);
//		if (skb->len > sizeof(struct udphdr) && encap_rcv != NULL) {
//			int ret;
//
//			ret = encap_rcv(sk, skb);
//			if (ret <= 0) {
//				UDP_INC_STATS_BH(sock_net(sk),
//						 UDP_MIB_INDATAGRAMS,
//						 is_udplite);
//				return -ret;
//			}
//		}
//
//		/* FALLTHROUGH -- it's a UDP Packet */
//	}

	/*
	 * 	UDP-Lite specific tests, ignored on UDP sockets
	 */
	if ((is_udplite & UDPLITE_RECV_CC)  &&  UDP_SKB_CB(skb)->partial_cov) {

		/*
		 * MIB statistics other than incrementing the error count are
		 * disabled for the following two types of errors: these depend
		 * on the application settings, not on the functioning of the
		 * protocol stack as such.
		 *
		 * RFC 3828 here recommends (sec 3.3): "There should also be a
		 * way ... to ... at least let the receiving application block
		 * delivery of packets with coverage values less than a value
		 * provided by the application."
		 */
		if (up->pcrlen == 0) {          /* full coverage was set  */
			LIMIT_NETDEBUG(KERN_WARNING "UDPLite: partial coverage %d while full coverage %d requested\n",
				       UDP_SKB_CB(skb)->cscov, skb->len);
			goto drop;
		}
		/* The next case involves violating the min. coverage requested
		 * by the receiver. This is subtle: if receiver wants x and x is
		 * greater than the buffersize/MTU then receiver will complain
		 * that it wants x while sender emits packets of smaller size y.
		 * Therefore the above ...()->partial_cov statement is essential.
		 */
		if (UDP_SKB_CB(skb)->cscov  <  up->pcrlen) {
			LIMIT_NETDEBUG(KERN_WARNING "UDPLite: coverage %d too small, need min %d\n",
				       UDP_SKB_CB(skb)->cscov, up->pcrlen);
			goto drop;
		}
	}

	if (rcu_access_pointer(sk->sk_filter) &&
	    udp_lib_checksum_complete(skb))
		goto csum_error;


	if (sk_rcvqueues_full(sk, skb, sk->sk_rcvbuf))
		goto drop;

	rc = 0;

//	ipv4_pktinfo_prepare(sk, skb);
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk))
		rc = __udp_queue_rcv_skb(sk, skb);
	else if (sk_add_backlog(sk, skb, sk->sk_rcvbuf)) {
		bh_unlock_sock(sk);
		goto drop;
	}
	bh_unlock_sock(sk);

	return rc;

csum_error:
	UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
drop:
	UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
	atomic_inc(&sk->sk_drops);
	kfree_skb(skb);
	return -1;
}
#endif
static int vmc_udp_rcv(struct sk_buff *skb)
{
	struct sock *sk;
	struct udphdr *uh;
	unsigned short ulen;
	__be32 saddr, daddr;

	uh = udp_hdr(skb);
	ulen = ntohs(uh->len);
	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;

	BUG_ON(ulen > skb->len);

	sk = udp4_lib_lookup(dev_net(skb->dev), saddr, uh->source,
			daddr, uh->dest, skb->skb_iif);

	WARN_ON(sk == NULL);
	if (sk != NULL)
	{
		int ret;

		ret = my_own_udp_queue_rcv_skb(sk, skb);
//		ret = udp_queue_rcv_skb(sk, skb);
		sock_put(sk);

		/* a return value > 0 means to resubmit the input, but
		 * it wants the return to be -protocol, or 0
		 */
		if (ret > 0)
		{
			EPRINTK("ret : %d\n", ret);
			return -ret;
		}
		return ret;
	}
	kfree_skb(skb);
	return -1;
}

static void skb_udp_add_header(struct sk_buff *skb , unsigned short dst_port, unsigned short src_port, uint32_t ip_addr, uint32_t data_len)
{
	struct udphdr *uh;
	struct iphdr *iph;

	skb_push(skb, UDP_HLEN);
	skb_reset_transport_header(skb);
	uh = udp_hdr(skb);
	uh->dest = htons(dst_port);
	uh->source = htons(src_port);
	uh->len = htons(data_len + UDP_HLEN);
	skb->network_header = 0;
	iph = ip_hdr(skb);
	iph->daddr = htonl(my_infor.ip_addr);
	iph->saddr = htonl(ip_addr);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = htons(ETH_P_IP);
	skb->dev = NIC;
	skb->skb_iif = NIC->ifindex;
	skb_shinfo(skb)->nr_frags = 0;
	skb_shinfo(skb)->frag_list = NULL;
	skb_shinfo(skb)->frags[0].page.p = NULL;
}

static int recv_section(co_located_vm *vm)
{
	xf_handle_t *rx_ring = vm->rx_ring;
	xf_descriptor_t *des = rx_ring->descriptor;
	bf_data_t *p_data_head = NULL;
	char *p_front = NULL, *p_back = NULL, *p_fifo = (char *)rx_ring->fifo, *p_end = &p_fifo[des->ring_size];
	uint32_t type = -1, data_len = 0;
	struct sk_buff *skb = NULL;
	struct receive_buf *buf = NULL;
	bool tcp_recv_full = false;

#if ENABLE_TWO_STAGE_RDWR
	spin_lock(&des->head_lock);
	p_data_head = (bf_data_t *)&p_fifo[(des->front_r & des->index_mask)];
	if (!p_data_head->complete || des->front_r == des->back)//data not write or empty
	{
		spin_unlock(&des->head_lock);
		return -1;
	}
	type = p_data_head->type;
	data_len = p_data_head->pkt_len;
	BUG_ON(type != XMIT_UDP && type != XMIT_TCP);
	p_front = &p_fifo[(des->front_r + (1 << MDATA_ORDER))&des->index_mask];
	p_back = &p_fifo[(des->front_r + ((1 + (data_len >> MDATA_ORDER) + !!(data_len&MDATA_SHIFT)) << MDATA_ORDER)) & des->index_mask];
#if ENABLE_AREA_LOCK
	reader_area_lock(des, des->front_r);
#endif
	des->front_r += (1 + (data_len >> MDATA_ORDER) + !!(data_len&MDATA_SHIFT)) << MDATA_ORDER;
	if (type == XMIT_TCP)
	{
		buf = kzalloc(sizeof(receive_buf) + data_len, GFP_ATOMIC);
		BUG_ON(!buf);
		buf->next = NULL;
		buf->len = data_len;
		buf->my_port = p_data_head->dst_port;
		buf->peer_port = p_data_head->src_port;
		buf->data = (unsigned char *)buf + sizeof(receive_buf);
		buf->complete = false;
		//add by newcent@Dec 2, 2015 tcp section should assure data order in vmc_sock same as data order in ring buffer
		//but for UDP, the protocol dose not promise correctness, so can insert sk_buff after data copy
		vmc_tcp_rcv(buf, vm);
	}
	spin_unlock(&des->head_lock);
	if (data_len == 0)
	{
		reader_area_unlock(des);
		goto jump;
	}
	if (type == XMIT_UDP)
	{
		skb = alloc_skb(data_len + IP_HLEN + UDP_HLEN, GFP_ATOMIC);
		skb_reserve(skb, IP_HLEN + UDP_HLEN);
		//  copy data from shared buffer to skb->data
		skb_put(skb, data_len);
		if (p_back >= p_front)
		{
			memcpy(skb->data, p_front, data_len);
		}
		else
		{
			memcpy(skb->data, p_front, p_end - p_front);
			memcpy(skb->data + (p_end - p_front), p_fifo, data_len - (p_end - p_front));
		}
		//add udp header
		skb_udp_add_header(skb, p_data_head->dst_port, p_data_head->src_port, vm->infor.ip_addr, data_len);
	}
	else
	{
		if (p_back > p_front || p_back == p_fifo)
		{
			memcpy(buf->data, p_front, data_len);
		}
		else
		{
			memcpy(buf->data, p_front, p_end - p_front);
			memcpy(buf->data + (p_end - p_front), p_fifo, data_len - (p_end - p_front));
		}
	}
#if ENABLE_AREA_LOCK
	reader_area_unlock(des);
#endif
	if (vm->rx_ring->descriptor->wait_for_space)
//		notify_remote_via_irq(VM_TX_IRQ_NS(vm));
		tell_remote_to_wakeup_xmit_ns(vm);
	if (type == XMIT_UDP)
	{
		vmc_udp_rcv(skb);
	}
	else
	{
		buf->complete = true;
		wake_up_vmc_tcp_sock(vm, buf->my_port, buf->peer_port);
		if (atomic_read(&des->tcp_buf_size) >= DEFAULT_MAX_TCP_BUF_SIZE)//give up cpu for user task read data
		{
			tcp_recv_full = true;
		}
	}
jump:
	spin_lock(&des->head_lock);
	des->front_w += (1 + (data_len >> MDATA_ORDER) + !!(data_len&MDATA_SHIFT)) << MDATA_ORDER;
	spin_unlock(&des->head_lock);
#else
	BUG_ON(before(des->back, des->front));
	spin_lock(&des->head_lock);
	p_data_head = (bf_data_t *)&p_fifo[(des->front & des->index_mask)];
	type = p_data_head->type;
	data_len = p_data_head->pkt_len;
	BUG_ON(type != XMIT_UDP && type != XMIT_TCP);
	p_front = &p_fifo[(des->front + (1 << MDATA_ORDER))&des->index_mask];
	p_back = &p_fifo[(des->front + ((1 + (data_len >> MDATA_ORDER) + !!(data_len&MDATA_SHIFT)) << MDATA_ORDER)) & des->index_mask];
	if (data_len == 0)
		goto jump;
	if (type == XMIT_UDP)
	{
		skb = alloc_skb(data_len + IP_HLEN + UDP_HLEN, GFP_ATOMIC);
		skb_reserve(skb, IP_HLEN + UDP_HLEN);
		//  copy data from shared buffer to skb->data
		skb_put(skb, data_len);
		if (p_back > p_front || p_back == p_fifo)
		{
			memcpy(skb->data, p_front, data_len);
		}
		else
		{
			if ((data_len - (p_end - p_front)) < 0)
			{
				DPRINTK("data_len:%d (p_end - p_front):%d\n", data_len, p_end - p_front);
				BUG();
			}
			BUG_ON((data_len - (p_end - p_front)) < 0);
			memcpy(skb->data, p_front, p_end - p_front);
			memcpy(skb->data + (p_end - p_front), p_fifo, data_len - (p_end - p_front));
		}
		//add udp header
		skb_udp_add_header(skb, p_data_head->dst_port, p_data_head->src_port, vm->infor.ip_addr, data_len);
	}
	else
	{
		buf = kzalloc(sizeof(receive_buf) + data_len, GFP_ATOMIC);
		BUG_ON(!buf);
		buf->next = NULL;
		buf->len = data_len;
		buf->my_port = p_data_head->dst_port;
		buf->peer_port = p_data_head->src_port;
		buf->data = (unsigned char *)buf + sizeof(receive_buf);
		if (p_back > p_front || p_back == p_fifo)
		{
			memcpy(buf->data, p_front, data_len);
		}
		else
		{
			BUG_ON((data_len - (p_end - p_front)) < 0);
			memcpy(buf->data, p_front, p_end - p_front);
			memcpy(buf->data + (p_end - p_front), p_fifo, data_len - (p_end - p_front));
		}
	}
	if (type == XMIT_UDP)
	{
		vmc_udp_rcv(skb);
	}
	else
	{
		vmc_tcp_rcv(buf, vm);
		if (atomic_read(&des->tcp_buf_size) >= DEFAULT_MAX_TCP_BUF_SIZE)//give up cpu for user task read data
		{
			tcp_recv_full = true;
		}
	}
jump:
	des->front += (1 + (data_len >> MDATA_ORDER) + !!(data_len&MDATA_SHIFT)) << MDATA_ORDER;
	spin_unlock(&des->head_lock);
	if (des->wait_for_space)
		notify_remote_via_irq(VM_TX_IRQ_NS(vm));
#endif
	if (tcp_recv_full)
		return -1;
	return 0;
}

#ifdef USE_NAPI_STRUCT

static int xenvmc_rx_poll(struct napi_struct *napi, int budget)
{
#if ENABLE_MULTI_RING_READER
	co_located_vm *vm = container_of(napi, co_located_vm, napi[smp_processor_id()%READER_NUM]);
#else
	co_located_vm *vm = container_of(napi, co_located_vm, napi);
#endif
	xf_handle_t *rx = vm->rx_ring;
//	xf_descriptor_t *des = rx->descriptor;
	bool tcp_recv_full = false;
	int work_done;
	unsigned long flags;

	rmb(); /* Ensure we see queued responses up to 'rp'. */

	work_done = 0;
	while (!xf_empty(rx) && (work_done < budget))
	{
		if (recv_section(vm))
		{
			tcp_recv_full = true;
			break;
		}

		NIC->last_rx = jiffies;
		work_done++;
	}

	if (work_done < budget)
	{
		local_irq_save(flags);
		if (xf_empty(rx) /*|| tcp_recv_full*/)
		{
			__napi_complete(napi);
			if (test_bit(WAIT_FOR_RX_CHANNEL_EMPTY, &vm->vm_flags) && xf_empty(rx))
				wake_up_interruptible(&vm->wait_queue);
		}
		local_irq_restore(flags);
	}

	return work_done;
}
#endif

#ifdef USE_NAPI_STRUCT
//add by newcent@Jul 8, 2015
//modified from netif_napi_add
static void napi_add_poll(struct napi_struct *napi,
            int (*poll)(struct napi_struct *, int), int weight)
{
    INIT_LIST_HEAD(&napi->poll_list);
    napi->gro_count = 0;
    napi->gro_list = NULL;
    napi->skb = NULL;
    napi->poll = poll;
    napi->weight = weight;
    napi->dev = NULL;
#ifdef CONFIG_NETPOLL
    spin_lock_init(&napi->poll_lock);
    napi->poll_owner = -1;
#endif
    set_bit(NAPI_STATE_SCHED, &napi->state);
}
#endif

co_located_vm *__insert_vm_to_table(HashTable * ht, u32 ip, u8 domid, char *mac)
{
	Bucket *ip_bucket = &ht->ip_table[hash_ip(ip)];
	co_located_vm * vm;
	int i;

	vm = kmem_cache_zalloc(ht->entries, GFP_ATOMIC);
	BUG_ON(!vm);
	memcpy(vm->infor.mac, mac, ETH_ALEN);
	vm->infor.ip_addr = ip;
	vm->infor.domid = domid;
	vm->ack_timer = NULL;
	vm->status = E_VMC_VM_STATUS_INIT;
	vm->listen_flag = 0xff;
	vm->retry_count = 0;
	vm->rx_ring = NULL;
	vm->tx_ring = NULL;
	for (i = 0; i < VMC_TCP_SOCK_HASH_SIZE; i++)
	{
		INIT_LIST_HEAD(&vm->vmc_tcp_sock[i]);
	}
	init_waitqueue_head(&vm->wait_queue);
	rwlock_init(&vm->lock);
#ifdef USE_NAPI_STRUCT
#if ENABLE_MULTI_RING_READER
	for (i = 0; i < READER_NUM; i++)
	{
		napi_add_poll(&vm->napi[i], xenvmc_rx_poll, 32);
	}
#else
	napi_add_poll(&vm->napi, xenvmc_rx_poll, 32);
#endif
#endif
//	spin_lock_irqsave(&glock, flags);
	write_lock(&ht->lock);
	list_add(&vm->ip_list, &(ip_bucket->bucket));
	ht->count++;
	write_unlock(&ht->lock);
	return vm;
}

co_located_vm *insert_vm_to_table(u32 ip, u8 domid, char *mac)
{
	HashTable *ip_domid_map = get_hash_table();
	return __insert_vm_to_table(ip_domid_map, ip, domid, mac);
}

int update_vm_status(co_located_vm *vm, u8 status)
{
	write_lock_irq(&vm->lock);
	vm->status = status;
	write_unlock_irq(&vm->lock);
	return 0;
}

int __mark_all_vm_suspend(HashTable *ht)
{
	co_located_vm *vm;
	struct list_head *x, *y;
	Bucket * table = ht->ip_table;
	int i;

	read_lock(&ht->lock);
	for(i = 0; i < HASH_SIZE; i++) {
		list_for_each_safe(x, y, &(table[i].bucket)) {
			vm = list_entry(x, co_located_vm, ip_list);
			update_vm_status(vm, E_VMC_VM_STATUS_SUSPEND);
//			notify_remote_via_irq(vm->rx_irq);
			tell_remote_to_receive(vm);
		}
	}
	read_unlock(&ht->lock);
	return 0;
}

int mark_all_vm_suspend(void)
{
	return __mark_all_vm_suspend(get_hash_table());
}

bool is_empty_vm_set(void)
{
	HashTable *ht = get_hash_table();
	return ht->count == 0;
}

bool need_wake_send_remove_vm(co_located_vm *vm) {
	HashTable *ht = get_hash_table();
	bool need_wake_up_freeze = false;

	write_lock(&ht->lock);
	list_del(&vm->ip_list);
	ht->count--;
	write_unlock(&ht->lock);

//	need_wake_up_send = test_bit(WAIT_FOR_VM_REMOVE, &vm->vm_flags);
	need_wake_up_freeze = test_bit(WAIT_FOR_VM_CONNECT_OR_DELETE, &vm->vm_flags);
	if (vm->listen_flag)
	{
		bf_destroy(vm);
	}
	else
	{
		bf_disconnect(vm);
	}

	if (vm->ack_timer)
		del_timer_sync(vm->ack_timer);
	kmem_cache_free(ht->entries, vm);
	return need_wake_up_freeze;
}

