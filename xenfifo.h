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



#ifndef _XENFIFO_H_
#define _XENFIFO_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>

#include <xen/xenbus.h>
#include <xen/evtchn.h>
#include <net/tcp.h>

#include "config.h"
#include "debug.h"

#define MAX_FIFO_PAGES 128
#define MAX_FIFO_PAGE_ORDER 7

/* 
 * Shared FIFO descriptor page 
 * 	sizeof(xf_descriptor_t) should be no bigger than PAGE_SIZE
 */
typedef struct xf_descriptor {
	uint32_t		wait_for_space			:1;//flag means share buffer no space to send by
	uint32_t		wait_for_peer			:1;//flag means send too fast, peer communicator need too large buffer to store buf received for user receiving
	uint32_t		reserved				:30;
	uint32_t 		num_pages;
	int 			grefs[MAX_FIFO_PAGES]; /* grant references to FIFO pages -- Not too many
				      pages expected right now */
	int 			dgref;
#if ENABLE_TWO_STAGE_RDWR
	uint32_t		front_r, front_w, back;
#if ENABLE_AREA_LOCK
	uint32_t		area_lock[READER_NUM];
#endif
#else
	uint32_t 		front, back; /* Range of these indices must be power of 2 and larger than max_data_entries.*/
#endif
#if ENABLE_SEND_RX_EVT_ON_DEMAND
#if ENABLE_MULTI_RING_READER
	uint8_t			napi_scheduled[READER_NUM];
#else
	uint8_t			napi_scheduled;
#endif
#endif
	uint32_t		ring_size;
	uint32_t		index_mask;
	spinlock_t 		head_lock;
	spinlock_t		tail_lock;
//	atomic_t		read;
//by newcent@Jul 16, 2015
/***for tcp used, means the size of the buf received by my_own_tcp_rcv but not read by user layer
	no need for udp, because udp protocol will discard the skb if upper layer can not read data in time*/
	atomic_t		tcp_buf_size;
}xf_descriptor_t;


typedef struct xf_handle {
	xf_descriptor_t*	descriptor;
	void*				fifo;
	int 				listen_flag;
	struct vm_struct*	descriptor_vmarea;
	grant_handle_t 		dhandle;
	struct vm_struct*	fifo_vmarea;
	grant_handle_t 		fhandles[MAX_FIFO_PAGES];
}xf_handle_t;


/******************* Listener functions *********************************/
extern xf_handle_t *xf_create(domid_t remote_domid, unsigned int ring_size);
extern int xf_destroy(xf_handle_t *xfl);
/******************* Connector functions *********************************/
extern xf_handle_t *xf_connect(domid_t remote_domid, int remote_gref);
extern int xf_disconnect(xf_handle_t *xfc);

/************** FUNCTIONS FOR BOTH LISTENER AND CONNECTOR ******************
 * Although it may be best if one side sticks to push/back and other to pop/front 
 ****************************************************************************/

#if ENABLE_TWO_STAGE_RDWR
#if ENABLE_AREA_LOCK
static inline void reader_area_lock(xf_descriptor_t *des, uint32_t reader_start_pos)
{
	des->area_lock[smp_processor_id()%READER_NUM] = reader_start_pos + des->ring_size;
}

static inline void reader_area_unlock(xf_descriptor_t *des)
{
	des->area_lock[smp_processor_id()%READER_NUM] = -1;//also can be other value
}

static inline bool check_conflict(xf_descriptor_t *des, uint32_t writer_end_pos)
{
	int i;
	for(i = 0; i < READER_NUM; i++)
	{
		if(des->area_lock[i] != -1 && after(writer_end_pos, des->area_lock[i]))
			return true;
	}
	return false;
}

static inline void writer_area_lock(xf_descriptor_t *des, uint32_t writer_end_pos)
{
	while(check_conflict(des, writer_end_pos))
		cpu_relax();
}
#endif
#endif

static inline uint32_t xf_size(xf_handle_t *h)
{
#if ENABLE_TWO_STAGE_RDWR
	return (h->descriptor->back - h->descriptor->front_w);
#else
	return h->descriptor->back - h->descriptor->front;
#endif
}

static inline uint32_t xf_free(xf_handle_t *h)
{
#if ENABLE_RESERVE_SIZE
	return  h->descriptor->ring_size>>1 - xf_size(h);
#else
	return  h->descriptor->ring_size - xf_size(h);
#endif
}

static inline int xf_full(xf_handle_t *h)
{
	return ( xf_size(h) == h->descriptor->ring_size);
}

static inline int xf_empty(xf_handle_t *h)
{
	return ( xf_size(h) == 0 );
}


/*
 * Return a reference to a free data value at the back of the FIFO. 
 * xf_back does not remove the data from the FIFO. Call xf_push to do so.
 * Returns  NULL if FIFO is FULL
 */
#define xf_back(handle, type) (  					\
{ 									\
type * _xf_ret;								\
do									\
{									\
	xf_descriptor_t *_xf_des = handle->descriptor;			\
	type *_xf_fifo = (type *)handle->fifo;				\
									\
	if( xf_full(handle) ) {						\
		_xf_ret = NULL;						\
		break;							\
	}								\
									\
	_xf_ret = &_xf_fifo[_xf_des->back & _xf_des->index_mask];	\
 									\
} while (0);								\
_xf_ret;								\
}									\
)

/*
 * Return a reference to the data value at the front of the FIFO. 
 * xf_front does not remove the data from the FIFO. Call xf_pop to do so.
 * Returns  NULL if FIFO is empty
 */
#define xf_front(handle, type) (  				\
{ 									\
type * _xf_ret;								\
do									\
{									\
	xf_descriptor_t *_xf_des = handle->descriptor;			\
	type *_xf_fifo = (type *)handle->fifo;				\
									\
	if( xf_empty(handle) ) {					\
		_xf_ret = NULL;						\
		break;							\
	}								\
									\
	_xf_ret = &_xf_fifo[_xf_des->front & _xf_des->index_mask];	\
 									\
} while (0);								\
_xf_ret;								\
}									\
)

/*
 * Return pointer to entry at position index in FIFO
 * Doesn't check if index is within front and back
 */
#define xf_entry(handle, type, index) (					\
{ 									\
type * _xf_ret;								\
do									\
{									\
	xf_descriptor_t *_xf_des = handle->descriptor;			\
	type *_xf_fifo = (type *)handle->fifo;				\
									\
	_xf_ret = &_xf_fifo[ (_xf_des->front + index) & _xf_des->index_mask]; \
 									\
} while (0);								\
_xf_ret;								\
}									\
)

#endif // _XENFIFO_H_
