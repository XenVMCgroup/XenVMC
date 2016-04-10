/*
 *
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



#ifndef _DISCOVERY_H_
#define _DISCOVERY_H_

#define DISCOVER_TIMEOUT 1

#include <uapi/linux/in.h>
#include "xenvmc_msg.h"

#define ETH_P_VMC			0x8888
#define HASH_SIZE			16

enum E_EVT_DOM0_EVENT_TYPE
{
	E_EVT_VMC_DOMU_REGISTER,
	E_EVT_VMC_DOMU_DELETE,
	E_EVT_VMC_DOMU_MIGRATING,
};

typedef struct evt_dom0
{
	struct list_head 	list;
	u8 					type;
	vm_infor 			infor;
}evt_dom0;

typedef struct Bucket
{
	struct list_head bucket;
} Bucket;

typedef struct HashTable
{
	ulong 		count;
	u8			completed;
	Bucket 		domid_table[HASH_SIZE];
	rwlock_t 	lock;
	struct kmem_cache *entries;
} Dom0_HashTable;

typedef struct vm_in_node
{
	struct list_head	domid_list;
	vm_infor 			infor;
	u8 	 				ack;
	struct xenbus_watch watch;
}vm_in_node;


#define LINK_HDR 			sizeof(struct ethhdr)
#define MSGSIZE				sizeof(message_t)
const int	headers = LINK_HDR + MSGSIZE;


#endif /* _DISCOVERY_H_ */
