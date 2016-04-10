/*
 * xensyscall.h
 *
 *  Created on: Nov 25, 2014
 *      Author: newcent
 */

#ifndef XENSYSCALL_H_
#define XENSYSCALL_H_


#define MAX_RETRY_COUNT 5

#define ETH_P_VMC			0x8888

enum E_VMC_VM_EVENT_TYPE
{
	//event for co-located vms
	E_VMC_EVT_REGISGER,
	E_VMC_EVT_REGISTER_FAILED,
	E_VMC_EVT_SELF_PREPARE_TO_MIGRATE,

	//3
	E_VMC_EVT_VM_ADD,
	E_VMC_EVT_VM_DELETE,
	E_VMC_EVT_VM_MIGRATING,

	//6
	//event for channel connect
	E_VMC_EVT_CHANNEL_CONNECT,
	E_VMC_EVT_CHANNEL_ACCEPT,
	E_VMC_EVT_CHANNEL_RELEASE,
	E_VMC_EVT_CHANNEL_RELEASE_ACK,

	//10
	//event for vmc_tcp_sock
	E_VMC_EVT_VMC_TCP_SOCK_CONNECT,
	E_VMC_EVT_VMC_TCP_SOCK_ACCEPT,
	E_VMC_EVT_VMC_TCP_SOCK_SHUTDOWN,
};

enum E_COLACATED_VM_STATUS
{
	E_NEW_VM,
	E_SHARE_MEM_LISTEN,
	E_ACTIVE,
	E_MIGRATE_OUT,
	E_DIED,
	E_NEED_DROP,
};

#define XENSYSCALL_ENTRY_ORDER 15

#define 	LINK_HDR 			sizeof(struct ethhdr)
#define 	MSGSIZE				sizeof(message_t)
#define 	headers 			(LINK_HDR + MSGSIZE)

#endif /* XENSYSCALL_H_ */
