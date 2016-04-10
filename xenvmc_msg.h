/*
 * xenvmc_msg.h
 *
 *  Created on: Nov 12, 2015
 *      Author: newcent
 */

#ifndef XENVMC_MSG_H_
#define XENVMC_MSG_H_

#define MAX_VM_NUM		(10)

enum E_MSG_TYPE
{
	E_VMC_MSG_REGISTER,
	E_VMC_MSG_DOMU_MIGRATING,

	E_VMC_MSG_CHANNEL_CONNECT,
	E_VMC_MSG_CHANNEL_ACCEPT,
	E_VMC_MSG_CHANNEL_RELEASE,
	E_VMC_MSG_CHANNEL_RELEASE_ACK,

	E_VMC_MSG_VMC_TCP_SOCK_CONNECT,
	E_VMC_MSG_VMC_TCP_SOCK_ACCEPT,
	E_VMC_MSG_VMC_TCP_SOCK_CLOSE,

	E_VMC_MSG_REGISTER_ACK,

	E_VMC_MSG_VM_ADD,
	E_VMC_MSG_VM_DELETE,
	E_VMC_MSG_VM_MIGRATING,

	E_VMC_MSG_VM_ADD_ACK,
	E_VMC_MSG_VM_DELETE_ACK,
	E_VMC_MSG_VM_MIGRATING_ACK,
};


typedef struct vm_item
{
	u8		mac[ETH_ALEN];
	u32		ip_addr;
	domid_t	domid;
}vm_infor;

typedef struct vm_set
{
	vm_infor	vm[MAX_VM_NUM];
	int			version;
	int			vm_num;
}vm_set;

typedef struct message
{
	u32		type;
	int 	vm_num;
	int 	vm_version;
//	vm_infor	vm[MAX_VM_NUM];
	u8		mac[MAX_VM_NUM][ETH_ALEN];
	u32		ip_addr[MAX_VM_NUM];
	domid_t	domid[MAX_VM_NUM];
	int gref_in;
	int gref_out;
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
	int remote_rx_evtchn[RX_EVTCHN_NUM];
#else
	int remote_rx_evtchn;
#endif
	int remote_tx_evtchn_ns;
	int remote_tx_evtchn_tsc;
	u16 src_port;
	u16 peer_port;
	u32	write_seq;
} message_t;

#endif /* XENVMC_MSG_H_ */
