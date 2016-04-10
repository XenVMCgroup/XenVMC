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

#ifndef BIFIFO_H
#define BIFIFO_H

int bf_create(co_located_vm *vm);
#if ENABLE_MULTI_RING_READER && ENABLE_MULTI_RX_EVTCHN
int bf_connect(co_located_vm *vm, int rgref_in, int rgref_out, int *remote_rx_evtchn, int remote_tx_evtchn_ns, int remote_tx_evtchn_tsc);
#else
int bf_connect(co_located_vm *vm, int rgref_in, int rgref_out, int remote_rx_evtchn, int remote_tx_evtchn_ns, int remote_tx_evtchn_tsc);
#endif
void bf_destroy(co_located_vm *vm);
void bf_disconnect(co_located_vm *vm);
irqreturn_t xenvmc_virq_interrupt(int irq, void *dev_id);

int 	update_vm_status(co_located_vm *vm, u8 status);
int 	mark_all_vm_suspend(void);
bool 	is_empty_vm_set(void);
bool 	need_wake_send_remove_vm(co_located_vm *vm);

void tell_remote_to_receive(co_located_vm *vm);
void tell_remote_to_wakeup_xmit_ns(co_located_vm *vm);
void tell_remote_to_wakeup_xmit_tsc(co_located_vm *vm);


#endif // BIFIFO_H
