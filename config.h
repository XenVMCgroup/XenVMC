/*
 * config.h
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
#ifndef CONFIG_H_
#define CONFIG_H_

//#define DEBUG

#define DEBUG_EVTCHN_REPONSE			1

#define DEFAULT_MAX_TCP_BUF_SIZE		(0x01<<22)
#define RING_BUF_SIZE					(0x1<<19)

#if 1
#define TCP_TX_WIN_SIZE					(RING_BUF_SIZE>>4)
#define TCP_RX_WIN_SIZE					(TCP_TX_WIN_SIZE>>1)
#else
#define TCP_RX_WIN_SIZE					(RING_BUF_SIZE>>4)
#define TCP_TX_WIN_SIZE					(TCP_RX_WIN_SIZE>>1)
#endif


#define ENABLE_SEND_RX_EVT_ON_DEMAND	0
//for multi-reader
#define TEST_RX_IPI_EVTCHN				0

#define ENABLE_MULTI_RING_READER		0
#if ENABLE_MULTI_RING_READER
	#define READER_NUM					2 //READER_NUM should not larger than NR_CPU
	#define ENABLE_TWO_STAGE_RDWR		1
	#define ENABLE_MULTI_RX_EVTCHN		0
	#if ENABLE_MULTI_RX_EVTCHN
		#define RX_EVTCHN_NUM				(READER_NUM)
	#endif
	#if ENABLE_TWO_STAGE_RDWR
		#define ENABLE_AREA_LOCK		1
		#if ENABLE_AREA_LOCK
			#define	ENABLE_RESERVE_SIZE			0
		#else
			#define ENABLE_RESERVE_SIZE			1
		#endif
	#endif
	#define VIRQ_VMC_RX					10
#else
	#define ENABLE_TWO_STAGE_RDWR		0
	#define ENABLE_RESERVE_SIZE			0
	#define ENABLE_AREA_LOCK			0
	#define ENABLE_MULTI_RX_EVTCHN		0
#endif

#endif /* CONFIG_H_ */
