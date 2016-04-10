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

#include <asm/xen/page.h>
#include <xen/grant_table.h>
#include <asm/xen/hypercall.h>
#include <linux/gfp.h>
#include <asm-generic/getorder.h>
#include "debug.h"
#include "xenfifo.h"
#include "maptable.h"

/*
 * Create a listener-end of FIFO to which a remote domain can connect
 *	Called by the listener end of FIFO
 *	
 * @remote_domid - remote domain  allowed to connect
 *
 * Returns: pointer to the shared FIFO struct
 */
//xf_handle_t *xf_create(domid_t remote_domid, unsigned int entry_size, unsigned int entry_order)
xf_handle_t *xf_create(domid_t remote_domid, unsigned int ring_size)
{
	unsigned long page_order = get_order(ring_size);
	xf_handle_t * xfl = NULL;
	xf_descriptor_t *des = NULL;
	int i;

	BUG_ON((1 << page_order)*PAGE_SIZE != ring_size);
	BUG_ON(sizeof(xf_descriptor_t) > PAGE_SIZE);

	if (page_order > MAX_FIFO_PAGE_ORDER)
	{
		EPRINTK("%d > 2^MAX_PAGE_ORDER pages requested for FIFO\n", 1<<page_order);
		goto err;
	}

	xfl = kzalloc(sizeof(xf_handle_t), GFP_KERNEL);
	if (!xfl)
	{
		EPRINTK("Out of memory\n");
		goto err;
	}
	xfl->descriptor = (xf_descriptor_t *) __get_free_page(GFP_KERNEL);
	if (!xfl->descriptor)
	{
		EPRINTK("Cannot allocate descriptor memory page for FIFO\n");
		goto err;
	}

	xfl->fifo = (void *) __get_free_pages(GFP_KERNEL, page_order);
	if (!xfl->fifo)
	{
		EPRINTK("Cannot allocate buffer memory pages for FIFO\n");
		goto err;
	}

	xfl->listen_flag = 1;
	des = xfl->descriptor;
	des->wait_for_peer = 0;
	des->wait_for_space = 0;
	atomic_set(&des->tcp_buf_size, 0);
	des->num_pages = (1 << page_order);
	des->index_mask = ring_size - 1;
	des->ring_size = ring_size;
	spin_lock_init(&des->head_lock);
	spin_lock_init(&des->tail_lock);
#if ENABLE_TWO_STAGE_RDWR
	des->front_r = xfl->descriptor->front_w = 0;
	des->back = 0;
#else
	des->front = des->back = 0;
#endif

	des->dgref = gnttab_grant_foreign_access(remote_domid,
			virt_to_mfn(des), 0);
	if (des->dgref < 0)
	{
		EPRINTK("Cannot share descriptor gref page %p\n", xfl->descriptor);
		goto err;
	}

	for (i = 0; i < des->num_pages; i++)
	{

		des->grefs[i] = gnttab_grant_foreign_access(remote_domid,
				virt_to_mfn(((uint8_t *)xfl->fifo) + i*PAGE_SIZE), 0);

		if (des->grefs[i] < 0)
		{
			EPRINTK("Cannot share FIFO %p page %d\n", xfl->fifo, i);
			while (--i)
				gnttab_end_foreign_access_ref(des->grefs[i], 0);
			gnttab_end_foreign_access_ref(des->dgref, 0);
			goto err;
		}
	}

	return xfl;

err:
	if (xfl)
	{
		if (des)
			free_page((unsigned long)des);
		if (xfl->fifo)
			free_pages((unsigned long) xfl->fifo, page_order);
		kfree(xfl);
	}

	return NULL;
}

/*
 * Destroy the FIFO
 * 	Can only be called by the creator (listener)
 *
 * Returns: 0 on success, -1 on failure
 */
int xf_destroy(xf_handle_t *xfl)
{
	int i;

	if (!xfl || !xfl->descriptor || !xfl->fifo)
	{
		EPRINTK("xfl OR descriptor OR fifo is NULL\n");
		return -1;
	}

	for (i = 0; i < xfl->descriptor->num_pages; i++)
	{
		gnttab_end_foreign_access_ref(xfl->descriptor->grefs[i], 0);
	}
	gnttab_end_foreign_access_ref(xfl->descriptor->dgref, 0);

	free_pages((unsigned long) xfl->fifo, get_order(xfl->descriptor->num_pages*PAGE_SIZE));
	free_page((unsigned long)xfl->descriptor);
	return 0;
}


/*
 * Connect to a FIFO listener on another domain
 */

xf_handle_t *xf_connect(domid_t remote_domid, int remote_gref)
{
	xf_handle_t *xfc = NULL;
	struct gnttab_map_grant_ref map_op;
	int ret;
	int i;

	xfc = kzalloc(sizeof(xf_handle_t), GFP_KERNEL);
	if (!xfc)
	{
		EPRINTK("Out of memory\n");
		return NULL;
	}

	xfc->descriptor_vmarea = alloc_vm_area(PAGE_SIZE, NULL);
	xfc->fifo_vmarea = alloc_vm_area(MAX_FIFO_PAGES * PAGE_SIZE, NULL);

	if (!xfc->descriptor_vmarea || !xfc->fifo_vmarea)
	{
		EPRINTK("error: cannot allocate memory for descriptor OR FIFO\n");
		goto err;
	}

	gnttab_set_map_op(&map_op, (unsigned long) xfc->descriptor_vmarea->addr, GNTMAP_host_map,
			remote_gref, remote_domid);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &map_op, 1);
	if (ret || (map_op.status != GNTST_okay))
	{
		EPRINTK("HYPERVISOR_grant_table_op failed ret = %d status = %d\n", ret, map_op.status);
		goto err;
	}

	xfc->listen_flag = 0;
	xfc->descriptor = xfc->descriptor_vmarea->addr;
	xfc->fifo = xfc->fifo_vmarea->addr;
	xfc->dhandle = map_op.handle;

	for (i = 0; i < xfc->descriptor->num_pages; i++)
	{

		gnttab_set_map_op(&map_op, (unsigned long) (xfc->fifo_vmarea->addr + i * PAGE_SIZE),
				GNTMAP_host_map, xfc->descriptor->grefs[i], remote_domid);

		ret = HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &map_op, 1);

		if (ret || (map_op.status != GNTST_okay))
		{
			struct gnttab_unmap_grant_ref unmap_op;

			EPRINTK("HYPERVISOR_grant_table_op failed ret = %d status = %d\n", ret, map_op.status);
			while (--i >= 0)
			{
				gnttab_set_unmap_op(&unmap_op, (unsigned long) xfc->fifo_vmarea->addr + i
						*PAGE_SIZE, GNTMAP_host_map, xfc->fhandles[i]);
				ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
				if (ret)
					EPRINTK("HYPERVISOR_grant_table_op unmap failed ret = %d \n", ret);
			}

			gnttab_set_unmap_op(&unmap_op, (unsigned long) xfc->descriptor_vmarea->addr,
					GNTMAP_host_map, xfc->dhandle);
			ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
			if (ret)
				EPRINTK("HYPERVISOR_grant_table_op unmap failed ret = %d \n", ret);

			goto err;
		}

		xfc->fhandles[i] = map_op.handle;
	}

	return xfc;

err:
	if (xfc)
	{
		if (xfc->fifo_vmarea)
			free_vm_area(xfc->fifo_vmarea);
		if (xfc->descriptor_vmarea)
			free_vm_area(xfc->descriptor_vmarea);
		kfree(xfc);
	}
	TRACE_ERROR;
	return NULL;
}

int xf_disconnect(xf_handle_t *xfc)
{
	struct gnttab_unmap_grant_ref unmap_op;
	int i, num_pages, ret;

	if (!xfc || !xfc->descriptor_vmarea || !xfc->descriptor || !xfc->fifo_vmarea || !xfc->fifo)
	{
		EPRINTK("Something is NULL\n");
		goto err;
	}

	num_pages = xfc->descriptor->num_pages;
	for (i = 0; i < num_pages; i++)
	{
		gnttab_set_unmap_op(&unmap_op, (unsigned long) (xfc->fifo_vmarea->addr + i * PAGE_SIZE),
				GNTMAP_host_map, xfc->fhandles[i]);
		ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
		if (ret)
			EPRINTK("HYPERVISOR_grant_table_op unmap failed ret = %d \n", ret);
	}

	gnttab_set_unmap_op(&unmap_op, (unsigned long) xfc->descriptor_vmarea->addr, GNTMAP_host_map,
			xfc->dhandle);
	ret = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1);
	if (ret)
		EPRINTK("HYPERVISOR_grant_table_op unmap failed ret = %d \n", ret);

	free_vm_area(xfc->descriptor_vmarea);
	free_vm_area(xfc->fifo_vmarea);

	kfree(xfc);

	return 0;
err:
	TRACE_ERROR;
	return -1;
}

