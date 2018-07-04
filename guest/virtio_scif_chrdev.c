/*
 * virtio_scif_chrdev.c
 *
 * Implementation of virtio-scif
 * character device
 *
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "virtio_scif.h"
#include "virtio_scif_chrdev.h"
#include "debug.h"
#include "virtio_scif_ioctl.h"

#include <linux/delay.h>
#include <linux/pagemap.h>

#include <linux/time.h>


/*
 * Global data
 */
struct cdev scif_cdev;


static inline uint64_t align_low(uint64_t data, uint32_t granularity)                                                                         
{                                                                                                                                             
        return ALIGN(data - (granularity - 1), granularity);                                                                                  
}

/**
 * Check to see if the virtqueue packet is for
 * us.
 **/
static int need_to_wakeup(struct scif_device *scif_dev, struct vq_packet *packet)
{
	struct vq_packet *iter;
	struct vq_packet *tmp;
	unsigned long flags;
	bool ret = false;

	debug("Entering");

	//TODO: maybe use reader/writer lock as an optimization
	spin_lock_irqsave(&scif_dev->reply_lock, flags);
	list_for_each_entry_safe(iter, tmp, &scif_dev->packet_list, list) {
		if (iter == packet) {
			list_del(&packet->list);
			kfree(packet);
			ret = true;

			break;
		}
	}
	spin_unlock_irqrestore(&scif_dev->reply_lock, flags);

	debug("Leaving");

	return ret;
}

//static off_t get_offset_from_addr(struct scif_open_file *scif_of, uint8_t * ptr64_t addr)
//{
//	off_t offset = -1;
//	struct reg_window *iter;
//
//	debug("Entering (PID: %d)", current->pid);
//
//	list_for_each_entry(iter, &scif_of->windows_list, list) {
//		debug("offset: 0x%lx, list_offset: 0x%lx), addr: 0x%lx", (long unsigned int)offset, (long unsigned int)iter->reg_offset, (long unsigned int)iter->uaddr);
//
//	}
//
//	debug("Leaving (PID: %d)", current->pid);
//
//	return offset;
//}

static int __release_locked_windows(struct scif_open_file *scif_of, off_t offset, size_t len)
{
	struct reg_window *iter;
	struct reg_window *tmp;
	struct page **pages;
	uint64_t *kaddr;
	size_t rem_len = len;
	int i, j = -1;
	int ret = -EINVAL;

	debug("Entering (PID: %d)", current->pid);

	if (down_interruptible(&scif_of->win_sem))
		return -EINTR;

	list_for_each_entry_safe(iter, tmp, &scif_of->windows_list, list) {
//	debug("unreg offset: 0x%lx, list_offset: 0x%lx)", (long unsigned int)offset, (long unsigned int)iter->reg_offset);
//	debug("unreg length: %d, list_nr_pages: %d)", (unsigned int)len, (unsigned int)iter->nr_pages);

	       /* 
 		* SCIF documentation states that only whole window can be unregistered,
		* but host driver lets us unregister portion of a window if the length
		* reaches window's end (MAYBE A BUG in host driver).
		* In any case, we follow the documentation here.
		*/
		if (offset == iter->reg_offset) {
			//FIXME: delete current window, but next one maynot be whole
			//if (len != (iter->nr_pages << PAGE_SHIFT))
			if (rem_len < (iter->nr_pages << PAGE_SHIFT))
			{
				up(&scif_of->win_sem);
				return -EINVAL;
			}

			pages = iter->pages;

			for (i = 0; i < iter->nr_pages; i++) {
			debug("FD: %d, pages[i] 0x%lx)", scif_of->host_fd.hfd, (long unsigned)pages[i]);
				kunmap(pages[i]);
				if (!PageReserved(pages[i]))
				//FIXME: optimization: mark explicitly touched pages in writes
					SetPageDirty(pages[i]);

				page_cache_release(pages[i]);
			}

			kfree(iter->kaddr);
			kfree(pages);

			list_del(&iter->list);

			rem_len -= ((iter->nr_pages << PAGE_SHIFT));
			//TODO: free the window
			debug("INSIDE SEMI-RELEASE %d)", current->pid);
			kfree(iter);
			if (rem_len <= 0)
				break;
		}
	}

	if (rem_len == 0)
		ret = 0;
	else 
		ret = -EINVAL;

	up(&scif_of->win_sem);

	debug("Leaving (PID: %d)", current->pid);

	return ret;
}

static int release_all_locked_windows(struct scif_open_file *scif_of)
{
	struct reg_window *iter;
	struct reg_window *tmp;
	struct page **pages;
	uint64_t *kaddr;
	int i, j = -1;
	int ret = -1;

	debug("Entering (PID: %d)", current->pid);

	if (down_interruptible(&scif_of->win_sem))
		return -EINTR;

	//list_for_each_entry(iter, &scif_of->windows_list, list) {
	list_for_each_entry_safe(iter, tmp, &scif_of->windows_list, list) {
		pages = iter->pages;

		for (i = 0; i < iter->nr_pages; i++) {
			kunmap(pages[i]);

			if (!PageReserved(pages[i])) {
			//FIXME: optimization: mark explicitly touched pages in writes
				SetPageDirty(pages[i]);
			}

			page_cache_release(pages[i]);
		}

		kfree(iter->kaddr);
		kfree(pages);

		list_del(&iter->list);

		kfree(iter);
	}

	up(&scif_of->win_sem);

	debug("Leaving (PID: %d)", current->pid);

	return 0;
}

static int release_locked_windows(struct scif_open_file *scif_of, int all, off_t offset, size_t len)
{
	if (all)
		return release_all_locked_windows(scif_of);
	else
		return __release_locked_windows(scif_of, offset, len);
}

static int lock_user_pages(struct scif_device *scif_dev, void **winp, struct scif_open_file *scif_of, struct scifioctl_reg **regp, struct scatterlist **old_sgs, struct vq_packet *packet, int *host_ret_val)
{
	struct reg_window *window = *winp;
	struct scifioctl_reg *reg = *regp;
	void *ptr64_t addr = reg->addr;
	uint64_t len = reg->len;
	off_t req_offset = reg->offset;
	int prot = reg->prot;
	int reg_flags = reg->flags;
	int64_t nr_pages;
	struct page **pages;
	uint64_t *kaddr, jaddr;
	struct scatterlist ret_val_sg, arg_sg, *tmp_sg, *addr_sg, **sgs;
	int i, j;
	unsigned long flags;
	unsigned int num_out = 0, num_in = 0;
	//int kmapped = -1, ret = -1, res = -1, host_ret_val = -1;
	int kmapped = -1, ret = -1, res = -1;

	debug("Entering (PID: %d)", current->pid);
	/* Below checks are performed at host driver as well */

	/* Unsupported flags */ 
	if (reg_flags & ~(SCIF_MAP_FIXED | SCIF_MAP_KERNEL))
		//return ERR_PTR(-EINVAL);
		return -EINVAL;

	/* Unsupported protection requested */
	if (prot & ~(SCIF_PROT_READ | SCIF_PROT_WRITE))
		//return ERR_PTR(-EINVAL);
		return -EINVAL;

	/* addr/len must be page aligned. len should be non zero */
	if ((!len) || 
		(align_low((uint64_t)addr, PAGE_SIZE) != (uint64_t)addr) || 
		(align_low((uint64_t)len, PAGE_SIZE) != (uint64_t)len))
		//return ERR_PTR(-EINVAL);
		return -EINVAL;

	/*
	 * req_offset is not page aligned/negative or offset+len
	 * wraps around with SCIF_MAP_FIXED.
	 */
	if ((reg_flags & SCIF_MAP_FIXED) &&
		((align_low(req_offset, PAGE_SIZE) != req_offset) || 
		(req_offset < 0) ||
		(req_offset + (off_t)len < req_offset)))
		//return ERR_PTR(-EINVAL);
		return -EINVAL;

	nr_pages = len >> PAGE_SHIFT;

	//allocate number of pages scattered entries plus 4 entries
	sgs = kmalloc((nr_pages + 4) * sizeof(struct scatterlist *), GFP_KERNEL);
	if (!sgs) 
		return -ENOMEM;

	//setup new sgs with first three old entries
	sgs[num_out++] = old_sgs[0];
	sgs[num_out++] = old_sgs[1];
	sgs[num_out++] = old_sgs[2];
	sg_init_one(&arg_sg, reg, sizeof(struct scifioctl_reg));
	sgs[num_out++] = &arg_sg;

	addr_sg = kmalloc(nr_pages * sizeof(struct scatterlist), GFP_KERNEL);
	if (!addr_sg) {
		kfree(sgs);
		ret = -ENOMEM;
		goto fail;
	}

	if ((pages = kmalloc(nr_pages * sizeof(*pages), GFP_KERNEL)) == NULL) {
		kfree(addr_sg);
		kfree(sgs);
		ret = -ENOMEM;
		goto fail;
	}

	down_read(&current->mm->mmap_sem);

	res = get_user_pages(
			current, 
			current->mm,
			(uint64_t)addr,
			nr_pages,
			!!(prot & SCIF_PROT_WRITE),
			0, /* don't force */
			pages,
			NULL);

	up_read(&current->mm->mmap_sem);

	if (res != nr_pages) {
		kfree(addr_sg);
		kfree(sgs);
		ret = -EFAULT; /* maybe not appropriate errno */
		goto fail;
	}

	kaddr = kmalloc(nr_pages * sizeof(*kaddr), GFP_KERNEL);
	if (!kaddr) {
		kfree(addr_sg);
		kfree(sgs);
		ret = -ENOMEM;

		goto fail;
	}

	/* add the set of pages to the respective window */
	window->uaddr = addr;
	window->pages = pages;
	window->kaddr = kaddr;
	window->nr_pages = nr_pages;

	//store the start of addr_sg in order to kfree() later on
	tmp_sg = addr_sg;
	for (i = 0; i < res; i++) {
		window->kaddr[i] = (uint64_t)kmap(pages[i]);
		debug("kmap address: 0x%llx", (uint64_t)(window->kaddr[i]));
		debug("ZERO kmap address: 0x%llx", (uint64_t)(window->kaddr[0]));
		debug("num_out: %d, num_in: %d\n", num_out, num_in);
		sg_init_one(addr_sg, (uint64_t *)(window->kaddr[i]), PAGE_SIZE);
		sgs[num_out++] = addr_sg++;
	}

	if (down_interruptible(&scif_of->win_sem)) {
		kmapped = 1;
		kfree(kaddr);
		kfree(tmp_sg);
		kfree(sgs);
		ret = -ERESTARTSYS;

		goto fail;
	}

	//TODO: what happens in case of an error in some of the pages in the host 
	//whilst others have been registered 
	list_add_tail(&window->list, &scif_of->windows_list);

	up(&scif_of->win_sem);

	sg_init_one(&ret_val_sg, host_ret_val, sizeof(*host_ret_val));
	sgs[num_out + num_in++] = &ret_val_sg;

	spin_lock_irqsave(&scif_dev->vq_lock, flags);
	ret = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
	if (unlikely(ret)) {
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);
		kfree(kaddr);
		kmapped = 1;
		kfree(tmp_sg);
		kfree(sgs);
		ret = -EAGAIN;

		goto fail_del_list;
	}
	virtqueue_kick(scif_dev->vq);
	spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

	kfree(tmp_sg);
	kfree(sgs);

	debug("Leaving (PID: %d)", current->pid);

	//return host_ret_val;
	return ret;

fail_del_list:
	if (down_interruptible(&scif_of->win_sem))
		return -EINTR;
	list_del(&window->list);
	up(&scif_of->win_sem);

fail:
	//put pages/dirty etc
	if (res > 0) {
		for (i = 0; i < res; i++) {
			if (!PageReserved(pages[i]))
			//probably not needed (pages are here untouched)
				SetPageDirty(pages[i]);
			page_cache_release(pages[i]);

			if (kmapped > 0) kunmap(pages[i]);
		}
		kfree(pages);
	}

	debug("Leaving with error (PID: %d)", current->pid);

	return ret;
}

static int readwrite_sg(struct scif_device *scif_dev, struct scif_open_file *scif_of, struct scifioctl_copy **copyp, struct scatterlist **old_sgs, int *host_ret_val)
{
	struct scifioctl_copy *copy = *copyp;
	struct vq_packet *packet;
	uint64_t len = copy->len;
	struct scatterlist type_sg, ret_val_sg, copy_sg, kaddr_sg, **sgs;
	int i, size, nchunks = len / KMALLOC_MAX_SIZE, rem = len % KMALLOC_MAX_SIZE;
	unsigned long flags;
	unsigned int num_out = 0, num_in = 0;
	void *kaddr;
	uint8_t * ptr64_t tmp_uaddr;
	int kmapped = -1, ret = -1;
	unsigned int type = VIRTIO_SCIF_IOCTL;

	debug("Entering (PID: %d) original length: %d, nchunks: %d. rem: %d", current->pid, (int)len, nchunks, rem);

	sgs = kmalloc(6 * sizeof(struct scatterlist *), GFP_KERNEL);
	if (!sgs) 
		return -ENOMEM;

	sg_init_one(&type_sg, &type, sizeof(type));
	sgs[num_out++] = &type_sg;

	//setup new sgs with two old entries
	//sgs[num_out++] = old_sgs[0];
	sgs[num_out++] = old_sgs[1];
	sgs[num_out++] = old_sgs[2];

	sg_init_one(&copy_sg, copy, sizeof(struct scifioctl_copy));
	sgs[num_out++] = &copy_sg;

	//this is for uarg->addr
	num_out++;

	sg_init_one(&ret_val_sg, host_ret_val, sizeof(*host_ret_val));
	sgs[num_out + num_in++] = &ret_val_sg;

	//re-use addr without re-allocating/freeing it
	kaddr = kmalloc(KMALLOC_MAX_SIZE, GFP_KERNEL);
	if (!sgs) {
		ret = -ENOMEM;
		goto err_sgs;
	}

	size = KMALLOC_MAX_SIZE;

	//copy->addr will be changed
	//by the host
	tmp_uaddr = copy->addr;
	for (i = 0; i < nchunks + 1; i++) {
		if (i == nchunks)
			size = rem;

		copy->len = size;

		if (copy_from_user(kaddr, (void __user *)(copy->addr + i * KMALLOC_MAX_SIZE), size)) {
			ret = -EFAULT;
			goto out;
		}
		
		//we want packet here 
		//only as a token identifier (+ it 
		//contains list elements for wakeup handling),
		//so re-allocate in every loop 
		//since it is freed on every
		//interrupt (inside need_to_wakeup())
		packet = kmalloc(sizeof(*packet), GFP_KERNEL);
		if (!packet) {
			ret = -ENOMEM;

			goto out;
		}

		sg_init_one(&kaddr_sg, kaddr, size);
		sgs[num_out - 1] = &kaddr_sg;
	
		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		ret = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(ret)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(packet);
			ret = -EAGAIN;
			goto out;
		}
		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);
		
		if (wait_event_interruptible(scif_dev->wq, need_to_wakeup(scif_dev, packet))) {
			ret = -ERESTARTSYS;
			kfree(packet);

			goto out;
		}

		ret = *host_ret_val;
		if (ret)
			goto out;

		copy->roffset += size;
		copy->addr = tmp_uaddr;
	}

	debug("Leaving (PID: %d)", current->pid);

out:
	kfree(sgs);
err_sgs:
	kfree(kaddr);
	kfree(*copyp);

	return ret;
}

/*************************************
 * Implementation of file operations
 * for the SCIF character device
 *************************************/

static int scif_chrdev_open(struct inode *inode, struct file *filp)
{
	struct vq_packet *packet;
	//struct scif_open_file *scif_of;
	struct scif_open_file *scif_of = NULL;
	struct scif_device *scif_dev;
	struct scatterlist lock_sg, out_sg, buf_sg, *sgs[3];
	unsigned long flags;
	int err;
	int ret = 0;

	debug("Entering (PID: %d)", current->pid);

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/* Associate this open file with the relevant scif device. */
	//scif_dev = get_scif_dev_by_minor(iminor(inode));
	scif_dev = scif_drvdata.scif_dev;
	if (!scif_dev) {
		debug("Could not find scif device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;

		goto out;
	}

	scif_of = kmalloc(sizeof(*scif_of), GFP_KERNEL);
	if (!scif_of) {
		ret = -ENOMEM;

		goto out;
	}

	//scif_of->scif_dev = scif_dev;
	scif_of->host_fd.hfd = -1;
	sema_init(&scif_of->win_sem, 1);

	init_waitqueue_head(&scif_of->poll_wq);
	INIT_LIST_HEAD(&scif_of->windows_list);
	filp->private_data = scif_of;

	packet = kmalloc(sizeof(*packet), GFP_KERNEL);
	if (!packet) {
		kfree(scif_of);
		ret = -ENOMEM;

		goto out;
	}

	packet->type = VIRTIO_SCIF_OPEN;

	//init_waitqueue_head(&scif_of->poll_wq);

	/**
	 * We need two sg lists, one for type and one to get the 
	 * file descriptor from the host.
	 * TODO: check if we can push both of them into one sg entry
	 **/
	sg_init_one(&out_sg, &packet->type, sizeof(packet->type));
	sgs[0] = &out_sg;
	sg_init_one(&buf_sg, &scif_of->host_fd, sizeof(scif_of->host_fd));
	//sg_init_one(&buf_sg, scif_of, sizeof(*scif_of));
	sgs[1] = &buf_sg;

	spin_lock_irqsave(&scif_dev->vq_lock, flags);
	err = virtqueue_add_sgs(scif_dev->vq, sgs, 1, 1, packet, GFP_ATOMIC);
	if (unlikely(err)) {
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		kfree(scif_of);
		//TODO: packet-heap will remain forever
		//kfree(packet);
		ret = -EAGAIN;

		goto out;
	}

	virtqueue_kick(scif_dev->vq);
	spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

	/* We only need packet as a token identifier of the request/reply */
	err = wait_event_interruptible(scif_dev->wq, need_to_wakeup(scif_dev, packet));

	if (err) {	
		kfree(scif_of);
		//TODO: packet-heap will remain forever
		//kfree(packet);
		ret = -EIO;

		goto out;
	}

	/* If host failed to open() return -ENODEV. */
	if (scif_of->host_fd.hfd == -1) {
		debug("Host failed to open device");
		kfree(scif_of);
		//kfree(packet);
		ret = -EBUSY;

		goto out;
	}

	//INIT_LIST_HEAD(&scif_of->windows_list);

	// free the reply packet
	//kfree(packet);

out:
	debug("Leaving (PID: %d, host->fd: %d)", current->pid, scif_of->host_fd.hfd);
	return ret;
}

static int scif_chrdev_release(struct inode *inode, struct file *filp)
{
	struct scif_open_file *scif_of = filp->private_data;
	struct scif_device *scif_dev = scif_drvdata.scif_dev;
	struct vq_packet *packet;
	struct scatterlist out_sg, buf_sg, *sgs[2];
	unsigned long flags;
	int err;
	int ret = 0;

	/* TODO: check if we need to explicitly call ioctl(SCIF_UNREG), despite closing the epd*/
	debug("Entering (PID: %d)", current->pid);

	packet = kmalloc(sizeof(*packet), GFP_KERNEL);
	if (!packet) {
		ret = -ENOMEM;
		goto out;
	}

	packet->type = VIRTIO_SCIF_CLOSE;

	sg_init_one(&out_sg, &packet->type, sizeof(packet->type));
	sgs[0] = &out_sg;
	sg_init_one(&buf_sg, &scif_of->host_fd, sizeof(scif_of->host_fd));
	//sg_init_one(&buf_sg, scif_of, sizeof(*scif_of));
	sgs[1] = &buf_sg;

	spin_lock_irqsave(&scif_dev->vq_lock, flags);
	err = virtqueue_add_sgs(scif_dev->vq, sgs, 2, 0, packet, GFP_ATOMIC);
	if (unlikely(err)) {
	//FIXME: especially for the release, block repeat until success, otherwise 
	//open file descriptor will remain on the host
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		kfree(scif_of);
		kfree(packet);
		ret = -EAGAIN;

		goto out;
	}

	virtqueue_kick(scif_dev->vq);
	spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

	/* We only need packet as a token identifier of the request/reply */
	err = wait_event_interruptible(scif_dev->wq, need_to_wakeup(scif_dev, packet));

	//FIXME: someone needs to cleanup list contents if a process gets interrupted
	//if (err = -ERSTARTSYS) ... process woken by a signal

	release_locked_windows(scif_of, 1, (off_t)NULL, (size_t)NULL);
	//release_locked_windows(scif_of, 0, (off_t)0x4000000000000000, (size_t)4096);

	kfree(scif_of);
	//kfree(packet);

out:
	debug("Leaving lock (PID: %d)", current->pid);
	return ret;
}

static long scif_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long uarg)
{
	struct vq_packet *packet;
	struct scif_open_file *scif_of = filp->private_data;
	struct scif_device *scif_dev = scif_drvdata.scif_dev;
	struct virtqueue *vq = scif_dev->vq;
	struct scatterlist type_sg, fd_sg, cmd_sg, ret_val_sg,
	                   arg1_sg, arg2_sg, arg3_sg, 
	                   *sgs[8];
	void *arg1 = NULL, *arg2 = NULL, *arg3 = NULL;
	unsigned int num_out = 0, num_in = 0, len;
	unsigned long flags;
	int ret = 0;
	int err;
	int host_ret_val = -1;
	__u32 ses_id;

	//struct timeval t0,t1,t2,t3,t4,t5,t6;
	//long temp;
	//do_gettimeofday(&t0);

	debug("Entering PID: %d\n", current->pid);

	packet = kmalloc(sizeof(*packet), GFP_KERNEL);
	if (!packet) {
		ret = -ENOMEM;
		goto out;
	}

	packet->type = VIRTIO_SCIF_IOCTL;

	/**
	 *  Add type, host_fd and cmd_sg lists. 
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&type_sg, &packet->type, sizeof(packet->type));
	sgs[num_out++] = &type_sg;
	sg_init_one(&fd_sg, &scif_of->host_fd, sizeof(scif_of->host_fd));
	//sg_init_one(&fd_sg, scif_of, sizeof(*scif_of));
	sgs[num_out++] = &fd_sg;
	sg_init_one(&cmd_sg, &cmd, sizeof(cmd));
	sgs[num_out++] = &cmd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
	case SCIF_GET_VERSION:
		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_BIND:
		arg1 = kmalloc(sizeof(uint16_t), GFP_KERNEL);
		if (!arg1) {
	   		ret = -ENOMEM;
		      	goto out_with_packet;
		}

//		scif_bind_handler(uarg, sgs, arg_sg1, (int *)arg1);
		if (copy_from_user(arg1, (void __user *)uarg, sizeof(uint16_t))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        sg_init_one(&arg1_sg, arg1, sizeof(uint16_t));
	        sgs[num_out++] = &arg1_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_LISTEN:
		arg1 = kmalloc(sizeof(int), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		*((int *)arg1) = (int)uarg;

	        sg_init_one(&arg1_sg, arg1, sizeof(void *));
	        sgs[num_out++] = &arg1_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

//			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_CONNECT:
		arg1 = kmalloc(sizeof(struct scifioctl_connect), GFP_KERNEL);
		if (!arg1) {
		 	ret = -ENOMEM;
		      	goto out_with_packet;
		}

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_connect))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

		// we violate the standard since scifioctl_connect has both 
		// in and out members, just to save some cycles..
	        sg_init_one(&arg1_sg, arg1, sizeof(struct scifioctl_connect));
	        sgs[num_out++] = &arg1_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_ACCEPTREQ:
		arg1 = kmalloc(sizeof(struct scifioctl_accept), GFP_KERNEL);
		if (!arg1) {
		 	ret = -ENOMEM;
		      	goto out_with_packet;
		}

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_accept))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        sg_init_one(&arg1_sg, arg1, sizeof(struct scifioctl_accept));
	        sgs[num_out++] = &arg1_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_ACCEPTREG:
		arg1 = kmalloc(sizeof(void *), GFP_KERNEL);
		if (!arg1) {
		 	ret = -ENOMEM;
		      	goto out_with_packet;
		}

		//void * seems weird but checkout real micscif driver 
		if (copy_from_user(arg1, (void __user *)uarg, sizeof(void *))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        sg_init_one(&arg1_sg, arg1, sizeof(void *));
	        sgs[num_out++] = &arg1_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_SEND:
		arg1 = kmalloc(sizeof(struct scifioctl_msg), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_msg))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        //sg_init_one(&arg1_sg, arg1, sizeof(void *));
	        sg_init_one(&arg1_sg, arg1, sizeof(struct scifioctl_msg));
	        sgs[num_out++] = &arg1_sg;

		arg2 = kmalloc(((struct scifioctl_msg *)arg1)->len, GFP_KERNEL);
		if (!arg2) {
			kfree(arg1);
		      	ret = -ENOMEM;
		    	goto out_with_packet;
		}

		if (copy_from_user(arg2, (void __user *)(((struct scifioctl_msg *)uarg)->msg), ((struct scifioctl_msg *)arg1)->len)) {
			kfree(arg2);
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        sg_init_one(&arg2_sg, arg2, ((struct scifioctl_msg *)arg1)->len);
	        sgs[num_out++] = &arg2_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg2);
			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_RECV:
		arg1 = kmalloc(sizeof(struct scifioctl_msg), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_msg))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        //sg_init_one(&arg1_sg, arg1, sizeof(void *));
	        sg_init_one(&arg1_sg, arg1, sizeof(struct scifioctl_msg));
	        sgs[num_out++] = &arg1_sg;

		arg2 = kmalloc(((struct scifioctl_msg *)arg1)->len, GFP_KERNEL);
		if (!arg2) {
			kfree(arg1);
			ret = -ENOMEM;
			goto out_with_packet;
		}

	        sg_init_one(&arg2_sg, arg2, ((struct scifioctl_msg *)arg1)->len);
	        sgs[num_out++] = &arg2_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg2);
			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_REG:
		arg1 = kmalloc(sizeof(struct scifioctl_reg), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}
		//ret = -ENOSYS;
		//goto out_with_packet;

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_reg))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

		arg2 = kmalloc(sizeof(struct reg_window), GFP_KERNEL);
		if (!arg2) {
			kfree(arg1);
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		err = lock_user_pages(scif_dev, 
					&arg2,
					scif_of, 
					(struct scifioctl_reg **)&arg1, 
					sgs, packet, &host_ret_val);
					//&sgs, packet, &host_ret_val);

		if (err < 0) {
			ret = err;
			kfree(arg1);
			kfree(arg2);
			goto out_with_packet;
		}

		break;

	case SCIF_UNREG:
		arg1 = kmalloc(sizeof(struct scifioctl_unreg), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_unreg))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        sg_init_one(&arg1_sg, arg1, sizeof(struct scifioctl_unreg));
	        sgs[num_out++] = &arg1_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);

		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

//		ret = release_locked_windows(scif_of, 
//						0, 
//						((struct scifioctl_unreg *)arg1)->offset, 
//						((struct scifioctl_unreg *)arg1)->len);

//		if (ret < 0) {
//			kfree(arg1);
//			goto out_with_packet;
//		}

		break;

	case SCIF_READFROM:
	case SCIF_WRITETO:
		arg1 = kmalloc(sizeof(struct scifioctl_copy), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_copy))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        sg_init_one(&arg1_sg, arg1, sizeof(struct scifioctl_copy));
	        sgs[num_out++] = &arg1_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_VREADFROM:
		arg1 = kmalloc(sizeof(struct scifioctl_copy), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_copy))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        //sg_init_one(&arg1_sg, arg1, sizeof(void *));
	        sg_init_one(&arg1_sg, arg1, sizeof(struct scifioctl_copy));
	        sgs[num_out++] = &arg1_sg;

		arg2 = kmalloc(((struct scifioctl_copy *)arg1)->len * sizeof(uint8_t), GFP_KERNEL);
		if (!arg2) {
			kfree(arg1);
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

	        sg_init_one(&arg2_sg, arg2, ((struct scifioctl_copy *)arg1)->len);
	        sgs[num_out++] = &arg2_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_VWRITETO:
		//we will re-allocate it iteratively
		//inside readwrite_sg()
		kfree(packet);

		arg1 = kmalloc(sizeof(struct scifioctl_copy), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_copy))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

		ret = readwrite_sg(scif_dev,
					scif_of, 
					(struct scifioctl_copy **)&arg1, 
					sgs, &host_ret_val);
		
		goto out;

		break;

//	case SCIF_VWRITETO:
//		arg1 = kmalloc(sizeof(struct scifioctl_copy), GFP_KERNEL);
//		if (!arg1) {
//			ret = -ENOMEM;
//		      	goto out_with_packet;
//		}
//
//		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_copy))) {
//			kfree(arg1);
//			ret = -EFAULT;
//			goto out_with_packet;
//		}
//
//	        sg_init_one(&arg1_sg, arg1, sizeof(void *));
//	        sgs[num_out++] = &arg1_sg;
//
//		arg2 = kmalloc(((struct scifioctl_copy *)arg1)->len * sizeof(uint8_t), GFP_KERNEL);
//		if (!arg2) {
//			kfree(arg1);
//			ret = -ENOMEM;
//		      	goto out_with_packet;
//		}
//
//		if (copy_from_user(arg2, (void __user *)((struct scifioctl_copy *)uarg)->addr, ((struct scifioctl_copy *)arg1)->len * sizeof(uint8_t))) {
//			kfree(arg2);
//			kfree(arg1);
//			ret = -EFAULT;
//			goto out_with_packet;
//		}
//
//	        sg_init_one(&arg2_sg, arg2, ((struct scifioctl_copy *)arg1)->len);
//	        sgs[num_out++] = &arg2_sg;
//
//		/**
//		 *  Add the host_return_val_sg to the list.
//		 *  This is also common to all ioctl commands.
//		 **/
//		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
//		sgs[num_out + num_in++] = &ret_val_sg;
//
//		spin_lock_irqsave(&scif_dev->vq_lock, flags);
//		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
//		if (unlikely(err)) {
//			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);
//
//			kfree(arg1);
//			ret = -EAGAIN;
//
//			goto out_with_packet;
//		}
//
//		virtqueue_kick(scif_dev->vq);
//		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);
//
//		break;

	case SCIF_FENCE_MARK:
		arg1 = kmalloc(sizeof(struct scifioctl_fence_mark), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_fence_mark))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        //sg_init_one(&arg1_sg, arg1, sizeof(void *));
	        sg_init_one(&arg1_sg, arg1, sizeof(struct scifioctl_fence_mark));
	        sgs[num_out++] = &arg1_sg;

		arg2 = kmalloc(sizeof(int), GFP_KERNEL);
		if (!arg2) {
			kfree(arg1);
		      	ret = -ENOMEM;
		    	goto out_with_packet;
		}

	        sg_init_one(&arg2_sg, arg2, sizeof(int));
	        sgs[num_out++] = &arg2_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg2);
			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_FENCE_WAIT:
		arg1 = kmalloc(sizeof(int), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		*((int *)arg1) = (int)uarg;

	        //sg_init_one(&arg1_sg, arg1, sizeof(void *));
	        sg_init_one(&arg1_sg, arg1, sizeof(int));
	        sgs[num_out++] = &arg1_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_FENCE_SIGNAL:
		arg1 = kmalloc(sizeof(struct scifioctl_fence_signal), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_fence_signal))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        sg_init_one(&arg1_sg, arg1, sizeof(struct scifioctl_fence_signal));
	        sgs[num_out++] = &arg1_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	case SCIF_GET_NODEIDS:
		arg1 = kmalloc(sizeof(struct scifioctl_nodeIDs), GFP_KERNEL);
		if (!arg1) {
			ret = -ENOMEM;
		      	goto out_with_packet;
		}

		if (copy_from_user(arg1, (void __user *)uarg, sizeof(struct scifioctl_nodeIDs))) {
			kfree(arg1);
			ret = -EFAULT;
			goto out_with_packet;
		}

	        //sg_init_one(&arg1_sg, arg1, sizeof(void *));
	        sg_init_one(&arg1_sg, arg1, sizeof(struct scifioctl_nodeIDs));
	        sgs[num_out++] = &arg1_sg;

		//FIXME: allocate the min of MAX_BOARD_SUPPORTED and 
		// user-supplied len (see host driver)
		arg2 = kmalloc(sizeof(uint16_t) * ((struct scifioctl_nodeIDs *)arg1)->len, GFP_KERNEL);
		if (!arg2) {
			kfree(arg1);
		      	ret = -ENOMEM;
		    	goto out_with_packet;
		}

	        sg_init_one(&arg2_sg, arg2, sizeof(sizeof(uint16_t) * ((struct scifioctl_nodeIDs *)arg1)->len));
	        sgs[num_out++] = &arg2_sg;

		arg3 = kmalloc(sizeof(uint16_t), GFP_KERNEL);
		if (!arg3) {
			kfree(arg1);
			kfree(arg2);
		      	ret = -ENOMEM;
		    	goto out_with_packet;
		}

	        sg_init_one(&arg3_sg, arg3, sizeof(uint16_t));
	        sgs[num_out++] = &arg3_sg;

		/**
		 *  Add the host_return_val_sg to the list.
		 *  This is also common to all ioctl commands.
		 **/
		sg_init_one(&ret_val_sg, &host_ret_val, sizeof(host_ret_val));
		sgs[num_out + num_in++] = &ret_val_sg;

		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		err = virtqueue_add_sgs(scif_dev->vq, sgs, num_out, num_in, packet, GFP_ATOMIC);
		if (unlikely(err)) {
			spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

			kfree(arg3);
			kfree(arg2);
			kfree(arg1);
			ret = -EAGAIN;

			goto out_with_packet;
		}

		virtqueue_kick(scif_dev->vq);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		break;

	default:
		printk(KERN_ALERT "SCIF_UNKNOWN\n");

		break;
	}

        /* We only need packet as a token identifier of the request/reply */
        err = wait_event_interruptible(scif_dev->wq, need_to_wakeup(scif_dev, packet));

	/* Check the ioctl return value of the host. */
	/* FIXME we need to free the allocated structures. */
//	if (host_ret_val == -1) {
//		debug("Host could not complete ioctl command.");
//		ret = -EBADF;
//		goto out;
//	}
	ret = host_ret_val;	

	/** 
	 *  Now do copy_to_user and cleanup. 
	 **/
	switch (cmd) {
	case SCIF_GET_VERSION:

		break;

	case SCIF_BIND:
		if (copy_to_user((void __user *)uarg, arg1, sizeof(uint16_t))) {
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}
		kfree(arg1);

		break;

	case SCIF_LISTEN:
		kfree(arg1);

		break;

	case SCIF_CONNECT:
		if (copy_to_user((void __user *)uarg, arg1, sizeof(struct scifioctl_connect))) {
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}
		kfree(arg1);

		break;

	case SCIF_ACCEPTREQ:
		if (copy_to_user((void __user *)uarg, arg1, sizeof(struct scifioctl_accept))) {
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}
		kfree(arg1);

		break;

	case SCIF_ACCEPTREG:
		kfree(arg1);

		break;

	case SCIF_SEND:
		if (copy_to_user(&((struct scifioctl_msg *)uarg)->out_len, &((struct scifioctl_msg *)arg1)->out_len, sizeof(int))) {
			kfree(arg2);
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}
		kfree(arg2);
		kfree(arg1);

		break;

	case SCIF_RECV:
		if (copy_to_user(&((struct scifioctl_msg *)uarg)->out_len, &((struct scifioctl_msg *)arg1)->out_len, sizeof(int))) {
			kfree(arg2);
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}

		if (copy_to_user(((struct scifioctl_msg *)uarg)->msg, arg2, ((struct scifioctl_msg *)arg1)->out_len)) {
			kfree(arg2);
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}

		kfree(arg2);
		kfree(arg1);

		break;

	case SCIF_REG:
		if (host_ret_val < 0) {
			kfree(arg1);
			//kfree(arg2);
			break;
		}
	
		if (copy_to_user(&((struct scifioctl_reg *)uarg)->out_offset, &((struct scifioctl_reg *)arg1)->out_offset, sizeof(off_t))) {
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}

		//((struct reg_window *)arg2)->reg_offset = ((struct scifioctl_reg *)arg1)->out_offset;
		//TODO: for list manipulation?/
		//also where it is freed??
		((struct reg_window *)arg2)->reg_offset = ((struct scifioctl_reg *)arg1)->out_offset;
		
		kfree(arg1);

		break;

	case SCIF_UNREG:
		err = release_locked_windows(scif_of, 
						0, 
						((struct scifioctl_unreg *)arg1)->offset, 
						((struct scifioctl_unreg *)arg1)->len);

		if (err < 0) {
			kfree(arg1);
			goto out_with_packet;
		}


		kfree(arg1);

		break;

	case SCIF_READFROM:
	case SCIF_WRITETO:
		kfree(arg1);

		break;

	case SCIF_VREADFROM:
		//maybe this is unnecessary(??)
		if (copy_to_user(((struct scifioctl_copy *)uarg)->addr, (struct scifioctl_reg *)arg2, ((struct scifioctl_copy *)arg1)->len * sizeof(uint8_t))) {
			kfree(arg2);
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}

		kfree(arg2);
		kfree(arg1);

		break;

	case SCIF_VWRITETO:
		kfree(arg1);
		kfree(arg2);

		break;

	case SCIF_FENCE_MARK:
		if (copy_to_user(((struct scifioctl_fence_mark *)uarg)->mark, arg2, sizeof(int))) {
			kfree(arg2);
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}
		
		kfree(arg2);
		kfree(arg1);

		break;

	case SCIF_FENCE_WAIT:
		kfree(arg1);

		break;

	case SCIF_FENCE_SIGNAL:
		kfree(arg1);

		break;

	case SCIF_GET_NODEIDS:
		if (copy_to_user(((struct scifioctl_nodeIDs *)uarg)->nodes, arg2, 
					sizeof(uint16_t) * ((struct scifioctl_nodeIDs *)arg1)->len)) {
			kfree(arg3);
			kfree(arg2);
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}

		if (copy_to_user(((struct scifioctl_nodeIDs *)uarg)->self, arg3, sizeof(uint16_t))) {
			kfree(arg3);
			kfree(arg2);
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}

		if (copy_to_user((struct scifioctl_nodeIDs *)uarg, arg1, sizeof(struct scifioctl_nodeIDs))) {
			kfree(arg3);
			kfree(arg2);
			kfree(arg1);
			ret = -EFAULT;

			goto out_with_packet;
		}
		
		kfree(arg3);
		kfree(arg2);
		kfree(arg1);

		break;

	default:

		break;
	}

out_with_packet:
	//kfree(packet);

out:
	debug("Leaving PID: %d", current->pid);
	return ret;
}

static void vma_pvt_release(struct kref *ref)
{
        struct vma_pvt *vmapvt = container_of(ref, struct vma_pvt, ref);

	//lazily free pages, due to allocation in terms of order
	free_pages(vmapvt->mapped_addr, vmapvt->order);
        kfree(vmapvt);
}

static void scif_chrdev_vma_open(struct vm_area_struct *vma)
{
	struct vma_pvt *vmapvt = ((vma)->vm_private_data);
	kref_get(&vmapvt->ref);
}

void scif_chrdev_munmap(struct vm_area_struct *vma)
{
	struct scif_device *scif_dev = scif_drvdata.scif_dev;
	struct vq_packet *packet;
	struct scatterlist out_sg, addr_sg, len_sg, *sgs[3];
	struct vma_pvt *vmapvt = ((vma)->vm_private_data);
	unsigned long addr;
	size_t len;
	unsigned long flags;
	int err = 0;
	//int ret = 0;
	//TODO: add vm_private field => store guest physical address to get it in the munmap case

	debug("Entering (PID: %d)", current->pid);
	printk(KERN_ALERT "Entering MUNMAP (PID: %d)\n", current->pid);
        
        /*
         * The kernel probably zeroes these out but we still want
         * to clean up our own mess just in case.
         */
//        vma->vm_ops = NULL;
//        ((vma)->vm_private_data) = NULL;
//        err = kref_put(&vmapvt->ref, vma_pvt_release);


	packet = kmalloc(sizeof(*packet), GFP_KERNEL);
	if (!packet) {
		//ret = -ENOMEM;
		goto out;
	}
	
	len = vma->vm_end - vma->vm_start;
	addr = virt_to_phys((void *)(vma->vm_start - vmapvt->vm_addr + vmapvt->mapped_addr));

	packet->type = VIRTIO_SCIF_MUNMAP;

	sg_init_one(&out_sg, &packet->type, sizeof(packet->type));
	sgs[0] = &out_sg;
	sg_init_one(&addr_sg, &addr, sizeof(addr));
	sgs[1] = &addr_sg;
	sg_init_one(&len_sg, &len, sizeof(len));
	sgs[2] = &len_sg;

	spin_lock_irqsave(&scif_dev->vq_lock, flags);
	err = virtqueue_add_sgs(scif_dev->vq, sgs, 3, 0, packet, GFP_ATOMIC);
	if (unlikely(err)) {
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		kfree(packet);
		//ret = -EAGAIN;

		goto out;
	}

	virtqueue_kick(scif_dev->vq);
	spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

	/* We only need packet as a token identifier of the request/reply */
	err = wait_event_interruptible(scif_dev->wq, need_to_wakeup(scif_dev, packet));

	if (err) {
		//TODO: packet-heap will remain forever
		//kfree(packet);
		//ret = -EIO;

		goto out;
	}

	//TODO: need to free_pages(), considering the ORDER variable (maybe lazily as a last workaround)

        /*
         * The kernel probably zeroes these out but we still want
         * to clean up our own mess just in case.
         */
        vma->vm_ops = NULL;
        ((vma)->vm_private_data) = NULL;
        err = kref_put(&vmapvt->ref, vma_pvt_release);
	printk("vma_release ret value: %d\n", err);

	//kfree(packet);
	
out:
	debug("Leaving (PID: %d)", current->pid);
}

static const struct vm_operations_struct scif_vm_ops = {                                                                                   
        .open = scif_chrdev_vma_open,
        .close = scif_chrdev_munmap,
};

static int scif_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct scif_open_file *scif_of = filp->private_data;
	struct scif_device *scif_dev = scif_drvdata.scif_dev;
	struct vq_packet *packet;
	//dma_addr_t bus_addr = -1;
	unsigned long page_addr = -1;
	unsigned long start_addr = 0x49;
	unsigned long * page_ptr = (unsigned long *)-1;
	struct scatterlist out_sg, buf_sg, page_sg, length_sg, order_sg, offset_sg, *sgs[6];
	unsigned long flags, offset;
	unsigned int length, order;
	struct vma_pvt *vmapvt;
	int err;
	int ret = 0;

	debug("Entering (PID: %d)", current->pid);

	packet = kmalloc(sizeof(*packet), GFP_KERNEL);
	if (!packet) {
		ret = -ENOMEM;

		goto out;
	}
	
	length = vma->vm_end - vma->vm_start;
	order = get_order(length);
	
	//allocate with buddy granularity (may alloc more pages than needed)
	page_addr = __get_free_pages(GFP_KERNEL, order);
	if (!page_addr) {
		debug("error allocating pages for scif_mmap\n");

		ret = -ENOMEM;
		goto out_with_packet;
	}

	//add return value check
	start_addr = virt_to_phys((void *)page_addr);//maybe virt_to_bus()

	offset = vma->vm_pgoff << PAGE_SHIFT;

	packet->type = VIRTIO_SCIF_MMAP;

	sg_init_one(&out_sg, &packet->type, sizeof(packet->type));
	sgs[0] = &out_sg;
	sg_init_one(&buf_sg, &scif_of->host_fd, sizeof(scif_of->host_fd));
	sgs[1] = &buf_sg;
	sg_init_one(&page_sg, &start_addr, sizeof(start_addr));
	sgs[2] = &page_sg;
	sg_init_one(&length_sg, &length, sizeof(length));
	sgs[3] = &length_sg;
	sg_init_one(&order_sg, &order, sizeof(order));
	sgs[4] = &order_sg;
	sg_init_one(&offset_sg, &offset, sizeof(offset));
	sgs[5] = &offset_sg;

	spin_lock_irqsave(&scif_dev->vq_lock, flags);
	err = virtqueue_add_sgs(scif_dev->vq, sgs, 6, 0, packet, GFP_ATOMIC);
	if (unlikely(err)) {
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		ret = -EAGAIN;
		//TODO: packet-heap will remain forever (see kfree(packet) at
		// the end of the function
		goto out_with_pages;
	}

	virtqueue_kick(scif_dev->vq);
	spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

	/* We only need packet as a token identifier of the request/reply */
	err = wait_event_interruptible(scif_dev->wq, need_to_wakeup(scif_dev, packet));

	if (err) {
		ret = -EIO;
		goto out_with_pages;
	}


	vmapvt = kmalloc(sizeof(*vmapvt), GFP_KERNEL);
	if (!vmapvt) {
		ret = -ENOMEM;
		goto out_with_pages;
	}

	kref_init(&vmapvt->ref);
	//kref_get(&vmapvt->ref);

	//perform the mapping
	//in page tables
	if (remap_pfn_range(vma, 
			vma->vm_start, 
			//bus_addr >> PAGE_SHIFT, 
			//vma->vm_pgoff, 
			start_addr >> PAGE_SHIFT, 
			length,
			vma->vm_page_prot)) {

		ret = -EAGAIN; //or -EFAULT?
		debug("error mapping pages to userspace\n");
		//TODO: munmap() at host-side

		goto out_with_pages;
	}

	vmapvt->vm_addr = vma->vm_start;
	vmapvt->mapped_addr = page_addr;
	vmapvt->order = order;

	vma->vm_ops = &scif_vm_ops;
	((vma)->vm_private_data) = vmapvt;
	//add kmalloc pvt_data
	//TODO: add vm_private field => store guest physical address to get it in the munmap case

	goto out_with_packet;
	
out_with_pages:
	free_pages(start_addr, order);

out_with_packet:
	//kfree(packet);

out:
	debug("Leaving (PID: %d)", current->pid);

	return ret;
}

static unsigned int scif_chrdev_poll(struct file *filp, poll_table *wait)
{
	struct scif_open_file *scif_of = filp->private_data;
	struct scif_poll_struct *poll_struct;
	struct scif_device *scif_dev = scif_drvdata.scif_dev;
	struct vq_packet *packet;
	struct scatterlist buf_psg, events_psg, revents_psg, *psgs[3];
	struct scatterlist out_sg, buf_sg, events_sg, revents_sg, *sgs[4];
//	short events, revents = 0;
//	short events2, revents2 = 0;
	short *events, *revents;
	short *events2, *revents2;
	short ret_events = 0;
	unsigned long flags;
	int err, retries = 0;
	int ret = 0;

	debug("Entering (PID: %d)", current->pid);

	poll_struct = kmalloc(sizeof(*poll_struct), GFP_KERNEL);
	if (!poll_struct)
		goto out_with_error;

	events = kmalloc(sizeof(*events), GFP_KERNEL);
	if (!events)
		goto out_with_poll_struct;

	revents = kmalloc(sizeof(*revents), GFP_KERNEL);
	if (!revents)
		goto out_with_events;

	events2 = kmalloc(sizeof(*events2), GFP_KERNEL);
	if (!events2)
		goto out_with_revents;

	revents2 = kmalloc(sizeof(*revents2), GFP_KERNEL);
	if (!revents2)
		goto out_with_events2;

	*events = 0;
	*revents =0;
	*events2 = 0;
	*revents2 = 0;

//	init_waitqueue_head(&poll_struct->poll_wq);
	poll_struct->events = events;
	poll_struct->revents = revents;
	poll_struct->of = scif_of;

	//the kernel has appended POLLERR | POLLHUP (see do_pollfd() at fs/select.c)
//	events = wait->_key & ~POLLERR;
//	events &= ~POLLHUP;
	*events = wait->_key & ~POLLERR;
	*events &= ~POLLHUP;
	*events2 = wait->_key & ~POLLERR;
	*events2 &= ~POLLHUP;

	//poll_wait(filp, &scif_of->poll_wq, wait);
	poll_wait(filp, &poll_struct->of->poll_wq, wait);

//retry:
	// Request to the host to spawn a thread which will poll 
	// for a sane amount of time. Then hosts wakes us up 
	// inside the poll interrupt handler
	sg_init_one(&buf_psg, &scif_of->host_fd, sizeof(scif_of->host_fd));
	psgs[0] = &buf_psg;
	sg_init_one(&events_psg, events, sizeof(events));
	psgs[1] = &events_psg;
	sg_init_one(&revents_psg, revents, sizeof(revents));
	psgs[2] = &revents_psg;

	spin_lock_irqsave(&scif_dev->poll_vq_lock, flags);
	//err = virtqueue_add_sgs(scif_dev->poll_vq, psgs, 2, 1, scif_of, GFP_ATOMIC);
	err = virtqueue_add_sgs(scif_dev->poll_vq, psgs, 2, 1, poll_struct, GFP_ATOMIC);
	if (unlikely(err)) {
		spin_unlock_irqrestore(&scif_dev->poll_vq_lock, flags);

		//ret = -EAGAIN;
		////kfree(packet);

		debug("error @scif_poll() add sgs: 0x%x", err);
		//TODO: check me out again
		//what to return and check if 
		//needs to manipulate revents
		//in any case
		//return POLLERR;
		goto out_with_revents2;
	}

	virtqueue_kick(scif_dev->poll_vq);
	spin_unlock_irqrestore(&scif_dev->poll_vq_lock, flags);

	packet = kmalloc(sizeof(*packet), GFP_KERNEL);
	if (!packet)
		goto out_with_revents2;
	
	packet->type = VIRTIO_SCIF_POLL;

	// perform a zero-timeout poll() on the host
	// to check if the epd is available right now
	sg_init_one(&out_sg, &packet->type, sizeof(packet->type));
	sgs[0] = &out_sg;
	sg_init_one(&buf_sg, &scif_of->host_fd, sizeof(scif_of->host_fd));
	sgs[1] = &buf_sg;
//	sg_init_one(&events_sg, &events, sizeof(events));
	sg_init_one(&events_sg, events2, sizeof(events2));
	sgs[2] = &events_sg;
//	sg_init_one(&revents_sg, &revents, sizeof(revents));
	sg_init_one(&revents_sg, revents2, sizeof(revents2));
	sgs[3] = &revents_sg;

	spin_lock_irqsave(&scif_dev->vq_lock, flags);
	err = virtqueue_add_sgs(scif_dev->vq, sgs, 3, 1, packet, GFP_ATOMIC);
	if (unlikely(err)) {
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

		goto out_with_revents2;
//		//ret = -EAGAIN;
//		kfree(packet);
//		return POLLERR;
	}

	virtqueue_kick(scif_dev->vq);
	spin_unlock_irqrestore(&scif_dev->vq_lock, flags);

	/* We only need packet as a token identifier of the request/reply */
	err = wait_event_interruptible(scif_dev->wq, need_to_wakeup(scif_dev, packet));

	if (err || *revents2 < 0) {
//		return POLLERR;
		goto out_with_revents2;
	}
	//kfree(packet);

	debug("Leaving (PID: %d)", current->pid);

	//goto out;
	ret_events = *revents2;
	kfree(events2);
	kfree(revents2);

	return ret_events;
	//return 0;

out_with_revents2:
	kfree(revents2);

out_with_events2:
	kfree(events2);

out_with_revents:
	kfree(revents);

out_with_events:
	kfree(events);

out_with_poll_struct:
	kfree(poll_struct);

out_with_error:
	return POLLERR;
}

static ssize_t scif_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations scif_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = scif_chrdev_open,
	.release        = scif_chrdev_release,
	.mmap           = scif_chrdev_mmap,
	.read           = scif_chrdev_read,
	.unlocked_ioctl = scif_chrdev_ioctl,
	.poll 		= scif_chrdev_poll,
};

int scif_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int scif_minor_cnt = SCIF_NR_DEVICES;

	debug("Initializing character device...");
	cdev_init(&scif_cdev, &scif_chrdev_fops);
	scif_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(SCIF_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, scif_minor_cnt, "scif_dev");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&scif_cdev, dev_no, scif_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, scif_minor_cnt);
out:
	return ret;
}

void scif_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int scif_minor_cnt = SCIF_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(SCIF_CHRDEV_MAJOR, 0);
	cdev_del(&scif_cdev);
	unregister_chrdev_region(dev_no, scif_minor_cnt);
	debug("leaving");
}
