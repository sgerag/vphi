/*
 * Virtio SCIF Device
 *
 * Implementation of Virtio-SCIF qemu backend device.
 *
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 *
 */

#include <qemu/iov.h>
//#include <hw/virtio/virtio-serial.h>
#include <hw/virtio/virtio-scif.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <hw/pci/pci.h>
#include <sys/mman.h>

#include <scif.h>
#include "../libscif-3.4/scif_ioctl.h"
//#include <scif_ioctl.h>
#include <pthread.h>

# define MREMAP_MAYMOVE 1
# define MREMAP_FIXED   2


#include <sys/time.h>

static QemuMutex vq_lock;
static QemuMutex vq_poll_lock;

static uint32_t get_features(VirtIODevice *vdev, uint32_t features)
{
	DEBUG_IN();

	DEBUG_OUT();
	return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
	DEBUG_IN();

	DEBUG_OUT();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
	DEBUG_IN();

	DEBUG_OUT();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
	DEBUG_IN();

	DEBUG_OUT();
}

static void vser_reset(VirtIODevice *vdev)
{
	DEBUG_IN();

	DEBUG_OUT();
}

static void scif_open_handler(struct scif_open_file *scif_of)
{
	DEBUG_IN();

	scif_of->fd = open(SCIFDEV_FILENAME, O_RDWR);

	if (scif_of->fd < 0)
	//FIXME: ret value? 
		perror("VIRTIO_SCIF_OPEN");

	DEBUG_OUT();
}

static void scif_close_handler(struct scif_open_file *scif_of)
{
	DEBUG_IN();

	void *end;

	//locking prevents a possible race between fcntl()
	//return at poll() and close() of fd
	//(see scif_poll_handler_async())
	qemu_mutex_lock(&vq_poll_lock);
	//FIXME: save return value
	close(scif_of->fd);
	qemu_mutex_unlock(&vq_poll_lock);

//	if (scif_of->fd < 0)
//		perror("VIRTIO_SCIF_OPEN");


	DEBUG_OUT();
}

static int scif_get_version_handler(struct scif_open_file *scif_of)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_GET_VERSION);
	if (ret < 0)
	 	ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_bind_handler(struct scif_open_file *scif_of, uint16_t **np)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_BIND, *np);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_listen_handler(struct scif_open_file *scif_of, int *backlog)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_LISTEN, *backlog);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_connect_handler(struct scif_open_file *scif_of, struct scifioctl_connect **req)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_CONNECT, *req);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static void *scif_connect_handler_async(void *arg)
{
	int *ret;
	struct scif_connect *req = (struct scif_connect *)arg;

	DEBUG_IN();

	ret = req->elem->in_sg[req->elem->in_num - 1].iov_base;
	
	//*ret = ioctl(req->scif_of->fd, SCIF_CONNECT, req->conn);
	*ret = ioctl(req->fd, SCIF_CONNECT, (struct scifioctl_connect *)req->elem->out_sg[3].iov_base);
	if (*ret < 0) {
		*ret = -errno;
//		goto out;
	}

	qemu_mutex_lock(&vq_lock);
	virtqueue_push(req->vq, req->elem, 0);
	virtio_notify(req->vdev, req->vq);
	qemu_mutex_unlock(&vq_lock);

out:
	free(req->elem);
	free(req);
	DEBUG_OUT();

	//return ret;
	return NULL;
}

static int scif_acceptreq_handler(struct scif_open_file *scif_of, struct scifioctl_acceptreq **req)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_ACCEPTREQ, *req);
	//FIXME: ret = errno ?? rethink everywhere
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static void *scif_acceptreq_handler_async(void *arg)
{
	int *ret;
	struct scif_acceptreq *req = (struct scif_acceptreq *)arg;

	DEBUG_IN();

	ret = req->elem->in_sg[req->elem->in_num - 1].iov_base;
	
	//*ret = ioctl(req->scif_of->fd, SCIF_ACCEPTREQ, req->acc);
	*ret = ioctl(req->fd, SCIF_ACCEPTREQ, (struct scifioctl_accept *)req->elem->out_sg[3].iov_base);
	if (*ret < 0) {
		*ret = -errno;
//		goto out;
	}

	qemu_mutex_lock(&vq_lock);
	virtqueue_push(req->vq, req->elem, 0);
	virtio_notify(req->vdev, req->vq);
	qemu_mutex_unlock(&vq_lock);

out:
	free(req->elem);
	free(req);

	DEBUG_OUT();

	//return ret;
	return NULL;
}

static int scif_acceptreg_handler(struct scif_open_file *scif_of, void **endpt)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_ACCEPTREG, *endpt);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_send_handler(struct scif_open_file *scif_of, struct scifioctl_msg **msg)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_SEND, *msg);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_recv_handler(struct scif_open_file *scif_of, struct scifioctl_msg **msg, void **rmsg)
{
	int ret = -1;

	DEBUG_IN();
	
	(*msg)->msg = *rmsg;
	ret = ioctl(scif_of->fd, SCIF_RECV, *msg);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static void *scif_sendrecv_handler_async(void *arg)
{
	int *ret;
	struct scif_msg *req = (struct scif_msg *)arg;
	void *msg = (struct scifioctl_msg *)req->elem->out_sg[4].iov_base;

	DEBUG_IN();

	((struct scifioctl_msg *)req->elem->out_sg[3].iov_base)->msg = msg;
	ret = req->elem->in_sg[req->elem->in_num - 1].iov_base;
	
	if (req->recv) {
		*ret = ioctl(req->fd, SCIF_RECV, (struct scifioctl_msg *)req->elem->out_sg[3].iov_base);
	}
	else
		*ret = ioctl(req->fd, SCIF_SEND, (struct scifioctl_msg *)req->elem->out_sg[3].iov_base);
	if (*ret < 0) {
		*ret = -errno;
	DEBUG("ERROR");
//		goto out;
	}

	qemu_mutex_lock(&vq_lock);
	virtqueue_push(req->vq, req->elem, 0);
	virtio_notify(req->vdev, req->vq);
	qemu_mutex_unlock(&vq_lock);

out:
	free(req->elem);
	free(req);

	DEBUG_OUT();

	//return ret;
	return NULL;
}

static int scif_reg_handler(VirtQueueElement *elem, struct scif_open_file *scif_of, struct scifioctl_reg **reg)
{
	int ret = -1, other_ret = -1, i = -1;
	int64_t nr_pages = -1;
	off_t out_offset = -1, temp_offset = -1;

	DEBUG_IN();
	
//	(*msg)->msg = *rmsg;
	
	//TODO: replace back to userspace guest user address + len (maybe not needed (copied_from_userspace))
	nr_pages = ((*reg)->len) >> PAGE_SHIFT;
	(*reg)->len = PAGE_SIZE;

	//only first out_offset matters for guest
	(*reg)->addr = elem->out_sg[4].iov_base;

	ret = ioctl(scif_of->fd, SCIF_REG, *reg);
	out_offset = (*reg)->out_offset;
	if (ret < 0) {
		ret = -errno;
		goto fail;
	}
	temp_offset = out_offset;

	for (i = 1; i < nr_pages; i++) {
		temp_offset += PAGE_SIZE;
		(*reg)->addr = elem->out_sg[i+4].iov_base;
		(*reg)->offset = temp_offset;

		other_ret = ioctl(scif_of->fd, SCIF_REG, *reg);
		if (other_ret < 0) {
			other_ret = -errno;
			goto fail;
		}
	}

	(*reg)->out_offset = out_offset;

	DEBUG_OUT();
	goto out;

	struct scifioctl_unreg unreg;
	off_t offset = -1;
	int j;

fail:
	offset = out_offset;

	//we assume host driver returned us contiguous offsets
	for (j = 0; j < i; j++) {
		unreg.offset = offset;
		unreg.len = PAGE_SIZE;
		ioctl(scif_of->fd, SCIF_UNREG, unreg);
		offset += PAGE_SIZE;
	}
out:

	return ret;
}

static int scif_regv_handler2(VirtQueueElement *elem, struct scif_open_file *scif_of, struct scifioctl_reg **reg)
{
	struct scifioctl_reg *regv;
	int ret = -1, i = -1;
	int64_t nr_pages = -1;
	off_t out_offset = -1, temp_offset = -1;
	void* new_addr;
	void* other_ret;

	DEBUG_IN();

	regv = malloc(sizeof(struct scifioctl_regv));
	if (!regv) {
		ret = -ENOMEM;
		goto out;
	}

	nr_pages = ((*reg)->len) >> PAGE_SHIFT;

	other_ret = posix_memalign(&new_addr, 4096, ((*reg)->len));

//	regv->sg_array = malloc(nr_pages * sizeof(struct sg_entry));
//	if (!(regv->sg_array)) {
//		ret = -ENOMEM;
//		goto out;
//	}

	//regv->nr_pages = nr_pages;
	regv->len = (*reg)->len;
	regv->offset = (*reg)->offset;
	regv->prot = (*reg)->prot;
	regv->flags = (*reg)->flags;

	//fill-in the structs
	for (i = 0; i < nr_pages; i++) {
		other_ret = mremap(elem->out_sg[i+4].iov_base, regv->len, regv->len, MREMAP_MAYMOVE|MREMAP_FIXED, new_addr+i*4096);
//		(regv->sg_array[i]).addr = elem->out_sg[i+4].iov_base;
	}
	regv->addr = new_addr;

	ret = ioctl(scif_of->fd, SCIF_REG, regv);
	//ret = ioctl(scif_of->fd, SCIF_REGV, regv);
	if (ret < 0) {
		ret = -errno;
		goto fail_with_addrs;
	}

	(*reg)->out_offset = regv->out_offset;

	DEBUG_OUT();

fail_with_addrs:
//	free(regv->sg_array);

out:
	free(regv);

	return ret;
}

static int scif_regv_handler(VirtQueueElement *elem, struct scif_open_file *scif_of, struct scifioctl_reg **reg)
{
	struct scifioctl_regv *regv;
	int ret = -1, other_ret = -1, i = -1;
	int64_t nr_pages = -1;
	off_t out_offset = -1, temp_offset = -1;

	DEBUG_IN();

	regv = malloc(sizeof(struct scifioctl_regv));
	if (!regv) {
		ret = -ENOMEM;
		goto out;
	}

	nr_pages = ((*reg)->len) >> PAGE_SHIFT;

	regv->sg_array = malloc(nr_pages * sizeof(struct sg_entry));
	if (!(regv->sg_array)) {
		ret = -ENOMEM;
		goto out;
	}

	regv->nr_pages = nr_pages;
	regv->offset = (*reg)->offset;
	regv->prot = (*reg)->prot;
	regv->flags = (*reg)->flags;

	//fill-in the structs
	for (i = 0; i < nr_pages; i++)
		(regv->sg_array[i]).addr = elem->out_sg[i+4].iov_base;

	ret = ioctl(scif_of->fd, SCIF_REGV, regv);
	if (ret < 0) {
		ret = -errno;
		goto fail_with_addrs;
	}

	(*reg)->out_offset = regv->out_offset;

	DEBUG_OUT();

fail_with_addrs:
	free(regv->sg_array);

out:
	free(regv);

	return ret;
}

static int scif_unregister_handler(struct scif_open_file *scif_of, struct scifioctl_unreg **unreg)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_UNREG, *unreg);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_readfrom_handler(struct scif_open_file *scif_of, struct scifioctl_copy **rfrom)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_READFROM, *rfrom);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_writeto_handler(struct scif_open_file *scif_of, struct scifioctl_copy **wto)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_WRITETO, *wto);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_vreadfrom_handler(struct scif_open_file *scif_of, struct scifioctl_copy **vrfrom)
{
	int ret = -1;

	DEBUG_IN();
	
(*vrfrom)->flags = ((*vrfrom)->flags) | SCIF_RMA_USECACHE;
	ret = ioctl(scif_of->fd, SCIF_VREADFROM, *vrfrom);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_vwriteto_handler(struct scif_open_file *scif_of, struct scifioctl_copy **vwto)
{
	int ret = -1;

	DEBUG_IN();
	
(*vwto)->flags = ((*vwto)->flags) | SCIF_RMA_USECACHE;
	ret = ioctl(scif_of->fd, SCIF_VWRITETO, *vwto);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_vwriteto_sg_handler(struct scif_open_file *scif_of, struct scifioctl_copy **vwto)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_VWRITETO, *vwto);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_fence_mark_handler(struct scif_open_file *scif_of, struct scifioctl_fence_mark **mark)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_FENCE_MARK, *mark);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_fence_wait_handler(struct scif_open_file *scif_of, int *wait)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_FENCE_WAIT, *wait);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_fence_signal_handler(struct scif_open_file *scif_of, struct scifioctl_fence_signal **sig)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_FENCE_SIGNAL, *sig);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_get_nodeids_handler(struct scif_open_file *scif_of, struct scifioctl_nodeIDs **ids)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = ioctl(scif_of->fd, SCIF_GET_NODEIDS, *ids);
	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_mmap_handler(struct scif_open_file *scif_of, void **addr, unsigned int length, unsigned long off)
{
	void *ret = (void *)-1;

	DEBUG_IN();

	ret = -8;
	ret = mmap(*addr, length, PROT_READ|PROT_WRITE, (MAP_FIXED | MAP_SHARED), scif_of->fd, off);
	if (ret == MAP_FAILED) {
		ret = -errno;
	}

	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_munmap_handler(void **addr, unsigned int length)
{
	int ret = -1;

	DEBUG_IN();
	
	ret = munmap(*addr, length);

	if (ret < 0)
		ret = -errno;

	DEBUG_OUT();

	return ret;
}

static int scif_poll_handler(struct scif_open_file *scif_of, short **events, short **revents)
{
	int ret = -1;
	struct pollfd sfd;

	DEBUG_IN();

	sfd.fd = scif_of->fd;
	sfd.events = **events;
	sfd.revents = **revents;
	
	//return immediately
	ret = poll(&sfd, 1, 0); 
	//ret = poll(&sfd, 1, 20000); 

	**events = sfd.events;
	**revents = sfd.revents;

	if (ret < 0) {
		ret = -errno;
	}

	DEBUG_OUT();

	return ret;
}

static void *scif_poll_handler_async(void *arg)
{
	//int ret = -1;
	int *ret;
//	struct pollfd sfd;
	int alive_fd;
	struct scif_poll *req = (struct scif_poll *)arg;

	DEBUG_IN();

//	sfd.fd = req->elem->out_sg[1].iov_base;
//	sfd.events = req->elem->out_sg[2].iov_base;
//	sfd.revents = req->elem->in_sg[0].iov_base;
	
	ret = req->elem->in_sg[req->elem->in_num - 1].iov_base;

	//poll for max timeout (let's say) a minute
	*ret = poll(&(req->sfd), 1, 24000);
	//*ret = poll(&(req->sfd), 1, 1500);
	//*ret = poll(&(req->sfd), 1, 80000);
	if (*ret <= 0) {
		//guest just returns POLLERR
		req->sfd.revents = -1;
		
//		goto out;
	}

	//1. locking here prevents a possible race between fcntl() return and
	//close() of fd (see scif_close_handler())
	//
	//2. TODO: there is another race (A-B-A): assume after poll() returns
	//the fd has been released, but another open() request from the guest
	//re-validates the same fd integer => fcntl() returns success (however
	//the open file referred is different). needs synchronization with the
	//guest, for now reduce the likelihood by increasing the timeout value
	//of the above poll()
	qemu_mutex_lock(&vq_poll_lock);
	alive_fd = fcntl(req->sfd.fd, F_GETFD);
	if (alive_fd == -1 && errno == 9) {
		qemu_mutex_unlock(&vq_poll_lock);
		goto out;
	}


	//qemu_mutex_lock(&vq_poll_lock);
	virtqueue_push(req->vq, req->elem, 0);
	virtio_notify(req->vdev, req->vq);
	qemu_mutex_unlock(&vq_poll_lock);

out:
	free(req->elem);
	free(req);
	DEBUG_OUT();

	//return ret;
	return NULL;
}



static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
	VirtQueueElement elem;
	//FIXME: just int MAYBE?
	struct vq_packet *req;
	struct scif_open_file *scif_of;
	int non_blocking = 0;
	unsigned int *cmd;
	int *ret_val = NULL;

	DEBUG_IN();

	DEBUG("I have an interrupt");
	//guest may have kicked us more than once
	while (virtqueue_pop(vq, &elem)) {
		DEBUG("I 've got an item from VQ :)");

		req = elem.out_sg[0].iov_base;

		switch (req->type) {
		case VIRTIO_SCIF_OPEN:
			DEBUG("VIRTIO_SCIF_OPEN");

//			scif_of = malloc(sizeof(struct scif_open_file));
//			scif_of->is_alloc = 1;

			//scif_of->fd = elem.in_sg[0].iov_base;
			scif_of = elem.in_sg[0].iov_base;
			scif_open_handler(scif_of);

			break;

		case VIRTIO_SCIF_CLOSE:
			DEBUG("VIRTIO_SCIF_CLOSE");

			//scif_of->fd = elem.out_sg[1].iov_base;
			scif_of = elem.out_sg[1].iov_base;
			scif_close_handler(scif_of);

			break;

		case VIRTIO_SCIF_IOCTL:
			DEBUG("VIRTIO_SCIF_IOCTL");
			
	                scif_of = elem.out_sg[1].iov_base;
	                cmd = elem.out_sg[2].iov_base;
			ret_val = elem.in_sg[elem.in_num - 1].iov_base;
			
			switch (*cmd) {
			case SCIF_GET_VERSION:
				DEBUG("VIRTIO_SCIF_GET_VERSION");

				*ret_val = scif_get_version_handler(scif_of);

				break;

			case SCIF_BIND:
				DEBUG("VIRTIO_SCIF_BIND");
				uint16_t *np = elem.out_sg[3].iov_base;

				*ret_val = scif_bind_handler(scif_of, &np);

				break;

			case SCIF_LISTEN:
				DEBUG("VIRTIO_SCIF_LISTEN");
				int *backlog = elem.out_sg[3].iov_base;

				*ret_val = scif_listen_handler(scif_of, backlog);

				break;

//			case SCIF_CONNECT:
//				DEBUG("VIRTIO_SCIF_CONNECT");
//				struct scifioctl_connect *req = elem.out_sg[3].iov_base;
//
//				*ret_val = scif_connect_handler(scif_of, &req);
//
//				break;
//
			case SCIF_CONNECT:
				DEBUG("VIRTIO_SCIF_CONNECT_ASYNC");
				non_blocking = 1;

				QemuThread conn_thr;

				struct scif_connect *sconn = malloc(sizeof(struct scif_connect));
				struct VirtQueueElement *conn_elem = malloc(sizeof(struct VirtQueueElement));
				memcpy(conn_elem, &elem, sizeof(struct VirtQueueElement));

				sconn->vdev = vdev;
				sconn->vq = vq;
				sconn->elem = conn_elem;
				//sconn->elem = &elem;
				sconn->fd = scif_of->fd;
				//sconn->scif_of = scif_of;
				//sconn->conn = elem.out_sg[3].iov_base;

				qemu_thread_create(&conn_thr, "scif_connect_thread", scif_connect_handler_async,
					       (void *)sconn, QEMU_THREAD_DETACHED);


				break;

//			case SCIF_ACCEPTREQ:
//				DEBUG("VIRTIO_SCIF_CONNECT");
//				struct scifioctl_accept *req = elem.out_sg[3].iov_base;
//
//				*ret_val = scif_acceptreq_handler(scif_of, &req);
//
//				break;

			case SCIF_ACCEPTREQ:
				DEBUG("VIRTIO_SCIF_ACCEPTREQ_ASYNC");
				non_blocking = 1;

				QemuThread acc_thr;

				struct scif_acceptreq *areq = malloc(sizeof(struct scif_acceptreq));
				struct VirtQueueElement *acc_elem = malloc(sizeof(struct VirtQueueElement));
				memcpy(acc_elem, &elem, sizeof(struct VirtQueueElement));

				areq->vdev = vdev;
				areq->vq = vq;
				areq->elem = acc_elem;
				//areq->elem = elem;
				areq->fd = scif_of->fd;
				//areq->scif_of = scif_of;
				//areq->acc = elem.out_sg[3].iov_base;

				qemu_thread_create(&acc_thr, "scif_acceptreq_thread", scif_acceptreq_handler_async,
					       (void *)areq, QEMU_THREAD_DETACHED);

				break;

			case SCIF_ACCEPTREG:
				DEBUG("VIRTIO_SCIF_ACCEPTREG");
				void *endpt = elem.out_sg[3].iov_base;

				*ret_val = scif_acceptreg_handler(scif_of, &endpt);

				break;
			
//			case SCIF_SEND:
//				DEBUG("VIRTIO_SCIF_SEND");
//				struct scifioctl_msg *send_msg = elem.out_sg[3].iov_base;
//				//void * ptr64_t msg = elem.out_sg[3].iov_base;
//				void *smsg = elem.out_sg[4].iov_base;
//
//				send_msg->msg = smsg;
//
//				*ret_val = scif_send_handler(scif_of, &send_msg);
//
//				break;

			case SCIF_SEND:
				DEBUG("VIRTIO_SCIF_SEND_ASYNC");
				non_blocking = 1;

				QemuThread send_thr;

				struct scif_msg *msend = malloc(sizeof(struct scif_msg));
				struct VirtQueueElement *send_elem = malloc(sizeof(struct VirtQueueElement));
				memcpy(send_elem, &elem, sizeof(struct VirtQueueElement));

				msend->vdev = vdev;
				msend->vq = vq;
				msend->elem = send_elem;
				//msend->elem = elem;
				msend->recv = 0;
				msend->fd = scif_of->fd;
				//msend->scif_of = scif_of;

				qemu_thread_create(&send_thr, "scif_send_thread", scif_sendrecv_handler_async,
					       (void *)msend, QEMU_THREAD_DETACHED);

				break;
			
//			case SCIF_RECV:
//				DEBUG("VIRTIO_SCIF_RECV");
//				struct scifioctl_msg *recv_msg = elem.out_sg[3].iov_base;
//				//void * ptr64_t msg = elem.out_sg[3].iov_base;
//				void *rmsg = elem.out_sg[4].iov_base;
//
//				//recv_msg->msg = rmsg;
//
//				*ret_val = scif_recv_handler(scif_of, &recv_msg, &rmsg);
//				//rmsg = recv_msg->msg;
//				//memcpy(rmsg, recv_msg->msg, );
//
//				break;

			case SCIF_RECV:
				DEBUG("VIRTIO_SCIF_RECV_ASYNC");
				non_blocking = 1;

				QemuThread recv_thr;

				struct scif_msg *mrecv = malloc(sizeof(struct scif_msg));
				struct VirtQueueElement *recv_elem = malloc(sizeof(struct VirtQueueElement));
				memcpy(recv_elem, &elem, sizeof(struct VirtQueueElement));

				mrecv->vdev = vdev;
				mrecv->vq = vq;
				mrecv->elem = recv_elem;
				//mrecv->elem = elem;
				mrecv->recv = 1;
				mrecv->fd = scif_of->fd;
				//mrecv->scif_of = scif_of;

				qemu_thread_create(&recv_thr, "scif_recv_thread", scif_sendrecv_handler_async,
					       (void *)mrecv, QEMU_THREAD_DETACHED);

				break;
			
			case SCIF_REG:
				DEBUG("VIRTIO_SCIF_REG");
				struct scifioctl_reg *reg = elem.out_sg[3].iov_base;
				
				//*ret_val = scif_reg_handler(&elem, scif_of, &reg);
				*ret_val = scif_regv_handler(&elem, scif_of, &reg);

				break;

			case SCIF_UNREG:
				DEBUG("VIRTIO_SCIF_UNREG");
				struct scifioctl_unreg *unreg = elem.out_sg[3].iov_base;

				*ret_val = scif_unregister_handler(scif_of, &unreg);

				break;

			case SCIF_READFROM:
				DEBUG("VIRTIO_SCIF_READFROM");
				struct scifioctl_copy *rfrom = elem.out_sg[3].iov_base;

				*ret_val = scif_readfrom_handler(scif_of, &rfrom);

				break;

			case SCIF_WRITETO:
				DEBUG("VIRTIO_SCIF_WRITETO");
				struct scifioctl_copy *wto = elem.out_sg[3].iov_base;

				*ret_val = scif_writeto_handler(scif_of, &wto);

				break;

			case SCIF_VREADFROM:
				DEBUG("VIRTIO_SCIF_VREADFROM");
				struct scifioctl_copy *vrfrom = elem.out_sg[3].iov_base;
				vrfrom->addr = elem.out_sg[4].iov_base;

				*ret_val = scif_vreadfrom_handler(scif_of, &vrfrom);

				break;
//
//			case SCIF_VWRITETO:
//				DEBUG("VIRTIO_SCIF_VWRITETO");
//				struct scifioctl_copy *vwto = elem.out_sg[3].iov_base;
//				vwto->addr = elem.out_sg[4].iov_base;
//
//				*ret_val = scif_vwriteto_handler(scif_of, &vwto);
//
//				break;

			case SCIF_VWRITETO:
				DEBUG("VIRTIO_SCIF_VWRITETO");
				struct scifioctl_copy *vwto = elem.out_sg[3].iov_base;
				vwto->addr = elem.out_sg[4].iov_base;

				*ret_val = scif_vwriteto_sg_handler(scif_of, &vwto);

				break;

			case SCIF_FENCE_MARK:
				DEBUG("VIRTIO_SCIF_FENCE_MARK");
				struct scifioctl_fence_mark *mark = elem.out_sg[3].iov_base;
				mark->mark = elem.out_sg[4].iov_base;

				*ret_val = scif_fence_mark_handler(scif_of, &mark);

				break;

			case SCIF_FENCE_WAIT:
				DEBUG("VIRTIO_SCIF_FENCE_WAIT");
				int *wait = elem.out_sg[3].iov_base;

				*ret_val = scif_fence_wait_handler(scif_of, wait);

				break;

			case SCIF_FENCE_SIGNAL:
				DEBUG("VIRTIO_SCIF_FENCE_SIGNAL");
				struct scifioctl_fence_signal *sig = elem.out_sg[3].iov_base;

				*ret_val = scif_fence_signal_handler(scif_of, &sig);

				break;

			case SCIF_GET_NODEIDS:
				DEBUG("VIRTIO_SCIF_GET_NODEIDS");
				struct scifioctl_nodeIDs *ids = elem.out_sg[3].iov_base;
				ids->nodes = elem.out_sg[4].iov_base;
				ids->self = elem.out_sg[5].iov_base;

				*ret_val = scif_get_nodeids_handler(scif_of, &ids);

				break;

			default:
                                DEBUG("Unknown cmd");
				
				*ret_val = EINVAL;

                        	break;
			}

			break;

		case VIRTIO_SCIF_MMAP:
			DEBUG("VIRTIO_SCIF_MMAP");
			scif_of = elem.out_sg[1].iov_base;
			hwaddr plen;
			unsigned long *page_addr = elem.out_sg[2].iov_base;
			//dma_addr_t *addr = elem.out_sg[3].iov_base;
			//unsigned long *addr = elem.out_sg[3].iov_base;
			unsigned int *length = elem.out_sg[3].iov_base;
			unsigned int *order = elem.out_sg[4].iov_base;
			unsigned long *offset = elem.out_sg[5].iov_base;
			void *addr;
			DEBUG("VIRTIO_SCIF_MMAP1");

			//addr = cpu_physical_memory_map(*page_addr, &length, 1); 
			addr = cpu_physical_memory_map(*page_addr, &plen, 1);

			scif_mmap_handler(scif_of, &addr, *length, *offset);
			cpu_physical_memory_unmap(addr, plen, 1, plen); 
			//*ret_val = scif_mmap_handler(vdev, vq, &elem, scif_of, &addr);

			break;

		case VIRTIO_SCIF_MUNMAP:
			DEBUG("VIRTIO_SCIF_MUNMAP");
			hwaddr plength;
			unsigned long *paddr = elem.out_sg[1].iov_base;
			//dma_addr_t *addr = elem.out_sg[3].iov_base;
			//unsigned long *addr = elem.out_sg[3].iov_base;
			unsigned int *len = elem.out_sg[2].iov_base;
			void *vaddr;

			//addr = cpu_physical_memory_map(*page_addr, &length, 1); 
				vaddr = cpu_physical_memory_map(*paddr, &plength, 1);
//
				scif_munmap_handler(&vaddr, *len);
				cpu_physical_memory_unmap(vaddr, plength, 1, plength); 
				printf("QEMU unmapped\n");
			//*ret_val = scif_munmap_handler(vdev, vq, &elem, scif_of, &addr);

			break;

		case VIRTIO_SCIF_POLL:
			DEBUG("VIRTIO_SCIF_POLL");
			scif_of = elem.out_sg[1].iov_base;
			short *events = elem.out_sg[2].iov_base;
			short *revents = elem.in_sg[0].iov_base;

			scif_poll_handler(scif_of, &events, &revents);

			break;

//		case VIRTIO_SCIF_POLL:
//				DEBUG("VIRTIO_SCIF_POLL");
//				non_blocking = 1;
//
//				QemuThread poll_thr;
////				struct pollfd sfd;
//				scif_of = elem.out_sg[1].iov_base;
//				short *events = elem.out_sg[2].iov_base;
//				short *revents = elem.in_sg[0].iov_base;
//
//				struct scif_poll *spoll = malloc(sizeof(struct scif_poll));
//				struct VirtQueueElement *poll_elem = malloc(sizeof(struct VirtQueueElement));
//				memcpy(poll_elem, &elem, sizeof(struct VirtQueueElement));
//
//				spoll->vdev = vdev;
//				spoll->vq = vq;
//				spoll->elem = poll_elem;
//
////				spoll->sfd = sfd;
//				spoll->sfd.fd = scif_of->fd;
//				spoll->sfd.events = *events;
//				spoll->sfd.revents = *revents;
//
//				qemu_thread_create(&poll_thr, "scif_poll_thread", scif_poll_handler_async,
//					       (void *)spoll, QEMU_THREAD_DETACHED);
//

				break;

		default:
			DEBUG("Unknown type");
//			printf("unknown type: 0x%lx", req->type);
		}

		//FIXME: lock virtqueue for access with worker threads
		if (!non_blocking) {
			qemu_mutex_lock(&vq_lock);
			virtqueue_push(vq, &elem, 0);
			qemu_mutex_unlock(&vq_lock);
		}

		// Blocking by default, since most
		// of the calls are blocking
		non_blocking = 0;
	}
	//FIXME: Maybe no guest notification is needed (if only blocking calls requested)
	/* Interrupt Coalescing (notify guest only once for many virtio elements) */
	qemu_mutex_lock(&vq_lock);
	virtio_notify(vdev, vq);
	qemu_mutex_unlock(&vq_lock);

	DEBUG_OUT();
}

static void vq_handle_poll_output(VirtIODevice *vdev, VirtQueue *vq)
{
	VirtQueueElement elem;
	struct vq_packet *req;
	struct scif_open_file *scif_of;
//	int non_blocking = 0;
//	unsigned int *cmd;
	int *ret_val = NULL;

	DEBUG_IN();

	while (virtqueue_pop(vq, &elem)) {
		DEBUG("I 've got an item from POLL VQ :)");

		DEBUG("VIRTIO_SCIF_POLL");

		QemuThread poll_thr;

		scif_of = elem.out_sg[0].iov_base;
		short *events = elem.out_sg[1].iov_base;
		short *revents = elem.in_sg[0].iov_base;

		struct scif_poll *spoll = malloc(sizeof(struct scif_poll));
		struct VirtQueueElement *poll_elem = malloc(sizeof(struct VirtQueueElement));
		memcpy(poll_elem, &elem, sizeof(struct VirtQueueElement));

		spoll->vdev = vdev;
		spoll->vq = vq;
		spoll->elem = poll_elem;
		//spoll->elem = &elem;

		//spoll->scif_of = scif_of;
		//spoll->scif_of->is_alloc = scif_of->is_alloc;
		//spoll->sfd.is_alloc = scif_of->is_alloc;
		//spoll->is_alloc = scif_of->is_alloc;
		spoll->sfd.fd = scif_of->fd;
		spoll->sfd.events = *events;
		spoll->sfd.revents = *revents;

		qemu_thread_create(&poll_thr, "scif_poll_thread", scif_poll_handler_async,
		       		(void *)spoll, QEMU_THREAD_DETACHED);
		       		//(void *)spoll, QEMU_THREAD_JOINABLE);

		
		//memcpy(&(scif_of->poll_id), &poll_thr, sizeof(scif_of->poll_id));
		//scif_of->poll_id = 19;
	}

	DEBUG_OUT();
}

static void virtio_scif_realize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();

	VirtIODevice *vdev = VIRTIO_DEVICE(dev);

	virtio_init(vdev, "virtio-scif", 11, 0);
	//virtio_add_queue(vdev, 1024, vq_handle_output);
	//virtio_add_queue(vdev, 4096, vq_handle_output);
	virtio_add_queue(vdev, 8192, vq_handle_output);
	//virtio_add_queue(vdev, 1024, vq_handle_poll_output);
	//virtio_add_queue(vdev, 4096, vq_handle_poll_output);
	virtio_add_queue(vdev, 8192, vq_handle_poll_output);
	
	qemu_mutex_init(&vq_lock);
	qemu_mutex_init(&vq_poll_lock);

	DEBUG_OUT();
}

static void virtio_scif_unrealize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();

	qemu_mutex_destroy(&vq_lock);
	qemu_mutex_destroy(&vq_poll_lock);

	DEBUG_OUT();
}

static Property virtio_scif_properties[] = {
	DEFINE_PROP_END_OF_LIST(),
};

static void virtio_scif_class_init(ObjectClass *klass, void *data)
{
	DeviceClass *dc = DEVICE_CLASS(klass);
	VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

	DEBUG_IN();
	dc->props = virtio_scif_properties;
	set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

	k->realize = virtio_scif_realize;
	k->unrealize = virtio_scif_unrealize;
	k->get_features = get_features;
	k->get_config = get_config;
	k->set_config = set_config;
	k->set_status = set_status;
	k->reset = vser_reset;

	DEBUG_OUT();
}

static const TypeInfo virtio_scif_info = {
	.name          = TYPE_VIRTIO_SCIF,
	.parent        = TYPE_VIRTIO_DEVICE,
	.instance_size = sizeof(VirtScif),
	.class_init    = virtio_scif_class_init,
};

static void virtio_scif_register_types(void)
{
	DEBUG_IN();

	type_register_static(&virtio_scif_info);

	DEBUG_OUT();
}

type_init(virtio_scif_register_types)
