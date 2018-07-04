#ifndef _VIRTIO_SCIF_H
#define _VIRTIO_SCIF_H

#include <linux/cdev.h>
#include "/root/xeon-phi/intel-original/mpss-3.4/src/include/scif.h"
#include "/root/xeon-phi/intel-original/mpss-3.4/src/include/scif_ioctl.h"

//#define VIRTIO_SCIF_BLOCK_SIZE    16

#define VIRTIO_SCIF_OPEN  0
#define VIRTIO_SCIF_CLOSE 1
#define VIRTIO_SCIF_IOCTL 2
#define VIRTIO_SCIF_MMAP 3
#define VIRTIO_SCIF_MUNMAP 4
#define VIRTIO_SCIF_POLL 5

/* The Virtio ID for virtio-scif */
#define VIRTIO_ID_SCIF            11

/**
 * Global driver data.
 **/
struct scif_driver_data {
//	/* The list of the devices we are handling. */
//	struct list_head devs;
	struct scif_device *scif_dev;	

	/* The minor number that we give to the next device. */
	unsigned int next_minor;

	spinlock_t lock;
};
extern struct scif_driver_data scif_drvdata;


/**
 * Device info.
 **/
struct scif_device {
	/* Next scif device in the list, head is in the scif_drvdata struct */
	//struct list_head list;

	/* The char device we are associated with. */
	struct cdev scif_cdev;

	/* The virtio device we are associated with. */
	struct virtio_device *vdev;

	struct virtqueue *vq;
	spinlock_t vq_lock;

	struct virtqueue *poll_vq;
	spinlock_t poll_vq_lock;

	/* The minor number of the device. */
	//unsigned int minor;

	/* A unique identifier of each vq cookie. */
	//unsigned int vq_elem_id;

	//spinlock_t lock;

	/*
 	 * waiting to be woken up when the virtqueue has data 
 	 * destined specifically to us
 	 */
	wait_queue_head_t wq;

	/* Request/reply index */
	//FIXME: what type?
	//TODO: add overflow handler.
//	unsigned int current_req_idx;
//	unsigned int current_reply_idx;

//	/* head of the replies */
//	struct vq_reply *reply;
	/* head of the reply packets */
	struct list_head packet_list;
	//struct vq_packet *packet;
	spinlock_t reply_lock;
};

/**
 * SCIF virtqueue packet
 **/
struct vq_packet {
	unsigned int type;

	/* list of unconsumed vq replies */
	struct list_head list;

	/* the actual buffer */
	//void *opaque;
	/* length of the buffer */
	//unsigned int len;
};

struct host_of {
	/* The fd that this device has on the Host. */
	int hfd;
//	int is_alloc;

	//dirty hack, in order to handle 
	//dangling host polling threads
//	uint64_t poll_host_id;
};

/**
 * SCIF open file.
 **/
struct scif_open_file {
	/* The scif device this open file is associated with. */
	//struct scif_device *scif_dev;
//	int idx;

//	struct vq_packet *req;

	/* The fd that this device has on the Host. */
	//int host_fd;
	struct host_of host_fd;

	wait_queue_head_t poll_wq;
//	struct work_struct poll_work;
	atomic_t is_polling;

	struct semaphore win_sem;
	struct list_head windows_list;
};

/**
 * SCIF registered window.
 **/
struct reg_window {
	/* The scif device this open file is associated with. */
	//struct scif_device *scif_dev;
	//int idx;
	//scif_epd_t epd;
	struct scif_open_file *epd;

	struct list_head list;
	//struct vq_packet *packet;
	
	//guest user requested address
	void __user *uaddr;

	int64_t nr_pages;
	struct page **pages;
	uint64_t reg_offset;

	uint64_t *kaddr;

//        struct idr epd_idr;
//        spinlock_t epd_idr_lock;
//
////	struct vq_packet *req;
//
//	/* The fd that this device has on the Host. */
//	int host_fd;
};

struct vma_pvt {
	unsigned long vm_addr;
	unsigned long mapped_addr;
	unsigned int order;
	struct kref ref;
};

///**
// * SCIF registered window.
// **/
//struct scif_registered_window {
//	/* The scif device this open file is associated with. */
//	//struct scif_device *scif_dev;
//	//int idx;
//	//scif_epd_t epd;
//	struct scif_open_file *epd;
//
//	struct list_head list;
//	//struct vq_packet *packet;
//	struct semaphore *sem;
//	
////        struct idr epd_idr;
////        spinlock_t epd_idr_lock;
////
//////	struct vq_packet *req;
////
////	/* The fd that this device has on the Host. */
////	int host_fd;
//};

/**
 * SCIF poll struct.
 **/
struct scif_poll_struct {
	short *events;
	short *revents;
	struct scif_open_file *of;
	//wait_queue_head_t poll_wq;
};


#endif
