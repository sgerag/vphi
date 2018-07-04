#ifndef VIRTIO_SCIF_H
#define VIRTIO_SCIF_H

#define DEBUG(str)
//#define DEBUG(str) \
//	printf("[VIRTIO-SCIF] FILE[%s] LINE[%d] FUNC[%s] STR[%s]\n", \
//	       __FILE__, __LINE__, __func__, str);
#define DEBUG_IN() DEBUG("IN")
#define DEBUG_OUT() DEBUG("OUT")

#define VIRTIO_SCIF_OPEN  0
#define VIRTIO_SCIF_CLOSE 1
#define VIRTIO_SCIF_IOCTL 2
#define VIRTIO_SCIF_MMAP 3
#define VIRTIO_SCIF_MUNMAP 4
#define VIRTIO_SCIF_POLL 5

#include "hw/virtio/virtio.h"
//#include <scif.h>
//#include <scif_ioctl.h>
#include <poll.h>

#define TYPE_VIRTIO_SCIF "virtio-scif"

#define SCIFDEV_FILENAME  "/dev/mic/scif"

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

typedef struct VirtScif {
    VirtIODevice parent_obj;
} VirtScif;

/**
 * SCIF virtqueue packet
 **/
struct vq_packet {
//        struct out_struct
//        {
                unsigned int type;
//                unsigned int idx;
//        } out;

        /* the actual buffer */
        //void *opaque;
        /* length of the buffer */
        //unsigned int len;
};

/**
 * SCIF virtqueue reply
 **/
struct vq_reply {
        /* list of unconsumed vq replies */
//        struct list_head list;

//      unsigned int idx;

        /* the returned vq packet */
        struct vq_packet *packet;
        unsigned int len;
};

/**
 * SCIF open file.
 **/
struct scif_open_file {
        /* The scif device this open file is associated with. */
        //struct scif_device *scif_dev;
       // int idx;

//      struct vq_packet *req;

        /* The fd that this device has on the Host. */
        int fd;

//	int is_alloc;
//
//	//dirty hack in order to handle
//	//dangling poll threads
//	//we assume sizeof(pid_t) == sizeof(pthread_t)
//	uint64_t poll_id;
};

struct scif_connect {
	VirtIODevice *vdev;
	VirtQueue *vq;
	VirtQueueElement *elem;
	struct scif_open_file *scif_of;
	int fd;
	struct scifioctl_connect *conn;
};

struct scif_acceptreq {
	VirtIODevice *vdev;
	VirtQueue *vq;
	VirtQueueElement *elem;
	struct scif_open_file *scif_of;
	int fd;
	struct scifioctl_accept *acc;
};

struct scif_msg {
	VirtIODevice *vdev;
	VirtQueue *vq;
	VirtQueueElement *elem;
	struct scif_open_file *scif_of;
	int fd;
	int recv; 	//boolean send/recv flag
	struct scifioctl_msg *msg;
	void *rmsg;	
};

struct scif_poll {
	VirtIODevice *vdev;
	VirtQueue *vq;
	VirtQueueElement *elem;
	int is_alloc;
	//struct scif_open_file *scif_of;
	struct pollfd sfd;
	short *events;
	short *revents;
};

struct mmap_priv {
	VirtIODevice *vdev;
	VirtQueue *vq;
	VirtQueueElement *elem;
	struct scif_open_file *scif_of;
	struct scifioctl_accept *acc;
};

#endif /* VIRTIO_SCIF_H */
