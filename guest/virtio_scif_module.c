#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>


#include <linux/proc_fs.h>
#include "virtio_scif.h"
#include "virtio_scif_chrdev.h"
#include "debug.h"


#define PCI_VENDOR_INTEL        0x8086

#define PCI_DEVICE_ABR_2249     0x2249
#define PCI_DEVICE_ABR_224a     0x224a

#define PCI_DEVICE_KNC_2250     0x2250
#define PCI_DEVICE_KNC_2251     0x2251
#define PCI_DEVICE_KNC_2252     0x2252
#define PCI_DEVICE_KNC_2253     0x2253
#define PCI_DEVICE_KNC_2254     0x2254
#define PCI_DEVICE_KNC_2255     0x2255
#define PCI_DEVICE_KNC_2256     0x2256
#define PCI_DEVICE_KNC_2257     0x2257
#define PCI_DEVICE_KNC_2258     0x2258
#define PCI_DEVICE_KNC_2259     0x2259
#define PCI_DEVICE_KNC_225a     0x225a

#define PCI_DEVICE_KNC_225b     0x225b
#define PCI_DEVICE_KNC_225c     0x225c
#define PCI_DEVICE_KNC_225d     0x225d
#define PCI_DEVICE_KNC_225e     0x225e

struct scif_driver_data scif_drvdata;

typedef struct mic_data {
	int32_t                 dd_numdevs;
//	int32_t                 dd_inuse;
//#ifdef USE_VCONSOLE
//	micvcons_port_t         dd_ports[MAX_BOARD_SUPPORTED];
//#endif
//	struct board_info       *dd_bi[MAX_BOARD_SUPPORTED];
	struct board_info       *dd_bi[256];
//	struct list_head        dd_bdlist;
//	micscif_pm_t            dd_pm;
//	uint64_t                sysram;
//	struct fasync_struct    *dd_fasync;
//	struct list_head        sku_table[MAX_DEV_IDS];
} mic_data_t;

mic_data_t mic_data;

typedef struct lindata {
    	dev_t                   dd_dev;
        struct cdev             dd_cdev;
        struct device           *dd_hostdev;
        struct device           *dd_scifdev;
        struct class            *dd_class;
        struct pci_driver       dd_pcidriver;
}mic_lindata_t;

mic_lindata_t mic_lindata;

struct mic_info {
        dev_t        	 m_dev;
//        struct cdev      m_cdev;
        struct class *   m_class;
        struct device *  m_scifdev;
} micinfo;

typedef struct _mic_ctx_t {
	struct board_info 	*bd_info;
	uint32_t 		bi_id;
	struct kernfs_node 	*sysfs_state;
	spinlock_t              sysfs_lock;


} mic_ctx_t;

typedef struct board_info {
	struct device 	*bi_sysfsdev;
	mic_ctx_t 	bi_ctx;
} bd_info_t;

static void vq_callback(struct virtqueue *vq)
{
	unsigned long flags;
	unsigned int len;
	struct scif_device *scif_dev = vq->vdev->priv;

	struct vq_packet *buf;
struct timeval t2, t3;
long temp;

	//do_gettimeofday(&t2);
	debug("Entering");

	/* We can get spurious callbacks, e.g. shared IRQs + virtio_pci. */
	/* MAYBE one interrupt for many packets?? */
	while (1){
		spin_lock_irqsave(&scif_dev->vq_lock, flags);
		buf = virtqueue_get_buf(scif_dev->vq, &len);
		spin_unlock_irqrestore(&scif_dev->vq_lock, flags);
		
		if (!buf) 	
			break;
		else {
			/* add the new reply packet to the list */
			spin_lock_irqsave(&scif_dev->reply_lock, flags);
			list_add_tail(&buf->list, &scif_dev->packet_list);
			spin_unlock_irqrestore(&scif_dev->reply_lock, flags);
		}
	}

	wake_up_interruptible(&scif_dev->wq);
	//do_gettimeofday(&t3);
	//temp = (long) (t3.tv_sec - t2.tv_sec)*1000000 + (t3.tv_usec - t2.tv_usec);
	//printk("IRQ microseconds??: %ld\n", temp);

	debug("Leaving");
}

static void vq_poll_callback(struct virtqueue *vq)
{
	unsigned long flags;
	unsigned int len;
	struct scif_device *scif_dev = vq->vdev->priv;

	//struct scif_open_file *pbuf;
	struct scif_poll_struct *pbuf;

	debug("Entering");

	/* We can get spurious callbacks, e.g. shared IRQs + virtio_pci. */
	/* MAYBE one interrupt for many packets?? */
	while (1){
		spin_lock_irqsave(&scif_dev->poll_vq_lock, flags);
		pbuf = virtqueue_get_buf(scif_dev->poll_vq, &len);
		spin_unlock_irqrestore(&scif_dev->poll_vq_lock, flags);
		
//		if (!pbuf)
//			break;
		if (!pbuf) {
			debug("REPORT bug");
			break;
		}

		//TODO: check pbuf->poll_wq (host could have interrupted us after 60 seconds
		//when fd has been closed)
		else if (!pbuf->of) {
			debug("REPORT bug2");
			break;
		}
		else {
//printk(KERN_ALERT "pbuf: 0x%lx", (long unsigned int)(pbuf));
////printk(KERN_ALERT "poll_wq: 0x%lx", (long unsigned int)(pbuf->poll_wq));
//printk(KERN_ALERT "&poll_wq: 0x%lx\n", (long unsigned int)&pbuf->of->poll_wq);
			wake_up_interruptible(&pbuf->of->poll_wq);
		}

//printk(KERN_ALERT "pbuf->events: 0x%lx\n", (long unsigned int)pbuf->events);
//printk(KERN_ALERT "pbuf->revents: 0x%lx\n", (long unsigned int)pbuf->revents);
		kfree(pbuf->events);
//		kfree(pbuf->revents);
		kfree(pbuf);
	}

	debug("Leaving");
}

static struct virtqueue *find_vq(struct virtio_device *vdev)
{
	int err;
	struct virtqueue *vq;

	debug("Entering");

	vq = virtio_find_single_vq(vdev, vq_callback, "scif-vq");
	if (IS_ERR(vq)) {
		debug("Could not find vq");
		vq = NULL;
	}

	debug("Leaving");

	return vq;
}
//
//static struct virtqueue *find_poll_vq(struct virtio_device *vdev)
//{
//	int err;
//	struct virtqueue *vq;
//
//	debug("Entering");
//
//	vq = virtio_find_single_vq(vdev, vq_poll_callback, "scif-poll-vq");
//	if (IS_ERR(vq)) {
//		debug("Could not find poll vq");
//		vq = NULL;
//	}
//
//	debug("Leaving");
//
//	return vq;
//}

/**
 * This function is called each time the kernel finds a virtio device
 * that we are associated with.
 **/
static int virtscif_probe(struct virtio_device *vdev)
{
	unsigned long flags;
	vq_callback_t **callbacks;
	struct virtqueue **vqs;
	const char *names[] = { "scif-vq", "scif-poll-vq" };
	//const char **names;
	struct scif_device *scif_dev;
	int ret = 0;

	debug("Entering");

	scif_dev = kmalloc(sizeof(*scif_dev), GFP_KERNEL);
	if (!scif_dev) {
		ret = -ENOMEM;
		goto out;
	}

	vqs = kmalloc(2*sizeof(*vqs), GFP_KERNEL);
	if (!vqs) {
		ret = -ENOMEM;
		goto err_vqs;
	}

	callbacks = kmalloc(2*sizeof(*callbacks), GFP_KERNEL);
	if (!callbacks) {
		ret = -ENOMEM;
		goto err_callbacks;
	}

//	names = kmalloc(2*sizeof(*names), GFP_KERNEL);
//	if (!names) {
//		ret = -ENOMEM;
//		goto err_names;
//	}

	callbacks[0] = vq_callback;
	callbacks[1] = vq_poll_callback;
//	sprintf(names[0], "scif-vq");
//	sprintf(names[1], "scif-poll-vq");
	//names[0] = "aaa";	
	//names[1] = "bbb";	

	scif_dev->vdev = vdev;

	vdev->priv = scif_dev;

	ret = vdev->config->find_vqs(scif_dev->vdev, 2, vqs, callbacks, names);
	if (ret)
		goto err_find;

	scif_dev->vq = vqs[0];
	scif_dev->poll_vq = vqs[1];

//	scif_dev->vq = find_vq(vdev);
//	if (!(scif_dev->vq)) {
//		ret = -ENXIO;
//		goto err_vqs;
//	}

//	scif_dev->poll_vq = find_poll_vq(vdev);
//	if (!(scif_dev->poll_vq)) {
//		ret = -ENXIO;
//		goto fail;
//	}

//	scif_dev->reply = kmalloc(sizeof(*(scif_dev->reply)), GFP_KERNEL);
//	if (!(scif_dev->reply)) {
//		ret = -ENOMEM;
//		goto fail;
//	}
//	scif_dev->packet = kmalloc(sizeof(*(scif_dev->packet)), GFP_KERNEL);
//	if (!(scif_dev->packet)) {
//		ret = -ENOMEM;
//		goto fail;
//	}

	//INIT_LIST_HEAD(&scif_dev->reply->list);
	INIT_LIST_HEAD(&scif_dev->packet_list);

	spin_lock_init(&scif_dev->vq_lock);
	spin_lock_init(&scif_dev->poll_vq_lock);
	spin_lock_init(&scif_dev->reply_lock);
	//spin_lock_init(&scif_dev->lock);

	init_waitqueue_head(&scif_dev->wq);
	
//	spin_lock_irqsave(&scif_dev->reply_lock, flags);
//	spin_unlock_irqrestore(&scif_dev->reply_lock, flags);

	/**
	 * Grab the next minor number and put the device in the driver's list. 
	 **/
	//spin_lock_irqsave(&scif_dev->lock, flags);
	scif_drvdata.scif_dev = scif_dev; //FIXME (lock?)
	//scif_dev->minor = scif_drvdata.next_minor++;
	//scif_drvdata.next_minor = 42;
	//scif_dev->current_req_idx = 19;
	//scif_dev->current_reply_idx = 0;
//	list_add_tail(&scif_dev->list, &scif_drvdata.devs);
	//spin_unlock_irqrestore(&scif_dev->lock, flags);
		
	//debug("Got minor = %u", scif_dev->minor);

	debug("Leaving");

	goto out;

err_find:
	kfree(callbacks);

//err_names:
//	kfree(names);

err_callbacks:
	kfree(vqs);

err_vqs:
	kfree(scif_dev);

out:
	return ret;
}

static void virtscif_remove(struct virtio_device *vdev)
{
	struct scif_device *scif_dev = vdev->priv;

	debug("Entering");

	/* Delete virtio device list entry. */
//	spin_lock_irq(&scif_drvdata.lock);
//	list_del(&scif_dev->list);
//	spin_unlock_irq(&scif_drvdata.lock);

	/* NEVER forget to reset virtio device and delete device virtqueues. */
	vdev->config->reset(vdev);
	vdev->config->del_vqs(vdev);

	kfree(scif_dev);

	debug("Leaving");
}

static struct virtio_device_id id_table[] = {
	{VIRTIO_ID_SCIF, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	0
};

static struct virtio_driver virtio_scif = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	virtscif_probe,
	.remove =	virtscif_remove,
};

extern struct attribute_group bd_attr_group;
extern struct attribute_group host_attr_group;
extern struct attribute_group scif_attr_group;


static int
mic_probe(struct pci_dev *pdev, const struct pci_device_id *ent)                                                                              
{
	int err = 0;
        bd_info_t *bd_info;
        mic_ctx_t *mic_ctx;


//NEVER CALLED ANYWAYS
//	if ((bd_info = (bd_info_t *)kzalloc(sizeof(bd_info_t), GFP_KERNEL)) == NULL) {
//		printk("MIC: probe failed allocating memory for bd_info\n");
//		return -ENOSPC;
//        }
//printk(KERN_ALERT "mic_PROBE()\n");
//
//        mic_ctx = &bd_info->bi_ctx;
//
//        if ((err = pci_enable_device(pdev))) {
//                printk(KERN_ALERT "pci_enable failed board #\n");
//        }
//
//	bd_info->bi_sysfsdev = device_create(mic_lindata.dd_class, &pdev->dev,
//                        mic_lindata.dd_dev + 2 + mic_ctx->bd_info->bi_ctx.bi_id,
//                        NULL, "mic%d", mic_ctx->bd_info->bi_ctx.bi_id);
//	err = sysfs_create_group(&mic_ctx->bd_info->bi_sysfsdev->kobj, &bd_attr_group);
//	mic_ctx->sysfs_state = sysfs_get_dirent(mic_ctx->bd_info->bi_sysfsdev->kobj.sd,
//                                "state");
//
//	dev_set_drvdata(mic_ctx->bd_info->bi_sysfsdev, mic_ctx);


//	list_add_tail(&bd_info->bi_list, &mic_data.dd_bdlist);
	mic_data.dd_numdevs++;

	return 0;

}

static void                                                                                                                                   
mic_remove(struct pci_dev *pdev)
{
	int32_t brdnum;
	bd_info_t *bd_info;
	//sgerag
	//mic_ctx_t *mic_ctx = pci_get_drvdata(pdev);

	if (mic_data.dd_numdevs - 1 < 0)
		return;
	mic_data.dd_numdevs--;
	brdnum = mic_data.dd_numdevs;

	/* Make sure boards are shutdown and not available. */
	bd_info = mic_data.dd_bi[brdnum];

	spin_lock_bh(&bd_info->bi_ctx.sysfs_lock);
	sysfs_put(bd_info->bi_ctx.sysfs_state);
	bd_info->bi_ctx.sysfs_state = NULL;
	spin_unlock_bh(&bd_info->bi_ctx.sysfs_lock);

//	if (bd_info->bi_ctx.bi_psmi.enabled) {
//		device_remove_bin_file(bd_info->bi_sysfsdev, &mic_psmi_ptes_attr);
//		sysfs_remove_group(&bd_info->bi_sysfsdev->kobj, &psmi_attr_group);
//	}
	sysfs_remove_group(&bd_info->bi_sysfsdev->kobj, &bd_attr_group);
//
//	free_sysfs_entries(&bd_info->bi_ctx);
	device_destroy(mic_lindata.dd_class,
		       mic_lindata.dd_dev + 2 + bd_info->bi_ctx.bi_id);

//	adapter_stop_device(&bd_info->bi_ctx, 1, 0);
//	/*
//	 * Need to wait for reset since accessing the card while GDDR training
//	 * is ongoing by adapter_remove(..) below for example can be fatal.
//	 */
//	wait_for_reset(&bd_info->bi_ctx);
//
//	mic_disable_interrupts(&bd_info->bi_ctx);
//
//	if (!bd_info->bi_ctx.msie) {
//		free_irq(bd_info->bi_ctx.bi_pdev->irq, &bd_info->bi_ctx);
//#ifdef CONFIG_PCI_MSI
//	} else {
//	free_irq(bd_info->bi_msix_entries[0].vector, &bd_info->bi_ctx);
//		pci_disable_msix(bd_info->bi_ctx.bi_pdev);
//#endif
//	}
//	adapter_remove(&bd_info->bi_ctx);
//	release_mem_region(bd_info->bi_ctx.aper.pa, bd_info->bi_ctx.aper.len);
//	release_mem_region(bd_info->bi_ctx.mmio.pa, bd_info->bi_ctx.mmio.len);
//	pci_disable_device(bd_info->bi_ctx.bi_pdev);
	kfree(bd_info);
}

static struct pci_device_id mic_pci_tbl[] = {
//#ifdef CONFIG_ML1OM
//	{ PCI_VENDOR_ID_INTEL,  PCI_DEVICE_ABR_2249, PCI_ANY_ID, PCI_ANY_ID,
//	  0, 0, 0 },
//	{ PCI_VENDOR_ID_INTEL,  PCI_DEVICE_ABR_224a, PCI_ANY_ID, PCI_ANY_ID,
//	  0, 0, 0 },
//#endif
//#ifdef CONFIG_MK1OM
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_2250, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_2251, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_2252, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_2253, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_2254, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_2255, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_2256, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_2257, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_2258, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_2259, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_225a, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_225b, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_225c, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_225d, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
	{ PCI_VENDOR_ID_INTEL, PCI_DEVICE_KNC_225e, PCI_ANY_ID, PCI_ANY_ID,
	  0, 0, 0 },
//#endif
	{ 0, }
};

//CHECK ./host/linux.c at host
static int scif_ctrl_create_sysfs(void) 
{
	int brdnum = mic_data.dd_numdevs;
	int ret = 0;
	bd_info_t *bd_info;
	mic_ctx_t *mic_ctx;

	mic_lindata.dd_pcidriver.name = "mic";
	mic_lindata.dd_pcidriver.id_table = mic_pci_tbl;
	mic_lindata.dd_pcidriver.probe = mic_probe;
	mic_lindata.dd_pcidriver.remove = mic_remove;


//	bd_info->bi_sysfsdev = device_create(mic_lindata.dd_class, &pdev->dev,
//			mic_lindata.dd_dev + 2 + mic_ctx->bd_info->bi_ctx.bi_id,
//			NULL, "mic%d", mic_ctx->bd_info->bi_ctx.bi_id);
//	err = sysfs_create_group(&mic_ctx->bd_info->bi_sysfsdev->kobj, &bd_attr_group);
//	mic_ctx->sysfs_state = sysfs_get_dirent(mic_ctx->bd_info->bi_sysfsdev->kobj.sd,
//				"state");


	//mic_lindata.dd_class = class_create(THIS_MODULE, "lala"); 
	mic_lindata.dd_class = class_create(THIS_MODULE, "mic"); 
	if (IS_ERR(mic_lindata.dd_class)) {
		printk(KERN_ALERT "ERROR class_create\n");

	}

        mic_lindata.dd_hostdev = device_create(mic_lindata.dd_class, NULL,                                                           
                                            mic_lindata.dd_dev, NULL, "ctrl");
        mic_lindata.dd_scifdev = device_create(mic_lindata.dd_class, NULL,
                                            mic_lindata.dd_dev + 1, NULL, "scif");
        ret = sysfs_create_group(&mic_lindata.dd_hostdev->kobj, &host_attr_group);
        ret = sysfs_create_group(&mic_lindata.dd_scifdev->kobj, &scif_attr_group);

        ret = pci_register_driver(&mic_lindata.dd_pcidriver);
        if (ret) {
                printk(KERN_ALERT "mic: failed to register pci driver %d\n", ret);
                //goto clean_unregister;                                                                                                        
        }

        if ((bd_info = (bd_info_t *)kzalloc(sizeof(bd_info_t), GFP_KERNEL)) == NULL) {                                                        
                printk("MIC: probe failed allocating memory for bd_info\n");
                return -ENOSPC;
        }

        mic_ctx = &bd_info->bi_ctx;
	//sgerag
	mic_ctx->bd_info = bd_info;

        bd_info->bi_sysfsdev = device_create(mic_lindata.dd_class, NULL,
                                            mic_lindata.dd_dev + 2, NULL, "mic0");
if (!(mic_ctx->bd_info))
	printk(KERN_ALERT "null mic_ctx");
if (!(mic_ctx->bd_info->bi_sysfsdev))
	printk(KERN_ALERT "null bd");
//if (!(mic_ctx->bd_info->bi_sysfsdev->kobj))
//	printk(KERN_ALERT "null bd kobj");
	ret = sysfs_create_group(&mic_ctx->bd_info->bi_sysfsdev->kobj, &bd_attr_group);
	mic_ctx->sysfs_state = sysfs_get_dirent(mic_ctx->bd_info->bi_sysfsdev->kobj.sd,
                                "state");

	dev_set_drvdata(mic_ctx->bd_info->bi_sysfsdev, mic_ctx);

	return ret;
}

//extern struct attribute_group scif_attr_group;
//
//static char *scif_devnode(struct device *dev, umode_t *mode)                                                                                  
//{
//	return kasprintf(GFP_KERNEL, "mic/%s", dev_name(dev));
//}
//
static int scif_create_sysfs(void) 
{
	long int result = 0;

//	micinfo.m_class = class_create(THIS_MODULE, "micscif");
//	//micinfo.m_class = class_create(THIS_MODULE, "mic");
//	if (IS_ERR(micinfo.m_class)) {
//		result = PTR_ERR(micinfo.m_class);
//	}
//
//	micinfo.m_class->devnode = scif_devnode;
//	//micinfo.m_class->devnode = "scif";
//	if (IS_ERR((int *)(result =
//		(long int)device_create(micinfo.m_class, NULL, micinfo.m_dev, NULL, "mic0")))) {
//		result = PTR_ERR((int *)result);
//		goto class_destroy;
//	}
//	if (IS_ERR(micinfo.m_scifdev =
//		device_create(micinfo.m_class, NULL, micinfo.m_dev + 1, NULL, "scif"))) {
//		result = PTR_ERR(micinfo.m_scifdev);
//		goto device_destroy;
//	}
//	if ((result = sysfs_create_group(&micinfo.m_scifdev->kobj, &host_attr_group)))
//		goto device_destroy1;
//
//	return result;
//
//device_destroy1:
//	device_destroy(micinfo.m_class, micinfo.m_dev + 1);
//device_destroy:
//	device_destroy(micinfo.m_class, micinfo.m_dev);                                                                                       
//class_destroy:
//	class_destroy(micinfo.m_class);

	return result;
}

/**
 * The function that is called when our module is being inserted in
 * the running kernel.
 **/
static int __init init(void)
{
	int ret = 0;
	debug("Entering");

	/* Register the character devices that we will use. */
	ret = scif_chrdev_init();
	if (ret < 0) {
		printk(KERN_ALERT "Could not initialize character devices.\n");
		goto out;
	}

//	INIT_LIST_HEAD(&scif_drvdata.devs);
//	spin_lock_init(&scif_drvdata.lock);

	/* Register the virtio driver. */
	ret = register_virtio_driver(&virtio_scif);
	if (ret < 0) {
		printk(KERN_ALERT "Failed to register virtio driver.\n");
		goto out_with_chrdev;
	}

	//FIXME: check ret value
	ret = scif_create_sysfs();
	ret = scif_ctrl_create_sysfs();

	debug("Leaving");
	return ret;

out_with_chrdev:
	debug("Leaving");
	scif_chrdev_destroy();
out:
	return ret;
}

void scif_destroy_sysfs(void) 
{
//	sysfs_remove_group(&micinfo.m_scifdev->kobj, &scif_attr_group);
//        device_destroy(micinfo.m_class, micinfo.m_dev + 1);
//        device_destroy(micinfo.m_class, micinfo.m_dev);
//        class_destroy(micinfo.m_class);
////        cdev_del(&(micinfo.m_cdev));
////        unregister_chrdev_region(micinfo.m_dev, 2);

	pci_unregister_driver(&mic_lindata.dd_pcidriver);
	//micpm_uninit();

	/* Uninit data structures for PM disconnect */
	//micpm_disconn_uninit(mic_data.dd_numdevs + 1);


	//micscif_kmem_cache_destroy();
	//vmcore_exit();
	//micveth_exit();
	//micscif_destroy();
	//ramoops_exit();

	device_destroy(mic_lindata.dd_class, mic_lindata.dd_dev + 1);
	device_destroy(mic_lindata.dd_class, mic_lindata.dd_dev);
	class_destroy(mic_lindata.dd_class);
	cdev_del(&mic_lindata.dd_cdev);
	unregister_chrdev_region(mic_lindata.dd_dev, 68);
//	unregister_pm_notifier(&mic_pm_notifer);
}

/**
 * The function that is called when our module is being removed.
 * Make sure to cleanup everything.
 **/
static void __exit fini(void)
{
	int32_t brdnum;
	bd_info_t *bd_info;

	debug("Entering");
	scif_chrdev_destroy();
	unregister_virtio_driver(&virtio_scif);
//	scif_destroy_sysfs();



        /* Close endpoints related to reverse registration */
//	acptboot_exit();
//
//#ifdef USE_VCONSOLE
//	micvcons_destroy(mic_data.dd_numdevs);
//#endif
//
	pci_unregister_driver(&mic_lindata.dd_pcidriver);
//	micpm_uninit();
//
///* Uninit data structures for PM disconnect */
//	micpm_disconn_uninit(mic_data.dd_numdevs + 1);
//
//#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,34))
//	pm_qos_remove_requirement(PM_QOS_CPU_DMA_LATENCY, "mic");
//#endif
//	micscif_kmem_cache_destroy();
//	vmcore_exit();
//	micveth_exit();
//	micscif_destroy();
//	ramoops_exit();
//
	//sgerag
	//mic_ctx_t *mic_ctx = pci_get_drvdata(pdev);

//	if (mic_data.dd_numdevs - 1 < 0)
//		return;
//	mic_data.dd_numdevs--;
//	brdnum = mic_data.dd_numdevs;

	/* Make sure boards are shutdown and not available. */
//	bd_info = mic_data.dd_bi[brdnum];
//
//	spin_lock_bh(&bd_info->bi_ctx.sysfs_lock);
//	sysfs_put(bd_info->bi_ctx.sysfs_state);
//	bd_info->bi_ctx.sysfs_state = NULL;
//	spin_unlock_bh(&bd_info->bi_ctx.sysfs_lock);

//	if (bd_info->bi_ctx.bi_psmi.enabled) {
//		device_remove_bin_file(bd_info->bi_sysfsdev, &mic_psmi_ptes_attr);
//		sysfs_remove_group(&bd_info->bi_sysfsdev->kobj, &psmi_attr_group);
//	}
//	sysfs_remove_group(&bd_info->bi_sysfsdev->kobj, &bd_attr_group);
//
//	free_sysfs_entries(&bd_info->bi_ctx);
//	device_destroy(mic_lindata.dd_class,
//		       mic_lindata.dd_dev + 2 + bd_info->bi_ctx.bi_id);
	device_destroy(mic_lindata.dd_class,
		       mic_lindata.dd_dev + 2);
	device_destroy(mic_lindata.dd_class, mic_lindata.dd_dev + 1);
	device_destroy(mic_lindata.dd_class, mic_lindata.dd_dev);
	class_destroy(mic_lindata.dd_class);
	class_destroy(mic_lindata.dd_class);
	cdev_del(&mic_lindata.dd_cdev);
	unregister_chrdev_region(mic_lindata.dd_dev, 68);
//	unregister_pm_notifier(&mic_pm_notifer);

	debug("Leaving");
}

module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_AUTHOR("Stefanos Gerangelos");
MODULE_DESCRIPTION("Virtio SCIF driver");
MODULE_LICENSE("GPL");
