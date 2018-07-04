/*
 * scif-chrdev.h
 *
 * Definition file for the virtio-scif character device
 *
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 */

#ifndef _SCIF_CHRDEV_H
#define _SCIF_CHRDEV_H

/*
 * SCIF character device
 */
#define SCIF_CHRDEV_MAJOR 71  /* Reserved for local / experimental use */
//#define SCIF_NR_DEVICES   32  /* Number of devices we support */
#define SCIF_NR_DEVICES   1  /* Number of devices we support */

/*
 * Init and destroy functions.
 */
int scif_chrdev_init(void);
void scif_chrdev_destroy(void);

#endif	/* _SCIF_CHRDEV_H */ 
