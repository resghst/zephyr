/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SHM_DEVICE_NAME		"sram0.shm"

#define RPMSG_VQ_0		(0) /* TX virtqueue queue index */
#define RPMSG_VQ_1		(1) /* RX virtqueue queue index */
#define VRING_COUNT		(2) /* Number of used vring buffers. */

#define IPC_INSTANCE_COUNT	(CONFIG_RPMSG_MULTI_INSTANCES_NO) /* Number of IPC instances.*/

/* Private macros. */
#define VRING_DESC_SIZEOF(num)	((num) * (sizeof(struct vring_desc)))
#define VRING_AVAIL_SIZEOF(num)	(sizeof(struct vring_avail) +  \
				((num) * sizeof(uint16_t)) + sizeof(uint16_t))
#define VRING_USED_SIZEOF(num)	(sizeof(struct vring_used) + \
				((num) * sizeof(struct vring_used_elem)) + \
				sizeof(uint16_t))

#define VRING_FIRST_SUM(num)	(VRING_DESC_SIZEOF(num) + VRING_AVAIL_SIZEOF(num))


/* Compute size of vring buffer based on its size and alignment. */
#define VRING_SIZE_COMPUTE(vring_size, align)	(ROUND_UP(VRING_FIRST_SUM((vring_size)),  \
						(align)) + VRING_USED_SIZEOF((vring_size)))

/* Macro for calculating used memory by virtqueue buffers for remote device. */
#define VIRTQUEUE_SIZE_GET(vring_size)	(RPMSG_BUFFER_SIZE * (vring_size))

/* Macro for getting the size of shared memory occupied by single IPC instance. */
#define SHMEM_INST_SIZE_GET(vring_size)	(VDEV_STATUS_SIZE +  \
					(VRING_COUNT * VIRTQUEUE_SIZE_GET((vring_size))) + \
					(VRING_COUNT * VRING_SIZE_COMPUTE((vring_size), \
					(VRING_ALIGNMENT))))

/* Returns size of used shared memory consumed by all IPC instances*/
#define SHMEM_CONSUMED_SIZE_GET(vring_size)	(IPC_INSTANCE_COUNT * \
						 SHMEM_INST_SIZE_GET((vring_size)))

/* Returns maximum allowable size of vring buffers to fit memory requirements. */
#define VRING_SIZE_GET(shmem_size)	((SHMEM_CONSUMED_SIZE_GET(32)) < (shmem_size) ? 32 :  \
					 (SHMEM_CONSUMED_SIZE_GET(16)) < (shmem_size) ? 16 :  \
					 (SHMEM_CONSUMED_SIZE_GET(8))  < (shmem_size) ? 8  :  \
					 (SHMEM_CONSUMED_SIZE_GET(4))  < (shmem_size) ? 4  :  \
					 (SHMEM_CONSUMED_SIZE_GET(2))  < (shmem_size) ? 2  : 1)

/* Returns size of used shared memory of single instance in case of using
 * maximum allowable vring buffer size.
 */
#define SHMEM_INST_SIZE_AUTOALLOC_GET(shmem_size) \
					(SHMEM_INST_SIZE_GET(VRING_SIZE_GET((shmem_size))))

/* Returns start address of ipc instance in shared memory. It assumes that
 * maximum allowable vring buffer size is used.
 */
#define SHMEM_INST_ADDR_AUTOALLOC_GET(shmem_addr, shmem_size, id) \
					((shmem_addr) + \
					((id) * (SHMEM_INST_SIZE_AUTOALLOC_GET(shmem_size))))

#ifdef CONFIG_RPMSG_MULTI_INSTANCE_MASTER
#define VIRTQUEUE_ID	(0)
#else
#define VIRTQUEUE_ID	(1)
#endif
