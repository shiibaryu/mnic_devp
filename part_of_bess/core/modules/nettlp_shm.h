#ifndef BESS_MODULES_SHM_H_
#define BESS_MODULES_SHM_H_

#define MAX_PKT_NUM	10
#define DESC_ENTRY_SIZE   512
#define TX_SHM_SIZE	1500*512
#define RX_SHM_SIZE	1500*512

struct tx_shm_conf{
	int idx;
	int sem_id;
	char *buf;
	char *current;
	unsigned short val[1];
};

struct rx_shm_conf{
	int idx;
	int sem_id;
	char *buf;
	unsigned short val[1];
};

#endif
