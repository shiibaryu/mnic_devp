#ifndef _NETTLP_SEM_H_
#define _NETTLP_SEM_H_

#include <sys/sem.h>

#define TX1_KEY_VAL	100
#define TX2_KEY_VAL	200
#define TX3_KEY_VAL	300
#define TX4_KEY_VAL	400
#define RX1_KEY_VAL	500
#define RX2_KEY_VAL	600
#define RX3_KEY_VAL	700
#define RX4_KEY_VAL	800

union semun{
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct sminfo *_buf;
};

enum SEMPHORE_OPERATION
{
	UNLOCK = -1,
	STOP   = 0,
	LOCK   = 1,
};

static void wait_bess(int tx_sem_id, union semun tx_sem)
{
	while(semctl(tx_sem_id,0,GETVAL,tx_sem) != 0){
	}
}

#endif
