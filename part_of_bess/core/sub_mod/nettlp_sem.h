#ifndef BESS_MODULE_SHM_L_
#define BESS_MODULE_SHM_L_

union semun{
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *__buf;
};

enum SEM_OPS{
	UNLOCK = -1,
	STOP = 0,
	LOCK = 1,
};

#endif
