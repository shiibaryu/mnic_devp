#include <sys/mman.h>
#include <sys/stat.h>       
#include <fcntl.h>           
#include <string.h>
#include <sys/sem.h>

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"

#include "nettlp_shm.h"
#include "rx_shm_port4.h"

#define RX_SHM_PATH "/rx_shm_port4"
#define RX_KEY_VAL   	800

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;

const Commands RxShmPort4::cmds = {
	{"add","EmptyArg",MODULE_CMD_FUNC(&RxShmPort4::CommandAdd),
		Command::THREAD_UNSAFE},
	{"clear","EmptyArg",MODULE_CMD_FUNC(&RxShmPort4::CommandClear),
		Command::THREAD_UNSAFE}};

union semun{
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *_buf;
};
union semun rx_sem4;
unsigned short set_val4[1];

enum SEM_OPS{
	UNLOCK = -1,
	STOP = 0,
	LOCK = 1,
};

char *shm4;
struct rx_shm_conf rx_shmc4;

CommandResponse RxShmPort4::Init(const bess::pb::EmptyArg &)
{
	int fd,ret;
	int mem_size = RX_SHM_SIZE;

	memset(&rx_shmc4,0,sizeof(rx_shmc4));

	fd = shm_open(RX_SHM_PATH,O_RDWR,0);
	if(fd == -1){
		fd = shm_open(RX_SHM_PATH, O_CREAT | O_EXCL | O_RDWR,0600);
		if(fd == -1){
			return CommandFailure(errno,"failed to shm_open()");
		}
	}

	ret = ftruncate(fd,mem_size);
	if(ret == -1){
		return CommandFailure(errno,"failed to ftruncate");
	}

	rx_shmc4.buf = (char *)mmap(NULL,mem_size,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
	if(rx_shmc4.buf == MAP_FAILED){
		return CommandFailure(errno,"failed to mmap for buffer");
	}
	shm4 = rx_shmc4.buf;

	close(fd);

	rx_shmc4.sem_id = semget(RX_KEY_VAL,1,0666 | IPC_CREAT);
	LOG(INFO) << "sem id 4 " << rx_shmc4.sem_id;
	if(rx_shmc4.sem_id == -1){
		return CommandFailure(errno,"failed to acquire semaphore");
	}

	rx_shmc4.idx = 0;
	
	set_val4[0] = 0;
	rx_sem4.array = set_val4;
	semctl(rx_shmc4.sem_id,0,SETALL,rx_sem4);

	return CommandSuccess();
}

CommandResponse RxShmPort4::CommandAdd(const bess::pb::EmptyArg &)
{
	return CommandSuccess();
}

CommandResponse RxShmPort4::CommandClear(const bess::pb::EmptyArg &)
{
	if(munmap(rx_shmc4.buf,RX_SHM_SIZE) == -1){
		LOG(INFO) << "failed to shm unmap";
	}

	if(shm_unlink(RX_SHM_PATH) == -1){
		LOG(INFO) << "failed to unlink shm";
	}

	auto result = semctl(rx_shmc4.sem_id,0,IPC_RMID,NULL);
	if(result == -1){
		LOG(INFO) << "failed to close semaphore";
	}
	return CommandSuccess();
}

void RxShmPort4::WritePkt(bess::PacketBatch *batch)
{
	uint32_t i,cnt,pktlen;
	//char *data;
	bess::Packet *pkt;

	pktlen = 0;

	cnt = batch->cnt();
	for(i=0;i<cnt;i++){
		while(semctl(rx_shmc4.sem_id,0,GETVAL,rx_sem4) != 0){}
		pkt = batch->pkts()[i];
		pktlen = pkt->data_len();
		if(pktlen > 0){
			memcpy(shm4,&pktlen,sizeof(uint32_t));

			memcpy(shm4,pkt->head_data(),pktlen);

			rx_shmc4.idx++;
			shm4 += pktlen;

			if(rx_shmc4.idx > DESC_ENTRY_SIZE - 1){
				rx_shmc4.idx = 0;
				shm4 = rx_shmc4.buf;
			}
		}
	}

	if(cnt && pktlen > 0){
		set_val4[0] = cnt;
		rx_sem4.array = set_val4;
		if(semctl(rx_shmc4.sem_id,0,SETALL,rx_sem4)==-1){
		}
	}
}

void RxShmPort4::ProcessBatch(Context *, bess::PacketBatch *batch)
{
	if(batch->cnt() > 0){
		LOG(INFO) << "yes";
		WritePkt(batch);
	}
}

ADD_MODULE(RxShmPort4,"rx_shm_port4","communication port for shared memory")
