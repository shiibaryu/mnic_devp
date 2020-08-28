#include <sys/mman.h>
#include <sys/stat.h>       
#include <fcntl.h>           
#include <string.h>
#include <sys/sem.h>

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"

#include "nettlp_shm.h"
#include "rx_shm_port1.h"

#define RX_SHM_PATH "/rx_shm_port1"
#define RX_KEY_VAL   	500

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;

const Commands RxShmPort1::cmds = {
	{"add","EmptyArg",MODULE_CMD_FUNC(&RxShmPort1::CommandAdd),
		Command::THREAD_UNSAFE},
	{"clear","EmptyArg",MODULE_CMD_FUNC(&RxShmPort1::CommandClear),
		Command::THREAD_UNSAFE}};

union semun{
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *_buf;
};
union semun rx_sem1;
unsigned short set_val[1];

enum SEM_OPS{
	UNLOCK = -1,
	STOP = 0,
	LOCK = 1,
};

char *shm1;
struct rx_shm_conf rx_shmc1;

CommandResponse RxShmPort1::Init(const bess::pb::EmptyArg &)
{
	int fd,ret;
	int mem_size = RX_SHM_SIZE;

	memset(&rx_shmc1,0,sizeof(rx_shmc1));

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

	rx_shmc1.buf = (char *)mmap(NULL,mem_size,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
	if(rx_shmc1.buf == MAP_FAILED){
		return CommandFailure(errno,"failed to mmap for buffer");
	}

	shm1 = rx_shmc1.buf;

	close(fd);

	rx_shmc1.sem_id = semget(RX_KEY_VAL,1,0666 | IPC_CREAT);
	LOG(INFO) << "sem id 1 " << rx_shmc1.sem_id;
	if(rx_shmc1.sem_id == -1){
		return CommandFailure(errno,"failed to acquire semaphore");
	}
	
	rx_shmc1.idx = 0;

	set_val[0] = 0;
	rx_sem1.array = set_val;
	semctl(rx_shmc1.sem_id,0,SETALL,rx_sem1);

	return CommandSuccess();
}

CommandResponse RxShmPort1::CommandAdd(const bess::pb::EmptyArg &)
{
	return CommandSuccess();
}

CommandResponse RxShmPort1::CommandClear(const bess::pb::EmptyArg &)
{
	if(munmap(rx_shmc1.buf,RX_SHM_SIZE) == -1){
		LOG(INFO) << "failed to shm unmap";
	}

	if(shm_unlink(RX_SHM_PATH) == -1){
		LOG(INFO) << "failed to unlink shm";
	}

	auto result = semctl(rx_shmc1.sem_id,0,IPC_RMID,NULL);
	if(result == -1){
		LOG(INFO) << "failed to close semaphore";
	}
	return CommandSuccess();
}

void RxShmPort1::WritePkt(bess::PacketBatch *batch)
{
	uint32_t i,cnt,pktlen;
	//char *data;
	bess::Packet *pkt; 

	pktlen = 0;

	cnt = batch->cnt();
	for(i=0;i<cnt;i++){
		while(semctl(rx_shmc1.sem_id,0,GETVAL,rx_sem1) != 0){}
		pkt = batch->pkts()[i];
		pktlen = pkt->data_len();
		if(pktlen > 0){
			bess::utils::CopyInlined(shm1,&pktlen,sizeof(uint32_t),true);
			shm1 += sizeof(uint32_t);

			bess::utils::CopyInlined(shm1,pkt->head_data(),pktlen,true);

			rx_shmc1.idx++;
			shm1 += pktlen;

			if(rx_shmc1.idx > DESC_ENTRY_SIZE - 1){
				rx_shmc1.idx = 0;
				shm1 = rx_shmc1.buf;
			}
		}
	}
	if(pktlen > 0 && cnt){
		set_val[0] = cnt;
		rx_sem1.array = set_val;

		if(semctl(rx_shmc1.sem_id,0,SETALL,rx_sem1)==-1){
			LOG(INFO) << "errrrrr";
		}

	}
}

void RxShmPort1::ProcessBatch(Context *, bess::PacketBatch *batch)
{
	if(batch->cnt() > 0){
		WritePkt(batch);
	}
}

ADD_MODULE(RxShmPort1,"rx_shm_port1","communication port for shared memory")
