#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>       
#include <fcntl.h>           
#include <string.h>
#include <sys/sem.h>

#include "../utils/ether.h"
#include "../utils/arp.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/icmp.h"
#include "../utils/tcp.h"
#include "../utils/checksum.h"

#include "nettlp_sem.h"
#include "nettlp_shm.h"
#include "tx_shm_port3.h"
#include "nettlp_packet.h"

#define SHM_PATH "/tx3_shm_port"
#define KEY_VAL		300

using namespace bess::utils;
using bess::utils::Ethernet;
using bess::utils::Arp;
using bess::utils::Ipv4;
using bess::utils::Udp;
using bess::utils::Icmp;
using bess::utils::Tcp;
using bess::utils::be16_t;
using bess::utils::be32_t;

const Commands TxShmPort3::cmds = {
	{"add","EmptyArg",MODULE_CMD_FUNC(&TxShmPort3::CommandAdd),
		Command::THREAD_UNSAFE},
	{"clear","EmptyArg",MODULE_CMD_FUNC(&TxShmPort3::CommandClear),
		Command::THREAD_UNSAFE}};

union semun sem3;
struct tx_shm_conf shmc3;

void TxShmPortThread3::Run()
{
}

void TxShmPort3::DeInit()
{
	auto result = semctl(shmc3.sem_id,1,IPC_RMID,NULL);
	if(result == -1){
		LOG(INFO) << "failed to close semaphore";
	}
}

CommandResponse TxShmPort3::Init(const bess::pb::EmptyArg &)
{
	int fd,ret,semval;
	int mem_size = TX_SHM_SIZE;
	const key_t key = KEY_VAL;

	task_id_t tid = RegisterTask(nullptr);
  	if (tid == INVALID_TASK_ID)
    		return CommandFailure(ENOMEM, "Task creation failed");

	template_size_ = MAX_TEMPLATE_SIZE;

	memset(&shmc3,0,sizeof(shmc3));

	fd = shm_open(SHM_PATH,O_RDWR,0);
	if(fd == -1){
		fd = shm_open(SHM_PATH,O_CREAT | O_EXCL | O_RDWR,0600);
		if(fd == -1){
			DeInit();
			return CommandFailure(errno,"failed to shm_open (O_CREAT)");
		}
	}
	
	ret = ftruncate(fd,mem_size);
	if(ret == -1){
		return CommandFailure(errno,"failed to ftruncate()");
	}

	shmc3.buf = (char *)mmap(NULL,mem_size,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
	shmc3.current = shmc3.buf;
	if(shmc3.buf == MAP_FAILED){
		return CommandFailure(errno,"failed to mmap for buffer");
	}

	memset(shmc3.buf,0,mem_size);
	close(fd);

	shmc3.sem_id = semget(key,1,0666 | IPC_CREAT);
	LOG(INFO) << "sem id 3 " << shmc3.sem_id;
	if(shmc3.sem_id == -1){
		return CommandFailure(errno,"failed to semget()");
	}

	shmc3.idx = 0;

	shmc3.val[0] = 0;
	sem3.array = shmc3.val;
	semctl(shmc3.sem_id,0,SETALL,sem3);


	/*ops[0].sem_num = 0;
	ops[0].sem_op = STOP;
	ops[0].sem_flg = SEM_UNDO;

	ops[1].sem_num = 0;
	ops[1].sem_op = LOCK;
	ops[1].sem_flg = SEM_UNDO;
*/

	LOG(INFO) << "Init done";
	semval = semctl(shmc3.sem_id,0,GETVAL,sem3);
	LOG(INFO) << "Sem val is   " << semval;

	/*
	if(!shm_thread_.Start()){
		DeInit();
		return CommandFailure(errno,"unable to start shm pooling thread");
	}*/

	return CommandSuccess();
}

CommandResponse TxShmPort3::CommandAdd(const bess::pb::EmptyArg &)
{
	return CommandSuccess();
}

CommandResponse TxShmPort3::CommandClear(const bess::pb::EmptyArg &)
{
	LOG(INFO) << "Clear";

	if(munmap(shmc3.buf,TX_SHM_SIZE) == -1){
		LOG(INFO) << "failed to unmap shm";
	}

	if(shm_unlink(SHM_PATH) == -1){
		LOG(INFO) << "failed to unmap shm";
	}

	auto result = semctl(shmc3.sem_id,0,IPC_RMID,NULL);
	if(result == -1){
		LOG(INFO) << "failed to close semaphore";
	}

	return CommandSuccess();
}

void TxShmPort3::FillPacket(bess::Packet *p,uint32_t length)
{
	char *bp;
	
	bp = p->buffer<char *>() + SNBUF_HEADROOM;
	p->set_data_off(SNBUF_HEADROOM);
	p->set_total_len(length);
	p->set_data_len(length);

	//bess::utils::CopyInlined(bp,shmc3.current,length,true);
	bess::utils::Copy(bp,shmc3.current,length,false);
	
	return;
}

void TxShmPort3::GeneratePackets(bess::Packet *p,uint32_t length)
{
	FillPacket(p,length);
}

struct task_result TxShmPort3::RunTask(Context *ctx, bess::PacketBatch *batch, void *)
{
	uint32_t i,length;
	uint32_t semval;
	unsigned int size=0;

       	semval = semctl(shmc3.sem_id,0,GETVAL,sem3);

	if(semval > 0){
		batch->clear();
		if(!current_worker.packet_pool()->AllocBulk(batch->pkts(),semval,100)){
			LOG(INFO) << "faield to allocate bulk packet";
		}

		for(i=0;i<semval;i++){
			bess::utils::CopyInlined(&length,shmc3.current,sizeof(uint32_t),false);
			shmc3.current += sizeof(uint32_t);
			//LOG(INFO) << "length " << length;

			//LOG(INFO) << "length " << length;
			GeneratePackets(batch->pkts()[i],length);

			size += length;
			shmc3.current += length;
			shmc3.idx++;

			if(shmc3.idx > DESC_ENTRY_SIZE-1){
				shmc3.idx = 0;
				shmc3.current = shmc3.buf;
			}
		}

		batch->set_cnt(semval);
		//LOG(INFO) << "tx3 ctr is " << semval;
		RunNextModule(ctx,batch);
		//memset(shmc3.buf,0,1500*semval);
		semctl(shmc3.sem_id,0,SETALL,sem3);
		//LOG(INFO) << "done" << semval;

		return {.block = 1, .packets = semval, .bits = size};
	}
	else{
		return {.block = 0, .packets = 0, .bits = 0};
	}
}

ADD_MODULE(TxShmPort3,"tx_shm_port3","communication port for shared memory")
