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

#include "nettlp_shm.h"
#include "nettlp_sem.h"
#include "tx_shm_port1.h"
#include "nettlp_packet.h"

#define SHM_PATH "/tx1_shm_port"
#define KEY_VAL		100

using namespace bess::utils;
using bess::utils::Ethernet;
using bess::utils::Arp;
using bess::utils::Ipv4;
using bess::utils::Udp;
using bess::utils::Icmp;
using bess::utils::Tcp;
using bess::utils::be16_t;
using bess::utils::be32_t;

const Commands TxShmPort1::cmds = {
	{"add","EmptyArg",MODULE_CMD_FUNC(&TxShmPort1::CommandAdd),
		Command::THREAD_UNSAFE},
	{"clear","EmptyArg",MODULE_CMD_FUNC(&TxShmPort1::CommandClear),
		Command::THREAD_UNSAFE}};

union semun sem1;
struct tx_shm_conf shmc1;

void TxShmPortThread1::Run()
{
}

void TxShmPort1::DeInit()
{
	auto result = semctl(shmc1.sem_id,1,IPC_RMID,NULL);
	if(result == -1){
		LOG(INFO) << "failed to close semaphore";
	}
}

CommandResponse TxShmPort1::Init(const bess::pb::EmptyArg &)
{
	int fd,ret,semval;
	int mem_size = TX_SHM_SIZE;
	const key_t key = KEY_VAL;

	task_id_t tid = RegisterTask(nullptr);
  	if (tid == INVALID_TASK_ID)
    		return CommandFailure(ENOMEM, "Task creation failed");

	template_size_ = MAX_TEMPLATE_SIZE;

	memset(&shmc1,0,sizeof(shmc1));

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

	shmc1.buf = (char *)mmap(NULL,mem_size,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
	shmc1.current = shmc1.buf;
	if(shmc1.buf == MAP_FAILED){
		return CommandFailure(errno,"failed to mmap for buffer");
	}

	memset(shmc1.buf,0,mem_size);
	close(fd);

	shmc1.sem_id = semget(key,1,0666 | IPC_CREAT);
	LOG(INFO) << "sem id 1 " << shmc1.sem_id;
	if(shmc1.sem_id == -1){
		return CommandFailure(errno,"failed to semget()");
	}

	shmc1.idx = 0;

	shmc1.val[0] = 0;
	sem1.array = shmc1.val;
	semctl(shmc1.sem_id,0,SETALL,sem1);


	LOG(INFO) << "Init done";
	semval = semctl(shmc1.sem_id,0,GETVAL,sem1);
	LOG(INFO) << "Sem val is   " << semval;

	/*
	if(!shm_thread_.Start()){
		DeInit();
		return CommandFailure(errno,"unable to start shm pooling thread");
	}*/

	return CommandSuccess();
}

CommandResponse TxShmPort1::CommandAdd(const bess::pb::EmptyArg &)
{
	return CommandSuccess();
}

CommandResponse TxShmPort1::CommandClear(const bess::pb::EmptyArg &)
{
	LOG(INFO) << "Clear";

	if(munmap(shmc1.buf,TX_SHM_SIZE) == -1){
		LOG(INFO) << "failed to unmap shm";
	}

	if(shm_unlink(SHM_PATH) == -1){
		LOG(INFO) << "failed to unmap shm";
	}

	auto result = semctl(shmc1.sem_id,0,IPC_RMID,NULL);
	if(result == -1){
		LOG(INFO) << "failed to close semaphore";
	}

	return CommandSuccess();
}

void TxShmPort1::FillPacket(bess::Packet *p, uint32_t length)
{
	char *bp;
	
	bp = p->buffer<char *>() + SNBUF_HEADROOM;
	p->set_data_off(SNBUF_HEADROOM);
	p->set_total_len(length);
	p->set_data_len(length);

	bess::utils::Copy(bp,shmc1.current,length,false);
	//bess::utils::CopyInlined(bp,shmc1.current,length,true);
	
	return;
}

void TxShmPort1::GeneratePackets(bess::Packet *p,uint32_t length)
{
	FillPacket(p,length);
}

struct task_result TxShmPort1::RunTask(Context *ctx, bess::PacketBatch *batch, void *)
{
	uint32_t i,length;
	uint32_t semval;
	unsigned int size=0;

       	semval = semctl(shmc1.sem_id,0,GETVAL,sem1);

	if(semval > 0){
		batch->clear();
		if(!current_worker.packet_pool()->AllocBulk(batch->pkts(),semval,100)){
			LOG(INFO) << "faield to allocate bulk packet";
		}

		for(i=0;i<semval;i++){	
			bess::utils::CopyInlined(&length,shmc1.current,sizeof(uint32_t),false);
			shmc1.current += sizeof(uint32_t);
			//LOG(INFO) << "   len  " << length;

			GeneratePackets(batch->pkts()[i],length);
			size += length;
			shmc1.current += length;
			shmc1.idx++;

			if(shmc1.idx > DESC_ENTRY_SIZE-1){
				shmc1.idx = 0;
				shmc1.current = shmc1.buf;				
			}
		}

		batch->set_cnt(semval);
		//LOG(INFO) << "tx1 ctr is " << semval;
		RunNextModule(ctx,batch);
		//memset(shmc1.buf,0,1500*semval);
		semctl(shmc1.sem_id,0,SETALL,sem1);
		//LOG(INFO) << "done" << semval;

		return {.block = 1, .packets = semval, .bits = size};
	}
	else{
		return {.block = 0, .packets = 0, .bits = 0};
	}
}

ADD_MODULE(TxShmPort1,"tx_shm_port1","communication port for shared memory")
