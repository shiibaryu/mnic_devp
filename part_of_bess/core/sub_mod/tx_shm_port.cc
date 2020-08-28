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

#include "tx_shm_port.h"
#include "nettlp_packet.h"

#define SHM_PATH "/tx1_shm_port"
#define KEY_VAL		100
#define TX_SHM_SIZE	1500*256

using namespace bess::utils;
using bess::utils::Ethernet;
using bess::utils::Arp;
using bess::utils::Ipv4;
using bess::utils::Udp;
using bess::utils::Icmp;
using bess::utils::Tcp;
using bess::utils::be16_t;
using bess::utils::be32_t;

const Commands TxShmPort::cmds = {
	{"add","EmptyArg",MODULE_CMD_FUNC(&TxShmPort::CommandAdd),
		Command::THREAD_UNSAFE},
	{"clear","EmptyArg",MODULE_CMD_FUNC(&TxShmPort::CommandClear),
		Command::THREAD_UNSAFE}};

union semun{
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *__buf;
};
union semun sem;
//sembuf ops[2];

enum SEM_OPS{
	UNLOCK = -1,
	STOP = 0,
	LOCK = 1,
};

struct shm_conf{
	int sem_id;
	char *buf;
	unsigned short val[1];
};
struct shm_conf shmc;

void TxShmPortThread::Run()
{
}

void TxShmPort::DeInit()
{
	auto result = semctl(shmc.sem_id,1,IPC_RMID,NULL);
	if(result == -1){
		LOG(INFO) << "failed to close semaphore";
	}
}

CommandResponse TxShmPort::Init(const bess::pb::EmptyArg &)
{
	int fd,ret,semval;
	int mem_size = TX_SHM_SIZE;
	const key_t key = KEY_VAL;

	task_id_t tid = RegisterTask(nullptr);
  	if (tid == INVALID_TASK_ID)
    		return CommandFailure(ENOMEM, "Task creation failed");

	template_size_ = MAX_TEMPLATE_SIZE;

	memset(&shmc,0,sizeof(shmc));

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

	shmc.buf = (char *)mmap(NULL,mem_size,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
	if(shmc.buf == MAP_FAILED){
		return CommandFailure(errno,"failed to mmap for buffer");
	}

	memset(shmc.buf,0,mem_size);
	close(fd);

	shmc.sem_id = semget(key,1,0666 | IPC_CREAT);
	if(shmc.sem_id == -1){
		return CommandFailure(errno,"failed to semget()");
	}

	shmc.val[0] = 0;
	sem.array = shmc.val;
	semctl(shmc.sem_id,0,SETALL,sem);


	/*ops[0].sem_num = 0;
	ops[0].sem_op = STOP;
	ops[0].sem_flg = SEM_UNDO;

	ops[1].sem_num = 0;
	ops[1].sem_op = LOCK;
	ops[1].sem_flg = SEM_UNDO;
*/

	LOG(INFO) << "Init done";
	semval = semctl(shmc.sem_id,0,GETVAL,sem);
	LOG(INFO) << "Sem val is   " << semval;

	/*
	if(!shm_thread_.Start()){
		DeInit();
		return CommandFailure(errno,"unable to start shm pooling thread");
	}*/

	return CommandSuccess();
}

CommandResponse TxShmPort::CommandAdd(const bess::pb::EmptyArg &)
{
	return CommandSuccess();
}

CommandResponse TxShmPort::CommandClear(const bess::pb::EmptyArg &)
{
	LOG(INFO) << "Clear";

	if(munmap(shmc.buf,TX_SHM_SIZE) == -1){
		LOG(INFO) << "failed to unmap shm";
	}

	if(shm_unlink(SHM_PATH) == -1){
		LOG(INFO) << "failed to unmap shm";
	}

	auto result = semctl(shmc.sem_id,0,IPC_RMID,NULL);
	if(result == -1){
		LOG(INFO) << "failed to close semaphore";
	}

	return CommandSuccess();
}

unsigned int TxShmPort::FillPacket(bess::Packet *p,uint32_t i)
{
	unsigned int total_size,header_size;
	char *pkt,*bp,*current_buf;
	struct ethhdr *eth;
	struct arphdr *arp;
	struct ipv4 *ipv4;
	struct udp *udp;
	struct tcp *tcp;
	struct icmpv4 *icmp;
	//size_t ip_bytes;
	bess::Packet *b_pkt;
	Ethernet *b_eth;
	Arp *b_arp;
	Ipv4 *b_ip;
	Udp *b_udp;
	Icmp *b_icmp;
	Tcp *b_tcp;
	//b_pkt = current_worker.packet_pool()->Alloc();

	//int template_size = 1000;

	b_pkt = p;
	current_buf = shmc.buf;
	current_buf += 1500*i;

	b_pkt->set_data_off(SNBUF_HEADROOM);

	bp = b_pkt->buffer<char *>() + SNBUF_HEADROOM;
	memcpy(p->head_data(),current_buf,1500);
	pkt = (char *)p->head_data();
	//bess::utils::Copy(b_pkt,pkt,template_size,true);

	b_eth = reinterpret_cast<Ethernet *>(bp);
	eth = (struct ethhdr *)pkt;
	b_eth->src_addr = Ethernet::Address(eth->src_addr);
	b_eth->dst_addr = Ethernet::Address(eth->dst_addr);
	b_eth->ether_type = be16_t(ntohs(eth->ether_type));
	total_size = sizeof(*eth);
	header_size = sizeof(*eth);

	if(b_eth->ether_type == be16_t(Ethernet::Type::kIpv4)){
		LOG(INFO) << "ip";

		ipv4  = (struct ipv4 *)(pkt + sizeof(*eth));
		b_ip = reinterpret_cast<Ipv4 *>(b_eth + 1);
		b_ip->src = be32_t(ipv4->src_ip.s_addr);
		b_ip->dst = be32_t(ipv4->dst_ip.s_addr);
		b_ip->version = (((ipv4)->version & 0x0f) >> 4);
		b_ip->header_length = ((ipv4)->ihl & 0x0f);
		b_ip->type_of_service = ipv4->tos;
		b_ip->length = be16_t(ntohs(ipv4->tot_len));
		b_ip->fragment_offset = be16_t(ntohs(ipv4->frag_off));
		b_ip->ttl = ipv4->ttl;
		b_ip->protocol = ipv4->protocol;
		b_ip->checksum =  0;

		total_size += ipv4->tot_len;
		b_pkt->set_total_len(total_size);
		header_size += b_ip->header_length;

		if(ipv4->protocol == PROTO_UDP){
			LOG(INFO) << "udp";
			udp = (struct udp *)(pkt + sizeof(*eth) + sizeof(*ipv4));
			b_udp = reinterpret_cast<Udp *>(b_ip + 1);
			b_udp->src_port = be16_t(udp->src_port);
			b_udp->dst_port = be16_t(udp->dst_port);
			b_udp->length = be16_t(udp->len);
			b_udp->checksum = 0;

			header_size += UDP_HDR_SIZE;
			b_pkt->set_data_len(total_size-header_size);
			
			return total_size;
		}
		else if(ipv4->protocol == PROTO_ICMP){
			LOG(INFO) << "icmp";

			icmp = (struct icmpv4 *)(pkt + sizeof(*eth) + sizeof(*ipv4));
			b_icmp = reinterpret_cast<Icmp *>(b_ip + 1);
			b_icmp->type = icmp->type;
			b_icmp->code = icmp->code;
			b_icmp->ident = be16_t(icmp->message.echo.id);
			b_icmp->seq_num = be16_t(icmp->message.echo.sequence);
			b_icmp->checksum = 0;

			header_size += ICMP_HDR_SIZE;
			b_pkt->set_data_len(total_size-header_size);

			return total_size;
		}
		else if(ipv4->protocol == PROTO_TCP){
			LOG(INFO) << "tcp";

			tcp = (struct tcp *)(pkt + sizeof(*eth) + sizeof(*ipv4));
			b_tcp = reinterpret_cast<Tcp *>(b_ip + 1);

			b_tcp->src_port = be16_t(ntohs(tcp->source));
			b_tcp->dst_port = be16_t(ntohs(tcp->dest));
			b_tcp->seq_num  = be32_t(ntohl(tcp->seq));
			b_tcp->ack_num 	= be32_t(ntohl(tcp->ack_seq));
			b_tcp->reserved = tcp->res1;
			b_tcp->offset   = tcp->doff;
			b_tcp->window   = be16_t(ntohs(tcp->window));
			b_tcp->checksum	= ntohs(tcp->check);
			b_tcp->flags 	= tcp_flag_word(tcp);
			b_tcp->urgent_ptr  = be16_t(ntohs(tcp->urg_ptr));

			b_pkt->set_total_len(total_size);
			b_pkt->set_data_len(0);

			return total_size;
		}

		b_pkt->set_data_len(total_size-header_size);

		return total_size;
	}
	else if(b_eth->ether_type == be16_t(Ethernet::Type::kArp)){
		LOG(INFO) << "arp";
		arp = (struct arphdr *)(pkt + 14);
		b_arp = reinterpret_cast<Arp *>(b_eth + 1);
		b_arp->hw_addr = be16_t(ntohs(arp->ar_hdr));
		b_arp->proto_addr = be16_t(ntohs(arp->ar_pro));
		b_arp->hw_addr_length = arp->ar_hln;
		b_arp->proto_addr_length = arp->ar_pln;
		b_arp->opcode = be16_t(ntohs(arp->ar_op));

		b_arp->sender_hw_addr = Ethernet::Address(arp->__ar_sha);
		b_arp->target_hw_addr = Ethernet::Address(arp->__ar_tha);
			
		b_arp->sender_ip_addr = be32_t(ntohl(*(uint32_t *)(arp->__ar_sip)));
		b_arp->target_ip_addr = be32_t(ntohl(*(uint32_t *)(arp->__ar_tip)));


		b_pkt->set_total_len(90);
		b_pkt->set_data_len(60);
		//b_pkt->set_total_len(total_size+sizeof(*arp));
		//b_pkt->set_data_len(0);

		return total_size;
	}
	else if(b_eth->ether_type == be16_t(Ethernet::Type::kIpv6)){
			// current not available
			LOG(INFO) << "v6";
			b_pkt->set_total_len(total_size);
			b_pkt->set_data_len(0);
			return total_size;
	}

	b_pkt->set_total_len(total_size);
	b_pkt->set_data_len(0);

	LOG(INFO) << "ether";
	return total_size;
}

unsigned int TxShmPort::GeneratePackets(Context *ctx, bess::PacketBatch *batch,bess::Packet *p,uint32_t i)
{
	unsigned int size;
	//bess::Packet *pkt = nullptr;// = current_worker.packet_pool()->Alloc();
	//bess::Packet *pkt =  current_worker.packet_pool()->Alloc();
	if(!p){
		LOG(INFO) << "pkt == null";
		return 0;
	}
	
	if(!ctx->current_ns){
		return 0;
	}

	size = FillPacket(p,i);

	//pkt->set_data_off(SNBUF_HEADROOM);
	//pkt->set_total_len(size);
	//pkt->set_data_len(size);

	if(p){
		batch->add(p);
	}	

	return size;
}

struct task_result TxShmPort::RunTask(Context *ctx, bess::PacketBatch *batch, void *)
{
	uint32_t i;
	uint32_t semval;
	unsigned int size=0;

       	semval = semctl(shmc.sem_id,0,GETVAL,sem);
	if(semval > 0){
		batch->clear();
		bess::Packet *pkt =  current_worker.packet_pool()->Alloc();
		for(i=0;i<semval;i++){
			size += GeneratePackets(ctx,batch,pkt,i);
		}
		batch->set_cnt(i-1);
		RunNextModule(ctx,batch);
		memset(shmc.buf,0,1500*semval);
		semctl(shmc.sem_id,0,SETALL,sem);
		return {.block = 1, .packets = semval, .bits = size};
	}
	else{
		return {.block = 0, .packets = 0, .bits = 0};
	}
}

ADD_MODULE(TxShmPort,"tx_shm_port1","communication port for shared memory")
