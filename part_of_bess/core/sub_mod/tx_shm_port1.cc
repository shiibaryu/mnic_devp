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
	unsigned int header_size;
	char *pkt,*bp/**current_pkt*/;
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
	
	b_pkt = p;
	b_pkt->set_data_off(SNBUF_HEADROOM);
	bp = b_pkt->buffer<char *>() + SNBUF_HEADROOM;

	memcpy(p->head_data(),shmc1.current,length);

	pkt = (char *)shmc1.current;
	//bess::utils::Copy(b_pkt,pkt,template_size,true);

	b_eth = reinterpret_cast<Ethernet *>(bp);
	eth = (struct ethhdr *)pkt;
	b_eth->src_addr = Ethernet::Address(eth->src_addr);
	b_eth->dst_addr = Ethernet::Address(eth->dst_addr);
	b_eth->ether_type = be16_t(ntohs(eth->ether_type));
	header_size = ETHER_HDR_SIZE;

	b_pkt->set_total_len(length);
	b_pkt->set_data_len(length);

	if(b_eth->ether_type == be16_t(Ethernet::Type::kIpv4)){
		//LOG(INFO) << "ip";

		ipv4  = (struct ipv4 *)(pkt + sizeof(*eth));
		b_ip = reinterpret_cast<Ipv4 *>(b_eth + 1);
		b_ip->src = be32_t(ntohl(ipv4->src_ip.s_addr));
		b_ip->dst = be32_t(ntohl(ipv4->dst_ip.s_addr));
		//LOG(INFO) << " " << ToIpv4Address(b_ip->src);
		//LOG(INFO) << " " << ToIpv4Address(b_ip->dst);

		b_ip->version = 4;
		b_ip->header_length = ipv4->ihl;
		b_ip->type_of_service = ipv4->tos;
		b_ip->length = be16_t(ntohs(ipv4->tot_len));
		b_ip->fragment_offset = be16_t(ntohs(ipv4->frag_off));
		b_ip->ttl = ipv4->ttl;
		b_ip->protocol = ipv4->protocol;
		b_ip->checksum =  ipv4->check;

		//LOG(INFO) << "Ipv" << b_ip->version;
		//LOG(INFO) << "length" << b_ip->length;
		//LOG(INFO) << "fragment off" << b_ip->fragment_offset;

		header_size += b_ip->header_length;

		if(ipv4->protocol == PROTO_UDP){
			//LOG(INFO) << "udp";
			udp = (struct udp *)(pkt + sizeof(*eth) + sizeof(*ipv4));
			b_udp = reinterpret_cast<Udp *>(b_ip + 1);
			b_udp->src_port = be16_t(ntohs(udp->src_port));
			b_udp->dst_port = be16_t(ntohs(udp->dst_port));
			b_udp->length = be16_t(ntohs(udp->len));
			b_udp->checksum = udp->check;

			header_size += UDP_HDR_SIZE;
			//b_pkt->set_data_len(txsq->length-header_size);
			
			return;
		}
		else if(ipv4->protocol == PROTO_ICMP){
			//LOG(INFO) << "icmp";

			icmp = (struct icmpv4 *)(pkt + sizeof(*eth) + sizeof(*ipv4));
			b_icmp = reinterpret_cast<Icmp *>(b_ip + 1);
			b_icmp->type = icmp->type;
			b_icmp->code = icmp->code;
			b_icmp->ident = be16_t(ntohs(icmp->message.echo.id));
			b_icmp->seq_num = be16_t(ntohs(icmp->message.echo.sequence));

			b_icmp->checksum = icmp->checksum;

			header_size += ICMP_HDR_SIZE;
			//LOG(INFO) << "icmp size is " << header_size;

			return;
		}
		else if(ipv4->protocol == PROTO_TCP){
			//LOG(INFO) << "tcp";

			tcp = (struct tcp *)(pkt + sizeof(*eth) + sizeof(*ipv4));
			b_tcp = reinterpret_cast<Tcp *>(b_ip + 1);

			b_tcp->src_port = be16_t(ntohs(tcp->source));
			b_tcp->dst_port = be16_t(ntohs(tcp->dest));
			b_tcp->seq_num  = be32_t(ntohl(tcp->seq));
			b_tcp->ack_num 	= be32_t(ntohl(tcp->ack_seq));
			b_tcp->reserved = tcp->res1;
			b_tcp->offset   = tcp->doff;
			b_tcp->window   = be16_t(ntohs(tcp->window));
			b_tcp->checksum = tcp->check;
			//b_tcp->flags 	= tcp_flag_word(tcp);
			b_tcp->urgent_ptr  = be16_t(ntohs(tcp->urg_ptr));

			if(tcp->fin){
				//LOG(INFO) << "fin";
				b_tcp->flags |= 0x01;
			}
			if(tcp->syn){
				//LOG(INFO) << "syn";
				b_tcp->flags |= 0x02;
			}
			if(tcp->rst){
				b_tcp->flags |= 0x04;
			}
			if(tcp->psh){
				b_tcp->flags |= 0x08;
			}
			if(tcp->ack){
				b_tcp->flags |= 0x10;
			}
			if(tcp->urg){
				b_tcp->flags |= 0x20;
			}

			header_size += tcp->doff;
			//LOG(INFO) << "doff is " << tcp->doff;
			//LOG(INFO) << "tcp size is " << header_size;
			//header_size += ntohs(tcp->doff);
			//b_pkt->set_data_len(txsq->length-header_size);

			return;
		}

		b_pkt->set_data_len(length-header_size);

		return;
	}
	else if(b_eth->ether_type == be16_t(Ethernet::Type::kArp)){
		//LOG(INFO) << "arp";
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

		header_size += ARP_HDR_SIZE;
		//b_pkt->set_data_len(txsq->length-header_size);

		return;
	}
	else if(b_eth->ether_type == be16_t(Ethernet::Type::kIpv6)){
			// current not available
			//LOG(INFO) << "v6";
			b_pkt->set_data_len(length);
			return;
	}

	//b_pkt->set_data_len(txsq->length-header_size);

	//LOG(INFO) << "ether";
	return;
}

void TxShmPort1::GeneratePackets(Context *ctx, bess::PacketBatch *batch,bess::Packet *p,uint32_t length)
{
	//bess::Packet *pkt = nullptr;// = current_worker.packet_pool()->Alloc();
	//bess::Packet *pkt =  current_worker.packet_pool()->Alloc();
	if(!p){
		//LOG(INFO) << "pkt == null";
		return;
	}
	
	if(!ctx->current_ns){
		return;
	}

	FillPacket(p,length);

	//pkt->set_data_off(SNBUF_HEADROOM);
	//pkt->set_total_len(size);
	//pkt->set_data_len(size);

	if(p){
		batch->add(p);
	}	

}

struct task_result TxShmPort1::RunTask(Context *ctx, bess::PacketBatch *batch, void *)
{
	uint32_t i,length;
	uint32_t semval;
	unsigned int size=0;

       	semval = semctl(shmc1.sem_id,0,GETVAL,sem1);

	if(semval > 0){
		batch->clear();
		bess::Packet *pkt =  current_worker.packet_pool()->Alloc();

		for(i=0;i<semval;i++){	
			memcpy(&length,shmc1.current,sizeof(uint32_t));
			shmc1.current += sizeof(uint32_t);
			LOG(INFO) << "length " << length;


			GeneratePackets(ctx,batch,pkt,length);

			size += length;
			shmc1.current += length;
			shmc1.idx++;

			if(shmc1.idx > DESC_ENTRY_SIZE-1){
				shmc1.idx = 0;
				shmc1.current = shmc1.buf;				
			}
		}

		batch->set_cnt(semval);
		LOG(INFO) << "tx1 ctr is " << semval;
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
