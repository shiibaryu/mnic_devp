#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/types.h>

#include <libtlp.h>

#include "nettlp_mnic_device.h"
#include "nettlp_shm.h"
#include "nettlp_sem.h"

struct nettlp_mnic *mnic_f;
void mnic_free(struct nettlp_mnic *mnic);

static int caught_signal;
int txsemid[TX_QUEUES],rxsemid[RX_QUEUES];
unsigned short init_val[1];

void signal_handler(int signal)
{
	int i,ret;
	char path[256];
	caught_signal = 1;

	mnic_free(mnic_f);
	
	for(i=0;i<TX_QUEUES;i++){
		snprintf(path,256,"tx%d_shm_port",i+1);
		if(shm_unlink(path) == -1){
			debug("failed tp unlink tx %d shm path",i);
		}

		ret = semctl(txsemid[i],0,IPC_RMID,NULL);
		if(ret == -1){
			debug("failed to close semaphore");
		}
	}

	for(i=0;i<RX_QUEUES;i++){
		snprintf(path,256,"rx_shm_port%d",i+1);
		if(shm_unlink(path) == -1){
			debug("failed tp unlink rx %d shm path",i);
		}

		ret = semctl(rxsemid[i],0,IPC_RMID,NULL);
		if(ret == -1){
			debug("failed to close semaphore");
		}
	}

	nettlp_stop_cb();
}

void *mnic_tx(void *arg)
{
	int ret,num;
	unsigned short num_wr[1];
	struct tx_ctl *txc = (struct tx_ctl *)arg;
	int offset = txc->offset;
	struct nettlp_mnic *mnic = txc->mnic;
	struct descriptor *tx_desc = mnic->tx_desc[offset];
	struct tx_desc_ctl *txd_ctl = mnic->tx_desc_ctl + offset;
	char *shm = mnic->tx_shm[offset];
	struct nettlp_msix *tx_irq = mnic->tx_irq + offset;

	num_wr[0] = 0;

	while(1){
		if(caught_signal){
			break;
		}

		if(txd_ctl->tail == txd_ctl->head){
			continue;
		}

		num = txd_ctl->tail - txd_ctl->head;

		if(num < 0){
			num += DESC_ENTRY_SIZE;
		}

		while(num != num_wr[0]){
			memcpy(shm,&tx_desc->length,sizeof(uint32_t));
			shm += sizeof(uint32_t);

			//info("length  %ld,  tx  %d",tx_desc->length, offset+1);

			ret = dma_read_aligned(&mnic->tx_nt[offset],tx_desc->addr,shm,tx_desc->length,MRRS);
			if(ret < 0){
				debug("failed to read tx pkt from %#lx, %lu-byte",tx_desc->addr,tx_desc->length);
				debug("ret is %d-byte",ret);
			}

			shm += tx_desc->length;
			num_wr[0]++;
			txd_ctl->head++;
			tx_desc++;

			ret = dma_write(&mnic->tx_nt[offset],tx_irq->addr,&tx_irq->data,sizeof(tx_irq->data));
			if(ret < 0){
				fprintf(stderr,"failed to send tx interrupt\n");
				perror("dma_write");
			}

			if(txd_ctl->head > DESC_ENTRY_SIZE - 1){
				txd_ctl->head = 0;
				tx_desc = mnic->tx_desc[offset];
				shm = mnic->tx_shm[offset];
			}

			if(num_wr[0] == BESS_MAX_PKT){
				mnic->tx_sem[offset].array = num_wr;

				wait_bess(mnic->tx_sem_id[offset],mnic->tx_sem[offset]);
				semctl(mnic->tx_sem_id[offset],0,SETALL,mnic->tx_sem[offset]);
				num_wr[0] = 0;
			
			}
		}

		if(num_wr[0] != 0){
			mnic->tx_sem[offset].array = num_wr;

			wait_bess(mnic->tx_sem_id[offset],mnic->tx_sem[offset]);
			semctl(mnic->tx_sem_id[offset],0,SETALL,mnic->tx_sem[offset]);
	
			num_wr[0] = 0;
		}

	}

	pthread_join(txc->tid,NULL);
	return NULL;
}

void mnic_rx(uint64_t idx,struct nettlp *nt,struct nettlp_mnic *mnic,unsigned int offset)
{
	int ret;
	struct descriptor *rx_desc = mnic->rx_desc[offset];
	uintptr_t *rx_desc_base = mnic->rx_desc_base + offset;
	struct rx_desc_ctl *rxd_ctl = mnic->rx_desc_ctl + offset;


	if(*rx_desc_base == 0){
		fprintf(stderr,"rx_desc base is 0\n");
		return;
	}

	rx_desc += rxd_ctl->tail;
	
	while(rxd_ctl->tail != idx){
		ret = dma_read(&mnic->rx_nt[offset],rxd_ctl->desc_tail,rx_desc,sizeof(struct descriptor));
		if(ret < sizeof(struct descriptor)){
			fprintf(stderr,"failed to read rx desc from %#lx\n",rxd_ctl->desc_tail);
			return;
		}

		rx_desc++;
		rxd_ctl->tail++;
		rxd_ctl->desc_tail += sizeof(struct descriptor);

		if(rxd_ctl->tail > DESC_ENTRY_SIZE-1){	
			rx_desc = mnic->rx_desc[offset];
			rxd_ctl->tail = 0;
			rxd_ctl->desc_tail = *rx_desc_base;
		}
	}

	mnic->rx_state[offset] = RX_STATE_READY;
}

static inline unsigned int get_bar4_rxt_offset(uintptr_t start,uintptr_t received)
{
	return (received - start - RX_BASE_SUM)/8;
}

static inline unsigned int get_bar4_tx_pkt_addr_offset(uintptr_t start,uintptr_t received)
{
	unsigned int offset;
	offset =  (received - start - (BAR4_TX_PKT_ADDR))/16;
	return offset;
}

static inline unsigned int get_bar4_tx_pkt_len_offset(uintptr_t start,uintptr_t received)
{
	unsigned int offset;
	offset =  (received - start - (BAR4_TX_PKT_LEN))/16;
	return offset;
}

int nettlp_mnic_mwr(struct nettlp *nt,struct tlp_mr_hdr *mh,void *data,size_t count,void *arg)
{
	uint64_t *d;
	unsigned int offset;
	struct nettlp_mnic *mnic = arg;
	uintptr_t dma_addr;

	dma_addr = tlp_mr_addr(mh);
	
	if(is_mwr_addr_rx_desc_base(mnic->bar4_start,dma_addr)){
		uintptr_t *rxd_base = mnic->rx_desc_base + mnic->rx_queue_id;
		struct rx_desc_ctl *rxd_ctl = mnic->rx_desc_ctl + mnic->rx_queue_id;
		*rxd_base = *((uintptr_t *)data);
		rxd_ctl->desc_head = *rxd_base;
		rxd_ctl->desc_tail = *rxd_base;
		info("Queue %d: RX desc base is %lx, queue id is %d",mnic->rx_queue_id,*rxd_base,mnic->rx_queue_id);
		mnic->rx_queue_id++;
	}
	else if(is_mwr_addr_rx_desc_ptr(mnic->bar4_start,dma_addr)){
		d = (uint64_t *)data;
		offset = get_bar4_rxt_offset(mnic->bar4_start,dma_addr);
		mnic_rx(*d,nt,mnic,offset);
	}
	else if(is_mwr_addr_tx_pkt_addr(mnic->bar4_start,dma_addr)){
		struct descriptor *tx_desc;

		offset = get_bar4_tx_pkt_addr_offset(mnic->bar4_start,dma_addr);
		tx_desc = mnic->tx_desc[offset] + (mnic->tx_desc_ctl + offset)->tail;
		memcpy(&tx_desc->addr,data,sizeof(uint64_t));;
		
	}
	else if(is_mwr_addr_tx_pkt_len(mnic->bar4_start,dma_addr)){
		struct descriptor *tx_desc;

		offset = get_bar4_tx_pkt_len_offset(mnic->bar4_start,dma_addr);
		tx_desc = mnic->tx_desc[offset] + (mnic->tx_desc_ctl + offset)->tail;
		memcpy(&tx_desc->length,data,sizeof(uint64_t));;
		
		if((mnic->tx_desc_ctl + offset)->tail != DESC_ENTRY_SIZE - 1){
			(mnic->tx_desc_ctl + offset)->tail++;
		}
		else{
			(mnic->tx_desc_ctl + offset)->tail = 0;
		}
	}
	
	
	return 0;
}

/*actual rx part*/
void *nettlp_mnic_shm_read_thread(void *arg)
{
	int i,ret,semval,idx;
	uint32_t length;
	union semun rx_sem;
	unsigned short clr[1];
	struct rx_shm_ctl *rx_shm_ctl = arg;
	uintptr_t rxd_addr;
	uintptr_t *rx_desc_base = rx_shm_ctl->desc_base;
	int sem_id = rx_shm_ctl->sem_id;
	char *shm = rx_shm_ctl->shm;
	//union semun rx_sem = rx_shm_ctl->semu;
	int *rx_state = rx_shm_ctl->state;
	struct descriptor *rx_desc = rx_shm_ctl->desc;
	struct nettlp_msix *rx_irq = rx_shm_ctl->irq;
	struct rx_desc_ctl *rxd_ctl = rx_shm_ctl->desc_ctl;
	struct nettlp *rx_nt = rx_shm_ctl->nt;

	clr[0] = 0;
	idx = rx_shm_ctl->idx;
	rx_sem = rx_shm_ctl->semu[idx];

	while(1){
		if(caught_signal){
			break;
		}
		
		semval = semctl(sem_id,0,GETVAL,rx_sem);
		if(semval <= 0){
			continue;
		}

		if(*rx_state != RX_STATE_READY){
			info("rx_state is not ready");
		}

		for(i=0;i<semval;i++){

			memcpy(&length,shm,sizeof(uint32_t));
			//info("length is %d",length);

			if(length <= 0 || *rx_state != RX_STATE_READY){
				continue;
			}

			*rx_state = RX_STATE_BUSY;
			rxd_addr = rxd_ctl->desc_head;
			shm += sizeof(uint32_t);
			//info("rx shm queue copy done ");

			ret = dma_write_aligned(rx_nt,rx_desc->addr,shm,length,MPS);
			if(ret < 0){
				debug("buf to rx_desc: failed to dma_write to %lx",rx_desc->addr);
				continue;
			}
	
			rx_desc->length = length;
			ret = dma_write(rx_nt,rxd_addr,rx_desc,sizeof(rx_desc));
			if(ret < 0){
				debug("rx_desc write_back: failed to dma_write to %#lx",rxd_addr);
				continue;
			}
		
			rx_desc++;
			shm += length;
			rxd_ctl->desc_head += sizeof(struct descriptor);
			rxd_ctl->head++;

			if(rxd_ctl->head > DESC_ENTRY_SIZE-1){
				rx_desc = rx_shm_ctl->desc;
				rxd_ctl->head = 0;
				rxd_ctl->desc_head = *rx_desc_base;
				shm = rx_shm_ctl->shm;
			};

			*rx_state = RX_STATE_READY;
		}

		if(*rx_state == RX_STATE_READY){
			//info("generate rx interrupt");
			ret = dma_write(rx_nt,rx_irq->addr,&rx_irq->data,sizeof(rx_irq->data));
			if(ret < 0){
				fprintf(stderr,"failed to generate Rx Interrupt\n");
				perror("dma_write for rx interrupt");
			}
		}

		rx_sem.array = clr;
		semctl(sem_id,0,SETALL,rx_sem);
		semval = 0;
		//info("Rx done. mnic received %d packets",i);
	}
	
	pthread_join(rx_shm_ctl->tid,NULL);

	return NULL;
}

void mnic_alloc(struct nettlp_mnic *mnic)
{
	mnic->tx_desc_base = calloc(TX_QUEUES,sizeof(uintptr_t));
	mnic->rx_desc_base = calloc(RX_QUEUES,sizeof(uintptr_t));
	mnic->rx_desc_addr = calloc(RX_QUEUES,sizeof(uintptr_t));

	mnic->tx_irq = calloc(TX_QUEUES,sizeof(struct nettlp_msix));
	mnic->rx_irq = calloc(RX_QUEUES,sizeof(struct nettlp_msix));

	mnic->tx_desc_ctl = calloc(TX_QUEUES,sizeof(struct tx_desc_ctl));
	mnic->rx_desc_ctl = calloc(RX_QUEUES,sizeof(struct rx_desc_ctl));

	for(int i=0;i<RX_QUEUES;i++){
		info("allocate i %d",i);
		mnic->tx_desc[i] = calloc(DESC_ENTRY_SIZE,sizeof(struct descriptor));
		info("desc length %ld",mnic->tx_desc[i]->length);
		mnic->rx_desc[i] = calloc(DESC_ENTRY_SIZE,sizeof(struct descriptor));
	}
}

void mnic_free(struct nettlp_mnic *mnic)
{
	int i;

	free(mnic->tx_desc_base);
	free(mnic->rx_desc_base);
	free(mnic->rx_desc_addr);

	free(mnic->tx_irq);
	free(mnic->rx_irq);

	free(mnic->tx_desc_ctl);
	free(mnic->rx_desc_ctl);

	for(i=0;i<RX_QUEUES;i++){
		free(mnic->tx_desc[i]);
		free(mnic->rx_desc[i]);
	}
}

int tx_shm_alloc(int mem_size,int *fd)
{
	int i;
	char path[256];

	for(i=0;i<TX_QUEUES;i++){
		snprintf(path,256,"tx%d_shm_port",i+1);
		fd[i] = shm_open(path,O_RDWR,0);
		if(fd[i] == -1){
			fd[i] = shm_open(path,O_CREAT | O_EXCL | O_RDWR,0600);
			if(fd[i] == -1){
				debug("failed to allocate %s",path);
				return -1;
			}
		}
	}

	return 0;
}

int rx_shm_alloc(int mem_size,int *fd)
{
	int i;
	char path[256];

	for(i=0;i<RX_QUEUES;i++){
		snprintf(path,256,"rx_shm_port%d",i+1);
		fd[i] = shm_open(path,O_RDWR,0);
		if(fd[i] == -1){
			fd[i] = shm_open(path,O_CREAT | O_EXCL | O_RDWR,0600);
			if(fd[i] == -1){
				debug("failed to allocate %s",path);
				return -1;
			}
		}
	}

	return 0;
}

char *shm_map(int fd,int mem_size)
{
	char *buf;

	ftruncate(fd,mem_size);

	buf = mmap(NULL,mem_size,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
	if(buf == MAP_FAILED){
		return NULL;
	}

	close(fd);

	return buf;
}

int sem_conf(struct nettlp_mnic *mnic)
{
	int i;
	int sem_flags = 0600;
	key_t key = 100;
	key_t rx_key = 500;

	for(i=0;i<TX_QUEUES;i++){
		mnic->tx_sem_id[i] = semget(key,1,sem_flags | IPC_CREAT);
		txsemid[i] = mnic->tx_sem_id[i];
		if(mnic->tx_sem_id[i] == -1){
			debug("failed to get semphore for tx");
			return -1;
		}
		key += 100;
	}

	for(i=0;i<RX_QUEUES;i++){
		mnic->rx_sem_id[i] = semget(rx_key,1,sem_flags | IPC_CREAT);
		rxsemid[i] = mnic->rx_sem_id[i];
		if(mnic->rx_sem_id[i] == -1){
			debug("failed to get semphore for rx");
			return -1;
		}
		rx_key += 100;
	}

	for(i=0;i<TX_QUEUES;i++){
		memset(&mnic->tx_sem[i],0,sizeof(mnic->tx_sem[i]));
	}

	for(i=0;i<RX_QUEUES;i++){
		memset(&mnic->rx_sem[i],0,sizeof(mnic->rx_sem[i]));
	}

	for(i=0;i<TX_QUEUES;i++){
		mnic->tx_ops[i].sem_num = 0;
		mnic->tx_ops[i].sem_op = UNLOCK;
		mnic->tx_ops[i].sem_flg = SEM_UNDO;
	}

	for(i=0;i<RX_QUEUES;i++){
		init_val[0] = 0;
		mnic->rx_sem[i].array = init_val;
		semctl(mnic->rx_sem_id[i],0,SETALL,mnic->rx_sem[i]);
	}
	
	for(i=0;i<RX_QUEUES;i++){
		mnic->rx_ops[i][0].sem_num = 0;
		mnic->rx_ops[i][0].sem_op  = STOP;
		mnic->rx_ops[i][0].sem_flg = SEM_UNDO;
	}

	return 0;
}

void usage()
{
	printf("usage\n"
	       "    -r remote addr\n"
	       "    -l local addr\n"
	       "    -R remote host addr (not TLP NIC)\n"
	       "\n"
	       "    -t tunif name (default tap0)\n"
		);	
}

int main(int argc,char **argv)
{
        int opt,ret,tx_mem_size,rx_mem_size,i,n;
        int tx_fd[TX_QUEUES],rx_fd[RX_QUEUES];
	struct nettlp nt,nts[16],*nts_ptr[16];
	struct nettlp_cb cb;
	struct in_addr host;
	struct nettlp_mnic mnic;	
	struct rx_shm_ctl rx_shm_ctl[4];
	struct nettlp_msix msix[16];
	struct nettlp rx_shm_nt[4];
	struct tx_ctl tx_ctl[2];
	cpu_set_t target_cpu_set;

	memset(&nt,0,sizeof(nt));

        while((opt = getopt(argc,argv,"r:l:R:")) != -1){
                switch(opt){
		case 'r':
			ret = inet_pton(AF_INET,optarg,&nt.remote_addr);
			if(ret < 1){
				perror("inet_pton");
				return -1;
			}
			break;
		case 'l':
			ret = inet_pton(AF_INET,optarg,&nt.local_addr);
			if(ret < 1){
				perror("inet_pton");
				return -1;
			}
			break;
		case 'R':
			ret = inet_pton(AF_INET,optarg,&host);
			if(ret < 1){
				perror("inet_pton");
				return -1;
			}

			nt.requester = nettlp_msg_get_dev_id(host);
			break;
		default:
			usage();
			return -1;
                }
        }
        
	memset(&mnic,0,sizeof(mnic));

	tx_mem_size = TX_SHM_SIZE;
	rx_mem_size = RX_SHM_SIZE;

	mnic_f = &mnic;

	mnic_alloc(&mnic);

	info("desc length %ld",mnic.tx_desc[0]->length);
	ret = tx_shm_alloc(tx_mem_size,tx_fd);
	if(ret == -1){
		return -1;
	}

	ret = rx_shm_alloc(rx_mem_size,rx_fd);
	if(ret == -1){
		return -1;
	}

	info("desc length %ld",mnic.tx_desc[0]->length);

	for(i=0;i<TX_QUEUES;i++){
		mnic.tx_shm[i] = shm_map(tx_fd[i],tx_mem_size);
		if(mnic.tx_shm[i] == NULL){
			debug("tx_shm_map");
			return -1;
		}
	}

	info("desc length %ld",mnic.tx_desc[i]->length);
	for(i=0;i<RX_QUEUES;i++){
		mnic.rx_shm[i] = shm_map(rx_fd[i],rx_mem_size);
		if(mnic.rx_shm[i] == NULL){
			debug("rx_shm map");
			return -1;
		}
	}

	info("desc length %ld",mnic.tx_desc[0]->length);
	ret = sem_conf(&mnic);
	if(ret < 0){
		debug("semconf");
	}

	info("desc length %ld",mnic.tx_desc[0]->length);
	for(n=0;n<2;n++){
		mnic.rx_state[n] = RX_STATE_INIT;
	}
	info("desc length %ld",mnic.tx_desc[0]->length);

	struct nettlp_msix *tx_irq = mnic.tx_irq;
	struct nettlp_msix *rx_irq = mnic.rx_irq;

	for(n=0;n<16;n++){
		nts[n] = nt;
 		nts[n].tag = n;
		nts_ptr[n] = &nts[n];
		nts[n].dir = DMA_ISSUED_BY_ADAPTER;

		ret = nettlp_init(nts_ptr[n]);
		if(ret < 0){
			debug("failed to init nettlp on tag %x\n",n);
			return ret;
		}
	}


	mnic.bar4_start = nettlp_msg_get_bar4_start(host);	
	if(mnic.bar4_start == 0){
		debug("failed to get BAR4 addr from %s\n",inet_ntoa(host));
		info("nettlp_msg_get_bar4_start");
		return -1;
	}

	ret = nettlp_msg_get_msix_table(host,msix,8);
	if(ret < 0){
		debug("faled to get msix table from %s\n",inet_ntoa(host));
		info("nettlp_msg_get_msix_table");
	}	

	for(i=0;i<8;i++){
		info("msix addr at %d is %#lx",i,msix[i].addr);
	}

	for(i=0;i<2;i++){
		*tx_irq = msix[i+2];
		*rx_irq = msix[i];
		tx_irq++;
		rx_irq++;
	}

	for(i=0;i<2;i++){
		memset(&mnic.tx_nt[i],0,sizeof(mnic.tx_nt[i]));
		memset(&mnic.rx_nt[i],0,sizeof(mnic.rx_nt[i]));
		memset(&rx_shm_nt[i],0,sizeof(rx_shm_nt[i]));
	}
	for(i=0;i<4;i++){
		mnic.tx_nt[i].tag = i;
		mnic.tx_nt[i].remote_addr = nt.remote_addr;
		mnic.tx_nt[i].local_addr = nt.local_addr;
		mnic.tx_nt[i].dir = DMA_ISSUED_BY_LIBTLP;
		mnic.tx_nt[i].requester = nt.requester;
		nettlp_init(&mnic.tx_nt[i]);

		mnic.rx_nt[i].tag = i+4;
		mnic.rx_nt[i].remote_addr = nt.remote_addr;
		mnic.rx_nt[i].local_addr = nt.local_addr;
		mnic.rx_nt[i].dir = DMA_ISSUED_BY_LIBTLP;
		mnic.rx_nt[i].requester= nt.requester;
		nettlp_init(&mnic.rx_nt[i]);

		rx_shm_nt[i].tag = i+8;
		rx_shm_nt[i].remote_addr = nt.remote_addr;
		rx_shm_nt[i].local_addr = nt.local_addr;
		rx_shm_nt[i].dir = DMA_ISSUED_BY_LIBTLP;
		rx_shm_nt[i].requester = nt.requester;
		nettlp_init(&rx_shm_nt[i]);
	}

	info("Device is %04x",nt.requester);
	info("BAR4 start adress is %#lx",mnic.bar4_start); 

	tx_irq = mnic.tx_irq;
	rx_irq = mnic.rx_irq;

	if(signal(SIGINT,signal_handler)==SIG_ERR){
		debug("failed to set signal");
		return -1;
	}

	for(i=0;i<RX_QUEUES;i++){
		rx_shm_ctl[i].sem_id = mnic.rx_sem_id[i];
		rx_shm_ctl[i].semu = &mnic.rx_sem[i];
		rx_shm_ctl[i].shm = mnic.rx_shm[i];
		rx_shm_ctl[i].state = &mnic.rx_state[i];
		rx_shm_ctl[i].irq = mnic.rx_irq + i;
		rx_shm_ctl[i].desc = mnic.rx_desc[i];
		rx_shm_ctl[i].desc_ctl = mnic.rx_desc_ctl + i;
		rx_shm_ctl[i].nt = &rx_shm_nt[i];
		rx_shm_ctl[i].desc_base = mnic.rx_desc_base + i;
		rx_shm_ctl[i].idx = i;

		if((ret = pthread_create(&rx_shm_ctl[i].tid,NULL,nettlp_mnic_shm_read_thread,&rx_shm_ctl[i])) != 0){
			debug("%d rx thread failed to be created",i);
		}

		CPU_ZERO(&target_cpu_set);
		CPU_SET(i+TX_QUEUES,&target_cpu_set);
		pthread_setaffinity_np(rx_shm_ctl[i].tid,sizeof(cpu_set_t),&target_cpu_set);
	}

	for(i=0;i<TX_QUEUES;i++){
		tx_ctl[i].offset = i;
		tx_ctl[i].mnic = &mnic;

		if((ret = pthread_create(&tx_ctl[i].tid,NULL,mnic_tx,&tx_ctl[i])) != 0){
			debug("%i tx thread failed to be created",i);
		}

		CPU_ZERO(&target_cpu_set);
		CPU_SET(i,&target_cpu_set);
		pthread_setaffinity_np(tx_ctl[i].tid,sizeof(cpu_set_t),&target_cpu_set);
	}

	info("start nettlp callback");
	memset(&cb,0,sizeof(cb));
	cb.mwr = nettlp_mnic_mwr;
	nettlp_run_cb(nts_ptr,8,&cb,&mnic);

        return 0;
}
