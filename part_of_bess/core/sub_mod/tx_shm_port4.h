#ifndef BESS_MODULES_SHMPORT_H_
#define BESS_MODULES_SHMPORT_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/syscallthread.h"

#define MAX_TEMPLATE_SIZE 1000

class TxShmPort4;

class TxShmPortThread4 final : public bess::utils::SyscallThreadPfuncs, public Module{
	public:
		TxShmPortThread4(TxShmPort4 *owner) : owner_(owner) {}
		void Run() override;
		
	private:
		TxShmPort4 *owner_;
};

class TxShmPort4 final : public Module{
	public:
		TxShmPort4()
		  : shm_thread_(this){}
		    //templ_(){}

		void DeInit() override;

		static const Commands cmds;

		struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg)override;
		
		CommandResponse Init(const bess::pb::EmptyArg &);
		CommandResponse CommandAdd(const bess::pb::EmptyArg &arg);
		CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

	private:
		void FillPacket(bess::Packet *p,uint32_t length);
		void GeneratePackets(Context *ctx, bess::PacketBatch *batch,bess::Packet *p,uint32_t length);

		friend class TxShmPortThread4;
		TxShmPortThread4 shm_thread_;

		int template_size_;

};

#endif 
