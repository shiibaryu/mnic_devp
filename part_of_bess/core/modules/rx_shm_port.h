#ifndef BESS_MODULES_SHMPORT_H_
#define BESS_MODULES_SHMPORT_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/syscallthread.h"

#define MAX_TEMPLATE_SIZE 1000

class RxShmPort;

class RxShmPort final : public Module{
	public:

		static const Commands cmds;

		void ProcessBatch(Context *ctx, bess::PacketBatch *batch)override;
		void WritePkt(bess::PacketBatch *batch);		

		CommandResponse Init(const bess::pb::EmptyArg &);
		CommandResponse CommandAdd(const bess::pb::EmptyArg &arg);
		CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

};

#endif 
