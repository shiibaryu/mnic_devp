#ifndef BESS_MODULES_RXPORT_H_
#define BESS_MODULES_RXPORT_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

class RxPort;

class RxPort final : public Module{
	public:

		static const Commands cmds;

		void ProcessBatch(Context *ctx,bess::PacketBatch *batch)override;
		
		CommandResponse Init(const bess::pb::EmptyArg &);
		CommandResponse CommandAdd(const bess::pb::EmptyArg &arg);
		CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
};

#endif
