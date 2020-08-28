/*#include <sys/mman.h>
#include <sys/stat.h>       
#include <fcntl.h>           
#include <string.h>

#include "rx_port.h"

const Commands RxPort::cmds = {
	{"add","EmptyArg",MODULE_CMD_FUNC(&RxPort::CommandAdd),
		Command::THREAD_UNSAFE},
	{"clear","EmptyArg",MODULE_CMD_FUNC(&RxPort::CommandClear),
		Command::THREAD_UNSAFE}};

CommandResponse RxPort::Init(const bess::pb::EmptyArg &)
{

}

CommandResponse RxPort::CommandAdd(const bess::pb::EmptyArg &)
{

}

CommandResponse RxPort::CommandClear(const bess::pb::EmptyArg &)
{
	
}

void RxPort::ProcessBatch(Context *ctx,bess::PacketBatch *batch)
{
	
}

ADD_MODULE(RxPort,"rx_port","bundling port of RxShmPorts");
*/
