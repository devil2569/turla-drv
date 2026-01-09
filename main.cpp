#include "driver/ioctl/ioctl.hpp"

auto driver_entry( PDRIVER_OBJECT drv, PUNICODE_STRING rp ) -> long
{
	DbgPrint("entering turla...");

    auto stat = []() -> NTSTATUS
    {
        return !turla_drv->initialize() ? STATUS_FAILED_DRIVER_ENTRY : STATUS_SUCCESS;
    }();

	return stat;
}