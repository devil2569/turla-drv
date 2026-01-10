#pragma once
#include "../windows_structs.hpp"
#include "interrupt_structs.h"

namespace windows {

    /*
        Definitions
    */

    constexpr auto SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE = 0xE;

    /*
        Global variables
    */

    segment_descriptor_register_64 constructed_idt_ptr = { 0 };

    segment_descriptor_interrupt_gate_64* constructed_idt_table = 0;

    /*
        Utility & Initialization
    */

    class interrupts final
    {
    public:
        auto initialize() -> project_status;

        auto create_interrupt_gate(void* assembly_handler, segment_descriptor_interrupt_gate_64 windows_gate) -> segment_descriptor_interrupt_gate_64;

    };
}

extern windows::interrupts turla_interrupts;

constexpr auto IA32_STAR = 0xC0000081;

extern "C" void nmi_handler(trap_frame* ctx);
