#include "interrupts.h"

auto windows::interrupts::create_interrupt_gate(void* assembly_handler, segment_descriptor_interrupt_gate_64 windows_gate) -> segment_descriptor_interrupt_gate_64
{
	segment_descriptor_interrupt_gate_64 gate;

	gate.interrupt_stack_table = windows_gate.interrupt_stack_table;
	gate.segment_selector = read_cs();
	gate.must_be_zero_0 = 0;
	gate.type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
	gate.must_be_zero_1 = 0;
	gate.descriptor_privilege_level = 0;
	gate.present = 1;
	gate.reserved = 0;

	uint64_t offset = (uint64_t)assembly_handler;
	gate.offset_low = (offset >> 0) & 0xFFFF;
	gate.offset_middle = (offset >> 16) & 0xFFFF;
	gate.offset_high = (offset >> 32) & 0xFFFFFFFF;

	return gate;
}

auto windows::interrupts::initialize() -> project_status
{
	PHYSICAL_ADDRESS max_addr = { 0 };
	max_addr.QuadPart = MAXULONG64;

	constructed_idt_table = (segment_descriptor_interrupt_gate_64*)MmAllocateContiguousMemory(sizeof(segment_descriptor_interrupt_gate_64) * 256, max_addr);
	if (!constructed_idt_table) return status_memory_alloc_failure;

	RtlZeroMemory(constructed_idt_table, sizeof(segment_descriptor_interrupt_gate_64) * 256);

	// copy windows idt
	segment_descriptor_register_64 idt = { 0 };
	__sidt(&idt);

	segment_descriptor_interrupt_gate_64* windows_idt = (segment_descriptor_interrupt_gate_64*)idt.base_address;
	if (!windows_idt) return status_failure;

	g_windows_nmi_handler = (static_cast<uint64_t>(windows_idt[exception_vector::nmi].offset_high) << 32) |
		(static_cast<uint64_t>(windows_idt[exception_vector::nmi].offset_middle) << 16) |
		(windows_idt[exception_vector::nmi].offset_low);

	constructed_idt_table[exception_vector::nmi] = create_interrupt_gate(nmi_isr, windows_idt[exception_vector::nmi]);
	constructed_idt_ptr.base_address = (uint64_t)constructed_idt_table;
	constructed_idt_ptr.limit = (sizeof(segment_descriptor_interrupt_gate_64) * 256) - 1;


	return status_success;
}

extern "C" void nmi_handler(trap_frame* ctx)
{
	uint64_t star_msr = __readmsr(IA32_STAR);
	KPCR * kcpr = (KPCR*)__readgsqword(0x18);
	uint64_t curr_user_panic_rip = 0;
	rflags curr_user_rflags = { 0 };

	curr_user_rflags.flags = ctx->rflags;
	curr_user_rflags.interrupt_enable_flag = 1;
	curr_user_rflags.virtual_8086_mode_flag = 0;
	curr_user_rflags.reserved1 = 0;
	curr_user_rflags.reserved2 = 0;
	curr_user_rflags.reserved3 = 0;
	curr_user_rflags.reserved4 = 0;
	curr_user_rflags.read_as_1 = 1;
	curr_user_rflags.nested_task_flag = 0;
	curr_user_rflags.io_privilege_level = 3;
	curr_user_rflags.resume_flag = 0;
	curr_user_rflags.alignment_check_flag = 0;

	uint16_t sysret_cs = (uint16_t)(((star_msr >> 48) + 16) | 3); 
	uint16_t sysret_ss = (uint16_t)(((star_msr >> 48) + 8) | 3);   

	ctx->rsp = kcpr->UserRsp;
	ctx->rip = curr_user_panic_rip;
	ctx->rflags = curr_user_rflags.flags;
	ctx->cs_selector = sysret_cs;
	ctx->ss_selector = sysret_ss;

	swap_gs();
}
