#include "../windows_structs.hpp"
#include "interrupt_structs.h"

#pragma pack(push, 1)
struct info_page
{
	segment_descriptor_register_64 constructed_idt;
	segment_descriptor_register_64 user_idt_storage;
	uint64_t user_cr3_storage;
	uint64_t nmi_panic_function_storage;
};
#pragma pack(pop)

extern "C" void* g_nmi_shellcode;

namespace windows
{

	inline void* g_enter_constructed_space_executed = 0;
	inline void* g_enter_constructed_space_shown = 0;
	inline void* g_exit_constructed_space = 0;

	extern "C" info_page* g_info_page; // An array of info_page_t's

	class shellcode final
	{
	public:
		inline project_status construct_shellcodes(
			void*& enter_constructed_space_executed,
			void*& enter_constructed_space_shown,
			void*& exit_constructed_space,
			void*& nmi_shellcode,
			segment_descriptor_register_64 my_idt_ptr,
			void* orig_data_ptr_value,
			void* handler_address,
			uint64_t constructed_cr3
		)
		{
			PHYSICAL_ADDRESS max_addr{};
			max_addr.QuadPart = MAXULONG64;

			info_page* info_page_ptr = nullptr;

			enter_constructed_space_executed = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
			enter_constructed_space_shown = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
			exit_constructed_space = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
			nmi_shellcode = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);

			info_page_ptr = static_cast<info_page*>(
				MmAllocateContiguousMemory(KeQueryActiveProcessorCount(0) * sizeof(info_page), max_addr)
				);

			if (!enter_constructed_space_executed || !enter_constructed_space_shown || !exit_constructed_space || !nmi_shellcode || !info_page_ptr)
				return status_memory_alloc_failure;

			memset(enter_constructed_space_executed, 0, PAGE_SIZE);
			memset(enter_constructed_space_shown, 0, PAGE_SIZE);
			memset(exit_constructed_space, 0, PAGE_SIZE);
			memset(nmi_shellcode, 0, PAGE_SIZE);
			memset(info_page_ptr, 0, KeQueryActiveProcessorCount(0) * sizeof(info_page));

			for (uint32_t i = 0; i < KeQueryActiveProcessorCount(0); ++i)
				info_page_ptr[i].constructed_idt = my_idt_ptr;

			construct_executed_enter_shellcode(enter_constructed_space_executed, orig_data_ptr_value, handler_address, constructed_cr3, info_page_ptr);

			construct_shown_enter_shellcode(enter_constructed_space_shown, orig_data_ptr_value, constructed_cr3);

			construct_exit_shellcode(exit_constructed_space, info_page_ptr);

			construct_nmi_shellcode(nmi_shellcode, get_windows_nmi_handler());

			g_enter_constructed_space_executed = enter_constructed_space_executed;
			g_enter_constructed_space_shown = enter_constructed_space_shown;
			g_exit_constructed_space = exit_constructed_space;
			g_nmi_shellcode = nmi_shellcode;

			g_info_page = info_page_ptr;


			return status_success;
		}

		inline void construct_executed_enter_shellcode(
			void* enter_constructed_space,
			void* orig_data_ptr_value,
			void* handler_address,
			uint64_t constructed_cr3,
			info_page* info_page_base
		)
		{
			static uint8_t start_place_holder_shellcode[] = {
				0xFA,
				0x0F, 0xAE, 0xF0,
				0x81, 0xFA, 0x69, 0x69, 0x00, 0x00,
				0x74, 0x0D,
				0xFB,
				0x48, 0xB8, 0,0,0,0,0,0,0,0,
				0xFF, 0xE0
			};

			static uint8_t cr3_pushing_shellcode[] = {
				0x48, 0x0F, 0x20, 0xD8,
				0x50
			};

			static uint8_t cr3_changing_shellcode[] = {
				0x48, 0xB8, 0,0,0,0,0,0,0,0,
				0x48, 0x0F, 0x22, 0xD8,
				0x48, 0xB8, 0,0,0,0,0,0,0,0,
				0x0F, 0x01, 0x38
			};

			static uint8_t calculate_base_shellcode[] = {
				0x53,
				0x51,
				0x52,
				0x48, 0x31, 0xC0,
				0xB8, 0x0B, 0x00, 0x00, 0x00,
				0x31, 0xC9,
				0x0F, 0xA2,
				0x8B, 0xC2,
				0x5A,
				0x59,
				0x5B,
				0x48, 0x6B, 0xC0, 0x00,
				0x53,
				0x48, 0xBB, 0,0,0,0,0,0,0,0,
				0x48, 0x01, 0xD8,
				0x5B,
				0x48, 0x8B, 0xD0
			};

			static uint8_t cr3_saving_shellcode[] = {
				0x52,
				0x48, 0x83, 0xC0, 0x00,
				0x48, 0x8B, 0x54, 0x24, 0x08,
				0x48, 0x89, 0x10,
				0x5A,
				0x48, 0x83, 0xC4, 0x08
			};

			static uint8_t nmi_panic_shellcode[] = {
				0x48, 0x8B, 0xC2,
				0x48, 0x83, 0xC0, 0x00,
				0x4C, 0x89, 0x00
			};

			static uint8_t idt_shellcode[] = {
				0x48, 0x8B, 0xC2,
				0x48, 0x83, 0xC0, 0x00,
				0x0F, 0x01, 0x08,
				0x48, 0x8B, 0xC2,
				0x48, 0x83, 0xC0, 0x00,
				0x0F, 0x01, 0x18
			};

			static uint8_t jump_to_handler_shellcode[] = {
				0x48, 0xB8, 0,0,0,0,0,0,0,0,
				0xFF, 0xE0
			};

			*(void**)(start_place_holder_shellcode + 15) = orig_data_ptr_value;
			*(uint64_t*)(cr3_changing_shellcode + 2) = constructed_cr3;
			*(uint64_t*)(cr3_changing_shellcode + 16) = (uint64_t)enter_constructed_space;

			*(uint8_t*)(calculate_base_shellcode + 23) = sizeof(info_page);
			*(void**)(calculate_base_shellcode + 27) = info_page_base;

			*(uint8_t*)(cr3_saving_shellcode + 4) = offsetof(info_page, user_cr3_storage);
			*(uint8_t*)(nmi_panic_shellcode + 6) = offsetof(info_page, nmi_panic_function_storage);
			*(uint8_t*)(idt_shellcode + 6) = offsetof(info_page, user_idt_storage);
			*(uint8_t*)(idt_shellcode + 16) = offsetof(info_page, constructed_idt);

			*(void**)(jump_to_handler_shellcode + 2) = handler_address;

			uint8_t* current_position = (uint8_t*)enter_constructed_space;

			memcpy(current_position, start_place_holder_shellcode, sizeof(start_place_holder_shellcode));
			current_position += sizeof(start_place_holder_shellcode);

			memcpy(current_position, cr3_pushing_shellcode, sizeof(cr3_pushing_shellcode));
			current_position += sizeof(cr3_pushing_shellcode);

			memcpy(current_position, cr3_changing_shellcode, sizeof(cr3_changing_shellcode));
			current_position += sizeof(cr3_changing_shellcode);

			memcpy(current_position, calculate_base_shellcode, sizeof(calculate_base_shellcode));
			current_position += sizeof(calculate_base_shellcode);

			memcpy(current_position, cr3_saving_shellcode, sizeof(cr3_saving_shellcode));
			current_position += sizeof(cr3_saving_shellcode);

			memcpy(current_position, nmi_panic_shellcode, sizeof(nmi_panic_shellcode));
			current_position += sizeof(nmi_panic_shellcode);

			memcpy(current_position, idt_shellcode, sizeof(idt_shellcode));
			current_position += sizeof(idt_shellcode);

			memcpy(current_position, jump_to_handler_shellcode, sizeof(jump_to_handler_shellcode));
		}
		inline void construct_exit_shellcode(void* exit_constructed_space, info_page* info_page_base) {

			static const uint8_t calculate_base_shellcode[] = {
				0x53,                                                       // push rbx
				0x51,                                                       // push rcx
				0x52,                                                       // push rdx
				0x48, 0x31, 0xC0,                                           // xor rax, rax (only eax, eax would be necessary but I want to clear rax fully for the imul)
				0xB8, 0x0B, 0x00, 0x00, 0x00,                               // mov eax, 0x0B (Leaf)
				0x31, 0xC9,                                                 // xor ecx, ecx
				0x0F, 0xA2,                                                 // cpuid
				0x8B, 0xC2,                                                 // mov eax, edx (Store Apic id in eax)
				0x5A,                                                       // pop rdx
				0x59,                                                       // pop rcx
				0x5B,                                                       // pop rbx
				0x48, 0x6B, 0xC0, 0x00,                                     // imul rax, rax, sizeof(info_page_t) (calculate the offset)
				0x53,                                                       // push rbx
				0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, imm64 (info_page_base)
				0x48, 0x01, 0xD8,                                           // add rax, rbx
				0x5B,                                                       // pop rbx
				0x48, 0x8B, 0xD0,                                           // mov rdx, rax (save &info_page_base[apic_id] into rdx)
			};


			static const uint8_t restore_cr3_shellcode[] = {
				0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_cr3_storage)
				0x48, 0x8B, 0x00,                                           // mov rax, [rax]
				0x0F, 0x22, 0xD8,                                           // mov cr3, rax
			};

			static const uint8_t restore_idt_shellcode[] = {
				0x48, 0x8B, 0xC2,                                           // mov rax, rdx (Restore &info_page_base[apic_id] from rdx)
				0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_idt_storage)
				0x0F, 0x01, 0x18,                                           // lidt [rax]
			};

			static const uint8_t return_shellcode[] = {
				0xC3														// ret
			};


			*(uint8_t*)((uint8_t*)calculate_base_shellcode + 23) = sizeof(info_page);

			*(void**)((uint8_t*)calculate_base_shellcode + 27) = info_page_base;

			*(uint8_t*)((uint8_t*)restore_cr3_shellcode + 3) = offsetof(info_page, user_cr3_storage);

			*(uint8_t*)((uint8_t*)restore_idt_shellcode + 6) = offsetof(info_page, user_idt_storage);

			uint8_t* current_position = (uint8_t*)exit_constructed_space;
			memcpy(current_position, calculate_base_shellcode, sizeof(calculate_base_shellcode));
			current_position += sizeof(calculate_base_shellcode);

			memcpy(current_position, restore_cr3_shellcode, sizeof(restore_cr3_shellcode));
			current_position += sizeof(restore_cr3_shellcode);

			memcpy(current_position, restore_idt_shellcode, sizeof(restore_idt_shellcode));
			current_position += sizeof(restore_idt_shellcode);

			memcpy(current_position, return_shellcode, sizeof(return_shellcode));
			current_position += sizeof(return_shellcode);
		}

		inline void construct_shown_enter_shellcode(void* enter_constructed_space, void* orig_data_ptr_value, uint64_t constructed_cr3) {
			static const uint8_t start_place_holder_shellcode[] = {
				0xFA,                                                       // cli
				0x0F, 0xAE, 0xF0,                                           // mfence
				0x81, 0xFA, 0x69, 0x69, 0x00, 0x00,                         // cmp edx, 0x6969
				0x74, 0x0D,                                                 // je skip_orig_function
				0xFB,                                                       // sti
				0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of orig_data_ptr_value)
				0xFF, 0xE0,                                                 // jmp rax
			};

			static const uint8_t cr3_pushing_shellcode[] = {
				// Store the User Cr3
				0x48, 0x0F, 0x20, 0xD8,										// mov rax, cr3
				0x50,														// push rax
			};

			static const uint8_t cr3_changing_shellcode[] = {
				// Change to constructed Cr3
				0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (constructed cr3 value)
				0x48, 0x0F, 0x22, 0xD8,                                     // mov cr3, rax

				// Flush the TLB for this page
				0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (page address)
				0x0F, 0x01, 0x38,											// invlpg [rax]
				0x58,														// pop rax <- Won't be executed anymore
			};

			static const uint8_t return_shellcode[] = {
				0xC3
			};

			*(void**)((uint8_t*)start_place_holder_shellcode + 15) = orig_data_ptr_value;
			*(uint64_t*)((uint8_t*)cr3_changing_shellcode + 2) = constructed_cr3;
			*(uint64_t*)((uint8_t*)cr3_changing_shellcode + 16) = (uint64_t)enter_constructed_space;


			uint8_t* current_position = (uint8_t*)enter_constructed_space;
			memcpy(current_position, start_place_holder_shellcode, sizeof(start_place_holder_shellcode));
			current_position += sizeof(start_place_holder_shellcode);

			memcpy(current_position, cr3_pushing_shellcode, sizeof(cr3_pushing_shellcode));
			current_position += sizeof(cr3_pushing_shellcode);

			memcpy(current_position, cr3_changing_shellcode, sizeof(cr3_changing_shellcode));
			current_position += sizeof(cr3_changing_shellcode);

			memcpy(current_position, return_shellcode, sizeof(return_shellcode));
			current_position += sizeof(return_shellcode);
		}

		inline void construct_nmi_shellcode(void* nmi_shellcode, void* windows_nmi_handler) {

			static const uint8_t restore_cr3_shellcode[] = {
				0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_cr3_storage)
				0x48, 0x8B, 0x00,                                           // mov rax, [rax]
				0x0F, 0x22, 0xD8,                                           // mov cr3, rax
			};

			static const uint8_t restore_idt_shellcode[] = {
				0x48, 0x8B, 0xC2,                                           // mov rax, rdx (Restore &info_page_base[apic_id] from rdx)
				0x48, 0x83, 0xC0, 0x00,                                     // add rax, offsetof(info_page_t, user_idt_storage)
				0x0F, 0x01, 0x18,                                           // lidt [rax]
			};

			static const uint8_t jump_windows_handler[] = {
				0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (address of handler_address)
				0xFF, 0xE0,                                                 // jmp rax
			};


			*(uint8_t*)((uint8_t*)restore_cr3_shellcode + 3) = offsetof(info_page, user_cr3_storage);

			*(uint8_t*)((uint8_t*)restore_idt_shellcode + 6) = offsetof(info_page, user_idt_storage);

			*(void**)((uint8_t*)jump_windows_handler + 2) = windows_nmi_handler;

			uint8_t* current_position = (uint8_t*)nmi_shellcode;
			memcpy(current_position, restore_cr3_shellcode, sizeof(restore_cr3_shellcode));
			current_position += sizeof(restore_cr3_shellcode);

			memcpy(current_position, restore_idt_shellcode, sizeof(restore_idt_shellcode));
			current_position += sizeof(restore_idt_shellcode);

			memcpy(current_position, jump_windows_handler, sizeof(jump_windows_handler));
			current_position += sizeof(jump_windows_handler);
		}

	};
}

extern windows::shellcode shellcode;
