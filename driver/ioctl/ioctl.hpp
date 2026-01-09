#pragma once
#include <ntifs.h>
#include <windef.h>
#include <cstdint>
#include "../windows_structs.hpp"

constexpr auto code_rw = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4561, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr auto code_ba = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6461, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr auto code_get_guarded_region = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7461, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr auto code_security = 0x85b3b69;

constexpr auto win_1803 = 17134;
constexpr auto win_1809 = 17763;
constexpr auto win_1903 = 18362;
constexpr auto win_1909 = 18363;
constexpr auto win_2004 = 19041;
constexpr auto win_20H2 = 19569;
constexpr auto win_21H1 = 20180;

constexpr auto page_offset_size = 12;
constexpr u64 pmask = (~0xfull << 8) & 0xfffffffffull;
extern UNICODE_STRING name, link;
enum class system_information_class_t : u32 {
	system_bigpool_information = 0x42
};

typedef struct _SYSTEM_BIGPOOL_ENTRY {
	PVOID VirtualAddress;
	ULONG_PTR NonPaged : 1;
	ULONG_PTR SizeInBytes;
	UCHAR Tag[4];
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

struct rw {
	INT32 security;
	INT32 process_id;
	u64 address;
	u64 buffer;
	u64 size;
	bool write;
};

struct ba {
	INT32 security;
	INT32 process_id;
	u64* address;
};

struct ga {
	INT32 security;
	u64* address;
};

extern "C" {
	auto ZwQuerySystemInformation(
		system_information_class_t info_class,
		void* system_information,
		u32 system_information_length,
		u32* return_length
	) -> NTSTATUS;

	auto PsGetProcessSectionBaseAddress(
		PEPROCESS process
	) -> void*;
	NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
}

namespace windows {
	class drv final {
	public:
		auto read_phys(
			void* target_address,
			void* buffer,
			SIZE_T size,
			SIZE_T* bytes_read
		) -> NTSTATUS;

		auto write_phys(
			void* target_address,
			void* buffer,
			SIZE_T size,
			SIZE_T* bytes_written
		) -> NTSTATUS;

		auto get_winver() -> INT32;

		auto get_process_cr3(
			PEPROCESS process
		) -> u64;

		auto translate_linear(
			u64 directory_table_base,
			u64 virtual_address
		) -> u64;

		auto frw(
			rw* request
		) -> NTSTATUS;

		auto fba(
			ba* request
		) -> NTSTATUS;

		auto fget_guarded_region(
			ga* request
		) -> NTSTATUS;

		auto initialize(

		) -> NTSTATUS;
	};
}

extern windows::drv* turla_drv;
