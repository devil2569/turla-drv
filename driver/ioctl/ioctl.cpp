#include "ioctl.hpp"

windows::drv* turla_drv = nullptr;
extern "C" NTSTATUS init_drv(PDRIVER_OBJECT drv_obj, PUNICODE_STRING path);
UNICODE_STRING name{};
UNICODE_STRING link{};

auto windows::drv::read_phys(void* target_address, void* buffer, SIZE_T size, SIZE_T* bytes_read)->NTSTATUS
{
	auto copy = [&](u64 pa)
	{
		MM_COPY_ADDRESS a{};
		a.PhysicalAddress.QuadPart = static_cast<LONGLONG>(pa);
		return MmCopyMemory(buffer, a, size, MM_COPY_MEMORY_PHYSICAL, bytes_read);
	};
	return target_address ? copy(reinterpret_cast<u64>(target_address)) : STATUS_UNSUCCESSFUL;
}

auto windows::drv::write_phys(void* target_address, void* buffer, SIZE_T size, SIZE_T* bytes_written)->NTSTATUS
{
	auto write = [&](PHYSICAL_ADDRESS pa)
	{
		auto m = MmMapIoSpaceEx(pa, size, PAGE_READWRITE);
		if (!m) return STATUS_UNSUCCESSFUL;
		memcpy(m, buffer, size);
		*bytes_written = size;
		MmUnmapIoSpace(m, size);
		return STATUS_SUCCESS;
	};
	if (!target_address) return STATUS_UNSUCCESSFUL;
	PHYSICAL_ADDRESS pa{};
	pa.QuadPart = reinterpret_cast<LONGLONG>(target_address);
	return write(pa);
}

auto windows::drv::get_winver()->INT32
{
	auto pick = [&](u32 b)
	{
		return b == win_1803 || b == win_1809 ? 0x0278 :
			b == win_1903 || b == win_1909 ? 0x0280 :
			0x0388;
	};
	RTL_OSVERSIONINFOW v{};
	RtlGetVersion(&v);
	return pick(v.dwBuildNumber);
}

auto windows::drv::get_process_cr3(PEPROCESS process)->u64
{
	auto read = [&](u32 off) {return *reinterpret_cast<u64*>(reinterpret_cast<u8*>(process) + off); };
	auto dir = read(0x28);
	return dir ? dir : read(get_winver());
}

auto windows::drv::translate_linear(u64 dtb, u64 va)->u64
{
	dtb &= ~0xf;
	auto idx = [&](int s) {return (va >> s) & 0x1ff; };
	auto readq = [&](u64 a, u64& o)
	{
			SIZE_T r{};
			return read_phys(reinterpret_cast<void*>(a), &o, sizeof(o), &r);
	};

	const u64 page_off = va & ~(~0ull << page_offset_size);
	u64 pdpe{}, pde{}, pte{}, final{};

	if (!NT_SUCCESS(readq(dtb + 8 * idx(39), pdpe)) || !(pdpe & 1)) return 0;
	if (!NT_SUCCESS(readq((pdpe & pmask) + 8 * idx(30), pde)) || !(pde & 1)) return 0;
	if (pde & 0x80) return (pde & (~0ull << 42 >> 12)) + (va & ~(~0ull << 30));
	if (!NT_SUCCESS(readq((pde & pmask) + 8 * idx(21), pte)) || !(pte & 1)) return 0;
	if (!NT_SUCCESS(readq((pte & pmask) + 8 * idx(12), final)) || !final) return 0;

	return (final & pmask) + page_off;
}

auto windows::drv::frw(rw* r)->NTSTATUS
{
	if (r->security != code_security || !r->process_id) return STATUS_UNSUCCESSFUL;

	auto with_proc = [&](auto fn)
	{
		PEPROCESS p{};
		if (!NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(r->process_id), &p)))
			return STATUS_UNSUCCESSFUL;
		auto s = fn(p);
		ObDereferenceObject(p);
		return s;
	};

	auto min64 = [&](u64 a, u64 b) {return a < b ? a : b; };

	return with_proc([&](PEPROCESS p)
	{
		auto cr3 = get_process_cr3(p);
		auto phys = translate_linear(cr3, r->address);
		if (!phys) return STATUS_UNSUCCESSFUL;

		const u64 max = PAGE_SIZE - (phys & 0xFFF);
		const u64 len = min64(max, r->size);
		SIZE_T done{};

		return r->write
			? write_phys(reinterpret_cast<void*>(phys), reinterpret_cast<void*>(r->buffer), len, &done)
			: read_phys(reinterpret_cast<void*>(phys), reinterpret_cast<void*>(r->buffer), len, &done);
	});
}

auto windows::drv::fba(ba* r)->NTSTATUS
{
	if (r->security != code_security || !r->process_id) return STATUS_UNSUCCESSFUL;

	auto with_proc = [&](auto fn)
	{
		PEPROCESS p{};
		if (!NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(r->process_id), &p)))
			return STATUS_UNSUCCESSFUL;
		auto s = fn(p);
		ObDereferenceObject(p);
		return s;
	};

	return with_proc([&](PEPROCESS p)
	{
		auto base = reinterpret_cast<u64>(PsGetProcessSectionBaseAddress(p));
		return base ? (RtlCopyMemory(r->address, &base, sizeof(base)), STATUS_SUCCESS) : STATUS_UNSUCCESSFUL;
	});
}

auto windows::drv::fget_guarded_region(ga* r)->NTSTATUS
{
	if (r->security != code_security) return STATUS_UNSUCCESSFUL;

	auto query = [&](void* b, u32 l, u32* o)
	{
		return ZwQuerySystemInformation(system_information_class_t::system_bigpool_information, b, l, o);
	};

	u32 len{};
	NTSTATUS st = query(nullptr, 0, &len);
	PSYSTEM_BIGPOOL_INFORMATION info{};

	auto cleanup = [&] {if (info) ExFreePool(info); };

	while (st == STATUS_INFO_LENGTH_MISMATCH)
	{
		cleanup();
		info = reinterpret_cast<PSYSTEM_BIGPOOL_INFORMATION>(ExAllocatePool(NonPagedPool, len));
		st = query(info, len, &len);
	}

	if (!info) return STATUS_UNSUCCESSFUL;

	auto match = [&](const SYSTEM_BIGPOOL_ENTRY& e)
	{
		const u8 tag[4] = { 'T','n','o','C' };
		return e.NonPaged && e.SizeInBytes == 0x200000 && !memcmp(e.Tag, tag, 4);
	};

	for (u32 i = 0; i < info->Count; i++)
	{
		if (match(info->AllocatedInfo[i]))
		{
			auto va = reinterpret_cast<u64>(info->AllocatedInfo[i].VirtualAddress) & ~1ull;
			RtlCopyMemory(r->address, &va, sizeof(va));
			cleanup();
			return STATUS_SUCCESS;
		}
	}

	cleanup();
	return STATUS_SUCCESS;
}

auto windows::drv::initialize()->NTSTATUS
{
	return NT_SUCCESS(IoCreateDriver(nullptr, &init_drv)) ? STATUS_SUCCESS : STATUS_FAILED_DRIVER_ENTRY;
}

auto unload_drv(PDRIVER_OBJECT drv_obj) -> void
{
	IoDeleteSymbolicLink(&link);
	IoDeleteDevice(drv_obj->DeviceObject);
}

auto unsupported_dispatch(PDEVICE_OBJECT device_obj, PIRP irp) -> NTSTATUS
{
	UNREFERENCED_PARAMETER(device_obj);
	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_NOT_SUPPORTED;
}

auto dispatch_handler(PDEVICE_OBJECT device_obj, PIRP irp) -> NTSTATUS
{
	UNREFERENCED_PARAMETER(device_obj);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS io_controller(PDEVICE_OBJECT device_obj, PIRP irp)
{
	UNREFERENCED_PARAMETER(device_obj);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	const ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

	auto complete = [&](NTSTATUS s, ULONG b)
	{
			irp->IoStatus.Status = s;
			irp->IoStatus.Information = b;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return s;
	};

	return
		code == code_rw && size == sizeof(rw) ? complete(turla_drv->frw(static_cast<rw*>(irp->AssociatedIrp.SystemBuffer)), sizeof(rw)) :
		code == code_ba && size == sizeof(ba) ? complete(turla_drv->fba(static_cast<ba*>(irp->AssociatedIrp.SystemBuffer)), sizeof(ba)) :
		code == code_get_guarded_region && size == sizeof(ga) ? complete(turla_drv->fget_guarded_region(static_cast<ga*>(irp->AssociatedIrp.SystemBuffer)), sizeof(ga)) :
		size ? complete(STATUS_INFO_LENGTH_MISMATCH, 0) : complete(STATUS_INVALID_DEVICE_REQUEST, 0);
}

auto init_drv(PDRIVER_OBJECT drv_obj, PUNICODE_STRING path) -> NTSTATUS
{
	UNREFERENCED_PARAMETER(path);

	PDEVICE_OBJECT device_obj = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&name, L"\\Device\\turla");
	RtlInitUnicodeString(&link, L"\\DosDevices\\turla");

	auto fail = [&](NTSTATUS s) {device_obj ? IoDeleteDevice(device_obj) : void(); return s; };

	status = IoCreateDevice(drv_obj, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_obj);
	if (!NT_SUCCESS(status)) return status;

	status = IoCreateSymbolicLink(&link, &name);
	if (!NT_SUCCESS(status)) return fail(status);

	for (u32 i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) drv_obj->MajorFunction[i] = unsupported_dispatch;

	drv_obj->MajorFunction[IRP_MJ_CREATE] = dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_CLOSE] = dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = io_controller;
	drv_obj->DriverUnload = unload_drv;

	device_obj->Flags |= DO_BUFFERED_IO;
	device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

	turla_drv = static_cast<windows::drv*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(windows::drv), 'turl'));
	return STATUS_SUCCESS;
}
