#include "Hooks.h"
#include <fltKernel.h>

namespace Hooks
{
    BOOLEAN gh_ExEnumHandleTable(
        PVOID HandleTable,
        PVOID EnumHandleProcedure,
        PVOID EnumParameter,
        PHANDLE Handle OPTIONAL
    )
    {
        DBG_PRINT("EnumHandleProcedure Called From: 0x%p, EnumHandleProcedure: 0x%p", _ReturnAddress(), EnumHandleProcedure);
        return TRUE;
    }

    NTSTATUS gh_ZwAllocateVirtualMemory(
        _In_    HANDLE    ProcessHandle,
        _Inout_ PVOID*    BaseAddress,
        _In_    ULONG_PTR ZeroBits,
        _Inout_ PSIZE_T   RegionSize,
        _In_    ULONG     AllocationType,
        _In_    ULONG     Protect
    )
    {
        DBG_PRINT("ZwAllocateVirtualMemory called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - ProcessHandle: 0x%p", ProcessHandle);
        if(BaseAddress)
            DBG_PRINT("     - BaseAddress (of allocation): 0x%p", *(ULONGLONG*)BaseAddress);
        if(RegionSize)
            DBG_PRINT("     - RegionSize: 0x%p", *(SIZE_T*)RegionSize);
        DBG_PRINT("     - Protect: 0x%p", Protect);

        return ZwAllocateVirtualMemory(
            ProcessHandle,
            BaseAddress,
            ZeroBits, 
            RegionSize,
            AllocationType, 
            Protect
        );
    }

    NTSTATUS gh_PsSetLoadImageNotifyRoutine(
        PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
    )
    {
        DBG_PRINT("PsSetLoadImageNotifyRoutine called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - NotifyRoutine: 0x%p", NotifyRoutine);
        return PsSetLoadImageNotifyRoutine(NotifyRoutine);
    }

    NTSTATUS gh_ObRegisterCallbacks(
        POB_CALLBACK_REGISTRATION CallbackRegistration,
        PVOID* RegistrationHandle
    )
    {
        DBG_PRINT("ObRegisterCallbacks called from: 0x%p", _ReturnAddress());
        return ObRegisterCallbacks(
            CallbackRegistration,
            RegistrationHandle
        );
    }

    NTSTATUS gh_ZwQuerySystemInformation(
        _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _Inout_   PVOID                    SystemInformation,
        _In_      ULONG                    SystemInformationLength,
        _Out_opt_ PULONG                   ReturnLength
    )
    {
        DBG_PRINT("ZwQuerySystemInformation called");
        DBG_PRINT("     - SystemInformationClass: 0x%p", SystemInformationClass);
        DBG_PRINT("     - SystemInformation: 0x%p", SystemInformation);
        DBG_PRINT("     - SystemInformationLength: 0x%p", SystemInformationLength);

        auto result = ZwQuerySystemInformation(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength,
            ReturnLength
        );

        if (SystemInformationLength && SystemInformation && ReturnLength && *ReturnLength)
        {
            switch (SystemInformationClass)
            {
            case SystemProcessInformation:
            {
                auto process_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(SystemInformation);
                process_info->NextEntryOffset = NULL;
                DBG_PRINT("Spoofed SystemProcessInformation.....");
                break;
            }
            case SystemModuleInformation:
            {
                auto module_info = reinterpret_cast<PRTL_PROCESS_MODULES>(SystemInformation);
                module_info->NumberOfModules = 1;
                DBG_PRINT("Spoofed SystemModuleInformation.....");
                break;
            }
            default:
                break;
            }
        }
        return result;
    }

    NTSTATUS gh_PsSetCreateProcessNotifyRoutineEx(
        PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
        BOOLEAN                           Remove
    )
    {
        DBG_PRINT("PsSetCreateProcessNotifyRoutineEx Called From 0x%p", _ReturnAddress());
        DBG_PRINT("     - NotifyRoutine: 0x%p", NotifyRoutine);
        DBG_PRINT("     - Remove: 0x%x", Remove);
        return PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, Remove);
    }

    NTSTATUS gh_IoCreateDevice(
        PDRIVER_OBJECT  DriverObject,
        ULONG           DeviceExtensionSize,
        PUNICODE_STRING DeviceName,
        DEVICE_TYPE     DeviceType,
        ULONG           DeviceCharacteristics,
        BOOLEAN         Exclusive,
        PDEVICE_OBJECT* DeviceObject
    )
    {
        DBG_PRINT("================= BattlEye =================");
        DBG_PRINT("     - BattlEye IRP_MJ_DEVICE_CONTROL: 0x%p", DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]);
        DBG_PRINT("     - BattlEye IRP_MJ_READ: 0x%p", DriverObject->MajorFunction[IRP_MJ_READ]);
        DBG_PRINT("     - BattlEye IRP_MJ_WRITE: 0x%p", DriverObject->MajorFunction[IRP_MJ_WRITE]);

        return IoCreateDevice(
            DriverObject,
            DeviceExtensionSize,
            DeviceName,
            DeviceType,
            DeviceCharacteristics,
            Exclusive,
            DeviceObject
        );
    }

    NTSTATUS gh_PsSetCreateThreadNotifyRoutine(
        PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
    )
    {
        DBG_PRINT("PsSetCreateThreadNotifyRoutine Called From 0x%p", _ReturnAddress());
        DBG_PRINT("     - NotifyRoutine: 0x%p", NotifyRoutine);
        return PsSetCreateThreadNotifyRoutine(NotifyRoutine);
    }

    PHYSICAL_ADDRESS gh_MmGetPhysicalAddress(
        PVOID BaseAddress
    )
    {
        DBG_PRINT("MmGetPhysicalAddress called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - BaseAddress (Virtual Address): 0x%p", BaseAddress);
        return MmGetPhysicalAddress(BaseAddress);
    }

    BOOLEAN gh_MmIsAddressValid(
        PVOID VirtualAddress
    )
    {
        DBG_PRINT("MmIsAddressValid Called From: 0x%p", _ReturnAddress());
        DBG_PRINT("     - NonPaged VirtualAddress: 0x%p", VirtualAddress);
        return MmIsAddressValid(VirtualAddress);
    }

    NTSTATUS gh_ZwDeviceIoControlFile(
        HANDLE           FileHandle,
        HANDLE           Event,
        PIO_APC_ROUTINE  ApcRoutine,
        PVOID            ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG            IoControlCode,
        PVOID            InputBuffer,
        ULONG            InputBufferLength,
        PVOID            OutputBuffer,
        ULONG            OutputBufferLength
    )
    {
        DBG_PRINT("ZwDeviceIoControlFile Called From 0x%p", _ReturnAddress());
        DBG_PRINT("     - FileHandle: 0x%p", FileHandle);
        DBG_PRINT("     - IoControlCode: 0x%p", IoControlCode);
        DBG_PRINT("     - OutputBufferLength: 0x%p", OutputBufferLength);
        DBG_PRINT("     - InoutBufferLength: 0x%p", InputBufferLength);
        const auto result = ZwDeviceIoControlFile(
            FileHandle,
            Event, 
            ApcRoutine, 
            ApcContext,
            IoStatusBlock,
            IoControlCode, 
            InputBuffer, 
            InputBufferLength, 
            OutputBuffer,
            OutputBufferLength
        );
        ULONG seed = 0x1000;
        for (auto idx = 0u; idx < OutputBufferLength; ++idx)
            *(unsigned char*)((unsigned char*)OutputBuffer + idx) = (unsigned char)RtlRandomEx(&seed);
        return result;
    }

    VOID gh_RtlInitAnsiString(
        PANSI_STRING          DestinationString,
        PCSZ SourceString
    )
    {
        DBG_PRINT("RtlInitAnsiString Called From: 0x%p", _ReturnAddress());
        DBG_PRINT("     - SourceString: 0x%s", SourceString);
        return RtlInitAnsiString(DestinationString, SourceString);
    }

    VOID gh_RtlInitUnicodeString(
        PUNICODE_STRING         DestinationString,
        PCWSTR SourceString
    )
    {
        DBG_PRINT("RtlInitUnicodeString Called From: 0x%p", _ReturnAddress());
        DBG_PRINT("     - SourceString: %ws", SourceString);
        return RtlInitUnicodeString(DestinationString, SourceString);
    }

    PVOID gh_MmMapIoSpace(
        PHYSICAL_ADDRESS    PhysicalAddress,
        SIZE_T              NumberOfBytes,
        MEMORY_CACHING_TYPE CacheType
    )
    {
        DBG_PRINT("MmMapIoSpace called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - PhysicalAddress: 0x%p", PhysicalAddress);
        DBG_PRINT("     - NumberOfBytes: 0x%p", NumberOfBytes);

        return MmMapIoSpace(
            PhysicalAddress,
            NumberOfBytes, 
            CacheType
        );
    }

    NTSTATUS gh_ZwOpenFile(
        PHANDLE            FileHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK   IoStatusBlock,
        ULONG              ShareAccess,
        ULONG              OpenOptions
    )
    {
        DBG_PRINT("ZwOpenFile called from: 0x%p", _ReturnAddress());
        if (ObjectAttributes)
            DBG_PRINT("     - ZwOpenFile(%ws)", ObjectAttributes->ObjectName->Buffer);

        const auto result = ZwOpenFile(
            FileHandle,
            DesiredAccess,
            ObjectAttributes,
            IoStatusBlock,
            ShareAccess,
            OpenOptions
        );
        DBG_PRINT("     - ZwOpenFile handle result: 0x%p", *(HANDLE*)FileHandle);
        return result;
    }

    void gh_KeStackAttachProcess(
        PRKPROCESS   PROCESS,
        PRKAPC_STATE ApcState
    )
    {
        DBG_PRINT("KeStackAttachProcess called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - Attaching to %s....", PsGetProcessImageFileName(PROCESS));
        KeStackAttachProcess(PROCESS, ApcState);
    }

    NTSTATUS gh_ZwCreateSection(
        PHANDLE            SectionHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PLARGE_INTEGER     MaximumSize,
        ULONG              SectionPageProtection,
        ULONG              AllocationAttributes,
        HANDLE             FileHandle
    )
    {
        DBG_PRINT("ZwCreateSection called from: 0x%p", _ReturnAddress());
        const auto result = ZwCreateSection(
            SectionHandle, 
            DesiredAccess,
            ObjectAttributes,
            MaximumSize,
            SectionPageProtection,
            AllocationAttributes,
            FileHandle
        );
        DBG_PRINT("     - DesiredAccess: 0x%p", DesiredAccess);
        DBG_PRINT("     - SectionPageProtection: 0x%p", SectionPageProtection);
        DBG_PRINT("     - SectionHandle: 0x%p", *SectionHandle);
        DBG_PRINT("     - FileHandle: 0x%p", FileHandle);
        return result;
    }

    NTSTATUS gh_ObOpenObjectByName(
        __in POBJECT_ATTRIBUTES ObjectAttributes,
        __in_opt POBJECT_TYPE ObjectType,
        __in KPROCESSOR_MODE AccessMode,
        __inout_opt PACCESS_STATE AccessState,
        __in_opt ACCESS_MASK DesiredAccess,
        __inout_opt PVOID ParseContext,
        __out PHANDLE Handle
    )
    {
        DBG_PRINT("ObOpenObjectByName called from: 0x%p", _ReturnAddress());
        const auto result = ObOpenObjectByName(
            ObjectAttributes,
            ObjectType, 
            AccessMode,
            AccessState,
            DesiredAccess, 
            ParseContext,
            Handle
        );
        DBG_PRINT("     - ObjectName: %s", ObjectAttributes->ObjectName->Buffer);
        return result;
    }

    NTSTATUS gh_ZwMapViewOfSection(
        HANDLE          SectionHandle,
        HANDLE          ProcessHandle,
        PVOID*          BaseAddress,
        ULONG_PTR       ZeroBits,
        SIZE_T          CommitSize,
        PLARGE_INTEGER  SectionOffset,
        PSIZE_T         ViewSize,
        SECTION_INHERIT InheritDisposition,
        ULONG           AllocationType,
        ULONG           Win32Protect
    )
    {
        const auto result = ZwMapViewOfSection(
            SectionHandle, 
            ProcessHandle,
            BaseAddress,
            ZeroBits, 
            CommitSize,
            SectionOffset,
            ViewSize, 
            InheritDisposition, 
            AllocationType, 
            Win32Protect
        );

        DBG_PRINT("ZwMapViewOfSection called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - SectionHandle: 0x%p", SectionHandle);
        DBG_PRINT("     - ProcessHandle: 0x%p", ProcessHandle);
        DBG_PRINT("     - ViewSize: 0x%p", *ViewSize);
        DBG_PRINT("     - Win32Protect: 0x%p", Win32Protect);
        return result;
    }

    NTSTATUS gh_MmCopyVirtualMemory
    (
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    )
    {
        DBG_PRINT("MmCopyVirtualMemory called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - SourceProcess: %s", PsGetProcessImageFileName(SourceProcess));
        DBG_PRINT("     - SourceAddress: 0x%p", SourceAddress);
        DBG_PRINT("     - TargetProcess: %s", PsGetProcessImageFileName(TargetProcess));
        DBG_PRINT("     - TargetAddress: 0x%p", TargetAddress);
        DBG_PRINT("     - BufferSize: 0x%p", BufferSize);

        const auto result = MmCopyVirtualMemory(
            SourceProcess, 
            SourceAddress,
            TargetProcess, 
            TargetAddress, 
            BufferSize,
            PreviousMode,
            ReturnSize
        );
        return result;
    }

    void gh_IofCompleteRequest(
        PIRP  Irp,
        CCHAR PriorityBoost
    )
    {
        auto StackLocation = IoGetCurrentIrpStackLocation(Irp);
        DBG_PRINT("IofCompleteRequest called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - Request Called From: %s", PsGetProcessImageFileName(IoGetCurrentProcess()));
        switch (StackLocation->MajorFunction)
        {
        case IRP_MJ_DEVICE_CONTROL:
            DBG_PRINT("     - IRP_MJ_DEVICE_CONTROL!");
            DBG_PRINT("     - IoControlCode:  0x%p", StackLocation->Parameters.DeviceIoControl.IoControlCode);
            DBG_PRINT("     - InputBufferLength: 0x%p", StackLocation->Parameters.DeviceIoControl.InputBufferLength);
            DBG_PRINT("     - OutputBufferLength: 0x%p", StackLocation->Parameters.DeviceIoControl.OutputBufferLength);
            DBG_PRINT("     - UserBuffer: 0x%p", Irp->UserBuffer);
            DBG_PRINT("     - MdlAddress: 0x%p", Irp->MdlAddress);
            DBG_PRINT("     - SystemBuffer: 0x%p", Irp->AssociatedIrp.SystemBuffer);
            break;
        case IRP_MJ_READ:
            DBG_PRINT("     - IRP_MJ_READ!");
            DBG_PRINT("     - ReadSize: 0x%p", StackLocation->Parameters.Read.Length);
            DBG_PRINT("     - UserBuffer: 0x%p", Irp->UserBuffer);
            DBG_PRINT("     - MdlAddress: 0x%p", Irp->MdlAddress);
            DBG_PRINT("     - SystemBuffer: 0x%p", Irp->AssociatedIrp.SystemBuffer);
            break;
        case IRP_MJ_WRITE:
            DBG_PRINT("     - IRP_MJ_WRITE!");
            DBG_PRINT("     - WriteSize: 0x%p", StackLocation->Parameters.Write.Length);
            DBG_PRINT("     - UserBuffer: 0x%p", Irp->UserBuffer);
            DBG_PRINT("     - MdlAddress: 0x%p", Irp->MdlAddress);
            DBG_PRINT("     - SystemBuffer: 0x%p", Irp->AssociatedIrp.SystemBuffer);
            break;
        default:
            DBG_PRINT("Unkown Major Function Type: 0x%p", StackLocation->MajorFunction);
            break;
        }
        IofCompleteRequest(Irp, PriorityBoost);
    }

    int gh_stricmp(
        const char* string1,
        const char* string2
    )
    {
        DBG_PRINT("_stricmp called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - string1: %s", string1);
        DBG_PRINT("     - string2: %s", string2);
        return reinterpret_cast<decltype(&stricmp)>(DriverUtil::GetSystemModuleExport("ntoskrnl.exe", "stricmp"))(string1, string2);
    }

    int gh_strnicmp(
        const char* string1,
        const char* string2,
        size_t count
    )
    {
        DBG_PRINT("_strnicmp called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - string1: %s", string1);
        DBG_PRINT("     - string2: %s", string2);
        DBG_PRINT("     - count: 0x%x", count);
        return reinterpret_cast<decltype(&strnicmp)>(DriverUtil::GetSystemModuleExport("ntoskrnl.exe", "strnicmp"))(string1, string2, count);
    }

    int gh_wcsncmp(const wchar_t* wcs1, const wchar_t* wcs2, size_t num)
    {
        DBG_PRINT("gh_wcsncmp called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - string1: %ws", wcs1);
        DBG_PRINT("     - string2: %ws", wcs2);
        DBG_PRINT("     - count: 0x%x", num);
        return wcsncmp(wcs1, wcs2, num);
    }

    int gh_wcsnicmp(
        const wchar_t* string1,
        const wchar_t* string2,
        size_t count
    )
    {
        DBG_PRINT("gh_wcsnicmp called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - string1: %ws", string1);
        DBG_PRINT("     - string2: %ws", string2);
        DBG_PRINT("     - count: 0x%x", count);
        return wcsncmp(string1, string2, count);
    }

    wchar_t* gh_wcsncat(wchar_t* dest, const wchar_t* src, size_t count)
    {
        DBG_PRINT("wcsncat called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - dest: %ws", dest);
        DBG_PRINT("     - src: %ws", src);
        DBG_PRINT("     - count: 0x%x", count);
        auto result = wcsncat(dest, src, count);
        DBG_PRINT("     - result: %ws", result);
        return result;
    }

    void gh_KeInitializeEvent(
        PRKEVENT   Event,
        EVENT_TYPE Type,
        BOOLEAN    State
    )
    {
        DBG_PRINT("KeInitializeEvent called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - Event: 0x%p", Event);
        DBG_PRINT("     - Type: 0x%x", Type);
        DBG_PRINT("     - State: 0x%x", State);
        KeInitializeEvent(Event, Type, State);
    }

    PVOID gh_ExAllocatePoolWithTag(
        POOL_TYPE   PoolType,
        SIZE_T      NumberOfBytes,
        ULONG       Tag
    )
    {
        auto result = ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);
        DBG_PRINT("ExAllocatePoolWithTag called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - PoolType: 0x%x", PoolType);
        DBG_PRINT("     - NumberOfBytes: 0x%x", NumberOfBytes);
        DBG_PRINT("     - Tag: 0x%x", Tag);
        DBG_PRINT("     - Allocate Pool at: 0x%p", result);
        return result;
    }

    PVOID gh_ExAllocatePool(
        POOL_TYPE PoolType,
        SIZE_T    NumberOfBytes
    )
    {
        auto result = ExAllocatePool(PoolType, NumberOfBytes);
        DBG_PRINT("ExAllocatePool called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - PoolType: 0x%x", PoolType);
        DBG_PRINT("     - NumberOfBytes: 0x%x", NumberOfBytes);
        DBG_PRINT("     - Allocate Pool at: 0x%p", result);
        return result;
    }

    void gh_ExFreePoolWithTag(
        PVOID P,
        ULONG Tag
    )
    {
        DBG_PRINT("ExFreePoolWithTag called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - Freeing pool at: 0x%p", P);
        DBG_PRINT("     - Pool Tag: 0x%x", Tag);
        return ExFreePoolWithTag(P, Tag);
    }

    void gh_ProbeForRead(
        volatile VOID* Address,
        SIZE_T              Length,
        ULONG               Alignment
    )
    {
        DBG_PRINT("ProbeForRead called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - Address: 0x%p", Address);
        DBG_PRINT("     - Length: 0x%x", Length);
        DBG_PRINT("     - Alignment: 0x%x", Alignment);

        __try
        {
            ProbeForRead(Address, Length, Alignment);
        }
        __except (STATUS_ACCESS_VIOLATION | STATUS_DATATYPE_MISALIGNMENT) {}
    }

    void gh_ProbeForWrite(
        volatile VOID* Address,
        SIZE_T        Length,
        ULONG         Alignment
    )
    {
        DBG_PRINT("ProbeForWrite called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - Address: 0x%p", Address);
        DBG_PRINT("     - Length: 0x%x", Length);
        DBG_PRINT("     - Alignment: 0x%x", Alignment);

        __try
        {
            ProbeForWrite(Address, Length, Alignment);
        }
        __except (STATUS_ACCESS_VIOLATION | STATUS_DATATYPE_MISALIGNMENT) {}
    }

    NTSTATUS gh_PsCreateSystemThread(
        PHANDLE            ThreadHandle,
        ULONG              DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE             ProcessHandle,
        PCLIENT_ID         ClientId,
        PKSTART_ROUTINE    StartRoutine,
        PVOID              StartContext
    )
    {
        DBG_PRINT("PsCreateSystemThread called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - StartRoutine: 0x%p", StartRoutine);
        DBG_PRINT("     - StartContext: 0x%p", StartContext);
        DBG_PRINT("     - ProcessHandle: 0x%p", ProcessHandle);
        DBG_PRINT("     - ClientId Pointer: 0x%p", ClientId);
        if (ClientId)
        {
            DBG_PRINT("     - ClientId->ProcessId: 0x%x", ClientId->UniqueProcess);
            DBG_PRINT("     - ClientId->ThreadId: 0x%x", ClientId->UniqueThread);
        }
        auto result = PsCreateSystemThread(
            ThreadHandle,
            DesiredAccess,
            ObjectAttributes,
            ProcessHandle, 
            ClientId, 
            StartRoutine,
            StartContext
        );
        DBG_PRINT("     - Thread Handle: 0x%x", *ThreadHandle);
        return result;
    }

    PMDL gh_IoAllocateMdl(
        __drv_aliasesMem PVOID VirtualAddress,
        ULONG                  Length,
        BOOLEAN                SecondaryBuffer,
        BOOLEAN                ChargeQuota,
        PIRP                   Irp
    )
    {
        DBG_PRINT("IoAllocateMdl called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - VirtualAddress: 0x%p", VirtualAddress);
        DBG_PRINT("     - Length: 0x%x", Length);
        DBG_PRINT("     - Irp: 0x%p", Irp);
        return IoAllocateMdl(
            VirtualAddress,
            Length, 
            SecondaryBuffer,
            ChargeQuota,
            Irp
        );
    }

    NTSTATUS gh_ObReferenceObjectByName(
            __in PUNICODE_STRING ObjectName,
            __in ULONG Attributes,
            __in_opt PACCESS_STATE AccessState,
            __in_opt ACCESS_MASK DesiredAccess,
            __in POBJECT_TYPE ObjectType,
            __in KPROCESSOR_MODE AccessMode,
            __inout_opt PVOID ParseContext,
            __out PVOID* Object
        )
    {
        DBG_PRINT("ObReferenceObjectByName called from: 0x%p", _ReturnAddress());
        if(ObjectName)
            DBG_PRINT("     - ObjectName: %ws", ObjectName->Buffer);

        return ObReferenceObjectByName(
            ObjectName, 
            Attributes,
            AccessState,
            DesiredAccess,
            ObjectType, 
            AccessMode,
            ParseContext, 
            Object
        );
    }

    NTSTATUS gh_MmCopyMemory(
        PVOID           TargetAddress,
        MM_COPY_ADDRESS SourceAddress,
        SIZE_T          NumberOfBytes,
        ULONG           Flags,
        PSIZE_T         NumberOfBytesTransferred
    )
    {
        DBG_PRINT("MmCopyMemory called from: 0x%p", _ReturnAddress());
        DBG_PRINT("     - TargetAddress: 0x%p", TargetAddress);
        DBG_PRINT("     - SourceAddress: 0x%p", SourceAddress);
        DBG_PRINT("     - Size: 0x%x", NumberOfBytes);
        DBG_PRINT("     - Flags: 0x%x", Flags);

        return MmCopyMemory(
            TargetAddress, 
            SourceAddress,
            NumberOfBytes,
            Flags, 
            NumberOfBytesTransferred
        );
    }

    ULONG gh_RtlWalkFrameChain(
        __out PVOID* Callers,
        __in ULONG 	Count,
        __in ULONG 	Flags
    )
    {
        return NULL;
    }

    PVOID gh_MmGetSystemRoutineAddress(
        PUNICODE_STRING SystemRoutineName
    )
    {
        DBG_PRINT("MmGetSystemRoutineAddress: %ws", SystemRoutineName->Buffer);
        if (wcsstr(SystemRoutineName->Buffer, L"ZwAllocateVirtualMemory"))
        {
            DBG_PRINT("Hooking ZwAllocateVirtualMemory");
            return &gh_ZwAllocateVirtualMemory;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"RtlInitUnicodeString"))
        {
            DBG_PRINT("Hooking RtlInitUnicodeString...");
            return &gh_RtlInitUnicodeString;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"RtlInitAnsiString"))
        {
            DBG_PRINT("Hooking RtlInitAnsiString...");
            return &gh_RtlInitAnsiString;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"MmIsAddressValid"))
        {
            DBG_PRINT("Hooking MmIsAddressValid...");
            return &gh_MmIsAddressValid;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"IoCreateDevice"))
        {
            DBG_PRINT("Hooking IoCreateDevice...");
            return &gh_IoCreateDevice;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"PsSetCreateProcessNotifyRoutineEx"))
        {
            DBG_PRINT("Hooking PsSetCreateProcessNotifyRoutineEx...");
            return &gh_PsSetCreateProcessNotifyRoutineEx;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ObRegisterCallbacks"))
        {
            DBG_PRINT("Hooking ObRegisterCallbacks...");
            return &gh_ObRegisterCallbacks;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"PsSetLoadImageNotifyRoutine"))
        {
            DBG_PRINT("Hooking PsSetLoadImageNotifyRoutine...");
            return &gh_PsSetLoadImageNotifyRoutine;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ExEnumHandleTable"))
        {
            //DBG_PRINT("Hooking ExEnumHandleTable...");
            //return &gh_ExEnumHandleTable;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"MmGetPhysicalAddress"))
        {
            DBG_PRINT("Hooking MmGetPhysicalAddress...");
            return &gh_MmGetPhysicalAddress;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"MmMapIoSpace"))
        {
            DBG_PRINT("Hooking MmMapIoSpace...");
            return &gh_MmMapIoSpace;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ZwOpenFile"))
        {
            DBG_PRINT("Hooking ZwOpenFile...");
            return &gh_ZwOpenFile;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"DeviceIoControlFile")) // Nt or Zw
        {
            DBG_PRINT("Hooking %ws....", SystemRoutineName->Buffer);
            return &gh_ZwDeviceIoControlFile;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"KeStackAttachProcess"))
        {
            DBG_PRINT("Hooking KeStackAttachProcess....");
            return &gh_KeStackAttachProcess;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ZwMapViewOfSection"))
        {
            DBG_PRINT("Hooking ZwMapViewOfSection....");
            return &gh_ZwMapViewOfSection;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ObOpenObjectByName"))
        {
            DBG_PRINT("Hooking ObOpenObjectByName....");
            return &gh_ObOpenObjectByName;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ZwCreateSection"))
        {
            DBG_PRINT("Hooking ZwCreateSection....");
            return &gh_ZwCreateSection;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"MmCopyVirtualMemory"))
        {
            DBG_PRINT("Hooking MmCopyVirtualMemory....");
            return &gh_MmCopyVirtualMemory;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"IofCompleteRequest"))
        {
            DBG_PRINT("Hooking IofCompleteRequest...");
            return &gh_IofCompleteRequest;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"QuerySystemInformation"))
        {
            DBG_PRINT("Hooking QuerySystemInformation...");
            return &gh_ZwQuerySystemInformation;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"stricmp"))
        {
            //DBG_PRINT("Hooking stricmp...");
            //return &gh_stricmp;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"strnicmp"))
        {
            //DBG_PRINT("Hooking strnicmp...");
            //return &gh_strnicmp;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"wcsncmp"))
        {
            DBG_PRINT("Hooking wcsncmp...");
            return &gh_wcsncmp;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"wcsnicmp"))
        {
            DBG_PRINT("Hooking wcsnicmp...");
            return &gh_wcsnicmp;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"wcsncat"))
        {
            DBG_PRINT("Hooking wcsncat...");
            return &gh_wcsncat;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"KeInitializeEvent"))
        {
            DBG_PRINT("Hooking KeInitializeEvent...");
            return &gh_KeInitializeEvent;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ExAllocatePoolWithTag"))
        {
            DBG_PRINT("Hooking ExAllocatePoolWithTag...");
            return &gh_ExAllocatePoolWithTag;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ExAllocatePool"))
        {
            DBG_PRINT("Hooking ExAllocatePool...");
            return &gh_ExAllocatePool;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ExFreePoolWithTag"))
        {
            DBG_PRINT("Hooking ExFreePoolWithTag...");
            return &gh_ExFreePoolWithTag;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ProbeForWrite"))
        {
            DBG_PRINT("Hooking ProbeForWrite...");
            return &gh_ProbeForWrite;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ProbeForRead"))
        {
            DBG_PRINT("Hooking ProbeForRead...");
            return &gh_ProbeForRead;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"PsCreateSystemThread"))
        {
            DBG_PRINT("Hooking PsCreateSystemThread...");
            return &gh_PsCreateSystemThread;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"ObReferenceObjectByName"))
        {
            DBG_PRINT("Hooking ObReferenceObjectByName...");
            return &gh_ObReferenceObjectByName;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"MmCopyMemory"))
        {
            DBG_PRINT("Hooking MmCopyMemory...");
            return &gh_MmCopyMemory;
        }
        else if (wcsstr(SystemRoutineName->Buffer, L"RtlWalkFrameChain"))
        {
            DBG_PRINT("Hooking RtlWalkFrameChain...");
            return &gh_RtlWalkFrameChain;
        }
        return MmGetSystemRoutineAddress(SystemRoutineName);
    }

    PVOID gh_FltGetRoutineAddress(
        PCSTR FltMgrRoutineName
    )
    {
        DBG_PRINT("FltGetRoutineAddress: %s", FltMgrRoutineName);
        return FltGetRoutineAddress(FltMgrRoutineName);
    }

    VOID gh_KeBugCheckEx(
        ULONG     BugCheckCode,
        ULONG_PTR BugCheckParameter1,
        ULONG_PTR BugCheckParameter2,
        ULONG_PTR BugCheckParameter3,
        ULONG_PTR BugCheckParameter4
    )
    { DBG_PRINT("KeBugCheckEx Called!"); }

    VOID LoadImageNotifyRoutine(
        PUNICODE_STRING FullImageName,
        HANDLE ProcessId,
        PIMAGE_INFO ImageInfo
    )
    {
        if (!ProcessId && FullImageName && wcsstr(FullImageName->Buffer, L"BEDaisy.sys"))
        {
            DBG_PRINT("> ============= Driver %ws ================", FullImageName->Buffer);
            DriverUtil::IATHook(
                ImageInfo->ImageBase,
                "KeBugCheckEx",
                &gh_KeBugCheckEx
            );

            DriverUtil::IATHook(
                ImageInfo->ImageBase,
                "MmGetSystemRoutineAddress",
                &gh_MmGetSystemRoutineAddress
            );

            DriverUtil::IATHook(
                ImageInfo->ImageBase,
                "FltGetRoutineAddress",
                &gh_FltGetRoutineAddress
            );
        }
    }
}