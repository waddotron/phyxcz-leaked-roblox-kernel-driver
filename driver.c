#include <ntifs.h>
#include <ntddk.h>

// --- IOCTL CODES ---
#define IOCTL_READ_MEM  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_WRITE_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_BASE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// --- STRUCTS ---
typedef struct _KERNEL_REQUEST {
    ULONG ProcessId;
    ULONGLONG Address;
    ULONGLONG Buffer;
    SIZE_T Size;
} KERNEL_REQUEST, *PKERNEL_REQUEST;

typedef struct _KERNEL_BASE_REQUEST {
    ULONG ProcessId;
    ULONGLONG BaseAddress;
} KERNEL_BASE_REQUEST, *PKERNEL_BASE_REQUEST;

PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, dos;

// --- MEMORY ROUTINES ---
NTSTATUS ReadVirtualMemory(PEPROCESS Process, PVOID SourceAddr, PVOID TargetAddr, SIZE_T Size) {
    SIZE_T Bytes;
    return MmCopyVirtualMemory(Process, SourceAddr, PsGetCurrentProcess(), TargetAddr, Size, KernelMode, &Bytes);
}

NTSTATUS WriteVirtualMemory(PEPROCESS Process, PVOID SourceAddr, PVOID TargetAddr, SIZE_T Size) {
    SIZE_T Bytes;
    // might require MDL mapping or CR0 modification.
    // For Bytecode, MmCopyVirtualMemory usually works if the page is writable
    return MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddr, Process, TargetAddr, Size, KernelMode, &Bytes);
}

// --- DISPATCHER ---
NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesIO = 0;

    if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_READ_MEM) {
            PKERNEL_REQUEST req = (PKERNEL_REQUEST)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS TargetProcess;
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)req->ProcessId, &TargetProcess))) {
                ReadVirtualMemory(TargetProcess, (PVOID)req->Address, (PVOID)req->Buffer, req->Size);
                ObDereferenceObject(TargetProcess);
                bytesIO = sizeof(KERNEL_REQUEST);
            }
        }
        else if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_WRITE_MEM) {
            PKERNEL_REQUEST req = (PKERNEL_REQUEST)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS TargetProcess;
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)req->ProcessId, &TargetProcess))) {
                WriteVirtualMemory(TargetProcess, (PVOID)req->Buffer, (PVOID)req->Address, req->Size);
                ObDereferenceObject(TargetProcess);
                bytesIO = sizeof(KERNEL_REQUEST);
            }
        }
        else if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_GET_BASE) {
            PKERNEL_BASE_REQUEST req = (PKERNEL_BASE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
            PEPROCESS TargetProcess;
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)req->ProcessId, &TargetProcess))) {
                req->BaseAddress = (ULONGLONG)PsGetProcessSectionBaseAddress(TargetProcess);
                ObDereferenceObject(TargetProcess);
                bytesIO = sizeof(KERNEL_BASE_REQUEST);
            }
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesIO;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// --- ENTRY POINT ---
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
    RtlInitUnicodeString(&dev, L"\\Device\\vylaraDriver");
    RtlInitUnicodeString(&dos, L"\\DosDevices\\vylaraDriver");
    IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
    IoCreateSymbolicLink(&dos, &dev);
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = DriverDispatch;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE]  = DriverDispatch;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
    return STATUS_SUCCESS;
}
