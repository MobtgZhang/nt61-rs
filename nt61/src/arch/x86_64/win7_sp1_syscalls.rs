//! Windows 7 SP1 (6.1.7601) x64 system-call index.
//!
//! Generated from the j00ru windows-syscalls x64 CSV. The native table is
//! the NTOSKRNL/NTDLL service table; the win32k table is the win32k.sys GUI
//! service table.

/// One entry in a Windows 7 x64 service table.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SyscallIndexEntry {
    pub number: u16,
    pub name: &'static str,
}

/// Windows 7 SP1 x64 native syscall table.
pub const NATIVE_SYSCALLS: [SyscallIndexEntry; 401] = [
    SyscallIndexEntry {
        number: 0x0000,
        name: "NtMapUserPhysicalPagesScatter",
    },
    SyscallIndexEntry {
        number: 0x0001,
        name: "NtWaitForSingleObject",
    },
    SyscallIndexEntry {
        number: 0x0002,
        name: "NtCallbackReturn",
    },
    SyscallIndexEntry {
        number: 0x0003,
        name: "NtReadFile",
    },
    SyscallIndexEntry {
        number: 0x0004,
        name: "NtDeviceIoControlFile",
    },
    SyscallIndexEntry {
        number: 0x0005,
        name: "NtWriteFile",
    },
    SyscallIndexEntry {
        number: 0x0006,
        name: "NtRemoveIoCompletion",
    },
    SyscallIndexEntry {
        number: 0x0007,
        name: "NtReleaseSemaphore",
    },
    SyscallIndexEntry {
        number: 0x0008,
        name: "NtReplyWaitReceivePort",
    },
    SyscallIndexEntry {
        number: 0x0009,
        name: "NtReplyPort",
    },
    SyscallIndexEntry {
        number: 0x000A,
        name: "NtSetInformationThread",
    },
    SyscallIndexEntry {
        number: 0x000B,
        name: "NtSetEvent",
    },
    SyscallIndexEntry {
        number: 0x000C,
        name: "NtClose",
    },
    SyscallIndexEntry {
        number: 0x000D,
        name: "NtQueryObject",
    },
    SyscallIndexEntry {
        number: 0x000E,
        name: "NtQueryInformationFile",
    },
    SyscallIndexEntry {
        number: 0x000F,
        name: "NtOpenKey",
    },
    SyscallIndexEntry {
        number: 0x0010,
        name: "NtEnumerateValueKey",
    },
    SyscallIndexEntry {
        number: 0x0011,
        name: "NtFindAtom",
    },
    SyscallIndexEntry {
        number: 0x0012,
        name: "NtQueryDefaultLocale",
    },
    SyscallIndexEntry {
        number: 0x0013,
        name: "NtQueryKey",
    },
    SyscallIndexEntry {
        number: 0x0014,
        name: "NtQueryValueKey",
    },
    SyscallIndexEntry {
        number: 0x0015,
        name: "NtAllocateVirtualMemory",
    },
    SyscallIndexEntry {
        number: 0x0016,
        name: "NtQueryInformationProcess",
    },
    SyscallIndexEntry {
        number: 0x0017,
        name: "NtWaitForMultipleObjects32",
    },
    SyscallIndexEntry {
        number: 0x0018,
        name: "NtWriteFileGather",
    },
    SyscallIndexEntry {
        number: 0x0019,
        name: "NtSetInformationProcess",
    },
    SyscallIndexEntry {
        number: 0x001A,
        name: "NtCreateKey",
    },
    SyscallIndexEntry {
        number: 0x001B,
        name: "NtFreeVirtualMemory",
    },
    SyscallIndexEntry {
        number: 0x001C,
        name: "NtImpersonateClientOfPort",
    },
    SyscallIndexEntry {
        number: 0x001D,
        name: "NtReleaseMutant",
    },
    SyscallIndexEntry {
        number: 0x001E,
        name: "NtQueryInformationToken",
    },
    SyscallIndexEntry {
        number: 0x001F,
        name: "NtRequestWaitReplyPort",
    },
    SyscallIndexEntry {
        number: 0x0020,
        name: "NtQueryVirtualMemory",
    },
    SyscallIndexEntry {
        number: 0x0021,
        name: "NtOpenThreadToken",
    },
    SyscallIndexEntry {
        number: 0x0022,
        name: "NtQueryInformationThread",
    },
    SyscallIndexEntry {
        number: 0x0023,
        name: "NtOpenProcess",
    },
    SyscallIndexEntry {
        number: 0x0024,
        name: "NtSetInformationFile",
    },
    SyscallIndexEntry {
        number: 0x0025,
        name: "NtMapViewOfSection",
    },
    SyscallIndexEntry {
        number: 0x0026,
        name: "NtAccessCheckAndAuditAlarm",
    },
    SyscallIndexEntry {
        number: 0x0027,
        name: "NtUnmapViewOfSection",
    },
    SyscallIndexEntry {
        number: 0x0028,
        name: "NtReplyWaitReceivePortEx",
    },
    SyscallIndexEntry {
        number: 0x0029,
        name: "NtTerminateProcess",
    },
    SyscallIndexEntry {
        number: 0x002A,
        name: "NtSetEventBoostPriority",
    },
    SyscallIndexEntry {
        number: 0x002B,
        name: "NtReadFileScatter",
    },
    SyscallIndexEntry {
        number: 0x002C,
        name: "NtOpenThreadTokenEx",
    },
    SyscallIndexEntry {
        number: 0x002D,
        name: "NtOpenProcessTokenEx",
    },
    SyscallIndexEntry {
        number: 0x002E,
        name: "NtQueryPerformanceCounter",
    },
    SyscallIndexEntry {
        number: 0x002F,
        name: "NtEnumerateKey",
    },
    SyscallIndexEntry {
        number: 0x0030,
        name: "NtOpenFile",
    },
    SyscallIndexEntry {
        number: 0x0031,
        name: "NtDelayExecution",
    },
    SyscallIndexEntry {
        number: 0x0032,
        name: "NtQueryDirectoryFile",
    },
    SyscallIndexEntry {
        number: 0x0033,
        name: "NtQuerySystemInformation",
    },
    SyscallIndexEntry {
        number: 0x0034,
        name: "NtOpenSection",
    },
    SyscallIndexEntry {
        number: 0x0035,
        name: "NtQueryTimer",
    },
    SyscallIndexEntry {
        number: 0x0036,
        name: "NtFsControlFile",
    },
    SyscallIndexEntry {
        number: 0x0037,
        name: "NtWriteVirtualMemory",
    },
    SyscallIndexEntry {
        number: 0x0038,
        name: "NtCloseObjectAuditAlarm",
    },
    SyscallIndexEntry {
        number: 0x0039,
        name: "NtDuplicateObject",
    },
    SyscallIndexEntry {
        number: 0x003A,
        name: "NtQueryAttributesFile",
    },
    SyscallIndexEntry {
        number: 0x003B,
        name: "NtClearEvent",
    },
    SyscallIndexEntry {
        number: 0x003C,
        name: "NtReadVirtualMemory",
    },
    SyscallIndexEntry {
        number: 0x003D,
        name: "NtOpenEvent",
    },
    SyscallIndexEntry {
        number: 0x003E,
        name: "NtAdjustPrivilegesToken",
    },
    SyscallIndexEntry {
        number: 0x003F,
        name: "NtDuplicateToken",
    },
    SyscallIndexEntry {
        number: 0x0040,
        name: "NtContinue",
    },
    SyscallIndexEntry {
        number: 0x0041,
        name: "NtQueryDefaultUILanguage",
    },
    SyscallIndexEntry {
        number: 0x0042,
        name: "NtQueueApcThread",
    },
    SyscallIndexEntry {
        number: 0x0043,
        name: "NtYieldExecution",
    },
    SyscallIndexEntry {
        number: 0x0044,
        name: "NtAddAtom",
    },
    SyscallIndexEntry {
        number: 0x0045,
        name: "NtCreateEvent",
    },
    SyscallIndexEntry {
        number: 0x0046,
        name: "NtQueryVolumeInformationFile",
    },
    SyscallIndexEntry {
        number: 0x0047,
        name: "NtCreateSection",
    },
    SyscallIndexEntry {
        number: 0x0048,
        name: "NtFlushBuffersFile",
    },
    SyscallIndexEntry {
        number: 0x0049,
        name: "NtApphelpCacheControl",
    },
    SyscallIndexEntry {
        number: 0x004A,
        name: "NtCreateProcessEx",
    },
    SyscallIndexEntry {
        number: 0x004B,
        name: "NtCreateThread",
    },
    SyscallIndexEntry {
        number: 0x004C,
        name: "NtIsProcessInJob",
    },
    SyscallIndexEntry {
        number: 0x004D,
        name: "NtProtectVirtualMemory",
    },
    SyscallIndexEntry {
        number: 0x004E,
        name: "NtQuerySection",
    },
    SyscallIndexEntry {
        number: 0x004F,
        name: "NtResumeThread",
    },
    SyscallIndexEntry {
        number: 0x0050,
        name: "NtTerminateThread",
    },
    SyscallIndexEntry {
        number: 0x0051,
        name: "NtReadRequestData",
    },
    SyscallIndexEntry {
        number: 0x0052,
        name: "NtCreateFile",
    },
    SyscallIndexEntry {
        number: 0x0053,
        name: "NtQueryEvent",
    },
    SyscallIndexEntry {
        number: 0x0054,
        name: "NtWriteRequestData",
    },
    SyscallIndexEntry {
        number: 0x0055,
        name: "NtOpenDirectoryObject",
    },
    SyscallIndexEntry {
        number: 0x0056,
        name: "NtAccessCheckByTypeAndAuditAlarm",
    },
    SyscallIndexEntry {
        number: 0x0057,
        name: "NtQuerySystemTime",
    },
    SyscallIndexEntry {
        number: 0x0058,
        name: "NtWaitForMultipleObjects",
    },
    SyscallIndexEntry {
        number: 0x0059,
        name: "NtSetInformationObject",
    },
    SyscallIndexEntry {
        number: 0x005A,
        name: "NtCancelIoFile",
    },
    SyscallIndexEntry {
        number: 0x005B,
        name: "NtTraceEvent",
    },
    SyscallIndexEntry {
        number: 0x005C,
        name: "NtPowerInformation",
    },
    SyscallIndexEntry {
        number: 0x005D,
        name: "NtSetValueKey",
    },
    SyscallIndexEntry {
        number: 0x005E,
        name: "NtCancelTimer",
    },
    SyscallIndexEntry {
        number: 0x005F,
        name: "NtSetTimer",
    },
    SyscallIndexEntry {
        number: 0x0060,
        name: "NtAcceptConnectPort",
    },
    SyscallIndexEntry {
        number: 0x0061,
        name: "NtAccessCheck",
    },
    SyscallIndexEntry {
        number: 0x0062,
        name: "NtAccessCheckByType",
    },
    SyscallIndexEntry {
        number: 0x0063,
        name: "NtAccessCheckByTypeResultList",
    },
    SyscallIndexEntry {
        number: 0x0064,
        name: "NtAccessCheckByTypeResultListAndAuditAlarm",
    },
    SyscallIndexEntry {
        number: 0x0065,
        name: "NtAccessCheckByTypeResultListAndAuditAlarmByHandle",
    },
    SyscallIndexEntry {
        number: 0x0066,
        name: "NtAddBootEntry",
    },
    SyscallIndexEntry {
        number: 0x0067,
        name: "NtAddDriverEntry",
    },
    SyscallIndexEntry {
        number: 0x0068,
        name: "NtAdjustGroupsToken",
    },
    SyscallIndexEntry {
        number: 0x0069,
        name: "NtAlertResumeThread",
    },
    SyscallIndexEntry {
        number: 0x006A,
        name: "NtAlertThread",
    },
    SyscallIndexEntry {
        number: 0x006B,
        name: "NtAllocateLocallyUniqueId",
    },
    SyscallIndexEntry {
        number: 0x006C,
        name: "NtAllocateReserveObject",
    },
    SyscallIndexEntry {
        number: 0x006D,
        name: "NtAllocateUserPhysicalPages",
    },
    SyscallIndexEntry {
        number: 0x006E,
        name: "NtAllocateUuids",
    },
    SyscallIndexEntry {
        number: 0x006F,
        name: "NtAlpcAcceptConnectPort",
    },
    SyscallIndexEntry {
        number: 0x0070,
        name: "NtAlpcCancelMessage",
    },
    SyscallIndexEntry {
        number: 0x0071,
        name: "NtAlpcConnectPort",
    },
    SyscallIndexEntry {
        number: 0x0072,
        name: "NtAlpcCreatePort",
    },
    SyscallIndexEntry {
        number: 0x0073,
        name: "NtAlpcCreatePortSection",
    },
    SyscallIndexEntry {
        number: 0x0074,
        name: "NtAlpcCreateResourceReserve",
    },
    SyscallIndexEntry {
        number: 0x0075,
        name: "NtAlpcCreateSectionView",
    },
    SyscallIndexEntry {
        number: 0x0076,
        name: "NtAlpcCreateSecurityContext",
    },
    SyscallIndexEntry {
        number: 0x0077,
        name: "NtAlpcDeletePortSection",
    },
    SyscallIndexEntry {
        number: 0x0078,
        name: "NtAlpcDeleteResourceReserve",
    },
    SyscallIndexEntry {
        number: 0x0079,
        name: "NtAlpcDeleteSectionView",
    },
    SyscallIndexEntry {
        number: 0x007A,
        name: "NtAlpcDeleteSecurityContext",
    },
    SyscallIndexEntry {
        number: 0x007B,
        name: "NtAlpcDisconnectPort",
    },
    SyscallIndexEntry {
        number: 0x007C,
        name: "NtAlpcImpersonateClientOfPort",
    },
    SyscallIndexEntry {
        number: 0x007D,
        name: "NtAlpcOpenSenderProcess",
    },
    SyscallIndexEntry {
        number: 0x007E,
        name: "NtAlpcOpenSenderThread",
    },
    SyscallIndexEntry {
        number: 0x007F,
        name: "NtAlpcQueryInformation",
    },
    SyscallIndexEntry {
        number: 0x0080,
        name: "NtAlpcQueryInformationMessage",
    },
    SyscallIndexEntry {
        number: 0x0081,
        name: "NtAlpcRevokeSecurityContext",
    },
    SyscallIndexEntry {
        number: 0x0082,
        name: "NtAlpcSendWaitReceivePort",
    },
    SyscallIndexEntry {
        number: 0x0083,
        name: "NtAlpcSetInformation",
    },
    SyscallIndexEntry {
        number: 0x0084,
        name: "NtAreMappedFilesTheSame",
    },
    SyscallIndexEntry {
        number: 0x0085,
        name: "NtAssignProcessToJobObject",
    },
    SyscallIndexEntry {
        number: 0x0086,
        name: "NtCancelIoFileEx",
    },
    SyscallIndexEntry {
        number: 0x0087,
        name: "NtCancelSynchronousIoFile",
    },
    SyscallIndexEntry {
        number: 0x0088,
        name: "NtCommitComplete",
    },
    SyscallIndexEntry {
        number: 0x0089,
        name: "NtCommitEnlistment",
    },
    SyscallIndexEntry {
        number: 0x008A,
        name: "NtCommitTransaction",
    },
    SyscallIndexEntry {
        number: 0x008B,
        name: "NtCompactKeys",
    },
    SyscallIndexEntry {
        number: 0x008C,
        name: "NtCompareTokens",
    },
    SyscallIndexEntry {
        number: 0x008D,
        name: "NtCompleteConnectPort",
    },
    SyscallIndexEntry {
        number: 0x008E,
        name: "NtCompressKey",
    },
    SyscallIndexEntry {
        number: 0x008F,
        name: "NtConnectPort",
    },
    SyscallIndexEntry {
        number: 0x0090,
        name: "NtCreateDebugObject",
    },
    SyscallIndexEntry {
        number: 0x0091,
        name: "NtCreateDirectoryObject",
    },
    SyscallIndexEntry {
        number: 0x0092,
        name: "NtCreateEnlistment",
    },
    SyscallIndexEntry {
        number: 0x0093,
        name: "NtCreateEventPair",
    },
    SyscallIndexEntry {
        number: 0x0094,
        name: "NtCreateIoCompletion",
    },
    SyscallIndexEntry {
        number: 0x0095,
        name: "NtCreateJobObject",
    },
    SyscallIndexEntry {
        number: 0x0096,
        name: "NtCreateJobSet",
    },
    SyscallIndexEntry {
        number: 0x0097,
        name: "NtCreateKeyTransacted",
    },
    SyscallIndexEntry {
        number: 0x0098,
        name: "NtCreateKeyedEvent",
    },
    SyscallIndexEntry {
        number: 0x0099,
        name: "NtCreateMailslotFile",
    },
    SyscallIndexEntry {
        number: 0x009A,
        name: "NtCreateMutant",
    },
    SyscallIndexEntry {
        number: 0x009B,
        name: "NtCreateNamedPipeFile",
    },
    SyscallIndexEntry {
        number: 0x009C,
        name: "NtCreatePagingFile",
    },
    SyscallIndexEntry {
        number: 0x009D,
        name: "NtCreatePort",
    },
    SyscallIndexEntry {
        number: 0x009E,
        name: "NtCreatePrivateNamespace",
    },
    SyscallIndexEntry {
        number: 0x009F,
        name: "NtCreateProcess",
    },
    SyscallIndexEntry {
        number: 0x00A0,
        name: "NtCreateProfile",
    },
    SyscallIndexEntry {
        number: 0x00A1,
        name: "NtCreateProfileEx",
    },
    SyscallIndexEntry {
        number: 0x00A2,
        name: "NtCreateResourceManager",
    },
    SyscallIndexEntry {
        number: 0x00A3,
        name: "NtCreateSemaphore",
    },
    SyscallIndexEntry {
        number: 0x00A4,
        name: "NtCreateSymbolicLinkObject",
    },
    SyscallIndexEntry {
        number: 0x00A5,
        name: "NtCreateThreadEx",
    },
    SyscallIndexEntry {
        number: 0x00A6,
        name: "NtCreateTimer",
    },
    SyscallIndexEntry {
        number: 0x00A7,
        name: "NtCreateToken",
    },
    SyscallIndexEntry {
        number: 0x00A8,
        name: "NtCreateTransaction",
    },
    SyscallIndexEntry {
        number: 0x00A9,
        name: "NtCreateTransactionManager",
    },
    SyscallIndexEntry {
        number: 0x00AA,
        name: "NtCreateUserProcess",
    },
    SyscallIndexEntry {
        number: 0x00AB,
        name: "NtCreateWaitablePort",
    },
    SyscallIndexEntry {
        number: 0x00AC,
        name: "NtCreateWorkerFactory",
    },
    SyscallIndexEntry {
        number: 0x00AD,
        name: "NtDebugActiveProcess",
    },
    SyscallIndexEntry {
        number: 0x00AE,
        name: "NtDebugContinue",
    },
    SyscallIndexEntry {
        number: 0x00AF,
        name: "NtDeleteAtom",
    },
    SyscallIndexEntry {
        number: 0x00B0,
        name: "NtDeleteBootEntry",
    },
    SyscallIndexEntry {
        number: 0x00B1,
        name: "NtDeleteDriverEntry",
    },
    SyscallIndexEntry {
        number: 0x00B2,
        name: "NtDeleteFile",
    },
    SyscallIndexEntry {
        number: 0x00B3,
        name: "NtDeleteKey",
    },
    SyscallIndexEntry {
        number: 0x00B4,
        name: "NtDeleteObjectAuditAlarm",
    },
    SyscallIndexEntry {
        number: 0x00B5,
        name: "NtDeletePrivateNamespace",
    },
    SyscallIndexEntry {
        number: 0x00B6,
        name: "NtDeleteValueKey",
    },
    SyscallIndexEntry {
        number: 0x00B7,
        name: "NtDisableLastKnownGood",
    },
    SyscallIndexEntry {
        number: 0x00B8,
        name: "NtDisplayString",
    },
    SyscallIndexEntry {
        number: 0x00B9,
        name: "NtDrawText",
    },
    SyscallIndexEntry {
        number: 0x00BA,
        name: "NtEnableLastKnownGood",
    },
    SyscallIndexEntry {
        number: 0x00BB,
        name: "NtEnumerateBootEntries",
    },
    SyscallIndexEntry {
        number: 0x00BC,
        name: "NtEnumerateDriverEntries",
    },
    SyscallIndexEntry {
        number: 0x00BD,
        name: "NtEnumerateSystemEnvironmentValuesEx",
    },
    SyscallIndexEntry {
        number: 0x00BE,
        name: "NtEnumerateTransactionObject",
    },
    SyscallIndexEntry {
        number: 0x00BF,
        name: "NtExtendSection",
    },
    SyscallIndexEntry {
        number: 0x00C0,
        name: "NtFilterToken",
    },
    SyscallIndexEntry {
        number: 0x00C1,
        name: "NtFlushInstallUILanguage",
    },
    SyscallIndexEntry {
        number: 0x00C2,
        name: "NtFlushInstructionCache",
    },
    SyscallIndexEntry {
        number: 0x00C3,
        name: "NtFlushKey",
    },
    SyscallIndexEntry {
        number: 0x00C4,
        name: "NtFlushProcessWriteBuffers",
    },
    SyscallIndexEntry {
        number: 0x00C5,
        name: "NtFlushVirtualMemory",
    },
    SyscallIndexEntry {
        number: 0x00C6,
        name: "NtFlushWriteBuffer",
    },
    SyscallIndexEntry {
        number: 0x00C7,
        name: "NtFreeUserPhysicalPages",
    },
    SyscallIndexEntry {
        number: 0x00C8,
        name: "NtFreezeRegistry",
    },
    SyscallIndexEntry {
        number: 0x00C9,
        name: "NtFreezeTransactions",
    },
    SyscallIndexEntry {
        number: 0x00CA,
        name: "NtGetContextThread",
    },
    SyscallIndexEntry {
        number: 0x00CB,
        name: "NtGetCurrentProcessorNumber",
    },
    SyscallIndexEntry {
        number: 0x00CC,
        name: "NtGetDevicePowerState",
    },
    SyscallIndexEntry {
        number: 0x00CD,
        name: "NtGetMUIRegistryInfo",
    },
    SyscallIndexEntry {
        number: 0x00CE,
        name: "NtGetNextProcess",
    },
    SyscallIndexEntry {
        number: 0x00CF,
        name: "NtGetNextThread",
    },
    SyscallIndexEntry {
        number: 0x00D0,
        name: "NtGetNlsSectionPtr",
    },
    SyscallIndexEntry {
        number: 0x00D1,
        name: "NtGetNotificationResourceManager",
    },
    SyscallIndexEntry {
        number: 0x00D2,
        name: "NtGetPlugPlayEvent",
    },
    SyscallIndexEntry {
        number: 0x00D3,
        name: "NtGetWriteWatch",
    },
    SyscallIndexEntry {
        number: 0x00D4,
        name: "NtImpersonateAnonymousToken",
    },
    SyscallIndexEntry {
        number: 0x00D5,
        name: "NtImpersonateThread",
    },
    SyscallIndexEntry {
        number: 0x00D6,
        name: "NtInitializeNlsFiles",
    },
    SyscallIndexEntry {
        number: 0x00D7,
        name: "NtInitializeRegistry",
    },
    SyscallIndexEntry {
        number: 0x00D8,
        name: "NtInitiatePowerAction",
    },
    SyscallIndexEntry {
        number: 0x00D9,
        name: "NtIsSystemResumeAutomatic",
    },
    SyscallIndexEntry {
        number: 0x00DA,
        name: "NtIsUILanguageComitted",
    },
    SyscallIndexEntry {
        number: 0x00DB,
        name: "NtListenPort",
    },
    SyscallIndexEntry {
        number: 0x00DC,
        name: "NtLoadDriver",
    },
    SyscallIndexEntry {
        number: 0x00DD,
        name: "NtLoadKey",
    },
    SyscallIndexEntry {
        number: 0x00DE,
        name: "NtLoadKey2",
    },
    SyscallIndexEntry {
        number: 0x00DF,
        name: "NtLoadKeyEx",
    },
    SyscallIndexEntry {
        number: 0x00E0,
        name: "NtLockFile",
    },
    SyscallIndexEntry {
        number: 0x00E1,
        name: "NtLockProductActivationKeys",
    },
    SyscallIndexEntry {
        number: 0x00E2,
        name: "NtLockRegistryKey",
    },
    SyscallIndexEntry {
        number: 0x00E3,
        name: "NtLockVirtualMemory",
    },
    SyscallIndexEntry {
        number: 0x00E4,
        name: "NtMakePermanentObject",
    },
    SyscallIndexEntry {
        number: 0x00E5,
        name: "NtMakeTemporaryObject",
    },
    SyscallIndexEntry {
        number: 0x00E6,
        name: "NtMapCMFModule",
    },
    SyscallIndexEntry {
        number: 0x00E7,
        name: "NtMapUserPhysicalPages",
    },
    SyscallIndexEntry {
        number: 0x00E8,
        name: "NtModifyBootEntry",
    },
    SyscallIndexEntry {
        number: 0x00E9,
        name: "NtModifyDriverEntry",
    },
    SyscallIndexEntry {
        number: 0x00EA,
        name: "NtNotifyChangeDirectoryFile",
    },
    SyscallIndexEntry {
        number: 0x00EB,
        name: "NtNotifyChangeKey",
    },
    SyscallIndexEntry {
        number: 0x00EC,
        name: "NtNotifyChangeMultipleKeys",
    },
    SyscallIndexEntry {
        number: 0x00ED,
        name: "NtNotifyChangeSession",
    },
    SyscallIndexEntry {
        number: 0x00EE,
        name: "NtOpenEnlistment",
    },
    SyscallIndexEntry {
        number: 0x00EF,
        name: "NtOpenEventPair",
    },
    SyscallIndexEntry {
        number: 0x00F0,
        name: "NtOpenIoCompletion",
    },
    SyscallIndexEntry {
        number: 0x00F1,
        name: "NtOpenJobObject",
    },
    SyscallIndexEntry {
        number: 0x00F2,
        name: "NtOpenKeyEx",
    },
    SyscallIndexEntry {
        number: 0x00F3,
        name: "NtOpenKeyTransacted",
    },
    SyscallIndexEntry {
        number: 0x00F4,
        name: "NtOpenKeyTransactedEx",
    },
    SyscallIndexEntry {
        number: 0x00F5,
        name: "NtOpenKeyedEvent",
    },
    SyscallIndexEntry {
        number: 0x00F6,
        name: "NtOpenMutant",
    },
    SyscallIndexEntry {
        number: 0x00F7,
        name: "NtOpenObjectAuditAlarm",
    },
    SyscallIndexEntry {
        number: 0x00F8,
        name: "NtOpenPrivateNamespace",
    },
    SyscallIndexEntry {
        number: 0x00F9,
        name: "NtOpenProcessToken",
    },
    SyscallIndexEntry {
        number: 0x00FA,
        name: "NtOpenResourceManager",
    },
    SyscallIndexEntry {
        number: 0x00FB,
        name: "NtOpenSemaphore",
    },
    SyscallIndexEntry {
        number: 0x00FC,
        name: "NtOpenSession",
    },
    SyscallIndexEntry {
        number: 0x00FD,
        name: "NtOpenSymbolicLinkObject",
    },
    SyscallIndexEntry {
        number: 0x00FE,
        name: "NtOpenThread",
    },
    SyscallIndexEntry {
        number: 0x00FF,
        name: "NtOpenTimer",
    },
    SyscallIndexEntry {
        number: 0x0100,
        name: "NtOpenTransaction",
    },
    SyscallIndexEntry {
        number: 0x0101,
        name: "NtOpenTransactionManager",
    },
    SyscallIndexEntry {
        number: 0x0102,
        name: "NtPlugPlayControl",
    },
    SyscallIndexEntry {
        number: 0x0103,
        name: "NtPrePrepareComplete",
    },
    SyscallIndexEntry {
        number: 0x0104,
        name: "NtPrePrepareEnlistment",
    },
    SyscallIndexEntry {
        number: 0x0105,
        name: "NtPrepareComplete",
    },
    SyscallIndexEntry {
        number: 0x0106,
        name: "NtPrepareEnlistment",
    },
    SyscallIndexEntry {
        number: 0x0107,
        name: "NtPrivilegeCheck",
    },
    SyscallIndexEntry {
        number: 0x0108,
        name: "NtPrivilegeObjectAuditAlarm",
    },
    SyscallIndexEntry {
        number: 0x0109,
        name: "NtPrivilegedServiceAuditAlarm",
    },
    SyscallIndexEntry {
        number: 0x010A,
        name: "NtPropagationComplete",
    },
    SyscallIndexEntry {
        number: 0x010B,
        name: "NtPropagationFailed",
    },
    SyscallIndexEntry {
        number: 0x010C,
        name: "NtPulseEvent",
    },
    SyscallIndexEntry {
        number: 0x010D,
        name: "NtQueryBootEntryOrder",
    },
    SyscallIndexEntry {
        number: 0x010E,
        name: "NtQueryBootOptions",
    },
    SyscallIndexEntry {
        number: 0x010F,
        name: "NtQueryDebugFilterState",
    },
    SyscallIndexEntry {
        number: 0x0110,
        name: "NtQueryDirectoryObject",
    },
    SyscallIndexEntry {
        number: 0x0111,
        name: "NtQueryDriverEntryOrder",
    },
    SyscallIndexEntry {
        number: 0x0112,
        name: "NtQueryEaFile",
    },
    SyscallIndexEntry {
        number: 0x0113,
        name: "NtQueryFullAttributesFile",
    },
    SyscallIndexEntry {
        number: 0x0114,
        name: "NtQueryInformationAtom",
    },
    SyscallIndexEntry {
        number: 0x0115,
        name: "NtQueryInformationEnlistment",
    },
    SyscallIndexEntry {
        number: 0x0116,
        name: "NtQueryInformationJobObject",
    },
    SyscallIndexEntry {
        number: 0x0117,
        name: "NtQueryInformationPort",
    },
    SyscallIndexEntry {
        number: 0x0118,
        name: "NtQueryInformationResourceManager",
    },
    SyscallIndexEntry {
        number: 0x0119,
        name: "NtQueryInformationTransaction",
    },
    SyscallIndexEntry {
        number: 0x011A,
        name: "NtQueryInformationTransactionManager",
    },
    SyscallIndexEntry {
        number: 0x011B,
        name: "NtQueryInformationWorkerFactory",
    },
    SyscallIndexEntry {
        number: 0x011C,
        name: "NtQueryInstallUILanguage",
    },
    SyscallIndexEntry {
        number: 0x011D,
        name: "NtQueryIntervalProfile",
    },
    SyscallIndexEntry {
        number: 0x011E,
        name: "NtQueryIoCompletion",
    },
    SyscallIndexEntry {
        number: 0x011F,
        name: "NtQueryLicenseValue",
    },
    SyscallIndexEntry {
        number: 0x0120,
        name: "NtQueryMultipleValueKey",
    },
    SyscallIndexEntry {
        number: 0x0121,
        name: "NtQueryMutant",
    },
    SyscallIndexEntry {
        number: 0x0122,
        name: "NtQueryOpenSubKeys",
    },
    SyscallIndexEntry {
        number: 0x0123,
        name: "NtQueryOpenSubKeysEx",
    },
    SyscallIndexEntry {
        number: 0x0124,
        name: "NtQueryPortInformationProcess",
    },
    SyscallIndexEntry {
        number: 0x0125,
        name: "NtQueryQuotaInformationFile",
    },
    SyscallIndexEntry {
        number: 0x0126,
        name: "NtQuerySecurityAttributesToken",
    },
    SyscallIndexEntry {
        number: 0x0127,
        name: "NtQuerySecurityObject",
    },
    SyscallIndexEntry {
        number: 0x0128,
        name: "NtQuerySemaphore",
    },
    SyscallIndexEntry {
        number: 0x0129,
        name: "NtQuerySymbolicLinkObject",
    },
    SyscallIndexEntry {
        number: 0x012A,
        name: "NtQuerySystemEnvironmentValue",
    },
    SyscallIndexEntry {
        number: 0x012B,
        name: "NtQuerySystemEnvironmentValueEx",
    },
    SyscallIndexEntry {
        number: 0x012C,
        name: "NtQuerySystemInformationEx",
    },
    SyscallIndexEntry {
        number: 0x012D,
        name: "NtQueryTimerResolution",
    },
    SyscallIndexEntry {
        number: 0x012E,
        name: "NtQueueApcThreadEx",
    },
    SyscallIndexEntry {
        number: 0x012F,
        name: "NtRaiseException",
    },
    SyscallIndexEntry {
        number: 0x0130,
        name: "NtRaiseHardError",
    },
    SyscallIndexEntry {
        number: 0x0131,
        name: "NtReadOnlyEnlistment",
    },
    SyscallIndexEntry {
        number: 0x0132,
        name: "NtRecoverEnlistment",
    },
    SyscallIndexEntry {
        number: 0x0133,
        name: "NtRecoverResourceManager",
    },
    SyscallIndexEntry {
        number: 0x0134,
        name: "NtRecoverTransactionManager",
    },
    SyscallIndexEntry {
        number: 0x0135,
        name: "NtRegisterProtocolAddressInformation",
    },
    SyscallIndexEntry {
        number: 0x0136,
        name: "NtRegisterThreadTerminatePort",
    },
    SyscallIndexEntry {
        number: 0x0137,
        name: "NtReleaseKeyedEvent",
    },
    SyscallIndexEntry {
        number: 0x0138,
        name: "NtReleaseWorkerFactoryWorker",
    },
    SyscallIndexEntry {
        number: 0x0139,
        name: "NtRemoveIoCompletionEx",
    },
    SyscallIndexEntry {
        number: 0x013A,
        name: "NtRemoveProcessDebug",
    },
    SyscallIndexEntry {
        number: 0x013B,
        name: "NtRenameKey",
    },
    SyscallIndexEntry {
        number: 0x013C,
        name: "NtRenameTransactionManager",
    },
    SyscallIndexEntry {
        number: 0x013D,
        name: "NtReplaceKey",
    },
    SyscallIndexEntry {
        number: 0x013E,
        name: "NtReplacePartitionUnit",
    },
    SyscallIndexEntry {
        number: 0x013F,
        name: "NtReplyWaitReplyPort",
    },
    SyscallIndexEntry {
        number: 0x0140,
        name: "NtRequestPort",
    },
    SyscallIndexEntry {
        number: 0x0141,
        name: "NtResetEvent",
    },
    SyscallIndexEntry {
        number: 0x0142,
        name: "NtResetWriteWatch",
    },
    SyscallIndexEntry {
        number: 0x0143,
        name: "NtRestoreKey",
    },
    SyscallIndexEntry {
        number: 0x0144,
        name: "NtResumeProcess",
    },
    SyscallIndexEntry {
        number: 0x0145,
        name: "NtRollbackComplete",
    },
    SyscallIndexEntry {
        number: 0x0146,
        name: "NtRollbackEnlistment",
    },
    SyscallIndexEntry {
        number: 0x0147,
        name: "NtRollbackTransaction",
    },
    SyscallIndexEntry {
        number: 0x0148,
        name: "NtRollforwardTransactionManager",
    },
    SyscallIndexEntry {
        number: 0x0149,
        name: "NtSaveKey",
    },
    SyscallIndexEntry {
        number: 0x014A,
        name: "NtSaveKeyEx",
    },
    SyscallIndexEntry {
        number: 0x014B,
        name: "NtSaveMergedKeys",
    },
    SyscallIndexEntry {
        number: 0x014C,
        name: "NtSecureConnectPort",
    },
    SyscallIndexEntry {
        number: 0x014D,
        name: "NtSerializeBoot",
    },
    SyscallIndexEntry {
        number: 0x014E,
        name: "NtSetBootEntryOrder",
    },
    SyscallIndexEntry {
        number: 0x014F,
        name: "NtSetBootOptions",
    },
    SyscallIndexEntry {
        number: 0x0150,
        name: "NtSetContextThread",
    },
    SyscallIndexEntry {
        number: 0x0151,
        name: "NtSetDebugFilterState",
    },
    SyscallIndexEntry {
        number: 0x0152,
        name: "NtSetDefaultHardErrorPort",
    },
    SyscallIndexEntry {
        number: 0x0153,
        name: "NtSetDefaultLocale",
    },
    SyscallIndexEntry {
        number: 0x0154,
        name: "NtSetDefaultUILanguage",
    },
    SyscallIndexEntry {
        number: 0x0155,
        name: "NtSetDriverEntryOrder",
    },
    SyscallIndexEntry {
        number: 0x0156,
        name: "NtSetEaFile",
    },
    SyscallIndexEntry {
        number: 0x0157,
        name: "NtSetHighEventPair",
    },
    SyscallIndexEntry {
        number: 0x0158,
        name: "NtSetHighWaitLowEventPair",
    },
    SyscallIndexEntry {
        number: 0x0159,
        name: "NtSetInformationDebugObject",
    },
    SyscallIndexEntry {
        number: 0x015A,
        name: "NtSetInformationEnlistment",
    },
    SyscallIndexEntry {
        number: 0x015B,
        name: "NtSetInformationJobObject",
    },
    SyscallIndexEntry {
        number: 0x015C,
        name: "NtSetInformationKey",
    },
    SyscallIndexEntry {
        number: 0x015D,
        name: "NtSetInformationResourceManager",
    },
    SyscallIndexEntry {
        number: 0x015E,
        name: "NtSetInformationToken",
    },
    SyscallIndexEntry {
        number: 0x015F,
        name: "NtSetInformationTransaction",
    },
    SyscallIndexEntry {
        number: 0x0160,
        name: "NtSetInformationTransactionManager",
    },
    SyscallIndexEntry {
        number: 0x0161,
        name: "NtSetInformationWorkerFactory",
    },
    SyscallIndexEntry {
        number: 0x0162,
        name: "NtSetIntervalProfile",
    },
    SyscallIndexEntry {
        number: 0x0163,
        name: "NtSetIoCompletion",
    },
    SyscallIndexEntry {
        number: 0x0164,
        name: "NtSetIoCompletionEx",
    },
    SyscallIndexEntry {
        number: 0x0165,
        name: "NtSetLdtEntries",
    },
    SyscallIndexEntry {
        number: 0x0166,
        name: "NtSetLowEventPair",
    },
    SyscallIndexEntry {
        number: 0x0167,
        name: "NtSetLowWaitHighEventPair",
    },
    SyscallIndexEntry {
        number: 0x0168,
        name: "NtSetQuotaInformationFile",
    },
    SyscallIndexEntry {
        number: 0x0169,
        name: "NtSetSecurityObject",
    },
    SyscallIndexEntry {
        number: 0x016A,
        name: "NtSetSystemEnvironmentValue",
    },
    SyscallIndexEntry {
        number: 0x016B,
        name: "NtSetSystemEnvironmentValueEx",
    },
    SyscallIndexEntry {
        number: 0x016C,
        name: "NtSetSystemInformation",
    },
    SyscallIndexEntry {
        number: 0x016D,
        name: "NtSetSystemPowerState",
    },
    SyscallIndexEntry {
        number: 0x016E,
        name: "NtSetSystemTime",
    },
    SyscallIndexEntry {
        number: 0x016F,
        name: "NtSetThreadExecutionState",
    },
    SyscallIndexEntry {
        number: 0x0170,
        name: "NtSetTimerEx",
    },
    SyscallIndexEntry {
        number: 0x0171,
        name: "NtSetTimerResolution",
    },
    SyscallIndexEntry {
        number: 0x0172,
        name: "NtSetUuidSeed",
    },
    SyscallIndexEntry {
        number: 0x0173,
        name: "NtSetVolumeInformationFile",
    },
    SyscallIndexEntry {
        number: 0x0174,
        name: "NtShutdownSystem",
    },
    SyscallIndexEntry {
        number: 0x0175,
        name: "NtShutdownWorkerFactory",
    },
    SyscallIndexEntry {
        number: 0x0176,
        name: "NtSignalAndWaitForSingleObject",
    },
    SyscallIndexEntry {
        number: 0x0177,
        name: "NtSinglePhaseReject",
    },
    SyscallIndexEntry {
        number: 0x0178,
        name: "NtStartProfile",
    },
    SyscallIndexEntry {
        number: 0x0179,
        name: "NtStopProfile",
    },
    SyscallIndexEntry {
        number: 0x017A,
        name: "NtSuspendProcess",
    },
    SyscallIndexEntry {
        number: 0x017B,
        name: "NtSuspendThread",
    },
    SyscallIndexEntry {
        number: 0x017C,
        name: "NtSystemDebugControl",
    },
    SyscallIndexEntry {
        number: 0x017D,
        name: "NtTerminateJobObject",
    },
    SyscallIndexEntry {
        number: 0x017E,
        name: "NtTestAlert",
    },
    SyscallIndexEntry {
        number: 0x017F,
        name: "NtThawRegistry",
    },
    SyscallIndexEntry {
        number: 0x0180,
        name: "NtThawTransactions",
    },
    SyscallIndexEntry {
        number: 0x0181,
        name: "NtTraceControl",
    },
    SyscallIndexEntry {
        number: 0x0182,
        name: "NtTranslateFilePath",
    },
    SyscallIndexEntry {
        number: 0x0183,
        name: "NtUmsThreadYield",
    },
    SyscallIndexEntry {
        number: 0x0184,
        name: "NtUnloadDriver",
    },
    SyscallIndexEntry {
        number: 0x0185,
        name: "NtUnloadKey",
    },
    SyscallIndexEntry {
        number: 0x0186,
        name: "NtUnloadKey2",
    },
    SyscallIndexEntry {
        number: 0x0187,
        name: "NtUnloadKeyEx",
    },
    SyscallIndexEntry {
        number: 0x0188,
        name: "NtUnlockFile",
    },
    SyscallIndexEntry {
        number: 0x0189,
        name: "NtUnlockVirtualMemory",
    },
    SyscallIndexEntry {
        number: 0x018A,
        name: "NtVdmControl",
    },
    SyscallIndexEntry {
        number: 0x018B,
        name: "NtWaitForDebugEvent",
    },
    SyscallIndexEntry {
        number: 0x018C,
        name: "NtWaitForKeyedEvent",
    },
    SyscallIndexEntry {
        number: 0x018D,
        name: "NtWaitForWorkViaWorkerFactory",
    },
    SyscallIndexEntry {
        number: 0x018E,
        name: "NtWaitHighEventPair",
    },
    SyscallIndexEntry {
        number: 0x018F,
        name: "NtWaitLowEventPair",
    },
    SyscallIndexEntry {
        number: 0x0190,
        name: "NtWorkerFactoryWorkerReady",
    },
];

/// Windows 7 SP1 x64 win32k syscall table.
pub static WIN32K_SYSCALLS: [SyscallIndexEntry; 827] = [
    SyscallIndexEntry {
        number: 0x1000,
        name: "NtUserGetThreadState",
    },
    SyscallIndexEntry {
        number: 0x1001,
        name: "NtUserPeekMessage",
    },
    SyscallIndexEntry {
        number: 0x1002,
        name: "NtUserCallOneParam",
    },
    SyscallIndexEntry {
        number: 0x1003,
        name: "NtUserGetKeyState",
    },
    SyscallIndexEntry {
        number: 0x1004,
        name: "NtUserInvalidateRect",
    },
    SyscallIndexEntry {
        number: 0x1005,
        name: "NtUserCallNoParam",
    },
    SyscallIndexEntry {
        number: 0x1006,
        name: "NtUserGetMessage",
    },
    SyscallIndexEntry {
        number: 0x1007,
        name: "NtUserMessageCall",
    },
    SyscallIndexEntry {
        number: 0x1008,
        name: "NtGdiBitBlt",
    },
    SyscallIndexEntry {
        number: 0x1009,
        name: "NtGdiGetCharSet",
    },
    SyscallIndexEntry {
        number: 0x100A,
        name: "NtUserGetDC",
    },
    SyscallIndexEntry {
        number: 0x100B,
        name: "NtGdiSelectBitmap",
    },
    SyscallIndexEntry {
        number: 0x100C,
        name: "NtUserWaitMessage",
    },
    SyscallIndexEntry {
        number: 0x100D,
        name: "NtUserTranslateMessage",
    },
    SyscallIndexEntry {
        number: 0x100E,
        name: "NtUserGetProp",
    },
    SyscallIndexEntry {
        number: 0x100F,
        name: "NtUserPostMessage",
    },
    SyscallIndexEntry {
        number: 0x1010,
        name: "NtUserQueryWindow",
    },
    SyscallIndexEntry {
        number: 0x1011,
        name: "NtUserTranslateAccelerator",
    },
    SyscallIndexEntry {
        number: 0x1012,
        name: "NtGdiFlush",
    },
    SyscallIndexEntry {
        number: 0x1013,
        name: "NtUserRedrawWindow",
    },
    SyscallIndexEntry {
        number: 0x1014,
        name: "NtUserWindowFromPoint",
    },
    SyscallIndexEntry {
        number: 0x1015,
        name: "NtUserCallMsgFilter",
    },
    SyscallIndexEntry {
        number: 0x1016,
        name: "NtUserValidateTimerCallback",
    },
    SyscallIndexEntry {
        number: 0x1017,
        name: "NtUserBeginPaint",
    },
    SyscallIndexEntry {
        number: 0x1018,
        name: "NtUserSetTimer",
    },
    SyscallIndexEntry {
        number: 0x1019,
        name: "NtUserEndPaint",
    },
    SyscallIndexEntry {
        number: 0x101A,
        name: "NtUserSetCursor",
    },
    SyscallIndexEntry {
        number: 0x101B,
        name: "NtUserKillTimer",
    },
    SyscallIndexEntry {
        number: 0x101C,
        name: "NtUserBuildHwndList",
    },
    SyscallIndexEntry {
        number: 0x101D,
        name: "NtUserSelectPalette",
    },
    SyscallIndexEntry {
        number: 0x101E,
        name: "NtUserCallNextHookEx",
    },
    SyscallIndexEntry {
        number: 0x101F,
        name: "NtUserHideCaret",
    },
    SyscallIndexEntry {
        number: 0x1020,
        name: "NtGdiIntersectClipRect",
    },
    SyscallIndexEntry {
        number: 0x1021,
        name: "NtUserCallHwndLock",
    },
    SyscallIndexEntry {
        number: 0x1022,
        name: "NtUserGetProcessWindowStation",
    },
    SyscallIndexEntry {
        number: 0x1023,
        name: "NtGdiDeleteObjectApp",
    },
    SyscallIndexEntry {
        number: 0x1024,
        name: "NtUserSetWindowPos",
    },
    SyscallIndexEntry {
        number: 0x1025,
        name: "NtUserShowCaret",
    },
    SyscallIndexEntry {
        number: 0x1026,
        name: "NtUserEndDeferWindowPosEx",
    },
    SyscallIndexEntry {
        number: 0x1027,
        name: "NtUserCallHwndParamLock",
    },
    SyscallIndexEntry {
        number: 0x1028,
        name: "NtUserVkKeyScanEx",
    },
    SyscallIndexEntry {
        number: 0x1029,
        name: "NtGdiSetDIBitsToDeviceInternal",
    },
    SyscallIndexEntry {
        number: 0x102A,
        name: "NtUserCallTwoParam",
    },
    SyscallIndexEntry {
        number: 0x102B,
        name: "NtGdiGetRandomRgn",
    },
    SyscallIndexEntry {
        number: 0x102C,
        name: "NtUserCopyAcceleratorTable",
    },
    SyscallIndexEntry {
        number: 0x102D,
        name: "NtUserNotifyWinEvent",
    },
    SyscallIndexEntry {
        number: 0x102E,
        name: "NtGdiExtSelectClipRgn",
    },
    SyscallIndexEntry {
        number: 0x102F,
        name: "NtUserIsClipboardFormatAvailable",
    },
    SyscallIndexEntry {
        number: 0x1030,
        name: "NtUserSetScrollInfo",
    },
    SyscallIndexEntry {
        number: 0x1031,
        name: "NtGdiStretchBlt",
    },
    SyscallIndexEntry {
        number: 0x1032,
        name: "NtUserCreateCaret",
    },
    SyscallIndexEntry {
        number: 0x1033,
        name: "NtGdiRectVisible",
    },
    SyscallIndexEntry {
        number: 0x1034,
        name: "NtGdiCombineRgn",
    },
    SyscallIndexEntry {
        number: 0x1035,
        name: "NtGdiGetDCObject",
    },
    SyscallIndexEntry {
        number: 0x1036,
        name: "NtUserDispatchMessage",
    },
    SyscallIndexEntry {
        number: 0x1037,
        name: "NtUserRegisterWindowMessage",
    },
    SyscallIndexEntry {
        number: 0x1038,
        name: "NtGdiExtTextOutW",
    },
    SyscallIndexEntry {
        number: 0x1039,
        name: "NtGdiSelectFont",
    },
    SyscallIndexEntry {
        number: 0x103A,
        name: "NtGdiRestoreDC",
    },
    SyscallIndexEntry {
        number: 0x103B,
        name: "NtGdiSaveDC",
    },
    SyscallIndexEntry {
        number: 0x103C,
        name: "NtUserGetForegroundWindow",
    },
    SyscallIndexEntry {
        number: 0x103D,
        name: "NtUserShowScrollBar",
    },
    SyscallIndexEntry {
        number: 0x103E,
        name: "NtUserFindExistingCursorIcon",
    },
    SyscallIndexEntry {
        number: 0x103F,
        name: "NtGdiGetDCDword",
    },
    SyscallIndexEntry {
        number: 0x1040,
        name: "NtGdiGetRegionData",
    },
    SyscallIndexEntry {
        number: 0x1041,
        name: "NtGdiLineTo",
    },
    SyscallIndexEntry {
        number: 0x1042,
        name: "NtUserSystemParametersInfo",
    },
    SyscallIndexEntry {
        number: 0x1043,
        name: "NtGdiGetAppClipBox",
    },
    SyscallIndexEntry {
        number: 0x1044,
        name: "NtUserGetAsyncKeyState",
    },
    SyscallIndexEntry {
        number: 0x1045,
        name: "NtUserGetCPD",
    },
    SyscallIndexEntry {
        number: 0x1046,
        name: "NtUserRemoveProp",
    },
    SyscallIndexEntry {
        number: 0x1047,
        name: "NtGdiDoPalette",
    },
    SyscallIndexEntry {
        number: 0x1048,
        name: "NtGdiPolyPolyDraw",
    },
    SyscallIndexEntry {
        number: 0x1049,
        name: "NtUserSetCapture",
    },
    SyscallIndexEntry {
        number: 0x104A,
        name: "NtUserEnumDisplayMonitors",
    },
    SyscallIndexEntry {
        number: 0x104B,
        name: "NtGdiCreateCompatibleBitmap",
    },
    SyscallIndexEntry {
        number: 0x104C,
        name: "NtUserSetProp",
    },
    SyscallIndexEntry {
        number: 0x104D,
        name: "NtGdiGetTextCharsetInfo",
    },
    SyscallIndexEntry {
        number: 0x104E,
        name: "NtUserSBGetParms",
    },
    SyscallIndexEntry {
        number: 0x104F,
        name: "NtUserGetIconInfo",
    },
    SyscallIndexEntry {
        number: 0x1050,
        name: "NtUserExcludeUpdateRgn",
    },
    SyscallIndexEntry {
        number: 0x1051,
        name: "NtUserSetFocus",
    },
    SyscallIndexEntry {
        number: 0x1052,
        name: "NtGdiExtGetObjectW",
    },
    SyscallIndexEntry {
        number: 0x1053,
        name: "NtUserDeferWindowPos",
    },
    SyscallIndexEntry {
        number: 0x1054,
        name: "NtUserGetUpdateRect",
    },
    SyscallIndexEntry {
        number: 0x1055,
        name: "NtGdiCreateCompatibleDC",
    },
    SyscallIndexEntry {
        number: 0x1056,
        name: "NtUserGetClipboardSequenceNumber",
    },
    SyscallIndexEntry {
        number: 0x1057,
        name: "NtGdiCreatePen",
    },
    SyscallIndexEntry {
        number: 0x1058,
        name: "NtUserShowWindow",
    },
    SyscallIndexEntry {
        number: 0x1059,
        name: "NtUserGetKeyboardLayoutList",
    },
    SyscallIndexEntry {
        number: 0x105A,
        name: "NtGdiPatBlt",
    },
    SyscallIndexEntry {
        number: 0x105B,
        name: "NtUserMapVirtualKeyEx",
    },
    SyscallIndexEntry {
        number: 0x105C,
        name: "NtUserSetWindowLong",
    },
    SyscallIndexEntry {
        number: 0x105D,
        name: "NtGdiHfontCreate",
    },
    SyscallIndexEntry {
        number: 0x105E,
        name: "NtUserMoveWindow",
    },
    SyscallIndexEntry {
        number: 0x105F,
        name: "NtUserPostThreadMessage",
    },
    SyscallIndexEntry {
        number: 0x1060,
        name: "NtUserDrawIconEx",
    },
    SyscallIndexEntry {
        number: 0x1061,
        name: "NtUserGetSystemMenu",
    },
    SyscallIndexEntry {
        number: 0x1062,
        name: "NtGdiDrawStream",
    },
    SyscallIndexEntry {
        number: 0x1063,
        name: "NtUserInternalGetWindowText",
    },
    SyscallIndexEntry {
        number: 0x1064,
        name: "NtUserGetWindowDC",
    },
    SyscallIndexEntry {
        number: 0x1065,
        name: "NtGdiD3dDrawPrimitives2",
    },
    SyscallIndexEntry {
        number: 0x1066,
        name: "NtGdiInvertRgn",
    },
    SyscallIndexEntry {
        number: 0x1067,
        name: "NtGdiGetRgnBox",
    },
    SyscallIndexEntry {
        number: 0x1068,
        name: "NtGdiGetAndSetDCDword",
    },
    SyscallIndexEntry {
        number: 0x1069,
        name: "NtGdiMaskBlt",
    },
    SyscallIndexEntry {
        number: 0x106A,
        name: "NtGdiGetWidthTable",
    },
    SyscallIndexEntry {
        number: 0x106B,
        name: "NtUserScrollDC",
    },
    SyscallIndexEntry {
        number: 0x106C,
        name: "NtUserGetObjectInformation",
    },
    SyscallIndexEntry {
        number: 0x106D,
        name: "NtGdiCreateBitmap",
    },
    SyscallIndexEntry {
        number: 0x106E,
        name: "NtUserFindWindowEx",
    },
    SyscallIndexEntry {
        number: 0x106F,
        name: "NtGdiPolyPatBlt",
    },
    SyscallIndexEntry {
        number: 0x1070,
        name: "NtUserUnhookWindowsHookEx",
    },
    SyscallIndexEntry {
        number: 0x1071,
        name: "NtGdiGetNearestColor",
    },
    SyscallIndexEntry {
        number: 0x1072,
        name: "NtGdiTransformPoints",
    },
    SyscallIndexEntry {
        number: 0x1073,
        name: "NtGdiGetDCPoint",
    },
    SyscallIndexEntry {
        number: 0x1074,
        name: "NtGdiCreateDIBBrush",
    },
    SyscallIndexEntry {
        number: 0x1075,
        name: "NtGdiGetTextMetricsW",
    },
    SyscallIndexEntry {
        number: 0x1076,
        name: "NtUserCreateWindowEx",
    },
    SyscallIndexEntry {
        number: 0x1077,
        name: "NtUserSetParent",
    },
    SyscallIndexEntry {
        number: 0x1078,
        name: "NtUserGetKeyboardState",
    },
    SyscallIndexEntry {
        number: 0x1079,
        name: "NtUserToUnicodeEx",
    },
    SyscallIndexEntry {
        number: 0x107A,
        name: "NtUserGetControlBrush",
    },
    SyscallIndexEntry {
        number: 0x107B,
        name: "NtUserGetClassName",
    },
    SyscallIndexEntry {
        number: 0x107C,
        name: "NtGdiAlphaBlend",
    },
    SyscallIndexEntry {
        number: 0x107D,
        name: "NtGdiDdBlt",
    },
    SyscallIndexEntry {
        number: 0x107E,
        name: "NtGdiOffsetRgn",
    },
    SyscallIndexEntry {
        number: 0x107F,
        name: "NtUserDefSetText",
    },
    SyscallIndexEntry {
        number: 0x1080,
        name: "NtGdiGetTextFaceW",
    },
    SyscallIndexEntry {
        number: 0x1081,
        name: "NtGdiStretchDIBitsInternal",
    },
    SyscallIndexEntry {
        number: 0x1082,
        name: "NtUserSendInput",
    },
    SyscallIndexEntry {
        number: 0x1083,
        name: "NtUserGetThreadDesktop",
    },
    SyscallIndexEntry {
        number: 0x1084,
        name: "NtGdiCreateRectRgn",
    },
    SyscallIndexEntry {
        number: 0x1085,
        name: "NtGdiGetDIBitsInternal",
    },
    SyscallIndexEntry {
        number: 0x1086,
        name: "NtUserGetUpdateRgn",
    },
    SyscallIndexEntry {
        number: 0x1087,
        name: "NtGdiDeleteClientObj",
    },
    SyscallIndexEntry {
        number: 0x1088,
        name: "NtUserGetIconSize",
    },
    SyscallIndexEntry {
        number: 0x1089,
        name: "NtUserFillWindow",
    },
    SyscallIndexEntry {
        number: 0x108A,
        name: "NtGdiExtCreateRegion",
    },
    SyscallIndexEntry {
        number: 0x108B,
        name: "NtGdiComputeXformCoefficients",
    },
    SyscallIndexEntry {
        number: 0x108C,
        name: "NtUserSetWindowsHookEx",
    },
    SyscallIndexEntry {
        number: 0x108D,
        name: "NtUserNotifyProcessCreate",
    },
    SyscallIndexEntry {
        number: 0x108E,
        name: "NtGdiUnrealizeObject",
    },
    SyscallIndexEntry {
        number: 0x108F,
        name: "NtUserGetTitleBarInfo",
    },
    SyscallIndexEntry {
        number: 0x1090,
        name: "NtGdiRectangle",
    },
    SyscallIndexEntry {
        number: 0x1091,
        name: "NtUserSetThreadDesktop",
    },
    SyscallIndexEntry {
        number: 0x1092,
        name: "NtUserGetDCEx",
    },
    SyscallIndexEntry {
        number: 0x1093,
        name: "NtUserGetScrollBarInfo",
    },
    SyscallIndexEntry {
        number: 0x1094,
        name: "NtGdiGetTextExtent",
    },
    SyscallIndexEntry {
        number: 0x1095,
        name: "NtUserSetWindowFNID",
    },
    SyscallIndexEntry {
        number: 0x1096,
        name: "NtGdiSetLayout",
    },
    SyscallIndexEntry {
        number: 0x1097,
        name: "NtUserCalcMenuBar",
    },
    SyscallIndexEntry {
        number: 0x1098,
        name: "NtUserThunkedMenuItemInfo",
    },
    SyscallIndexEntry {
        number: 0x1099,
        name: "NtGdiExcludeClipRect",
    },
    SyscallIndexEntry {
        number: 0x109A,
        name: "NtGdiCreateDIBSection",
    },
    SyscallIndexEntry {
        number: 0x109B,
        name: "NtGdiGetDCforBitmap",
    },
    SyscallIndexEntry {
        number: 0x109C,
        name: "NtUserDestroyCursor",
    },
    SyscallIndexEntry {
        number: 0x109D,
        name: "NtUserDestroyWindow",
    },
    SyscallIndexEntry {
        number: 0x109E,
        name: "NtUserCallHwndParam",
    },
    SyscallIndexEntry {
        number: 0x109F,
        name: "NtGdiCreateDIBitmapInternal",
    },
    SyscallIndexEntry {
        number: 0x10A0,
        name: "NtUserOpenWindowStation",
    },
    SyscallIndexEntry {
        number: 0x10A1,
        name: "NtGdiDdDeleteSurfaceObject",
    },
    SyscallIndexEntry {
        number: 0x10A2,
        name: "NtGdiDdCanCreateSurface",
    },
    SyscallIndexEntry {
        number: 0x10A3,
        name: "NtGdiDdCreateSurface",
    },
    SyscallIndexEntry {
        number: 0x10A4,
        name: "NtUserSetCursorIconData",
    },
    SyscallIndexEntry {
        number: 0x10A5,
        name: "NtGdiDdDestroySurface",
    },
    SyscallIndexEntry {
        number: 0x10A6,
        name: "NtUserCloseDesktop",
    },
    SyscallIndexEntry {
        number: 0x10A7,
        name: "NtUserOpenDesktop",
    },
    SyscallIndexEntry {
        number: 0x10A8,
        name: "NtUserSetProcessWindowStation",
    },
    SyscallIndexEntry {
        number: 0x10A9,
        name: "NtUserGetAtomName",
    },
    SyscallIndexEntry {
        number: 0x10AA,
        name: "NtGdiDdResetVisrgn",
    },
    SyscallIndexEntry {
        number: 0x10AB,
        name: "NtGdiExtCreatePen",
    },
    SyscallIndexEntry {
        number: 0x10AC,
        name: "NtGdiCreatePaletteInternal",
    },
    SyscallIndexEntry {
        number: 0x10AD,
        name: "NtGdiSetBrushOrg",
    },
    SyscallIndexEntry {
        number: 0x10AE,
        name: "NtUserBuildNameList",
    },
    SyscallIndexEntry {
        number: 0x10AF,
        name: "NtGdiSetPixel",
    },
    SyscallIndexEntry {
        number: 0x10B0,
        name: "NtUserRegisterClassExWOW",
    },
    SyscallIndexEntry {
        number: 0x10B1,
        name: "NtGdiCreatePatternBrushInternal",
    },
    SyscallIndexEntry {
        number: 0x10B2,
        name: "NtUserGetAncestor",
    },
    SyscallIndexEntry {
        number: 0x10B3,
        name: "NtGdiGetOutlineTextMetricsInternalW",
    },
    SyscallIndexEntry {
        number: 0x10B4,
        name: "NtGdiSetBitmapBits",
    },
    SyscallIndexEntry {
        number: 0x10B5,
        name: "NtUserCloseWindowStation",
    },
    SyscallIndexEntry {
        number: 0x10B6,
        name: "NtUserGetDoubleClickTime",
    },
    SyscallIndexEntry {
        number: 0x10B7,
        name: "NtUserEnableScrollBar",
    },
    SyscallIndexEntry {
        number: 0x10B8,
        name: "NtGdiCreateSolidBrush",
    },
    SyscallIndexEntry {
        number: 0x10B9,
        name: "NtUserGetClassInfoEx",
    },
    SyscallIndexEntry {
        number: 0x10BA,
        name: "NtGdiCreateClientObj",
    },
    SyscallIndexEntry {
        number: 0x10BB,
        name: "NtUserUnregisterClass",
    },
    SyscallIndexEntry {
        number: 0x10BC,
        name: "NtUserDeleteMenu",
    },
    SyscallIndexEntry {
        number: 0x10BD,
        name: "NtGdiRectInRegion",
    },
    SyscallIndexEntry {
        number: 0x10BE,
        name: "NtUserScrollWindowEx",
    },
    SyscallIndexEntry {
        number: 0x10BF,
        name: "NtGdiGetPixel",
    },
    SyscallIndexEntry {
        number: 0x10C0,
        name: "NtUserSetClassLong",
    },
    SyscallIndexEntry {
        number: 0x10C1,
        name: "NtUserGetMenuBarInfo",
    },
    SyscallIndexEntry {
        number: 0x10C2,
        name: "NtGdiDdCreateSurfaceEx",
    },
    SyscallIndexEntry {
        number: 0x10C3,
        name: "NtGdiDdCreateSurfaceObject",
    },
    SyscallIndexEntry {
        number: 0x10C4,
        name: "NtGdiGetNearestPaletteIndex",
    },
    SyscallIndexEntry {
        number: 0x10C5,
        name: "NtGdiDdLockD3D",
    },
    SyscallIndexEntry {
        number: 0x10C6,
        name: "NtGdiDdUnlockD3D",
    },
    SyscallIndexEntry {
        number: 0x10C7,
        name: "NtGdiGetCharWidthW",
    },
    SyscallIndexEntry {
        number: 0x10C8,
        name: "NtUserInvalidateRgn",
    },
    SyscallIndexEntry {
        number: 0x10C9,
        name: "NtUserGetClipboardOwner",
    },
    SyscallIndexEntry {
        number: 0x10CA,
        name: "NtUserSetWindowRgn",
    },
    SyscallIndexEntry {
        number: 0x10CB,
        name: "NtUserBitBltSysBmp",
    },
    SyscallIndexEntry {
        number: 0x10CC,
        name: "NtGdiGetCharWidthInfo",
    },
    SyscallIndexEntry {
        number: 0x10CD,
        name: "NtUserValidateRect",
    },
    SyscallIndexEntry {
        number: 0x10CE,
        name: "NtUserCloseClipboard",
    },
    SyscallIndexEntry {
        number: 0x10CF,
        name: "NtUserOpenClipboard",
    },
    SyscallIndexEntry {
        number: 0x10D0,
        name: "NtGdiGetStockObject",
    },
    SyscallIndexEntry {
        number: 0x10D1,
        name: "NtUserSetClipboardData",
    },
    SyscallIndexEntry {
        number: 0x10D2,
        name: "NtUserEnableMenuItem",
    },
    SyscallIndexEntry {
        number: 0x10D3,
        name: "NtUserAlterWindowStyle",
    },
    SyscallIndexEntry {
        number: 0x10D4,
        name: "NtGdiFillRgn",
    },
    SyscallIndexEntry {
        number: 0x10D5,
        name: "NtUserGetWindowPlacement",
    },
    SyscallIndexEntry {
        number: 0x10D6,
        name: "NtGdiModifyWorldTransform",
    },
    SyscallIndexEntry {
        number: 0x10D7,
        name: "NtGdiGetFontData",
    },
    SyscallIndexEntry {
        number: 0x10D8,
        name: "NtUserGetOpenClipboardWindow",
    },
    SyscallIndexEntry {
        number: 0x10D9,
        name: "NtUserSetThreadState",
    },
    SyscallIndexEntry {
        number: 0x10DA,
        name: "NtGdiOpenDCW",
    },
    SyscallIndexEntry {
        number: 0x10DB,
        name: "NtUserTrackMouseEvent",
    },
    SyscallIndexEntry {
        number: 0x10DC,
        name: "NtGdiGetTransform",
    },
    SyscallIndexEntry {
        number: 0x10DD,
        name: "NtUserDestroyMenu",
    },
    SyscallIndexEntry {
        number: 0x10DE,
        name: "NtGdiGetBitmapBits",
    },
    SyscallIndexEntry {
        number: 0x10DF,
        name: "NtUserConsoleControl",
    },
    SyscallIndexEntry {
        number: 0x10E0,
        name: "NtUserSetActiveWindow",
    },
    SyscallIndexEntry {
        number: 0x10E1,
        name: "NtUserSetInformationThread",
    },
    SyscallIndexEntry {
        number: 0x10E2,
        name: "NtUserSetWindowPlacement",
    },
    SyscallIndexEntry {
        number: 0x10E3,
        name: "NtUserGetControlColor",
    },
    SyscallIndexEntry {
        number: 0x10E4,
        name: "NtGdiSetMetaRgn",
    },
    SyscallIndexEntry {
        number: 0x10E5,
        name: "NtGdiSetMiterLimit",
    },
    SyscallIndexEntry {
        number: 0x10E6,
        name: "NtGdiSetVirtualResolution",
    },
    SyscallIndexEntry {
        number: 0x10E7,
        name: "NtGdiGetRasterizerCaps",
    },
    SyscallIndexEntry {
        number: 0x10E8,
        name: "NtUserSetWindowWord",
    },
    SyscallIndexEntry {
        number: 0x10E9,
        name: "NtUserGetClipboardFormatName",
    },
    SyscallIndexEntry {
        number: 0x10EA,
        name: "NtUserRealInternalGetMessage",
    },
    SyscallIndexEntry {
        number: 0x10EB,
        name: "NtUserCreateLocalMemHandle",
    },
    SyscallIndexEntry {
        number: 0x10EC,
        name: "NtUserAttachThreadInput",
    },
    SyscallIndexEntry {
        number: 0x10ED,
        name: "NtGdiCreateHalftonePalette",
    },
    SyscallIndexEntry {
        number: 0x10EE,
        name: "NtUserPaintMenuBar",
    },
    SyscallIndexEntry {
        number: 0x10EF,
        name: "NtUserSetKeyboardState",
    },
    SyscallIndexEntry {
        number: 0x10F0,
        name: "NtGdiCombineTransform",
    },
    SyscallIndexEntry {
        number: 0x10F1,
        name: "NtUserCreateAcceleratorTable",
    },
    SyscallIndexEntry {
        number: 0x10F2,
        name: "NtUserGetCursorFrameInfo",
    },
    SyscallIndexEntry {
        number: 0x10F3,
        name: "NtUserGetAltTabInfo",
    },
    SyscallIndexEntry {
        number: 0x10F4,
        name: "NtUserGetCaretBlinkTime",
    },
    SyscallIndexEntry {
        number: 0x10F5,
        name: "NtGdiQueryFontAssocInfo",
    },
    SyscallIndexEntry {
        number: 0x10F6,
        name: "NtUserProcessConnect",
    },
    SyscallIndexEntry {
        number: 0x10F7,
        name: "NtUserEnumDisplayDevices",
    },
    SyscallIndexEntry {
        number: 0x10F8,
        name: "NtUserEmptyClipboard",
    },
    SyscallIndexEntry {
        number: 0x10F9,
        name: "NtUserGetClipboardData",
    },
    SyscallIndexEntry {
        number: 0x10FA,
        name: "NtUserRemoveMenu",
    },
    SyscallIndexEntry {
        number: 0x10FB,
        name: "NtGdiSetBoundsRect",
    },
    SyscallIndexEntry {
        number: 0x10FC,
        name: "NtGdiGetBitmapDimension",
    },
    SyscallIndexEntry {
        number: 0x10FD,
        name: "NtUserConvertMemHandle",
    },
    SyscallIndexEntry {
        number: 0x10FE,
        name: "NtUserDestroyAcceleratorTable",
    },
    SyscallIndexEntry {
        number: 0x10FF,
        name: "NtUserGetGUIThreadInfo",
    },
    SyscallIndexEntry {
        number: 0x1100,
        name: "NtGdiCloseFigure",
    },
    SyscallIndexEntry {
        number: 0x1101,
        name: "NtUserSetWindowsHookAW",
    },
    SyscallIndexEntry {
        number: 0x1102,
        name: "NtUserSetMenuDefaultItem",
    },
    SyscallIndexEntry {
        number: 0x1103,
        name: "NtUserCheckMenuItem",
    },
    SyscallIndexEntry {
        number: 0x1104,
        name: "NtUserSetWinEventHook",
    },
    SyscallIndexEntry {
        number: 0x1105,
        name: "NtUserUnhookWinEvent",
    },
    SyscallIndexEntry {
        number: 0x1106,
        name: "NtUserLockWindowUpdate",
    },
    SyscallIndexEntry {
        number: 0x1107,
        name: "NtUserSetSystemMenu",
    },
    SyscallIndexEntry {
        number: 0x1108,
        name: "NtUserThunkedMenuInfo",
    },
    SyscallIndexEntry {
        number: 0x1109,
        name: "NtGdiBeginPath",
    },
    SyscallIndexEntry {
        number: 0x110A,
        name: "NtGdiEndPath",
    },
    SyscallIndexEntry {
        number: 0x110B,
        name: "NtGdiFillPath",
    },
    SyscallIndexEntry {
        number: 0x110C,
        name: "NtUserCallHwnd",
    },
    SyscallIndexEntry {
        number: 0x110D,
        name: "NtUserDdeInitialize",
    },
    SyscallIndexEntry {
        number: 0x110E,
        name: "NtUserModifyUserStartupInfoFlags",
    },
    SyscallIndexEntry {
        number: 0x110F,
        name: "NtUserCountClipboardFormats",
    },
    SyscallIndexEntry {
        number: 0x1110,
        name: "NtGdiAddFontMemResourceEx",
    },
    SyscallIndexEntry {
        number: 0x1111,
        name: "NtGdiEqualRgn",
    },
    SyscallIndexEntry {
        number: 0x1112,
        name: "NtGdiGetSystemPaletteUse",
    },
    SyscallIndexEntry {
        number: 0x1113,
        name: "NtGdiRemoveFontMemResourceEx",
    },
    SyscallIndexEntry {
        number: 0x1114,
        name: "NtUserEnumDisplaySettings",
    },
    SyscallIndexEntry {
        number: 0x1115,
        name: "NtUserPaintDesktop",
    },
    SyscallIndexEntry {
        number: 0x1116,
        name: "NtGdiExtEscape",
    },
    SyscallIndexEntry {
        number: 0x1117,
        name: "NtGdiSetBitmapDimension",
    },
    SyscallIndexEntry {
        number: 0x1118,
        name: "NtGdiSetFontEnumeration",
    },
    SyscallIndexEntry {
        number: 0x1119,
        name: "NtUserChangeClipboardChain",
    },
    SyscallIndexEntry {
        number: 0x111A,
        name: "NtUserSetClipboardViewer",
    },
    SyscallIndexEntry {
        number: 0x111B,
        name: "NtUserShowWindowAsync",
    },
    SyscallIndexEntry {
        number: 0x111C,
        name: "NtGdiCreateColorSpace",
    },
    SyscallIndexEntry {
        number: 0x111D,
        name: "NtGdiDeleteColorSpace",
    },
    SyscallIndexEntry {
        number: 0x111E,
        name: "NtUserActivateKeyboardLayout",
    },
    SyscallIndexEntry {
        number: 0x111F,
        name: "NtGdiAbortDoc",
    },
    SyscallIndexEntry {
        number: 0x1120,
        name: "NtGdiAbortPath",
    },
    SyscallIndexEntry {
        number: 0x1121,
        name: "NtGdiAddEmbFontToDC",
    },
    SyscallIndexEntry {
        number: 0x1122,
        name: "NtGdiAddFontResourceW",
    },
    SyscallIndexEntry {
        number: 0x1123,
        name: "NtGdiAddRemoteFontToDC",
    },
    SyscallIndexEntry {
        number: 0x1124,
        name: "NtGdiAddRemoteMMInstanceToDC",
    },
    SyscallIndexEntry {
        number: 0x1125,
        name: "NtGdiAngleArc",
    },
    SyscallIndexEntry {
        number: 0x1126,
        name: "NtGdiAnyLinkedFonts",
    },
    SyscallIndexEntry {
        number: 0x1127,
        name: "NtGdiArcInternal",
    },
    SyscallIndexEntry {
        number: 0x1128,
        name: "NtGdiBRUSHOBJ_DeleteRbrush",
    },
    SyscallIndexEntry {
        number: 0x1129,
        name: "NtGdiBRUSHOBJ_hGetColorTransform",
    },
    SyscallIndexEntry {
        number: 0x112A,
        name: "NtGdiBRUSHOBJ_pvAllocRbrush",
    },
    SyscallIndexEntry {
        number: 0x112B,
        name: "NtGdiBRUSHOBJ_pvGetRbrush",
    },
    SyscallIndexEntry {
        number: 0x112C,
        name: "NtGdiBRUSHOBJ_ulGetBrushColor",
    },
    SyscallIndexEntry {
        number: 0x112D,
        name: "NtGdiBeginGdiRendering",
    },
    SyscallIndexEntry {
        number: 0x112E,
        name: "NtGdiCLIPOBJ_bEnum",
    },
    SyscallIndexEntry {
        number: 0x112F,
        name: "NtGdiCLIPOBJ_cEnumStart",
    },
    SyscallIndexEntry {
        number: 0x1130,
        name: "NtGdiCLIPOBJ_ppoGetPath",
    },
    SyscallIndexEntry {
        number: 0x1131,
        name: "NtGdiCancelDC",
    },
    SyscallIndexEntry {
        number: 0x1132,
        name: "NtGdiChangeGhostFont",
    },
    SyscallIndexEntry {
        number: 0x1133,
        name: "NtGdiCheckBitmapBits",
    },
    SyscallIndexEntry {
        number: 0x1134,
        name: "NtGdiClearBitmapAttributes",
    },
    SyscallIndexEntry {
        number: 0x1135,
        name: "NtGdiClearBrushAttributes",
    },
    SyscallIndexEntry {
        number: 0x1136,
        name: "NtGdiColorCorrectPalette",
    },
    SyscallIndexEntry {
        number: 0x1137,
        name: "NtGdiConfigureOPMProtectedOutput",
    },
    SyscallIndexEntry {
        number: 0x1138,
        name: "NtGdiConvertMetafileRect",
    },
    SyscallIndexEntry {
        number: 0x1139,
        name: "NtGdiCreateBitmapFromDxSurface",
    },
    SyscallIndexEntry {
        number: 0x113A,
        name: "NtGdiCreateColorTransform",
    },
    SyscallIndexEntry {
        number: 0x113B,
        name: "NtGdiCreateEllipticRgn",
    },
    SyscallIndexEntry {
        number: 0x113C,
        name: "NtGdiCreateHatchBrushInternal",
    },
    SyscallIndexEntry {
        number: 0x113D,
        name: "NtGdiCreateMetafileDC",
    },
    SyscallIndexEntry {
        number: 0x113E,
        name: "NtGdiCreateOPMProtectedOutputs",
    },
    SyscallIndexEntry {
        number: 0x113F,
        name: "NtGdiCreateRoundRectRgn",
    },
    SyscallIndexEntry {
        number: 0x1140,
        name: "NtGdiCreateServerMetaFile",
    },
    SyscallIndexEntry {
        number: 0x1141,
        name: "NtGdiD3dContextCreate",
    },
    SyscallIndexEntry {
        number: 0x1142,
        name: "NtGdiD3dContextDestroy",
    },
    SyscallIndexEntry {
        number: 0x1143,
        name: "NtGdiD3dContextDestroyAll",
    },
    SyscallIndexEntry {
        number: 0x1144,
        name: "NtGdiD3dValidateTextureStageState",
    },
    SyscallIndexEntry {
        number: 0x1145,
        name: "NtGdiDDCCIGetCapabilitiesString",
    },
    SyscallIndexEntry {
        number: 0x1146,
        name: "NtGdiDDCCIGetCapabilitiesStringLength",
    },
    SyscallIndexEntry {
        number: 0x1147,
        name: "NtGdiDDCCIGetTimingReport",
    },
    SyscallIndexEntry {
        number: 0x1148,
        name: "NtGdiDDCCIGetVCPFeature",
    },
    SyscallIndexEntry {
        number: 0x1149,
        name: "NtGdiDDCCISaveCurrentSettings",
    },
    SyscallIndexEntry {
        number: 0x114A,
        name: "NtGdiDDCCISetVCPFeature",
    },
    SyscallIndexEntry {
        number: 0x114B,
        name: "NtGdiDdAddAttachedSurface",
    },
    SyscallIndexEntry {
        number: 0x114C,
        name: "NtGdiDdAlphaBlt",
    },
    SyscallIndexEntry {
        number: 0x114D,
        name: "NtGdiDdAttachSurface",
    },
    SyscallIndexEntry {
        number: 0x114E,
        name: "NtGdiDdBeginMoCompFrame",
    },
    SyscallIndexEntry {
        number: 0x114F,
        name: "NtGdiDdCanCreateD3DBuffer",
    },
    SyscallIndexEntry {
        number: 0x1150,
        name: "NtGdiDdColorControl",
    },
    SyscallIndexEntry {
        number: 0x1151,
        name: "NtGdiDdCreateD3DBuffer",
    },
    SyscallIndexEntry {
        number: 0x1152,
        name: "NtGdiDdCreateDirectDrawObject",
    },
    SyscallIndexEntry {
        number: 0x1153,
        name: "NtGdiDdCreateFullscreenSprite",
    },
    SyscallIndexEntry {
        number: 0x1154,
        name: "NtGdiDdCreateMoComp",
    },
    SyscallIndexEntry {
        number: 0x1155,
        name: "NtGdiDdDDIAcquireKeyedMutex",
    },
    SyscallIndexEntry {
        number: 0x1156,
        name: "NtGdiDdDDICheckExclusiveOwnership",
    },
    SyscallIndexEntry {
        number: 0x1157,
        name: "NtGdiDdDDICheckMonitorPowerState",
    },
    SyscallIndexEntry {
        number: 0x1158,
        name: "NtGdiDdDDICheckOcclusion",
    },
    SyscallIndexEntry {
        number: 0x1159,
        name: "NtGdiDdDDICheckSharedResourceAccess",
    },
    SyscallIndexEntry {
        number: 0x115A,
        name: "NtGdiDdDDICheckVidPnExclusiveOwnership",
    },
    SyscallIndexEntry {
        number: 0x115B,
        name: "NtGdiDdDDICloseAdapter",
    },
    SyscallIndexEntry {
        number: 0x115C,
        name: "NtGdiDdDDIConfigureSharedResource",
    },
    SyscallIndexEntry {
        number: 0x115D,
        name: "NtGdiDdDDICreateAllocation",
    },
    SyscallIndexEntry {
        number: 0x115E,
        name: "NtGdiDdDDICreateContext",
    },
    SyscallIndexEntry {
        number: 0x115F,
        name: "NtGdiDdDDICreateDCFromMemory",
    },
    SyscallIndexEntry {
        number: 0x1160,
        name: "NtGdiDdDDICreateDevice",
    },
    SyscallIndexEntry {
        number: 0x1161,
        name: "NtGdiDdDDICreateKeyedMutex",
    },
    SyscallIndexEntry {
        number: 0x1162,
        name: "NtGdiDdDDICreateOverlay",
    },
    SyscallIndexEntry {
        number: 0x1163,
        name: "NtGdiDdDDICreateSynchronizationObject",
    },
    SyscallIndexEntry {
        number: 0x1164,
        name: "NtGdiDdDDIDestroyAllocation",
    },
    SyscallIndexEntry {
        number: 0x1165,
        name: "NtGdiDdDDIDestroyContext",
    },
    SyscallIndexEntry {
        number: 0x1166,
        name: "NtGdiDdDDIDestroyDCFromMemory",
    },
    SyscallIndexEntry {
        number: 0x1167,
        name: "NtGdiDdDDIDestroyDevice",
    },
    SyscallIndexEntry {
        number: 0x1168,
        name: "NtGdiDdDDIDestroyKeyedMutex",
    },
    SyscallIndexEntry {
        number: 0x1169,
        name: "NtGdiDdDDIDestroyOverlay",
    },
    SyscallIndexEntry {
        number: 0x116A,
        name: "NtGdiDdDDIDestroySynchronizationObject",
    },
    SyscallIndexEntry {
        number: 0x116B,
        name: "NtGdiDdDDIEscape",
    },
    SyscallIndexEntry {
        number: 0x116C,
        name: "NtGdiDdDDIFlipOverlay",
    },
    SyscallIndexEntry {
        number: 0x116D,
        name: "NtGdiDdDDIGetContextSchedulingPriority",
    },
    SyscallIndexEntry {
        number: 0x116E,
        name: "NtGdiDdDDIGetDeviceState",
    },
    SyscallIndexEntry {
        number: 0x116F,
        name: "NtGdiDdDDIGetDisplayModeList",
    },
    SyscallIndexEntry {
        number: 0x1170,
        name: "NtGdiDdDDIGetMultisampleMethodList",
    },
    SyscallIndexEntry {
        number: 0x1171,
        name: "NtGdiDdDDIGetOverlayState",
    },
    SyscallIndexEntry {
        number: 0x1172,
        name: "NtGdiDdDDIGetPresentHistory",
    },
    SyscallIndexEntry {
        number: 0x1173,
        name: "NtGdiDdDDIGetPresentQueueEvent",
    },
    SyscallIndexEntry {
        number: 0x1174,
        name: "NtGdiDdDDIGetProcessSchedulingPriorityClass",
    },
    SyscallIndexEntry {
        number: 0x1175,
        name: "NtGdiDdDDIGetRuntimeData",
    },
    SyscallIndexEntry {
        number: 0x1176,
        name: "NtGdiDdDDIGetScanLine",
    },
    SyscallIndexEntry {
        number: 0x1177,
        name: "NtGdiDdDDIGetSharedPrimaryHandle",
    },
    SyscallIndexEntry {
        number: 0x1178,
        name: "NtGdiDdDDIInvalidateActiveVidPn",
    },
    SyscallIndexEntry {
        number: 0x1179,
        name: "NtGdiDdDDILock",
    },
    SyscallIndexEntry {
        number: 0x117A,
        name: "NtGdiDdDDIOpenAdapterFromDeviceName",
    },
    SyscallIndexEntry {
        number: 0x117B,
        name: "NtGdiDdDDIOpenAdapterFromHdc",
    },
    SyscallIndexEntry {
        number: 0x117C,
        name: "NtGdiDdDDIOpenKeyedMutex",
    },
    SyscallIndexEntry {
        number: 0x117D,
        name: "NtGdiDdDDIOpenResource",
    },
    SyscallIndexEntry {
        number: 0x117E,
        name: "NtGdiDdDDIOpenSynchronizationObject",
    },
    SyscallIndexEntry {
        number: 0x117F,
        name: "NtGdiDdDDIPollDisplayChildren",
    },
    SyscallIndexEntry {
        number: 0x1180,
        name: "NtGdiDdDDIPresent",
    },
    SyscallIndexEntry {
        number: 0x1181,
        name: "NtGdiDdDDIQueryAdapterInfo",
    },
    SyscallIndexEntry {
        number: 0x1182,
        name: "NtGdiDdDDIQueryAllocationResidency",
    },
    SyscallIndexEntry {
        number: 0x1183,
        name: "NtGdiDdDDIQueryResourceInfo",
    },
    SyscallIndexEntry {
        number: 0x1184,
        name: "NtGdiDdDDIQueryStatistics",
    },
    SyscallIndexEntry {
        number: 0x1185,
        name: "NtGdiDdDDIReleaseKeyedMutex",
    },
    SyscallIndexEntry {
        number: 0x1186,
        name: "NtGdiDdDDIReleaseProcessVidPnSourceOwners",
    },
    SyscallIndexEntry {
        number: 0x1187,
        name: "NtGdiDdDDIRender",
    },
    SyscallIndexEntry {
        number: 0x1188,
        name: "NtGdiDdDDISetAllocationPriority",
    },
    SyscallIndexEntry {
        number: 0x1189,
        name: "NtGdiDdDDISetContextSchedulingPriority",
    },
    SyscallIndexEntry {
        number: 0x118A,
        name: "NtGdiDdDDISetDisplayMode",
    },
    SyscallIndexEntry {
        number: 0x118B,
        name: "NtGdiDdDDISetDisplayPrivateDriverFormat",
    },
    SyscallIndexEntry {
        number: 0x118C,
        name: "NtGdiDdDDISetGammaRamp",
    },
    SyscallIndexEntry {
        number: 0x118D,
        name: "NtGdiDdDDISetProcessSchedulingPriorityClass",
    },
    SyscallIndexEntry {
        number: 0x118E,
        name: "NtGdiDdDDISetQueuedLimit",
    },
    SyscallIndexEntry {
        number: 0x118F,
        name: "NtGdiDdDDISetVidPnSourceOwner",
    },
    SyscallIndexEntry {
        number: 0x1190,
        name: "NtGdiDdDDISharedPrimaryLockNotification",
    },
    SyscallIndexEntry {
        number: 0x1191,
        name: "NtGdiDdDDISharedPrimaryUnLockNotification",
    },
    SyscallIndexEntry {
        number: 0x1192,
        name: "NtGdiDdDDISignalSynchronizationObject",
    },
    SyscallIndexEntry {
        number: 0x1193,
        name: "NtGdiDdDDIUnlock",
    },
    SyscallIndexEntry {
        number: 0x1194,
        name: "NtGdiDdDDIUpdateOverlay",
    },
    SyscallIndexEntry {
        number: 0x1195,
        name: "NtGdiDdDDIWaitForIdle",
    },
    SyscallIndexEntry {
        number: 0x1196,
        name: "NtGdiDdDDIWaitForSynchronizationObject",
    },
    SyscallIndexEntry {
        number: 0x1197,
        name: "NtGdiDdDDIWaitForVerticalBlankEvent",
    },
    SyscallIndexEntry {
        number: 0x1198,
        name: "NtGdiDdDeleteDirectDrawObject",
    },
    SyscallIndexEntry {
        number: 0x1199,
        name: "NtGdiDdDestroyD3DBuffer",
    },
    SyscallIndexEntry {
        number: 0x119A,
        name: "NtGdiDdDestroyFullscreenSprite",
    },
    SyscallIndexEntry {
        number: 0x119B,
        name: "NtGdiDdDestroyMoComp",
    },
    SyscallIndexEntry {
        number: 0x119C,
        name: "NtGdiDdEndMoCompFrame",
    },
    SyscallIndexEntry {
        number: 0x119D,
        name: "NtGdiDdFlip",
    },
    SyscallIndexEntry {
        number: 0x119E,
        name: "NtGdiDdFlipToGDISurface",
    },
    SyscallIndexEntry {
        number: 0x119F,
        name: "NtGdiDdGetAvailDriverMemory",
    },
    SyscallIndexEntry {
        number: 0x11A0,
        name: "NtGdiDdGetBltStatus",
    },
    SyscallIndexEntry {
        number: 0x11A1,
        name: "NtGdiDdGetDC",
    },
    SyscallIndexEntry {
        number: 0x11A2,
        name: "NtGdiDdGetDriverInfo",
    },
    SyscallIndexEntry {
        number: 0x11A3,
        name: "NtGdiDdGetDriverState",
    },
    SyscallIndexEntry {
        number: 0x11A4,
        name: "NtGdiDdGetDxHandle",
    },
    SyscallIndexEntry {
        number: 0x11A5,
        name: "NtGdiDdGetFlipStatus",
    },
    SyscallIndexEntry {
        number: 0x11A6,
        name: "NtGdiDdGetInternalMoCompInfo",
    },
    SyscallIndexEntry {
        number: 0x11A7,
        name: "NtGdiDdGetMoCompBuffInfo",
    },
    SyscallIndexEntry {
        number: 0x11A8,
        name: "NtGdiDdGetMoCompFormats",
    },
    SyscallIndexEntry {
        number: 0x11A9,
        name: "NtGdiDdGetMoCompGuids",
    },
    SyscallIndexEntry {
        number: 0x11AA,
        name: "NtGdiDdGetScanLine",
    },
    SyscallIndexEntry {
        number: 0x11AB,
        name: "NtGdiDdLock",
    },
    SyscallIndexEntry {
        number: 0x11AC,
        name: "NtGdiDdNotifyFullscreenSpriteUpdate",
    },
    SyscallIndexEntry {
        number: 0x11AD,
        name: "NtGdiDdQueryDirectDrawObject",
    },
    SyscallIndexEntry {
        number: 0x11AE,
        name: "NtGdiDdQueryMoCompStatus",
    },
    SyscallIndexEntry {
        number: 0x11AF,
        name: "NtGdiDdQueryVisRgnUniqueness",
    },
    SyscallIndexEntry {
        number: 0x11B0,
        name: "NtGdiDdReenableDirectDrawObject",
    },
    SyscallIndexEntry {
        number: 0x11B1,
        name: "NtGdiDdReleaseDC",
    },
    SyscallIndexEntry {
        number: 0x11B2,
        name: "NtGdiDdRenderMoComp",
    },
    SyscallIndexEntry {
        number: 0x11B3,
        name: "NtGdiDdSetColorKey",
    },
    SyscallIndexEntry {
        number: 0x11B4,
        name: "NtGdiDdSetExclusiveMode",
    },
    SyscallIndexEntry {
        number: 0x11B5,
        name: "NtGdiDdSetGammaRamp",
    },
    SyscallIndexEntry {
        number: 0x11B6,
        name: "NtGdiDdSetOverlayPosition",
    },
    SyscallIndexEntry {
        number: 0x11B7,
        name: "NtGdiDdUnattachSurface",
    },
    SyscallIndexEntry {
        number: 0x11B8,
        name: "NtGdiDdUnlock",
    },
    SyscallIndexEntry {
        number: 0x11B9,
        name: "NtGdiDdUpdateOverlay",
    },
    SyscallIndexEntry {
        number: 0x11BA,
        name: "NtGdiDdWaitForVerticalBlank",
    },
    SyscallIndexEntry {
        number: 0x11BB,
        name: "NtGdiDeleteColorTransform",
    },
    SyscallIndexEntry {
        number: 0x11BC,
        name: "NtGdiDescribePixelFormat",
    },
    SyscallIndexEntry {
        number: 0x11BD,
        name: "NtGdiDestroyOPMProtectedOutput",
    },
    SyscallIndexEntry {
        number: 0x11BE,
        name: "NtGdiDestroyPhysicalMonitor",
    },
    SyscallIndexEntry {
        number: 0x11BF,
        name: "NtGdiDoBanding",
    },
    SyscallIndexEntry {
        number: 0x11C0,
        name: "NtGdiDrawEscape",
    },
    SyscallIndexEntry {
        number: 0x11C1,
        name: "NtGdiDvpAcquireNotification",
    },
    SyscallIndexEntry {
        number: 0x11C2,
        name: "NtGdiDvpCanCreateVideoPort",
    },
    SyscallIndexEntry {
        number: 0x11C3,
        name: "NtGdiDvpColorControl",
    },
    SyscallIndexEntry {
        number: 0x11C4,
        name: "NtGdiDvpCreateVideoPort",
    },
    SyscallIndexEntry {
        number: 0x11C5,
        name: "NtGdiDvpDestroyVideoPort",
    },
    SyscallIndexEntry {
        number: 0x11C6,
        name: "NtGdiDvpFlipVideoPort",
    },
    SyscallIndexEntry {
        number: 0x11C7,
        name: "NtGdiDvpGetVideoPortBandwidth",
    },
    SyscallIndexEntry {
        number: 0x11C8,
        name: "NtGdiDvpGetVideoPortConnectInfo",
    },
    SyscallIndexEntry {
        number: 0x11C9,
        name: "NtGdiDvpGetVideoPortField",
    },
    SyscallIndexEntry {
        number: 0x11CA,
        name: "NtGdiDvpGetVideoPortFlipStatus",
    },
    SyscallIndexEntry {
        number: 0x11CB,
        name: "NtGdiDvpGetVideoPortInputFormats",
    },
    SyscallIndexEntry {
        number: 0x11CC,
        name: "NtGdiDvpGetVideoPortLine",
    },
    SyscallIndexEntry {
        number: 0x11CD,
        name: "NtGdiDvpGetVideoPortOutputFormats",
    },
    SyscallIndexEntry {
        number: 0x11CE,
        name: "NtGdiDvpGetVideoSignalStatus",
    },
    SyscallIndexEntry {
        number: 0x11CF,
        name: "NtGdiDvpReleaseNotification",
    },
    SyscallIndexEntry {
        number: 0x11D0,
        name: "NtGdiDvpUpdateVideoPort",
    },
    SyscallIndexEntry {
        number: 0x11D1,
        name: "NtGdiDvpWaitForVideoPortSync",
    },
    SyscallIndexEntry {
        number: 0x11D2,
        name: "NtGdiDxgGenericThunk",
    },
    SyscallIndexEntry {
        number: 0x11D3,
        name: "NtGdiEllipse",
    },
    SyscallIndexEntry {
        number: 0x11D4,
        name: "NtGdiEnableEudc",
    },
    SyscallIndexEntry {
        number: 0x11D5,
        name: "NtGdiEndDoc",
    },
    SyscallIndexEntry {
        number: 0x11D6,
        name: "NtGdiEndGdiRendering",
    },
    SyscallIndexEntry {
        number: 0x11D7,
        name: "NtGdiEndPage",
    },
    SyscallIndexEntry {
        number: 0x11D8,
        name: "NtGdiEngAlphaBlend",
    },
    SyscallIndexEntry {
        number: 0x11D9,
        name: "NtGdiEngAssociateSurface",
    },
    SyscallIndexEntry {
        number: 0x11DA,
        name: "NtGdiEngBitBlt",
    },
    SyscallIndexEntry {
        number: 0x11DB,
        name: "NtGdiEngCheckAbort",
    },
    SyscallIndexEntry {
        number: 0x11DC,
        name: "NtGdiEngComputeGlyphSet",
    },
    SyscallIndexEntry {
        number: 0x11DD,
        name: "NtGdiEngCopyBits",
    },
    SyscallIndexEntry {
        number: 0x11DE,
        name: "NtGdiEngCreateBitmap",
    },
    SyscallIndexEntry {
        number: 0x11DF,
        name: "NtGdiEngCreateClip",
    },
    SyscallIndexEntry {
        number: 0x11E0,
        name: "NtGdiEngCreateDeviceBitmap",
    },
    SyscallIndexEntry {
        number: 0x11E1,
        name: "NtGdiEngCreateDeviceSurface",
    },
    SyscallIndexEntry {
        number: 0x11E2,
        name: "NtGdiEngCreatePalette",
    },
    SyscallIndexEntry {
        number: 0x11E3,
        name: "NtGdiEngDeleteClip",
    },
    SyscallIndexEntry {
        number: 0x11E4,
        name: "NtGdiEngDeletePalette",
    },
    SyscallIndexEntry {
        number: 0x11E5,
        name: "NtGdiEngDeletePath",
    },
    SyscallIndexEntry {
        number: 0x11E6,
        name: "NtGdiEngDeleteSurface",
    },
    SyscallIndexEntry {
        number: 0x11E7,
        name: "NtGdiEngEraseSurface",
    },
    SyscallIndexEntry {
        number: 0x11E8,
        name: "NtGdiEngFillPath",
    },
    SyscallIndexEntry {
        number: 0x11E9,
        name: "NtGdiEngGradientFill",
    },
    SyscallIndexEntry {
        number: 0x11EA,
        name: "NtGdiEngLineTo",
    },
    SyscallIndexEntry {
        number: 0x11EB,
        name: "NtGdiEngLockSurface",
    },
    SyscallIndexEntry {
        number: 0x11EC,
        name: "NtGdiEngMarkBandingSurface",
    },
    SyscallIndexEntry {
        number: 0x11ED,
        name: "NtGdiEngPaint",
    },
    SyscallIndexEntry {
        number: 0x11EE,
        name: "NtGdiEngPlgBlt",
    },
    SyscallIndexEntry {
        number: 0x11EF,
        name: "NtGdiEngStretchBlt",
    },
    SyscallIndexEntry {
        number: 0x11F0,
        name: "NtGdiEngStretchBltROP",
    },
    SyscallIndexEntry {
        number: 0x11F1,
        name: "NtGdiEngStrokeAndFillPath",
    },
    SyscallIndexEntry {
        number: 0x11F2,
        name: "NtGdiEngStrokePath",
    },
    SyscallIndexEntry {
        number: 0x11F3,
        name: "NtGdiEngTextOut",
    },
    SyscallIndexEntry {
        number: 0x11F4,
        name: "NtGdiEngTransparentBlt",
    },
    SyscallIndexEntry {
        number: 0x11F5,
        name: "NtGdiEngUnlockSurface",
    },
    SyscallIndexEntry {
        number: 0x11F6,
        name: "NtGdiEnumFonts",
    },
    SyscallIndexEntry {
        number: 0x11F7,
        name: "NtGdiEnumObjects",
    },
    SyscallIndexEntry {
        number: 0x11F8,
        name: "NtGdiEudcLoadUnloadLink",
    },
    SyscallIndexEntry {
        number: 0x11F9,
        name: "NtGdiExtFloodFill",
    },
    SyscallIndexEntry {
        number: 0x11FA,
        name: "NtGdiFONTOBJ_cGetAllGlyphHandles",
    },
    SyscallIndexEntry {
        number: 0x11FB,
        name: "NtGdiFONTOBJ_cGetGlyphs",
    },
    SyscallIndexEntry {
        number: 0x11FC,
        name: "NtGdiFONTOBJ_pQueryGlyphAttrs",
    },
    SyscallIndexEntry {
        number: 0x11FD,
        name: "NtGdiFONTOBJ_pfdg",
    },
    SyscallIndexEntry {
        number: 0x11FE,
        name: "NtGdiFONTOBJ_pifi",
    },
    SyscallIndexEntry {
        number: 0x11FF,
        name: "NtGdiFONTOBJ_pvTrueTypeFontFile",
    },
    SyscallIndexEntry {
        number: 0x1200,
        name: "NtGdiFONTOBJ_pxoGetXform",
    },
    SyscallIndexEntry {
        number: 0x1201,
        name: "NtGdiFONTOBJ_vGetInfo",
    },
    SyscallIndexEntry {
        number: 0x1202,
        name: "NtGdiFlattenPath",
    },
    SyscallIndexEntry {
        number: 0x1203,
        name: "NtGdiFontIsLinked",
    },
    SyscallIndexEntry {
        number: 0x1204,
        name: "NtGdiForceUFIMapping",
    },
    SyscallIndexEntry {
        number: 0x1205,
        name: "NtGdiFrameRgn",
    },
    SyscallIndexEntry {
        number: 0x1206,
        name: "NtGdiFullscreenControl",
    },
    SyscallIndexEntry {
        number: 0x1207,
        name: "NtGdiGetBoundsRect",
    },
    SyscallIndexEntry {
        number: 0x1208,
        name: "NtGdiGetCOPPCompatibleOPMInformation",
    },
    SyscallIndexEntry {
        number: 0x1209,
        name: "NtGdiGetCertificate",
    },
    SyscallIndexEntry {
        number: 0x120A,
        name: "NtGdiGetCertificateSize",
    },
    SyscallIndexEntry {
        number: 0x120B,
        name: "NtGdiGetCharABCWidthsW",
    },
    SyscallIndexEntry {
        number: 0x120C,
        name: "NtGdiGetCharacterPlacementW",
    },
    SyscallIndexEntry {
        number: 0x120D,
        name: "NtGdiGetColorAdjustment",
    },
    SyscallIndexEntry {
        number: 0x120E,
        name: "NtGdiGetColorSpaceforBitmap",
    },
    SyscallIndexEntry {
        number: 0x120F,
        name: "NtGdiGetDeviceCaps",
    },
    SyscallIndexEntry {
        number: 0x1210,
        name: "NtGdiGetDeviceCapsAll",
    },
    SyscallIndexEntry {
        number: 0x1211,
        name: "NtGdiGetDeviceGammaRamp",
    },
    SyscallIndexEntry {
        number: 0x1212,
        name: "NtGdiGetDeviceWidth",
    },
    SyscallIndexEntry {
        number: 0x1213,
        name: "NtGdiGetDhpdev",
    },
    SyscallIndexEntry {
        number: 0x1214,
        name: "NtGdiGetETM",
    },
    SyscallIndexEntry {
        number: 0x1215,
        name: "NtGdiGetEmbUFI",
    },
    SyscallIndexEntry {
        number: 0x1216,
        name: "NtGdiGetEmbedFonts",
    },
    SyscallIndexEntry {
        number: 0x1217,
        name: "NtGdiGetEudcTimeStampEx",
    },
    SyscallIndexEntry {
        number: 0x1218,
        name: "NtGdiGetFontFileData",
    },
    SyscallIndexEntry {
        number: 0x1219,
        name: "NtGdiGetFontFileInfo",
    },
    SyscallIndexEntry {
        number: 0x121A,
        name: "NtGdiGetFontResourceInfoInternalW",
    },
    SyscallIndexEntry {
        number: 0x121B,
        name: "NtGdiGetFontUnicodeRanges",
    },
    SyscallIndexEntry {
        number: 0x121C,
        name: "NtGdiGetGlyphIndicesW",
    },
    SyscallIndexEntry {
        number: 0x121D,
        name: "NtGdiGetGlyphIndicesWInternal",
    },
    SyscallIndexEntry {
        number: 0x121E,
        name: "NtGdiGetGlyphOutline",
    },
    SyscallIndexEntry {
        number: 0x121F,
        name: "NtGdiGetKerningPairs",
    },
    SyscallIndexEntry {
        number: 0x1220,
        name: "NtGdiGetLinkedUFIs",
    },
    SyscallIndexEntry {
        number: 0x1221,
        name: "NtGdiGetMiterLimit",
    },
    SyscallIndexEntry {
        number: 0x1222,
        name: "NtGdiGetMonitorID",
    },
    SyscallIndexEntry {
        number: 0x1223,
        name: "NtGdiGetNumberOfPhysicalMonitors",
    },
    SyscallIndexEntry {
        number: 0x1224,
        name: "NtGdiGetOPMInformation",
    },
    SyscallIndexEntry {
        number: 0x1225,
        name: "NtGdiGetOPMRandomNumber",
    },
    SyscallIndexEntry {
        number: 0x1226,
        name: "NtGdiGetObjectBitmapHandle",
    },
    SyscallIndexEntry {
        number: 0x1227,
        name: "NtGdiGetPath",
    },
    SyscallIndexEntry {
        number: 0x1228,
        name: "NtGdiGetPerBandInfo",
    },
    SyscallIndexEntry {
        number: 0x1229,
        name: "NtGdiGetPhysicalMonitorDescription",
    },
    SyscallIndexEntry {
        number: 0x122A,
        name: "NtGdiGetPhysicalMonitors",
    },
    SyscallIndexEntry {
        number: 0x122B,
        name: "NtGdiGetRealizationInfo",
    },
    SyscallIndexEntry {
        number: 0x122C,
        name: "NtGdiGetServerMetaFileBits",
    },
    SyscallIndexEntry {
        number: 0x122D,
        name: "NtGdiGetSpoolMessage",
    },
    SyscallIndexEntry {
        number: 0x122E,
        name: "NtGdiGetStats",
    },
    SyscallIndexEntry {
        number: 0x122F,
        name: "NtGdiGetStringBitmapW",
    },
    SyscallIndexEntry {
        number: 0x1230,
        name: "NtGdiGetSuggestedOPMProtectedOutputArraySize",
    },
    SyscallIndexEntry {
        number: 0x1231,
        name: "NtGdiGetTextExtentExW",
    },
    SyscallIndexEntry {
        number: 0x1232,
        name: "NtGdiGetUFI",
    },
    SyscallIndexEntry {
        number: 0x1233,
        name: "NtGdiGetUFIPathname",
    },
    SyscallIndexEntry {
        number: 0x1234,
        name: "NtGdiGradientFill",
    },
    SyscallIndexEntry {
        number: 0x1235,
        name: "NtGdiHLSurfGetInformation",
    },
    SyscallIndexEntry {
        number: 0x1236,
        name: "NtGdiHLSurfSetInformation",
    },
    SyscallIndexEntry {
        number: 0x1237,
        name: "NtGdiHT_Get8BPPFormatPalette",
    },
    SyscallIndexEntry {
        number: 0x1238,
        name: "NtGdiHT_Get8BPPMaskPalette",
    },
    SyscallIndexEntry {
        number: 0x1239,
        name: "NtGdiIcmBrushInfo",
    },
    SyscallIndexEntry {
        number: 0x123A,
        name: "NtGdiInit",
    },
    SyscallIndexEntry {
        number: 0x123B,
        name: "NtGdiInitSpool",
    },
    SyscallIndexEntry {
        number: 0x123C,
        name: "NtGdiMakeFontDir",
    },
    SyscallIndexEntry {
        number: 0x123D,
        name: "NtGdiMakeInfoDC",
    },
    SyscallIndexEntry {
        number: 0x123E,
        name: "NtGdiMakeObjectUnXferable",
    },
    SyscallIndexEntry {
        number: 0x123F,
        name: "NtGdiMakeObjectXferable",
    },
    SyscallIndexEntry {
        number: 0x1240,
        name: "NtGdiMirrorWindowOrg",
    },
    SyscallIndexEntry {
        number: 0x1241,
        name: "NtGdiMonoBitmap",
    },
    SyscallIndexEntry {
        number: 0x1242,
        name: "NtGdiMoveTo",
    },
    SyscallIndexEntry {
        number: 0x1243,
        name: "NtGdiOffsetClipRgn",
    },
    SyscallIndexEntry {
        number: 0x1244,
        name: "NtGdiPATHOBJ_bEnum",
    },
    SyscallIndexEntry {
        number: 0x1245,
        name: "NtGdiPATHOBJ_bEnumClipLines",
    },
    SyscallIndexEntry {
        number: 0x1246,
        name: "NtGdiPATHOBJ_vEnumStart",
    },
    SyscallIndexEntry {
        number: 0x1247,
        name: "NtGdiPATHOBJ_vEnumStartClipLines",
    },
    SyscallIndexEntry {
        number: 0x1248,
        name: "NtGdiPATHOBJ_vGetBounds",
    },
    SyscallIndexEntry {
        number: 0x1249,
        name: "NtGdiPathToRegion",
    },
    SyscallIndexEntry {
        number: 0x124A,
        name: "NtGdiPlgBlt",
    },
    SyscallIndexEntry {
        number: 0x124B,
        name: "NtGdiPolyDraw",
    },
    SyscallIndexEntry {
        number: 0x124C,
        name: "NtGdiPolyTextOutW",
    },
    SyscallIndexEntry {
        number: 0x124D,
        name: "NtGdiPtInRegion",
    },
    SyscallIndexEntry {
        number: 0x124E,
        name: "NtGdiPtVisible",
    },
    SyscallIndexEntry {
        number: 0x124F,
        name: "NtGdiQueryFonts",
    },
    SyscallIndexEntry {
        number: 0x1250,
        name: "NtGdiRemoveFontResourceW",
    },
    SyscallIndexEntry {
        number: 0x1251,
        name: "NtGdiRemoveMergeFont",
    },
    SyscallIndexEntry {
        number: 0x1252,
        name: "NtGdiResetDC",
    },
    SyscallIndexEntry {
        number: 0x1253,
        name: "NtGdiResizePalette",
    },
    SyscallIndexEntry {
        number: 0x1254,
        name: "NtGdiRoundRect",
    },
    SyscallIndexEntry {
        number: 0x1255,
        name: "NtGdiSTROBJ_bEnum",
    },
    SyscallIndexEntry {
        number: 0x1256,
        name: "NtGdiSTROBJ_bEnumPositionsOnly",
    },
    SyscallIndexEntry {
        number: 0x1257,
        name: "NtGdiSTROBJ_bGetAdvanceWidths",
    },
    SyscallIndexEntry {
        number: 0x1258,
        name: "NtGdiSTROBJ_dwGetCodePage",
    },
    SyscallIndexEntry {
        number: 0x1259,
        name: "NtGdiSTROBJ_vEnumStart",
    },
    SyscallIndexEntry {
        number: 0x125A,
        name: "NtGdiScaleViewportExtEx",
    },
    SyscallIndexEntry {
        number: 0x125B,
        name: "NtGdiScaleWindowExtEx",
    },
    SyscallIndexEntry {
        number: 0x125C,
        name: "NtGdiSelectBrush",
    },
    SyscallIndexEntry {
        number: 0x125D,
        name: "NtGdiSelectClipPath",
    },
    SyscallIndexEntry {
        number: 0x125E,
        name: "NtGdiSelectPen",
    },
    SyscallIndexEntry {
        number: 0x125F,
        name: "NtGdiSetBitmapAttributes",
    },
    SyscallIndexEntry {
        number: 0x1260,
        name: "NtGdiSetBrushAttributes",
    },
    SyscallIndexEntry {
        number: 0x1261,
        name: "NtGdiSetColorAdjustment",
    },
    SyscallIndexEntry {
        number: 0x1262,
        name: "NtGdiSetColorSpace",
    },
    SyscallIndexEntry {
        number: 0x1263,
        name: "NtGdiSetDeviceGammaRamp",
    },
    SyscallIndexEntry {
        number: 0x1264,
        name: "NtGdiSetFontXform",
    },
    SyscallIndexEntry {
        number: 0x1265,
        name: "NtGdiSetIcmMode",
    },
    SyscallIndexEntry {
        number: 0x1266,
        name: "NtGdiSetLinkedUFIs",
    },
    SyscallIndexEntry {
        number: 0x1267,
        name: "NtGdiSetMagicColors",
    },
    SyscallIndexEntry {
        number: 0x1268,
        name: "NtGdiSetOPMSigningKeyAndSequenceNumbers",
    },
    SyscallIndexEntry {
        number: 0x1269,
        name: "NtGdiSetPUMPDOBJ",
    },
    SyscallIndexEntry {
        number: 0x126A,
        name: "NtGdiSetPixelFormat",
    },
    SyscallIndexEntry {
        number: 0x126B,
        name: "NtGdiSetRectRgn",
    },
    SyscallIndexEntry {
        number: 0x126C,
        name: "NtGdiSetSizeDevice",
    },
    SyscallIndexEntry {
        number: 0x126D,
        name: "NtGdiSetSystemPaletteUse",
    },
    SyscallIndexEntry {
        number: 0x126E,
        name: "NtGdiSetTextJustification",
    },
    SyscallIndexEntry {
        number: 0x126F,
        name: "NtGdiSfmGetNotificationTokens",
    },
    SyscallIndexEntry {
        number: 0x1270,
        name: "NtGdiStartDoc",
    },
    SyscallIndexEntry {
        number: 0x1271,
        name: "NtGdiStartPage",
    },
    SyscallIndexEntry {
        number: 0x1272,
        name: "NtGdiStrokeAndFillPath",
    },
    SyscallIndexEntry {
        number: 0x1273,
        name: "NtGdiStrokePath",
    },
    SyscallIndexEntry {
        number: 0x1274,
        name: "NtGdiSwapBuffers",
    },
    SyscallIndexEntry {
        number: 0x1275,
        name: "NtGdiTransparentBlt",
    },
    SyscallIndexEntry {
        number: 0x1276,
        name: "NtGdiUMPDEngFreeUserMem",
    },
    SyscallIndexEntry {
        number: 0x1277,
        name: "NtGdiUnloadPrinterDriver",
    },
    SyscallIndexEntry {
        number: 0x1278,
        name: "NtGdiUnmapMemFont",
    },
    SyscallIndexEntry {
        number: 0x1279,
        name: "NtGdiUpdateColors",
    },
    SyscallIndexEntry {
        number: 0x127A,
        name: "NtGdiUpdateTransform",
    },
    SyscallIndexEntry {
        number: 0x127B,
        name: "NtGdiWidenPath",
    },
    SyscallIndexEntry {
        number: 0x127C,
        name: "NtGdiXFORMOBJ_bApplyXform",
    },
    SyscallIndexEntry {
        number: 0x127D,
        name: "NtGdiXFORMOBJ_iGetXform",
    },
    SyscallIndexEntry {
        number: 0x127E,
        name: "NtGdiXLATEOBJ_cGetPalette",
    },
    SyscallIndexEntry {
        number: 0x127F,
        name: "NtGdiXLATEOBJ_hGetColorTransform",
    },
    SyscallIndexEntry {
        number: 0x1280,
        name: "NtGdiXLATEOBJ_iXlate",
    },
    SyscallIndexEntry {
        number: 0x1281,
        name: "NtUserAddClipboardFormatListener",
    },
    SyscallIndexEntry {
        number: 0x1282,
        name: "NtUserAssociateInputContext",
    },
    SyscallIndexEntry {
        number: 0x1283,
        name: "NtUserBlockInput",
    },
    SyscallIndexEntry {
        number: 0x1284,
        name: "NtUserBuildHimcList",
    },
    SyscallIndexEntry {
        number: 0x1285,
        name: "NtUserBuildPropList",
    },
    SyscallIndexEntry {
        number: 0x1286,
        name: "NtUserCalculatePopupWindowPosition",
    },
    SyscallIndexEntry {
        number: 0x1287,
        name: "NtUserCallHwndOpt",
    },
    SyscallIndexEntry {
        number: 0x1288,
        name: "NtUserChangeDisplaySettings",
    },
    SyscallIndexEntry {
        number: 0x1289,
        name: "NtUserChangeWindowMessageFilterEx",
    },
    SyscallIndexEntry {
        number: 0x128A,
        name: "NtUserCheckAccessForIntegrityLevel",
    },
    SyscallIndexEntry {
        number: 0x128B,
        name: "NtUserCheckDesktopByThreadId",
    },
    SyscallIndexEntry {
        number: 0x128C,
        name: "NtUserCheckWindowThreadDesktop",
    },
    SyscallIndexEntry {
        number: 0x128D,
        name: "NtUserChildWindowFromPointEx",
    },
    SyscallIndexEntry {
        number: 0x128E,
        name: "NtUserClipCursor",
    },
    SyscallIndexEntry {
        number: 0x128F,
        name: "NtUserCreateDesktopEx",
    },
    SyscallIndexEntry {
        number: 0x1290,
        name: "NtUserCreateInputContext",
    },
    SyscallIndexEntry {
        number: 0x1291,
        name: "NtUserCreateWindowStation",
    },
    SyscallIndexEntry {
        number: 0x1292,
        name: "NtUserCtxDisplayIOCtl",
    },
    SyscallIndexEntry {
        number: 0x1293,
        name: "NtUserDestroyInputContext",
    },
    SyscallIndexEntry {
        number: 0x1294,
        name: "NtUserDisableThreadIme",
    },
    SyscallIndexEntry {
        number: 0x1295,
        name: "NtUserDisplayConfigGetDeviceInfo",
    },
    SyscallIndexEntry {
        number: 0x1296,
        name: "NtUserDisplayConfigSetDeviceInfo",
    },
    SyscallIndexEntry {
        number: 0x1297,
        name: "NtUserDoSoundConnect",
    },
    SyscallIndexEntry {
        number: 0x1298,
        name: "NtUserDoSoundDisconnect",
    },
    SyscallIndexEntry {
        number: 0x1299,
        name: "NtUserDragDetect",
    },
    SyscallIndexEntry {
        number: 0x129A,
        name: "NtUserDragObject",
    },
    SyscallIndexEntry {
        number: 0x129B,
        name: "NtUserDrawAnimatedRects",
    },
    SyscallIndexEntry {
        number: 0x129C,
        name: "NtUserDrawCaption",
    },
    SyscallIndexEntry {
        number: 0x129D,
        name: "NtUserDrawCaptionTemp",
    },
    SyscallIndexEntry {
        number: 0x129E,
        name: "NtUserDrawMenuBarTemp",
    },
    SyscallIndexEntry {
        number: 0x129F,
        name: "NtUserDwmStartRedirection",
    },
    SyscallIndexEntry {
        number: 0x12A0,
        name: "NtUserDwmStopRedirection",
    },
    SyscallIndexEntry {
        number: 0x12A1,
        name: "NtUserEndMenu",
    },
    SyscallIndexEntry {
        number: 0x12A2,
        name: "NtUserEndTouchOperation",
    },
    SyscallIndexEntry {
        number: 0x12A3,
        name: "NtUserEvent",
    },
    SyscallIndexEntry {
        number: 0x12A4,
        name: "NtUserFlashWindowEx",
    },
    SyscallIndexEntry {
        number: 0x12A5,
        name: "NtUserFrostCrashedWindow",
    },
    SyscallIndexEntry {
        number: 0x12A6,
        name: "NtUserGetAppImeLevel",
    },
    SyscallIndexEntry {
        number: 0x12A7,
        name: "NtUserGetCaretPos",
    },
    SyscallIndexEntry {
        number: 0x12A8,
        name: "NtUserGetClipCursor",
    },
    SyscallIndexEntry {
        number: 0x12A9,
        name: "NtUserGetClipboardViewer",
    },
    SyscallIndexEntry {
        number: 0x12AA,
        name: "NtUserGetComboBoxInfo",
    },
    SyscallIndexEntry {
        number: 0x12AB,
        name: "NtUserGetCursorInfo",
    },
    SyscallIndexEntry {
        number: 0x12AC,
        name: "NtUserGetDisplayConfigBufferSizes",
    },
    SyscallIndexEntry {
        number: 0x12AD,
        name: "NtUserGetGestureConfig",
    },
    SyscallIndexEntry {
        number: 0x12AE,
        name: "NtUserGetGestureExtArgs",
    },
    SyscallIndexEntry {
        number: 0x12AF,
        name: "NtUserGetGestureInfo",
    },
    SyscallIndexEntry {
        number: 0x12B0,
        name: "NtUserGetGuiResources",
    },
    SyscallIndexEntry {
        number: 0x12B1,
        name: "NtUserGetImeHotKey",
    },
    SyscallIndexEntry {
        number: 0x12B2,
        name: "NtUserGetImeInfoEx",
    },
    SyscallIndexEntry {
        number: 0x12B3,
        name: "NtUserGetInputLocaleInfo",
    },
    SyscallIndexEntry {
        number: 0x12B4,
        name: "NtUserGetInternalWindowPos",
    },
    SyscallIndexEntry {
        number: 0x12B5,
        name: "NtUserGetKeyNameText",
    },
    SyscallIndexEntry {
        number: 0x12B6,
        name: "NtUserGetKeyboardLayoutName",
    },
    SyscallIndexEntry {
        number: 0x12B7,
        name: "NtUserGetLayeredWindowAttributes",
    },
    SyscallIndexEntry {
        number: 0x12B8,
        name: "NtUserGetListBoxInfo",
    },
    SyscallIndexEntry {
        number: 0x12B9,
        name: "NtUserGetMenuIndex",
    },
    SyscallIndexEntry {
        number: 0x12BA,
        name: "NtUserGetMenuItemRect",
    },
    SyscallIndexEntry {
        number: 0x12BB,
        name: "NtUserGetMouseMovePointsEx",
    },
    SyscallIndexEntry {
        number: 0x12BC,
        name: "NtUserGetPriorityClipboardFormat",
    },
    SyscallIndexEntry {
        number: 0x12BD,
        name: "NtUserGetRawInputBuffer",
    },
    SyscallIndexEntry {
        number: 0x12BE,
        name: "NtUserGetRawInputData",
    },
    SyscallIndexEntry {
        number: 0x12BF,
        name: "NtUserGetRawInputDeviceInfo",
    },
    SyscallIndexEntry {
        number: 0x12C0,
        name: "NtUserGetRawInputDeviceList",
    },
    SyscallIndexEntry {
        number: 0x12C1,
        name: "NtUserGetRegisteredRawInputDevices",
    },
    SyscallIndexEntry {
        number: 0x12C2,
        name: "NtUserGetTopLevelWindow",
    },
    SyscallIndexEntry {
        number: 0x12C3,
        name: "NtUserGetTouchInputInfo",
    },
    SyscallIndexEntry {
        number: 0x12C4,
        name: "NtUserGetUpdatedClipboardFormats",
    },
    SyscallIndexEntry {
        number: 0x12C5,
        name: "NtUserGetWOWClass",
    },
    SyscallIndexEntry {
        number: 0x12C6,
        name: "NtUserGetWindowCompositionAttribute",
    },
    SyscallIndexEntry {
        number: 0x12C7,
        name: "NtUserGetWindowCompositionInfo",
    },
    SyscallIndexEntry {
        number: 0x12C8,
        name: "NtUserGetWindowDisplayAffinity",
    },
    SyscallIndexEntry {
        number: 0x12C9,
        name: "NtUserGetWindowMinimizeRect",
    },
    SyscallIndexEntry {
        number: 0x12CA,
        name: "NtUserGetWindowRgnEx",
    },
    SyscallIndexEntry {
        number: 0x12CB,
        name: "NtUserGhostWindowFromHungWindow",
    },
    SyscallIndexEntry {
        number: 0x12CC,
        name: "NtUserHardErrorControl",
    },
    SyscallIndexEntry {
        number: 0x12CD,
        name: "NtUserHiliteMenuItem",
    },
    SyscallIndexEntry {
        number: 0x12CE,
        name: "NtUserHungWindowFromGhostWindow",
    },
    SyscallIndexEntry {
        number: 0x12CF,
        name: "NtUserHwndQueryRedirectionInfo",
    },
    SyscallIndexEntry {
        number: 0x12D0,
        name: "NtUserHwndSetRedirectionInfo",
    },
    SyscallIndexEntry {
        number: 0x12D1,
        name: "NtUserImpersonateDdeClientWindow",
    },
    SyscallIndexEntry {
        number: 0x12D2,
        name: "NtUserInitTask",
    },
    SyscallIndexEntry {
        number: 0x12D3,
        name: "NtUserInitialize",
    },
    SyscallIndexEntry {
        number: 0x12D4,
        name: "NtUserInitializeClientPfnArrays",
    },
    SyscallIndexEntry {
        number: 0x12D5,
        name: "NtUserInjectGesture",
    },
    SyscallIndexEntry {
        number: 0x12D6,
        name: "NtUserInternalGetWindowIcon",
    },
    SyscallIndexEntry {
        number: 0x12D7,
        name: "NtUserIsTopLevelWindow",
    },
    SyscallIndexEntry {
        number: 0x12D8,
        name: "NtUserIsTouchWindow",
    },
    SyscallIndexEntry {
        number: 0x12D9,
        name: "NtUserLoadKeyboardLayoutEx",
    },
    SyscallIndexEntry {
        number: 0x12DA,
        name: "NtUserLockWindowStation",
    },
    SyscallIndexEntry {
        number: 0x12DB,
        name: "NtUserLockWorkStation",
    },
    SyscallIndexEntry {
        number: 0x12DC,
        name: "NtUserLogicalToPhysicalPoint",
    },
    SyscallIndexEntry {
        number: 0x12DD,
        name: "NtUserMNDragLeave",
    },
    SyscallIndexEntry {
        number: 0x12DE,
        name: "NtUserMNDragOver",
    },
    SyscallIndexEntry {
        number: 0x12DF,
        name: "NtUserMagControl",
    },
    SyscallIndexEntry {
        number: 0x12E0,
        name: "NtUserMagGetContextInformation",
    },
    SyscallIndexEntry {
        number: 0x12E1,
        name: "NtUserMagSetContextInformation",
    },
    SyscallIndexEntry {
        number: 0x12E2,
        name: "NtUserManageGestureHandlerWindow",
    },
    SyscallIndexEntry {
        number: 0x12E3,
        name: "NtUserMenuItemFromPoint",
    },
    SyscallIndexEntry {
        number: 0x12E4,
        name: "NtUserMinMaximize",
    },
    SyscallIndexEntry {
        number: 0x12E5,
        name: "NtUserModifyWindowTouchCapability",
    },
    SyscallIndexEntry {
        number: 0x12E6,
        name: "NtUserNotifyIMEStatus",
    },
    SyscallIndexEntry {
        number: 0x12E7,
        name: "NtUserOpenInputDesktop",
    },
    SyscallIndexEntry {
        number: 0x12E8,
        name: "NtUserOpenThreadDesktop",
    },
    SyscallIndexEntry {
        number: 0x12E9,
        name: "NtUserPaintMonitor",
    },
    SyscallIndexEntry {
        number: 0x12EA,
        name: "NtUserPhysicalToLogicalPoint",
    },
    SyscallIndexEntry {
        number: 0x12EB,
        name: "NtUserPrintWindow",
    },
    SyscallIndexEntry {
        number: 0x12EC,
        name: "NtUserQueryDisplayConfig",
    },
    SyscallIndexEntry {
        number: 0x12ED,
        name: "NtUserQueryInformationThread",
    },
    SyscallIndexEntry {
        number: 0x12EE,
        name: "NtUserQueryInputContext",
    },
    SyscallIndexEntry {
        number: 0x12EF,
        name: "NtUserQuerySendMessage",
    },
    SyscallIndexEntry {
        number: 0x12F0,
        name: "NtUserRealChildWindowFromPoint",
    },
    SyscallIndexEntry {
        number: 0x12F1,
        name: "NtUserRealWaitMessageEx",
    },
    SyscallIndexEntry {
        number: 0x12F2,
        name: "NtUserRegisterErrorReportingDialog",
    },
    SyscallIndexEntry {
        number: 0x12F3,
        name: "NtUserRegisterHotKey",
    },
    SyscallIndexEntry {
        number: 0x12F4,
        name: "NtUserRegisterRawInputDevices",
    },
    SyscallIndexEntry {
        number: 0x12F5,
        name: "NtUserRegisterServicesProcess",
    },
    SyscallIndexEntry {
        number: 0x12F6,
        name: "NtUserRegisterSessionPort",
    },
    SyscallIndexEntry {
        number: 0x12F7,
        name: "NtUserRegisterTasklist",
    },
    SyscallIndexEntry {
        number: 0x12F8,
        name: "NtUserRegisterUserApiHook",
    },
    SyscallIndexEntry {
        number: 0x12F9,
        name: "NtUserRemoteConnect",
    },
    SyscallIndexEntry {
        number: 0x12FA,
        name: "NtUserRemoteRedrawRectangle",
    },
    SyscallIndexEntry {
        number: 0x12FB,
        name: "NtUserRemoteRedrawScreen",
    },
    SyscallIndexEntry {
        number: 0x12FC,
        name: "NtUserRemoteStopScreenUpdates",
    },
    SyscallIndexEntry {
        number: 0x12FD,
        name: "NtUserRemoveClipboardFormatListener",
    },
    SyscallIndexEntry {
        number: 0x12FE,
        name: "NtUserResolveDesktopForWOW",
    },
    SyscallIndexEntry {
        number: 0x12FF,
        name: "NtUserSendTouchInput",
    },
    SyscallIndexEntry {
        number: 0x1300,
        name: "NtUserSetAppImeLevel",
    },
    SyscallIndexEntry {
        number: 0x1301,
        name: "NtUserSetChildWindowNoActivate",
    },
    SyscallIndexEntry {
        number: 0x1302,
        name: "NtUserSetClassWord",
    },
    SyscallIndexEntry {
        number: 0x1303,
        name: "NtUserSetCursorContents",
    },
    SyscallIndexEntry {
        number: 0x1304,
        name: "NtUserSetDisplayConfig",
    },
    SyscallIndexEntry {
        number: 0x1305,
        name: "NtUserSetGestureConfig",
    },
    SyscallIndexEntry {
        number: 0x1306,
        name: "NtUserSetImeHotKey",
    },
    SyscallIndexEntry {
        number: 0x1307,
        name: "NtUserSetImeInfoEx",
    },
    SyscallIndexEntry {
        number: 0x1308,
        name: "NtUserSetImeOwnerWindow",
    },
    SyscallIndexEntry {
        number: 0x1309,
        name: "NtUserSetInternalWindowPos",
    },
    SyscallIndexEntry {
        number: 0x130A,
        name: "NtUserSetLayeredWindowAttributes",
    },
    SyscallIndexEntry {
        number: 0x130B,
        name: "NtUserSetMenu",
    },
    SyscallIndexEntry {
        number: 0x130C,
        name: "NtUserSetMenuContextHelpId",
    },
    SyscallIndexEntry {
        number: 0x130D,
        name: "NtUserSetMenuFlagRtoL",
    },
    SyscallIndexEntry {
        number: 0x130E,
        name: "NtUserSetMirrorRendering",
    },
    SyscallIndexEntry {
        number: 0x130F,
        name: "NtUserSetObjectInformation",
    },
    SyscallIndexEntry {
        number: 0x1310,
        name: "NtUserSetProcessDPIAware",
    },
    SyscallIndexEntry {
        number: 0x1311,
        name: "NtUserSetShellWindowEx",
    },
    SyscallIndexEntry {
        number: 0x1312,
        name: "NtUserSetSysColors",
    },
    SyscallIndexEntry {
        number: 0x1313,
        name: "NtUserSetSystemCursor",
    },
    SyscallIndexEntry {
        number: 0x1314,
        name: "NtUserSetSystemTimer",
    },
    SyscallIndexEntry {
        number: 0x1315,
        name: "NtUserSetThreadLayoutHandles",
    },
    SyscallIndexEntry {
        number: 0x1316,
        name: "NtUserSetWindowCompositionAttribute",
    },
    SyscallIndexEntry {
        number: 0x1317,
        name: "NtUserSetWindowDisplayAffinity",
    },
    SyscallIndexEntry {
        number: 0x1318,
        name: "NtUserSetWindowRgnEx",
    },
    SyscallIndexEntry {
        number: 0x1319,
        name: "NtUserSetWindowStationUser",
    },
    SyscallIndexEntry {
        number: 0x131A,
        name: "NtUserSfmDestroyLogicalSurfaceBinding",
    },
    SyscallIndexEntry {
        number: 0x131B,
        name: "NtUserSfmDxBindSwapChain",
    },
    SyscallIndexEntry {
        number: 0x131C,
        name: "NtUserSfmDxGetSwapChainStats",
    },
    SyscallIndexEntry {
        number: 0x131D,
        name: "NtUserSfmDxOpenSwapChain",
    },
    SyscallIndexEntry {
        number: 0x131E,
        name: "NtUserSfmDxQuerySwapChainBindingStatus",
    },
    SyscallIndexEntry {
        number: 0x131F,
        name: "NtUserSfmDxReleaseSwapChain",
    },
    SyscallIndexEntry {
        number: 0x1320,
        name: "NtUserSfmDxReportPendingBindingsToDwm",
    },
    SyscallIndexEntry {
        number: 0x1321,
        name: "NtUserSfmDxSetSwapChainBindingStatus",
    },
    SyscallIndexEntry {
        number: 0x1322,
        name: "NtUserSfmDxSetSwapChainStats",
    },
    SyscallIndexEntry {
        number: 0x1323,
        name: "NtUserSfmGetLogicalSurfaceBinding",
    },
    SyscallIndexEntry {
        number: 0x1324,
        name: "NtUserShowSystemCursor",
    },
    SyscallIndexEntry {
        number: 0x1325,
        name: "NtUserSoundSentry",
    },
    SyscallIndexEntry {
        number: 0x1326,
        name: "NtUserSwitchDesktop",
    },
    SyscallIndexEntry {
        number: 0x1327,
        name: "NtUserTestForInteractiveUser",
    },
    SyscallIndexEntry {
        number: 0x1328,
        name: "NtUserTrackPopupMenuEx",
    },
    SyscallIndexEntry {
        number: 0x1329,
        name: "NtUserUnloadKeyboardLayout",
    },
    SyscallIndexEntry {
        number: 0x132A,
        name: "NtUserUnlockWindowStation",
    },
    SyscallIndexEntry {
        number: 0x132B,
        name: "NtUserUnregisterHotKey",
    },
    SyscallIndexEntry {
        number: 0x132C,
        name: "NtUserUnregisterSessionPort",
    },
    SyscallIndexEntry {
        number: 0x132D,
        name: "NtUserUnregisterUserApiHook",
    },
    SyscallIndexEntry {
        number: 0x132E,
        name: "NtUserUpdateInputContext",
    },
    SyscallIndexEntry {
        number: 0x132F,
        name: "NtUserUpdateInstance",
    },
    SyscallIndexEntry {
        number: 0x1330,
        name: "NtUserUpdateLayeredWindow",
    },
    SyscallIndexEntry {
        number: 0x1331,
        name: "NtUserUpdatePerUserSystemParameters",
    },
    SyscallIndexEntry {
        number: 0x1332,
        name: "NtUserUpdateWindowTransform",
    },
    SyscallIndexEntry {
        number: 0x1333,
        name: "NtUserUserHandleGrantAccess",
    },
    SyscallIndexEntry {
        number: 0x1334,
        name: "NtUserValidateHandleSecure",
    },
    SyscallIndexEntry {
        number: 0x1335,
        name: "NtUserWaitForInputIdle",
    },
    SyscallIndexEntry {
        number: 0x1336,
        name: "NtUserWaitForMsgAndEvent",
    },
    SyscallIndexEntry {
        number: 0x1337,
        name: "NtUserWindowFromPhysicalPoint",
    },
    SyscallIndexEntry {
        number: 0x1338,
        name: "NtUserYieldTask",
    },
    SyscallIndexEntry {
        number: 0x1339,
        name: "NtUserSetClassLongPtr",
    },
    SyscallIndexEntry {
        number: 0x133A,
        name: "NtUserSetWindowLongPtr",
    },
];

/// Look up a native or win32k syscall by its Windows 7 x64 index.
pub fn lookup_syscall(number: u16) -> Option<(&'static str, bool)> {
    NATIVE_SYSCALLS
        .iter()
        .find(|entry| entry.number == number)
        .map(|entry| (entry.name, false))
        .or_else(|| {
            WIN32K_SYSCALLS
                .iter()
                .find(|entry| entry.number == number)
                .map(|entry| (entry.name, true))
        })
}

#[cfg(test)]
mod tests {
    use super::{lookup_syscall, NATIVE_SYSCALLS, WIN32K_SYSCALLS};

    #[test]
    fn native_table_is_ordered_and_unique() {
        for pair in NATIVE_SYSCALLS.windows(2) {
            assert!(pair[0].number < pair[1].number);
            assert!(!pair[0].name.is_empty());
            assert!(!pair[1].name.is_empty());
        }
    }

    #[test]
    fn win32k_table_is_ordered_and_unique() {
        for pair in WIN32K_SYSCALLS.windows(2) {
            assert!(pair[0].number < pair[1].number);
            assert!(!pair[0].name.is_empty());
            assert!(!pair[1].name.is_empty());
        }
    }

    #[test]
    fn lookup_matches_windows_7_sp1_indices() {
        assert_eq!(lookup_syscall(0x0003), Some(("NtReadFile", false)));
        assert_eq!(lookup_syscall(0x1338), Some(("NtUserYieldTask", true)));
        assert_eq!(
            lookup_syscall(0x1339),
            Some(("NtUserSetClassLongPtr", true))
        );
    }
}
