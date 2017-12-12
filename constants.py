DRVOBJ_START_IO_OFFSET_X86 = 0x00
DRVOBJ_START_IO_OFFSET_X64 = 0x60
DRVOBJ_DRIVER_UNLOAD_OFFSET_X86 = 0x00
DRVOBJ_DRIVER_UNLOAD_OFFSET_X64 = 0x68
DRVOBJ_MAJOR_FUNCTION_OFFSET_X86 = 0x00
DRVOBJ_MAJOR_FUNCTION_OFFSET_X64 = 0x70

IRP_MJ_CREATE                   = 0x00
IRP_MJ_CREATE_NAMED_PIPE        = 0x01
IRP_MJ_CLOSE                    = 0x02
IRP_MJ_READ                     = 0x03
IRP_MJ_WRITE                    = 0x04
IRP_MJ_QUERY_INFORMATION        = 0x05
IRP_MJ_SET_INFORMATION          = 0x06
IRP_MJ_QUERY_EA                 = 0x07
IRP_MJ_SET_EA                   = 0x08
IRP_MJ_FLUSH_BUFFERS            = 0x09
IRP_MJ_QUERY_VOLUME_INFORMATION = 0x0a
IRP_MJ_SET_VOLUME_INFORMATION   = 0x0b
IRP_MJ_DIRECTORY_CONTROL        = 0x0c
IRP_MJ_FILE_SYSTEM_CONTROL      = 0x0d
IRP_MJ_DEVICE_CONTROL           = 0x0e
IRP_MJ_INTERNAL_DEVICE_CONTROL  = 0x0f
IRP_MJ_SHUTDOWN                 = 0x10
IRP_MJ_LOCK_CONTROL             = 0x11
IRP_MJ_CLEANUP                  = 0x12
IRP_MJ_CREATE_MAILSLOT          = 0x13
IRP_MJ_QUERY_SECURITY           = 0x14
IRP_MJ_SET_SECURITY             = 0x15
IRP_MJ_POWER                    = 0x16
IRP_MJ_SYSTEM_CONTROL           = 0x17
IRP_MJ_DEVICE_CHANGE            = 0x18
IRP_MJ_QUERY_QUOTA              = 0x19
IRP_MJ_SET_QUOTA                = 0x1a
IRP_MJ_PNP                      = 0x1b
IRP_MJ_PNP_POWER                = IRP_MJ_PNP
IRP_MJ_MAXIMUM_FUNCTION         = 0x1b

IRP_MJ_NAMES = {
    IRP_MJ_CREATE: "Create",
    IRP_MJ_CREATE_NAMED_PIPE: "CreateNamedPipe",
    IRP_MJ_CLOSE: "Close",
    IRP_MJ_READ: "Read",
    IRP_MJ_WRITE: "Write",
    IRP_MJ_QUERY_INFORMATION: "QueryInformation",
    IRP_MJ_SET_INFORMATION: "SetInformation",
    IRP_MJ_QUERY_EA: "QueryEa",
    IRP_MJ_SET_EA: "SetEa",
    IRP_MJ_FLUSH_BUFFERS: "FlushBuffers",
    IRP_MJ_QUERY_VOLUME_INFORMATION: "QueryVolumeInformation",
    IRP_MJ_SET_VOLUME_INFORMATION: "SetVolumeInformation",
    IRP_MJ_DIRECTORY_CONTROL: "DirectoryControl",
    IRP_MJ_FILE_SYSTEM_CONTROL: "FileSystemControl",
    IRP_MJ_DEVICE_CONTROL: "DeviceControl",
    IRP_MJ_INTERNAL_DEVICE_CONTROL: "InternalDeviceControl",
    IRP_MJ_SHUTDOWN: "Shutdown",
    IRP_MJ_LOCK_CONTROL: "LockControl",
    IRP_MJ_CLEANUP: "Cleanup",
    IRP_MJ_CREATE_MAILSLOT: "CreateMailslot",
    IRP_MJ_QUERY_SECURITY: "QuerySecurity",
    IRP_MJ_SET_SECURITY: "SetSecurity",
    IRP_MJ_POWER: "Power",
    IRP_MJ_SYSTEM_CONTROL: "SystemControl",
    IRP_MJ_DEVICE_CHANGE: "DeviceChange",
    IRP_MJ_QUERY_QUOTA: "QueryQuota",
    IRP_MJ_SET_QUOTA: "SetQuota",
    IRP_MJ_PNP: "Pnp",
}