class Offsets(object):
    def __init__(self, address_size):
        if address_size == 4:
            self.FAST_IO_DISPATCH_START = 0x4
            self.DRVOBJ_FAST_IO_DISPATCH_OFFSET = 0x28
            self.DRVOBJ_START_IO_OFFSET = 0x30
            self.DRVOBJ_DRIVER_UNLOAD_OFFSET = 0x34
            self.DRVOBJ_MAJOR_FUNCTION_OFFSET = 0x38

        elif address_size == 8:
            self.FAST_IO_DISPATCH_START = 0x8
            self.DRVOBJ_FAST_IO_DISPATCH_OFFSET = 0x50
            self.DRVOBJ_START_IO_OFFSET = 0x60
            self.DRVOBJ_DRIVER_UNLOAD_OFFSET = 0x68
            self.DRVOBJ_MAJOR_FUNCTION_OFFSET = 0x70

        self.FAST_IO_DISPATCH_END = \
            self.FAST_IO_DISPATCH_START + address_size * len(FAST_IO_NAMES)
        self.DRVOBJ_LAST_MAJOR_FUNCTION_OFFSET = \
            self.DRVOBJ_MAJOR_FUNCTION_OFFSET + address_size * IRP_MJ_MAXIMUM_FUNCTION


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

FAST_IO_NAMES = [
    "CheckIfPossible",
    "Read",
    "Write",
    "QueryBasicInfo",
    "QueryStandardInfo",
    "Lock",
    "UnlockSingle",
    "UnlockAll",
    "UnlockAllByKey",
    "DeviceControl",
    "AcquireFileForNtCreateSection",
    "ReleaseFileForNtCreateSection",
    "DetachDevice",
    "QueryNetworkOpenInfo",
    "AcquireForModWrite",
    "MdlRead",
    "MdlReadComplete",
    "PrepareMdlWrite",
    "MdlWriteComplete",
    "ReadCompressed",
    "WriteCompressed",
    "MdlReadCompleteCompressed",
    "MdlWriteCompleteCompressed",
    "QueryOpen",
    "ReleaseForModWrite",
    "AcquireForCcFlush",
    "ReleaseForCcFlush",
]

DEVICE_TYPES = {
   0x01: "FILE_DEVICE_BEEP",
   0x02: "FILE_DEVICE_CD_ROM",
   0x03: "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
   0x04: "FILE_DEVICE_CONTROLLER",
   0x05: "FILE_DEVICE_DATALINK",
   0x06: "FILE_DEVICE_DFS",
   0x07: "FILE_DEVICE_DISK",
   0x08: "FILE_DEVICE_DISK_FILE_SYSTEM",
   0x09: "FILE_DEVICE_FILE_SYSTEM",
   0x0a: "FILE_DEVICE_INPORT_PORT",
   0x0b: "FILE_DEVICE_KEYBOARD",
   0x0c: "FILE_DEVICE_MAILSLOT",
   0x0d: "FILE_DEVICE_MIDI_IN",
   0x0e: "FILE_DEVICE_MIDI_OUT",
   0x0f: "FILE_DEVICE_MOUSE",
   0x10: "FILE_DEVICE_MULTI_UNC_PROVIDER",
   0x11: "FILE_DEVICE_NAMED_PIPE",
   0x12: "FILE_DEVICE_NETWORK",
   0x13: "FILE_DEVICE_NETWORK_BROWSER",
   0x14: "FILE_DEVICE_NETWORK_FILE_SYSTEM",
   0x15: "FILE_DEVICE_NULL",
   0x16: "FILE_DEVICE_PARALLEL_PORT",
   0x17: "FILE_DEVICE_PHYSICAL_NETCARD",
   0x18: "FILE_DEVICE_PRINTER",
   0x19: "FILE_DEVICE_SCANNER",
   0x1a: "FILE_DEVICE_SERIAL_MOUSE_PORT",
   0x1b: "FILE_DEVICE_SERIAL_PORT",
   0x1c: "FILE_DEVICE_SCREEN",
   0x1d: "FILE_DEVICE_SOUND",
   0x1e: "FILE_DEVICE_STREAMS",
   0x1f: "FILE_DEVICE_TAPE",
   0x20: "FILE_DEVICE_TAPE_FILE_SYSTEM",
   0x21: "FILE_DEVICE_TRANSPORT",
   0x22: "FILE_DEVICE_UNKNOWN",
   0x23: "FILE_DEVICE_VIDEO",
   0x24: "FILE_DEVICE_VIRTUAL_DISK",
   0x25: "FILE_DEVICE_WAVE_IN",
   0x26: "FILE_DEVICE_WAVE_OUT",
   0x27: "FILE_DEVICE_8042_PORT",
   0x28: "FILE_DEVICE_NETWORK_REDIRECTOR",
   0x29: "FILE_DEVICE_BATTERY",
   0x2a: "FILE_DEVICE_BUS_EXTENDER",
   0x2b: "FILE_DEVICE_MODEM",
   0x2c: "FILE_DEVICE_VDM",
   0x2d: "FILE_DEVICE_MASS_STORAGE",
   0x2e: "FILE_DEVICE_SMB",
   0x2f: "FILE_DEVICE_KS",
   0x30: "FILE_DEVICE_CHANGER",
   0x31: "FILE_DEVICE_SMARTCARD",
   0x32: "FILE_DEVICE_ACPI",
   0x33: "FILE_DEVICE_DVD",
   0x34: "FILE_DEVICE_FULLSCREEN_VIDEO",
   0x35: "FILE_DEVICE_DFS_FILE_SYSTEM",
   0x36: "FILE_DEVICE_DFS_VOLUME",
   0x37: "FILE_DEVICE_SERENUM",
   0x38: "FILE_DEVICE_TERMSRV",
   0x39: "FILE_DEVICE_KSEC",
   0x3A: "FILE_DEVICE_FIPS",
   0x3B: "FILE_DEVICE_INFINIBAND",
   0x3E: "FILE_DEVICE_VMBUS",
   0x3F: "FILE_DEVICE_CRYPT_PROVIDER",
   0x40: "FILE_DEVICE_WPD",
   0x41: "FILE_DEVICE_BLUETOOTH",
   0x42: "FILE_DEVICE_MT_COMPOSITE",
   0x43: "FILE_DEVICE_MT_TRANSPORT",
   0x44: "FILE_DEVICE_BIOMETRIC",
   0x45: "FILE_DEVICE_PMI",
   0x46: "FILE_DEVICE_EHSTOR",
   0x47: "FILE_DEVICE_DEVAPI",
   0x48: "FILE_DEVICE_GPIO",
   0x49: "FILE_DEVICE_USBEX",
   0x50: "FILE_DEVICE_CONSOLE",
   0x51: "FILE_DEVICE_NFP",
   0x52: "FILE_DEVICE_SYSENV",
   0x53: "FILE_DEVICE_VIRTUAL_BLOCK",
   0x54: "FILE_DEVICE_POINT_OF_SERVICE",
   0x55: "FILE_DEVICE_STORAGE_REPLICATION",
   0x56: "FILE_DEVICE_TRUST_ENV",
   0x57: "FILE_DEVICE_UCM",
   0x58: "FILE_DEVICE_UCMTCPCI",
}

METHODS = {
    0x00: "METHOD_BUFFERED",
    0x01: "METHOD_IN_DIRECT",
    0x02: "METHOD_OUT_DIRECT",
    0x03: "METHOD_NEITHER",
}

ACCESS = {
    0x00: "FILE_ANY_ACCESS",
    0x01: "FILE_READ_ACCESS",
    0x02: "FILE_WRITE_ACCESS",
}
