#!/usr/bin/env python2

"""

TODO:
Support x86 and x64.
Follow calls from _start to find the real DriverEntry when tail call optimization isn't used.
Determine supported IOCTLs (support switch or branch on IOCTL code).
Regenerate header files with CTL_CODE macro definitions.
"""

from binaryninja import *

from pdb import set_trace as trace
from pprint import pprint

DRVOBJ_START_IO_OFFSET = 0x60
DRVOBJ_DRIVER_UNLOAD_OFFSET = 0x68
DRVOBJ_MJ_OFFSETS = {
    0x70: "Create",
    0x78: "CreateNamedPipe",
    0x80: "Close",
    0x88: "Read",
    0x90: "Write",
    0x98: "QueryInformation",
    0xa0: "SetInformation",
    0xa8: "QueryEa",
    0xb0: "SetEa",
    0xb8: "FlushBuffers",
    0xc0: "QueryVolumeInformation",
    0xc8: "SetVolumeInformation",
    0xd0: "DirectoryControl",
    0xd8: "FileSystemControl",
    0xe0: "DeviceControl",
    0xe8: "InternalDeviceControl",
    0xf0: "Shutdown",
    0xf8: "LockControl",
    0x100: "Cleanup",
    0x108: "CreateMailslot",
    0x110: "QuerySecurity",
    0x118: "SetSecurity",
    0x120: "Power",
    0x128: "SystemControl",
    0x130: "DeviceChange",
    0x138: "QueryQuota",
    0x140: "SetQuota",
    0x148: "Pnp",
    0x150: "PnpPower"
}

class DispatchRoutine(object):
    # static counters to ensure unique names
    unknown_ctr = 0
    multiple_ctr = 0

    def __init__(self, address):
        self.address = address
        self.uses = []

    @property
    def name(self):
        if len(self.uses) == 0:
            self.unknown_ctr += 1
            return "DispatchUnknown{:d}".format(self.unknown_ctr)
        elif len(self.uses) < 4:
            return "Dispatch{:s}".format("".join(self.uses))
        else:
            self.multiple_ctr += 1
            return "DispatchMultiple{:d}".format(self.multiple_ctr)

    def add_use(self, name):
        self.uses.append(name)

    def __str__(self):
        return "<{:s} 0x{:016x}>".format(self.name, self.address)


def create_named_function(bv, address, name, comment=None):
    bv.add_function(address)
    func = bv.get_function_at(address)
    func.name = name
    if comment is not None:
        func.set_comment_at(address, comment)


def get_store_offset_value(inst):
    """Get the store offset and const value.

    :return: Tuple of (offset, const)
    """
    value = inst.src.value.value

    offset = 0
    inst = inst.dest
    while inst.operation != MediumLevelILOperation.MLIL_VAR:
        if inst.operation == MediumLevelILOperation.MLIL_ADD:
            assert(inst.right.value.is_constant)
            offset += inst.right.value.value
            inst = inst.left
        else:
            print inst
            assert(False)

    return (offset, value)



def get_dispatch_routines(bv):
    bv.update_analysis()
    entry = bv.entry_function
    #entry = bv.get_function_at(0x1c0001300) - beep.sys (DriverEntry isn't the entry point. It's the second function call. AcgHelper.sys uses tail call optimization for this function)

    mlil = entry.medium_level_il
    arg0 = entry.parameter_vars[0]

    # TODO: Follow calls so we recurse into real DriverEntry (beep.sys)

    # Breadth first search of all arg0 uses
    # Traverse the def-use chain until we get to a store with constant as the source
    # Get the store offset and constant source value
    stores = []
    uses = mlil.get_var_uses(arg0)
    while len(uses) > 0:
        use = mlil[uses[0]]
        uses = uses[1:]

        # Parse all store operations
        if use.operation == MediumLevelILOperation.MLIL_STORE and use.src.value.is_constant:
            off, val = get_store_offset_value(use)
            stores.append((off, val))

        # Get new uses
        if use.operation == MediumLevelILOperation.MLIL_SET_VAR:
            dest = use.dest
            uses += mlil.get_var_uses(dest)

    # Create functions and label them
    dispatch_routines = {}
    create_named_function(bv, bv.entry_point, "DriverEntry")
    for offset, address in stores:
        if offset == DRVOBJ_DRIVER_UNLOAD_OFFSET:
            create_named_function(bv, address, "DriverUnload")
        elif offset == DRVOBJ_START_IO_OFFSET:
            create_named_function(bv, address, "DriverStartIo")
        elif offset in DRVOBJ_MJ_OFFSETS:
            if address not in dispatch_routines:
                dispatch_routines[address] = DispatchRoutine(address)
            mj_function = DRVOBJ_MJ_OFFSETS[offset]
            dispatch_routines[address].add_use(mj_function)

    return dispatch_routines.values()

def label_dispatch_routines(bv):
    bv.begin_undo_actions()
    routines = get_dispatch_routines(bv)
    for routine in routines:
        print routine
        irps = ["IRP_MJ_" + use for use in routine.uses]
        create_named_function(bv, routine.address, routine.name, "Dispatch routine for: \n" + "\n".join(irps))
    bv.commit_undo_actions()
    bv.update_analysis()


if __name__ == "__main__":
    bv = BinaryViewType["PE"].open("/home/user/driver.sys")
    routines = label_dispatch_routines(bv)
