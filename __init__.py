#!/usr/bin/env python2

"""

TODO:
Follow calls from _start to find the real DriverEntry when tail call optimization isn't used.
Determine supported IOCTLs (support switch or branch on IOCTL code).
Regenerate header files with CTL_CODE macro definitions.
"""

from binaryninja import *
from constants import *

from pdb import set_trace as trace
from pprint import pprint

class DispatchRoutine(object):

    def __init__(self, address):
        self.address = address
        self.irps = []

    @property
    def name(self):
        irps = [IRP_MJ_NAMES[i] for i in self.irps]
        return "Dispatch{:s}".format("".join(irps))
        
    def add_irp(self, irp):
        self.irps.append(irp)

    def label(self, bv):
        """Create a named function and insert comments about supported IRPs."""
        irps = ["IRP_MJ_" + IRP_MJ_NAMES[i] for i in self.irps]
        comment = "Dispatch routine for: \n" + "\n".join(irps)
        create_named_function(bv, self.address, self.name, comment)

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
    entry.name = "DriverEntry"

    for offset, address in stores:
        if offset == DRVOBJ_DRIVER_UNLOAD_OFFSET_X64:
            create_named_function(bv, address, "DriverUnload")
        elif offset == DRVOBJ_START_IO_OFFSET_X64:
            create_named_function(bv, address, "DriverStartIo")
        elif (offset >= DRVOBJ_MAJOR_FUNCTION_OFFSET_X64 and 
                offset <= DRVOBJ_MAJOR_FUNCTION_OFFSET_X64 + bv.arch.address_size * IRP_MJ_MAXIMUM_FUNCTION):
            mj_function = (offset - DRVOBJ_MAJOR_FUNCTION_OFFSET_X64) / bv.arch.address_size
            if not address in dispatch_routines:
                dispatch_routines[address] = DispatchRoutine(address)
            dispatch_routines[address].add_irp(mj_function)

    return dispatch_routines.values()

def label_dispatch_routines(bv):
    bv.begin_undo_actions()
    routines = get_dispatch_routines(bv)
    for routine in routines:
        print routine
        routine.label(bv)
    bv.commit_undo_actions()
    bv.update_analysis()


if __name__ == "__main__":
    bv = BinaryViewType["PE"].open("/home/user/driver.sys")
    routines = label_dispatch_routines(bv)
