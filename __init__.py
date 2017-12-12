#!/usr/bin/env python2

"""

TODO:
Get DRVOBJ offsets for i386
Determine supported IOCTLs (support switch or branch on IOCTL code).
Regenerate header files with CTL_CODE macro definitions.
"""

from binaryninja import *
from constants import *

from pdb import set_trace as trace
from pprint import pprint

class DispatchRoutine(object):
    """Helper class to name dispatch routines."""

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
    """Create and name a function. Add an optional comment."""
    bv.add_function(address)
    func = bv.get_function_at(address)
    func.name = name
    if comment is not None:
        func.set_comment_at(address, comment)


def get_store_offset_value(inst):
    """Get the store offset and const value.

    :return: Tuple of (offset, const value)
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


def get_dispatch_routines(bv, driver_entry):
    """Get a list of all IRP_MJ dispatch routines set up in DriverEntry.

    Find all routines by searching for constant value stores to certain
    offsets in the DriverObject.
    """
    
    mlil = driver_entry.medium_level_il
    driver_object = driver_entry.parameter_vars[0]

    # Breadth first search of all driver_object uses
    # Traverse the def-use chain until we get to a store with constant as the source
    # Get the store offset and constant source value
    stores = []
    uses = mlil.get_var_uses(driver_object)
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

    # Get the right offsets for our architecture
    if bv.arch.address_size == 4:
        unload_offset = DRVOBJ_DRIVER_UNLOAD_OFFSET_X86
        start_io_offset = DRVOBJ_START_IO_OFFSET_X86
        major_function_offset = DRVOBJ_MAJOR_FUNCTION_OFFSET_X86
    else:
        driver_unload_offset = DRVOBJ_DRIVER_UNLOAD_OFFSET_X64
        driver_start_io_offset = DRVOBJ_START_IO_OFFSET_X64
        major_function_offset = DRVOBJ_MAJOR_FUNCTION_OFFSET_X64

    # Create functions and label them
    dispatch_routines = {}
    for offset, address in stores:
        if offset == driver_unload_offset:
            create_named_function(bv, address, "DriverUnload")

        elif offset == driver_start_io_offset:
            create_named_function(bv, address, "DriverStartIo")

        elif (offset >= major_function_offset and 
                offset <= major_function_offset + bv.arch.address_size * IRP_MJ_MAXIMUM_FUNCTION):
            mj_function = (offset - major_function_offset) / bv.arch.address_size
            if not address in dispatch_routines:
                dispatch_routines[address] = DispatchRoutine(address)
            dispatch_routines[address].add_irp(mj_function)

    return dispatch_routines.values()


def get_driver_entry(bv):
    """Get the DriverEntry function.

    The first basic block at _start is provided by the compiler, and has two
    function calls. The second is always DriverEntry. Sometimes, tail-call
    optimization is applied and _start and DriverEntry are folded into a
    single function.
    """
    _start = bv.entry_function
    if len(_start.basic_blocks) > 1:    # Tail-call optimized
        _start.name = "DriverEntry"
        return _start

    # Non-optimized. Get the call target of the second call
    block = _start.low_level_il.basic_blocks[0]
    calls = [inst for inst in block if inst.operation == LowLevelILOperation.LLIL_CALL]
    assert(len(calls) == 2)
    
    call_target = calls[1].dest.value.value
    entry = bv.get_function_at(call_target)
    entry.name = "DriverEntry"
    return entry


def label_dispatch_routines(bv):
    bv.begin_undo_actions()

    bv.update_analysis()
    driver_entry = get_driver_entry(bv)
    routines = get_dispatch_routines(bv, driver_entry)
    for routine in routines:
        print routine
        routine.label(bv)

    bv.commit_undo_actions()
    bv.update_analysis()


if __name__ == "__main__":
    bv = BinaryViewType["PE"].open("/home/user/driver.sys")
    label_dispatch_routines(bv)

