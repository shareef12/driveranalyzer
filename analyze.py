from binaryninja import LowLevelILOperation

import constants
import ioctl
import util


class DispatchRoutine(object):
    """Helper class to name dispatch routines semi-intelligently."""

    def __init__(self, address):
        self.address = address
        self.irps = []

    @property
    def name(self):
        if len(self.irps) > constants.IRP_MJ_MAXIMUM_FUNCTION / 2:
            return "DispatchDefault"
        irp_names = [constants.IRP_MJ_NAMES[i] for i in self.irps]
        return "Dispatch{:s}".format("".join(irp_names))

    def add_irp(self, irp):
        self.irps.append(irp)

    def label(self, bv):
        """Create a named function and insert comments about supported IRPs."""
        irp_names = ["IRP_MJ_" + constants.IRP_MJ_NAMES[i] for i in self.irps]
        comment = "Dispatch routine for: \n" + "\n".join(irp_names)
        util.create_named_function(bv, self.address, self.name, comment)

    def __repr__(self):
        return "<{:s} 0x{:016x}>".format(self.name, self.address)


def get_driver_entry(bv):
    """Get the DriverEntry function.

    The first basic block at _start is provided by the compiler, and has two
    function calls. The second is always DriverEntry. Sometimes, tail-call
    optimization is applied and _start and DriverEntry are folded into a
    single function.
    """

    _start = bv.entry_function
    if len(_start.basic_blocks) > 1:  # Tail-call optimized
        return _start

    # Non-optimized. Get the call target of the second call
    block = _start.low_level_il.basic_blocks[0]
    calls = [inst for inst in block if inst.operation == LowLevelILOperation.LLIL_CALL]
    assert (len(calls) == 2)

    call_target = calls[1].dest.value.value
    entry = bv.get_function_at(call_target)
    return entry


def label_dispatch_routines(bv, driver_entry):
    """Get a list of all IRP_MJ dispatch routines set up in DriverEntry. Label
        all driver callback routines.

    Find all routines by searching for constant value stores to certain
    offsets in the DriverObject.
    """
    print "Finding dispatch routines..."

    # Get all constant stores to offsets of the DriverObject
    mlil = driver_entry.medium_level_il
    driver_object = driver_entry.parameter_vars[0]
    stores = util.get_offset_stores(mlil, driver_object)

    # Create functions and label them. Don't label an IRP dispatch routine
    # until we know about every IRP it handles.
    dispatch_routines = {}
    dispatch_table = [None] * constants.IRP_MJ_MAXIMUM_FUNCTION
    consts = constants.Offsets(bv.arch.address_size)
    for offset, address in stores:
        if offset == consts.DRVOBJ_DRIVER_UNLOAD_OFFSET:
            util.create_named_function(bv, address, "DriverUnload")

        elif offset == consts.DRVOBJ_START_IO_OFFSET:
            util.create_named_function(bv, address, "DriverStartIo")

        elif consts.DRVOBJ_MAJOR_FUNCTION_OFFSET <= offset <= consts.DRVOBJ_LAST_MAJOR_FUNCTION_OFFSET:
            mj_function = (offset - consts.DRVOBJ_MAJOR_FUNCTION_OFFSET) / bv.arch.address_size
            if address not in dispatch_routines:
                dispatch_routines[address] = DispatchRoutine(address)
            dispatch_routines[address].add_irp(mj_function)
            dispatch_table[mj_function] = address

    # Now that we have complete info about IRP handlers, label them.
    print "Done. Found {:d} routines.".format(len(dispatch_routines))
    for routine in dispatch_routines.values():
        print routine.name, hex(routine.address)
        routine.label(bv)

    # Return a list of IRP handlers in the form of a dispatch table
    return dispatch_table


def label_ioctls(bv, dispatch_device_control):
    print "Finding ioctls..."
    ioctls = ioctl.find_ioctls(bv.file.filename, dispatch_device_control, bv.arch.address_size)
    for code in sorted(ioctls):
        print ioctl.get_macro(code)
        for address in ioctls[code]:
            funcs = bv.get_functions_containing(address)
            assert len(funcs) == 1
            funcs[0].set_comment_at(address, "Handler for IOCTL_{:x}".format(code))


def label_all(bv):
    driver_entry = get_driver_entry(bv)
    util.create_named_function(bv, driver_entry.start, "DriverEntry")

    dispatch_table = label_dispatch_routines(bv, driver_entry)
    dispatch_device_control = dispatch_table[constants.IRP_MJ_DEVICE_CONTROL]
    bv.update_analysis_and_wait()
    if dispatch_device_control is not None:
        label_ioctls(bv, dispatch_device_control)
