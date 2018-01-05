import collections

from binaryninja import LowLevelILOperation

import constants
import ioctl
import util


class IrpDispatchRoutine(object):
    """Helper class to name dispatch routines semi-intelligently."""
    def __init__(self, irps):
        self.irps = irps

    @property
    def name(self):
        if len(self.irps) > constants.IRP_MJ_MAXIMUM_FUNCTION / 2:
            return "DispatchDefault"
        irp_names = [constants.IRP_MJ_NAMES[i] for i in self.irps]
        return "Dispatch{:s}".format("".join(irp_names))

    @property
    def comment(self):
        irp_names = ["IRP_MJ_" + constants.IRP_MJ_NAMES[i] for i in self.irps]
        return "Dispatch routine for: \n" + "\n".join(irp_names)


class FastIoDispatchRoutine(object):
    """Helper class to name dispatch routines semi-intelligently."""
    def __init__(self, routines):
        self.routines = routines

    @property
    def name(self):
        if len(self.routines) > len(constants.FAST_IO_NAMES) / 2:
            return "FastIoDefault"
        routine_names = [constants.FAST_IO_NAMES[i] for i in self.routines]
        return "FastIo{:s}".format("".join(routine_names))

    @property
    def comment(self):
        routine_names = ["FastIo" + constants.FAST_IO_NAMES[i] for i in self.routines]
        return "Dispatch routine for: \n" + "\n".join(routine_names)


class DispatchTable(object):
    """Helper class to maintain the state of a dispatch table.

    Maintain two structures:
    1. Map of routine addresses to a list of callbacks they support (1 to many)
    2. List of routine addresses indexed by the callback they support (1 to 1)
    """
    def __init__(self, size, routine_type):
        self.routine_type = routine_type
        self.routines = collections.defaultdict(list)
        self.table = [None] * size

    def add(self, address, routine):
        self.routines[address].append(routine)
        self.table[routine] = address

    def label_all(self, bv):
        for address, routines in self.routines.iteritems():
            routine = self.routine_type(routines)
            print hex(address), routine.name
            util.create_named_function(bv, address, routine.name, routine.comment)


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


def label_fastio_dispatch_routines(bv, driver_entry, stores):
    """Label all found FastIo dispatch routines."""
    offsets = constants.Offsets(bv.arch.address_size)
    fastio_dispatch_table = stores.get(offsets.DRVOBJ_FAST_IO_DISPATCH_OFFSET)
    if fastio_dispatch_table is None:
        return

    # Get stores setting up the FastIo dispatch table
    stores = util.get_stores_by_offset(driver_entry, fastio_dispatch_table.src)
    constant_src_stores = {k: v.value.value for k, v in stores.iteritems() if v.value.is_constant}

    dispatch_table = DispatchTable(len(constants.FAST_IO_NAMES), FastIoDispatchRoutine)
    for offset, address in constant_src_stores.iteritems():
        if offsets.FAST_IO_DISPATCH_START <= offset <= offsets.FAST_IO_DISPATCH_END:
            routine = (offset - offsets.FAST_IO_DISPATCH_START) / bv.arch.address_size
            dispatch_table.add(address, routine)

    dispatch_table.label_all(bv)
    return dispatch_table.table


def label_irp_dispatch_routines(bv, stores):
    """Label all found IRP dispatch routines."""
    # Create functions and label them. Don't label an IRP dispatch routine
    # until we know about every IRP it handles.
    dispatch_table = DispatchTable(constants.IRP_MJ_MAXIMUM_FUNCTION, IrpDispatchRoutine)
    offsets = constants.Offsets(bv.arch.address_size)
    for offset, address in stores.iteritems():
        if offsets.DRVOBJ_MAJOR_FUNCTION_OFFSET <= offset <= offsets.DRVOBJ_LAST_MAJOR_FUNCTION_OFFSET:
            mj_function = (offset - offsets.DRVOBJ_MAJOR_FUNCTION_OFFSET) / bv.arch.address_size
            dispatch_table.add(address, mj_function)

    print "Done. Found {:d} IRP dispatch routines.".format(len(dispatch_table.routines))
    dispatch_table.label_all(bv)
    return dispatch_table.table


def label_driver_object_routines(bv, driver_entry):
    """Label DriverUnload, DriverStartIo, and all found IRP dispatch routines."""
    print "Labeling DriverObject callback routines."
    if len(driver_entry.parameter_vars) == 0:
        print "Done. Found 0 routines."
        return [None] * constants.IRP_MJ_MAXIMUM_FUNCTION

    # Get all stores to offsets of the DriverObject
    driver_object = driver_entry.parameter_vars[0]
    stores = util.get_stores_by_offset(driver_entry, driver_object)
    constant_src_stores = {k: v.value.value for k, v in stores.iteritems() if v.value.is_constant}

    # Label DriverUnload
    offsets = constants.Offsets(bv.arch.address_size)
    address = constant_src_stores.get(offsets.DRVOBJ_DRIVER_UNLOAD_OFFSET)
    if address:
        util.create_named_function(bv, address, "DriverUnload")

    # Label DriverStartIo
    address = constant_src_stores.get(offsets.DRVOBJ_START_IO_OFFSET)
    if address:
        util.create_named_function(bv, address, "DriverStartIo")

    # Label FastIo and IRP dispatch routines
    label_fastio_dispatch_routines(bv, driver_entry, stores)
    dispatch_table = label_irp_dispatch_routines(bv, constant_src_stores)
    return dispatch_table


def label_ioctls(bv, dispatch_device_control):
    """Find supported IOCTLs and print corresponding CTL_CODE macros.

    For each IOCTL, add a comment at the start of the handling code denoting
    which IOCTL is being handled. Print the CTL_CODE macro to the log console.
    """
    print "Finding ioctls..."
    ioctls = ioctl.find_ioctls(bv.file.filename, dispatch_device_control, bv.arch.address_size)
    for code in sorted(ioctls):
        print ioctl.get_macro(code)
        for address in ioctls[code]:
            funcs = bv.get_functions_containing(address)
            assert len(funcs) == 1
            funcs[0].set_comment_at(address, "Handler for IOCTL_{:x}".format(code))


def label_all(bv):
    """Find and label DriverEntry, IRP dispatch routines, and IOCTLs."""
    driver_entry = get_driver_entry(bv)
    util.create_named_function(bv, driver_entry.start, "DriverEntry")

    dispatch_table = label_driver_object_routines(bv, driver_entry)

    # TODO: Label other stuff based on function calls
    bv.update_analysis_and_wait()





    dispatch_device_control = dispatch_table[constants.IRP_MJ_DEVICE_CONTROL]
    if dispatch_device_control is not None:
        label_ioctls(bv, dispatch_device_control)
