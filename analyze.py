from __future__ import print_function

import collections

from binaryninja import LowLevelILOperation

import constants
import ioctl
import util


class IrpDispatchRoutine(object):
    """Helper class to name dispatch routines semi-intelligently.

    If the dispatch routine handles:
    More than half the IRPs : "DispatchDefault"
    One IRP                 : "Dispatch<IrpName>"
    Multiple IRPs           : "Dispatch_<Irp1Name>_<Irp2Name>..."
    """
    def __init__(self, irps):
        self.irps = irps

    @property
    def name(self):
        if len(self.irps) > constants.IRP_MJ_MAXIMUM_FUNCTION / 2:
            return "DispatchDefault"
        irp_names = [constants.IRP_MJ_NAMES[i] for i in self.irps]
        if len(irp_names) == 1:
            return "Dispatch{:s}".format(irp_names[0])
        return "Dispatch_{:s}".format("_".join(irp_names))

    @property
    def comment(self):
        irp_names = ["IRP_MJ_" + constants.IRP_MJ_NAMES[i] for i in self.irps]
        return "Dispatch routine for:\n  * " + "\n  * ".join(irp_names)


class FastIoDispatchRoutine(object):
    """Helper class to name dispatch routines semi-intelligently.

    If the dispatch routine handles:
    More than half the callbacks : "FastIoDefault"
    One callback                 : "FastIo<CallbackName>"
    Multiple callbacks           : "FastIo_<Callback1Name>_<Callback2Name>..."
    """
    def __init__(self, routines):
        self.routines = routines

    @property
    def name(self):
        if len(self.routines) > len(constants.FAST_IO_NAMES) / 2:
            return "FastIoDefault"
        routine_names = [constants.FAST_IO_NAMES[i] for i in self.routines]
        if len(routine_names) == 1:
            return "FastIo{:s}".format(routine_names[0])
        return "FastIo_{:s}".format("_".join(routine_names))

    @property
    def comment(self):
        routine_names = ["FastIo" + constants.FAST_IO_NAMES[i] for i in self.routines]
        return "Dispatch routine for:\n  * " + "\n  * ".join(routine_names)


class DispatchTable(object):
    """Helper class to maintain the state of a dispatch table.

    Maintain two structures:
    1. Map of routine addresses to a list of callbacks they support (1 to many)
    2. List of routine addresses indexed by the callback they support (1 to 1)

    :member routine_type: The class type of the routine (IrpDispatchRoutine or
        FastIoDispatchRoutine)
    :member routines: A dictionary mapping a single routine address to a list
        of codes it implements.
    :member table: A table mapping each code to a routine address.
    """
    def __init__(self, routine_type, size):
        self.routine_type = routine_type
        self.routines = collections.defaultdict(list)
        self.table = [None] * size

    def add(self, address, routine):
        self.routines[address].append(routine)
        self.table[routine] = address

    def label_all(self, bv):
        for address, routines in self.routines.items():
            routine = self.routine_type(routines)
            print("    {:s}: 0x{:x}".format(routine.name, address))
            util.create_named_function(bv, address, routine.name, routine.comment)


class Analysis:
    """Top-level class used to cache analysis results.

    The IOCTL finding analysis requires the results of other analysis runs.
    Caching the results of previous analysis runs will allow us to get fatster
    results to the user.
    """

    def __init__(self, bv):
        self.bv = bv
        self._offsets = constants.Offsets(bv.arch.address_size)

        self.driver_entry = None
        self.driver_unload = None
        self.driver_start_io = None
        self.major_function_table = None
        self.fast_io_dispatch_table = None

    def _get_driver_entry(self):
        """Get the DriverEntry function.

        The first basic block at _start is provided by the compiler, and has two
        function calls. The second is always DriverEntry. Sometimes, tail-call
        optimization is applied and _start and DriverEntry are folded into a
        single function.
        """
        _start = self.bv.entry_function
        if len(_start.basic_blocks) > 1:  # Tail-call optimized
            return _start

        # Non-optimized. Get the call target of the second call
        block = _start.low_level_il.basic_blocks[0]
        calls = [inst for inst in block if inst.operation == LowLevelILOperation.LLIL_CALL]
        assert (len(calls) == 2)

        call_target = calls[1].dest.value.value
        entry = self.bv.get_function_at(call_target)
        return entry


    def _get_irp_major_function_table(self, drvobj_stores):
        """Find IRP MajorFunction dispatch routines.

        :param drvobj_stores: A dict of stores that occurred at offsets from
            the DriverObject. Maps offsets to the contents of the store.
        :return: A DispatchTable object representing the MajorFunction
            dispatch table in the DriverObject.
        """
        # IRP dispatch routine addresses should never by dynamically computed.
        # The src for the store instruction should always be a constant.
        constant_src_stores = {k: v.value.value for k, v in drvobj_stores.items() if v.value.is_constant}

        # Search all stores for ones that occur to the MajorFunction table.
        major_function_table = DispatchTable(IrpDispatchRoutine, constants.IRP_MJ_MAXIMUM_FUNCTION)
        for offset, address in constant_src_stores.items():
            if self._offsets.DRVOBJ_MAJOR_FUNCTION_OFFSET <= offset <= self._offsets.DRVOBJ_LAST_MAJOR_FUNCTION_OFFSET:
                mj_function = (offset - self._offsets.DRVOBJ_MAJOR_FUNCTION_OFFSET) / self.bv.arch.address_size
                major_function_table.add(address, mj_function)

        return major_function_table

    def _get_fast_io_dispatch_table(self, drvobj_stores):
        """Find FastIo dispatch routines.

        :param drvobj_stores: A dict of stores that occurred at offsets from
            the DriverObject. Maps offsets to the contents of the store.
        :return: A DispatchTable object representing the FastIoDispatch
            table in the DriverObject.
        """
        fast_io_dispatch_table = DispatchTable(FastIoDispatchRoutine, len(constants.FAST_IO_NAMES))

        # Unlike the IRP MajorFunction table, the FastIoDispatch table is a pointer.
        # Dereference this pointer before finding constant source stores.
        fastio_dispatch = drvobj_stores.get(self._offsets.DRVOBJ_FAST_IO_DISPATCH_OFFSET)
        if fastio_dispatch is None:
            return fast_io_dispatch_table

        # Get stores setting up the FastIoDispatch table. These routine
        # addresses should never by dynamically computed. The src for the
        # store instruction should always be a constant.
        fastio_dispatch_stores = util.get_stores_by_offset(self.driver_entry, fastio_dispatch.src)
        constant_src_stores = {k: v.value.value for k, v in fastio_dispatch_stores.items() if v.value.is_constant}

        for offset, address in constant_src_stores.iteritems():
            if self._offsets.FAST_IO_DISPATCH_START <= offset <= self._offsets.FAST_IO_DISPATCH_END:
                routine = (offset - self._offsets.FAST_IO_DISPATCH_START) / self.bv.arch.address_size
                fast_io_dispatch_table.add(address, routine)

        return fast_io_dispatch_table

    def _analyze_driver(self):
        """Analyze the DriverEntry to find dispatch routines.

        This function will attempt to identify all DriverObject dispatch
        routines, including DriverEntry, DriverUnload, DriverStartIo,
        the IRP MajorFunction table, and the FastIoDispatch table.
        """
        self.driver_entry = self._get_driver_entry()

        if len(self.driver_entry.parameter_vars) == 0:
            print("[-] Bad DriverEntry (0x{:x}): detected 0 parameters", self.driver_entry.start)
            return

        # Get all stores that occurred where the destination was an offset from the DriverObject
        driver_object = self.driver_entry.parameter_vars[0]
        drvobj_stores = util.get_stores_by_offset(self.driver_entry, driver_object)

        # DriverUnload and DriverStartIo address should never by dynamically computed.
        # The src for the store instruction should always be a constant.
        constant_src_stores = {k: v.value.value for k, v in drvobj_stores.items() if v.value.is_constant}
        self.driver_start_io = constant_src_stores.get(self._offsets.DRVOBJ_START_IO_OFFSET)
        self.driver_unload = constant_src_stores.get(self._offsets.DRVOBJ_DRIVER_UNLOAD_OFFSET)

        # Find routines for the driver's MajorFunction and FastIoDispatch tables
        if not self.major_function_table:
            self.major_function_table = self._get_irp_major_function_table(drvobj_stores)
        if not self.fast_io_dispatch_table:
            self.fast_io_dispatch_table = self._get_fast_io_dispatch_table(drvobj_stores)

    def label_driver_dispatch_routines(self):
        print("[*] Labeling DriverObject callback routines")
        if not self.driver_entry:
            self._analyze_driver()

        # Label dispatch routines in the DriverObject
        util.create_named_function(self.bv, self.driver_entry.start, "DriverEntry")
        if self.driver_unload:
            print("    DriverUnload: 0x{:x}".format(self.driver_unload))
            util.create_named_function(self.bv, self.driver_unload, "DriverUnload")
        if self.driver_start_io:
            print("    DriverStartIo: 0x{:x}".format(self.driver_start_io))
            util.create_named_function(self.bv, self.driver_start_io, "DriverStartIo")

        # Label IRP MajorFunciton and FastIoDispatch routines
        print("[+] Detected {:d} IRP Dispatch Routines".format(len(self.major_function_table.routines)))
        self.major_function_table.label_all(self.bv)

        print("[+] Detected {:d} FastIoDispatch Routines".format(len(self.fast_io_dispatch_table.routines)))
        self.fast_io_dispatch_table.label_all(self.bv)

    def label_callback_routines(self):
        raise NotImplementedError()

    def find_ioctls(self, dispatch_device_control=None):
        """Find supported IOCTLs and print corresponding CTL_CODE macros.

        For each IOCTL, add a comment at the start of the handling code denoting
        which IOCTL is being handled. Print the CTL_CODE macro to the log console.

        :param dispatch_device_control: Address of the IRP_MJ_DEVICE_CONTROL
            handler function. This parameter is optional, as we can find this
            function automatically in most cases.
        """
        print("[*] Finding IOCTLs")
        if not dispatch_device_control:
            if not self.major_function_table:
                self._analyze_driver()

            dispatch_device_control = self.major_function_table.table[constants.IRP_MJ_DEVICE_CONTROL]
            if not dispatch_device_control:
                print("[-] Could not find IRP_MJ_DEVICE_CONTROL dispatch routine")
                return

        ioctls = ioctl.find_ioctls(self.bv.file.filename, dispatch_device_control, self.bv.arch.address_size)
        print("[+] Found {:d} IOCTLs:".format(len(ioctls)))
        print()
        for code in sorted(ioctls):
            print(ioctl.get_macro(code))
            for address in ioctls[code]:
                funcs = self.bv.get_functions_containing(address)
                assert len(funcs) == 1
                funcs[0].set_comment_at(address, "Handler for IOCTL_{:x}".format(code))
        print()
