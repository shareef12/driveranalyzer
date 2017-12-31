"""
TODO:
 - x86 structs for IRP and IOSL

Errors
 - MDL copy function causes it to run forever (memset with a symbolic len will cause state
   explosion.
 - NT_ASSERT compiles to int 0x2c, which pyvex doesn't lift
 - cr3 reading/writing isn't modeled well by pyvex
"""

import collections
import struct
import time

import angr
from angr.calling_conventions import SimCCSystemVAMD64, PointerWrapper
import claripy

import constants


class SimCCMicrosoftAMD64(SimCCSystemVAMD64):
    """angr doesn't natively support Microsoft x64 stdcall calling convention."""
    ARG_REGS = ['rcx', 'rdx', 'r8', 'r9']
    CALLEE_CLEANUP = True   # stdcall


class Structure(object):
    def __init__(self):
        self._fields = getattr(self, "_fields", [])
        for name, value in self._fields:
            if type(value) in (int, long):
                setattr(self, name, claripy.BVS(name, value))
            else:
                setattr(self, name, value)

    def pack(self):
        return tuple(getattr(self, n) for n, _ in self._fields)


class SymbolicIrp(Structure):
    def __init__(self, address_bits):
        self._fields = [
            ("type", 16),
            ("size", 16),
            ("allocation_processor_number", 16),
            ("reserved", 16),
            ("mdl_address", address_bits),
            ("flags", 32),
            ("pad1", claripy.BVV(0, 32)),   # Concretize padding

            ("associated_irp", address_bits),
            ("thread_list_entry", address_bits * 2),
            ("io_status_status", address_bits),
            ("io_status_information", address_bits),

            ("requestor_mode", 8),
            ("pending_returned", 8),
            ("stack_count", 8),
            ("current_location", 8),
            ("cancel", 8),
            ("cancel_irql", 8),
            ("apc_environment", 8),
            ("allocation_flags", 8),

            # User fields
            ("user_iosb", address_bits),
            ("user_event", address_bits),
            ("overlay", address_bits * 2),
            ("cancel_routine", address_bits),
            ("user_buffer", address_bits),

            # Kernel fields. Members of Tail.Overlay.
            ("driver_context", address_bits * 4),
            ("thread", address_bits),
            ("auxiliary_buffer", address_bits),
            ("list_entry", address_bits * 2),
            ("current_stack_location", address_bits),
            ("original_file_object", address_bits),
            ("irp_extension", address_bits),
        ]
        super(SymbolicIrp, self).__init__()


class SymbolicDeviceControlIoStackLocation(Structure):
    def __init__(self, address_bits):
        self._fields = [
            ("major_function", claripy.BVV(constants.IRP_MJ_DEVICE_CONTROL, 8)),
            ("minor_function", 8),
            ("flags", 8),
            ("control", 8),
            ("pad1", claripy.BVV(0, 32)),   # concretize padding

            ("output_buffer_length", 32),
            ("pad2", claripy.BVV(0, 32)),   # TODO: only on x64?
            ("input_buffer_length", 32),
            ("pad3", claripy.BVV(0, 32)),
            ("io_control_code", 32),
            ("pad4", claripy.BVV(0, 32)),
            ("type3_input_buffer", address_bits),

            ("device_object", address_bits),
            ("file_object", address_bits),
            ("completion_routine", address_bits),
            ("context", address_bits),
        ]
        super(SymbolicDeviceControlIoStackLocation, self).__init__()


def swap32(n):
    return struct.unpack("<I", struct.pack(">I", n))[0]


def get_macro(code):
    """Convert a IOCTL code into a CTL_CODE macro string."""
    type = (code >> 16) & 0xffff
    access = (code >> 14) & 0x03
    function = (code >> 2) & 0x0fff
    method = code & 0x03

    try:
        stype = constants.DEVICE_TYPES[type]
    except KeyError:
        stype = "FILE_DEVICE_CUSTOM_{:x}".format(type)
    saccess = constants.ACCESS[access]
    smethod = constants.METHODS[method]
    return "#define IOCTL_{:x}      CTL_CODE({:s}, {:d}, {:s}, {:s})".format(
        code, stype, function, smethod, saccess)


def find_ioctls(filename, dispatch_device_control, address_size=8):
    """Symbolically explore the dispatch function to find IOCTLs"""
    proj = angr.Project(filename, auto_load_libs=False)

    # Create a call state with a symbolic IRP
    sirp = SymbolicIrp(address_size * 8)
    siosl = SymbolicDeviceControlIoStackLocation(address_size * 8)
    sirp.current_stack_location = PointerWrapper(siosl.pack())
    irp = sirp.pack()

    cc = SimCCMicrosoftAMD64(proj.arch)
    state = proj.factory.call_state(dispatch_device_control,
                                    claripy.BVS("DeviceObject", 64), irp,
                                    cc=cc, ret_addr=0xdeadbeef)

    def ioctl_constrained(st):
        """Return true if the IOCTL code is constrained to a single value."""
        try:
            st.solver.eval_one(siosl.io_control_code)
            return True
        except angr.SimValueError:
            return False

    # Run until all states finish
    simgr = proj.factory.simgr(state)
    print "Running symbolic analysis..."
    start = time.time()
    while len(simgr.active) > 0:
        simgr.explore(find=ioctl_constrained, avoid=0xdeadbeef)
    stop = time.time()
    print "Done. Took {:f} seconds. Found {:d} IOCTLs.".format(stop - start, len(simgr.found))
    #print simgr

    # Return a map of IOCTL codes to a list of handler addresses
    ioctls = collections.defaultdict(list)
    for s in simgr.found:
        code = swap32(s.solver.eval_one(siosl.io_control_code))
        start = s.solver.eval_one(s.regs.rip)
        ioctls[code].append(start)
    return ioctls
