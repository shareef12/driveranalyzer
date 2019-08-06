"""Use symbolic execution to determine supported IOCTLs.

This function will attempt to symbolically execute the driver's IOCTL
dispatch routine with a symbolid IRP. Once the IRP's io_control_code
field is constrained to a single value, terminate the symbolic execution
for that path and report the code as supported.

TODO:
 - memory_endness isn't set correctly for x64 calling convention. Have to `swap32` the
   solved ioctl. Figure out how to fix this and remove the `swap32` hack.
 - State explosion can occur on a memcpy with a symbolic state. This can occur if
   an IOCTL handling routine reads the len parameter from the symbolic IRP SystemBuffer.
 - NT_ASSERT compiles to int 0x2c, which pyvex doesn't lift
 - cr3 reading/writing isn't modeled well by pyvex
"""

from __future__ import print_function
from builtins import int    # python2/3 compatibility for isinstance() checks
import collections
import struct

import angr
from angr.calling_conventions import SimCCStdcall, SimCCSystemVAMD64, PointerWrapper
import claripy

import constants


class SimCCMicrosoftAMD64(SimCCSystemVAMD64):
    """Angr doesn't define the Microsoft x64 calling convention."""
    ARG_REGS = ['rcx', 'rdx', 'r8', 'r9']
    FP_ARG_REGS = ['xmm0', 'xmm1', 'xmm2', 'xmm3']
    STACKARG_SP_BUFF = 32   # Shadow space


class SymbolicStructure(object):
    """Base class for symbolic structures.

    Child classes should define the _fields member as a list of tuples, where
    each tuple is a (name, size) pair. If size is an int, the field will be
    converted to a symbolic variable. Otherwise, it will remain as defined in
    the child class.
    """

    def __init__(self):
        self._fields = getattr(self, "_fields", [])
        for name, value in self._fields:
            if isinstance(value, int):
                setattr(self, name, claripy.BVS(name, value))
            else:
                setattr(self, name, value)

    def pack(self):
        """Return a representation that can be used by angr as a function argument."""
        return tuple(getattr(self, n) for n, _ in self._fields)


class SymbolicIrp(SymbolicStructure):
    def __init__(self, address_bits):
        if address_bits == 32:
            self._fields = [
                ("type", 16),
                ("size", 16),
                ("mdl_address", address_bits),
                ("flags", 32)]
        else:
            self._fields = [
                ("type", 16),
                ("size", 16),
                ("allocation_processor_number", 16),
                ("reserved", 16),
                ("mdl_address", address_bits),
                ("flags", 32),
                ("pad1", claripy.BVV(0, 32))]   # Concretize padding

        self._fields += [
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
            ("original_file_object", address_bits)]
        if address_bits == 64:
            self._fields += [("irp_extension", address_bits)]

        super(SymbolicIrp, self).__init__()


class SymbolicDeviceIoControlIoStackLocation(SymbolicStructure):
    def __init__(self, address_bits):
        self._fields = [
            ("major_function", claripy.BVV(constants.IRP_MJ_DEVICE_CONTROL, 8)),
            ("minor_function", 8),
            ("flags", 8),
            ("control", 8)]

        if address_bits == 32:
            self._fields += [
                ("output_buffer_length", 32),
                ("input_buffer_length", 32),
                ("io_control_code", 32),
                ("type3_input_buffer", address_bits)]
        else:
            self._fields += [
                ("pad1", claripy.BVV(0, 32)),   # concretize padding
                ("output_buffer_length", 32),
                ("pad2", claripy.BVV(0, 32)),
                ("input_buffer_length", 32),
                ("pad3", claripy.BVV(0, 32)),
                ("io_control_code", 32),
                ("pad4", claripy.BVV(0, 32)),
                ("type3_input_buffer", address_bits)]

        self._fields += [
            ("device_object", address_bits),
            ("file_object", address_bits),
            ("completion_routine", address_bits),
            ("context", address_bits)]

        super(SymbolicDeviceIoControlIoStackLocation, self).__init__()


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
    """Symbolically explore the dispatch function to find supported IOCTLs.

    We want to symbolically explore the function until we enter a state
    where the IOCTL is constrained to a single value. Return a map of IOCTL
    codes to a list of addresses where the handling code starts.
    """
    proj = angr.Project(filename, auto_load_libs=False)

    # Create a call state with a symbolic IRP
    sirp = SymbolicIrp(address_size * 8)
    siosl = SymbolicDeviceIoControlIoStackLocation(address_size * 8)
    sirp.current_stack_location = PointerWrapper(siosl.pack())
    irp = sirp.pack()

    if address_size == 4:
        cc = SimCCStdcall(proj.arch)
    else:
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
    while len(simgr.active) > 0:
        simgr.explore(find=ioctl_constrained, avoid=0xdeadbeef)
    #print(simgr)

    # Return a map of IOCTL codes to a list of handler addresses
    ioctls = collections.defaultdict(list)
    for s in simgr.found:
        # For some reason, the memory_endness for x64 symbolic variables isn't getting
        # set correctly. Account for little-endian manually.
        if address_size == 4:
            code = s.solver.eval_one(siosl.io_control_code)
            start = s.solver.eval_one(s.regs.eip)
        else:
            code = swap32(s.solver.eval_one(siosl.io_control_code))
            start = s.solver.eval_one(s.regs.rip)
        ioctls[code].append(start)

    return ioctls
