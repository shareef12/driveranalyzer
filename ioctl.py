"""
TODO:
Verify that IRP and IOSL offsets are correct for both x86 and x64
Find out how to import angr in binja python - binja overrides sys.path
Look at how PEFile manages its structs. Maybe we can do something similar to
    remove repetition between __init__() and packed() methods.
Test
"""

import struct
import time

import angr
import claripy

import constants


class SimCCMicrosoftAMD64(angr.calling_conventions.SimCCSystemVAMD64):
    """angr doesn't natively support Microsoft x64 stdcall calling convention."""
    ARG_REGS = ['rcx', 'rdx', 'r8', 'r9']
    #CALLEE_CLEANUP = True  # stdcall


class SymbolicDeviceControlIoStackLocation(object):

    def __init__(self, address_size):
        self.major_function = claripy.BVV(constants.IRP_MJ_DEVICE_CONTROL, 1)   # Concretize!
        self.minor_function = claripy.BVS("MinorFunction", 1)
        self.flags = claripy.BVS("Flags", 1)
        self.control = claripy.BVS("Control", 1)

        self.output_buffer_length = claripy.BVS("OutputBufferLength", 4)
        self.input_buffer_length = claripy.BVS("InputBufferLength", 4)
        self.io_control_code = claripy.BVS("IoControlCode", 4)
        self.type3_input_buffer = claripy.BVS("Type3InputBuffer", address_size)

    def packed(self):
        return [
            self.major_function,
            self.minor_function,
            self.flags,
            self.control,
            self.output_buffer_length,
            self.input_buffer_length,
            self.io_control_code,
            self.type3_input_buffer]


class SymbolicIrp(object):

    def __init__(self, address_size):
        self.type = claripy.BVS("Type", 16)
        self.size = claripy.BVS("Size", 16)
        self.mdl_address = claripy.BVS("MdlAddress", address_size)
        self.flags = claripy.BVS("Flags", 32)

        self.associated_irp = claripy.BVS("AssociatedIrp", address_size)
        self.thread_list_entry = claripy.BVS("ThreadListEntry", address_size * 2)
        self.io_status_status = claripy.BVS("IoStatusStatus", address_size)
        self.io_status_information = claripy.BVS("IoStatusInformation", address_size)

        self.requestor_mode = claripy.BVS("RequestorMode", 1)
        self.pending_returned = claripy.BVS("PendingReturned", 1)
        self.stack_count = claripy.BVS("StackCount", 1)
        self.current_location = claripy.BVS("CurrentLocation", 1)
        self.cancel = claripy.BVS("Cancel", 1)
        self.cancel_irql = claripy.BVS("CancelIrql", 1)
        self.apc_environment = claripy.BVS("ApcEnvironment", 1)
        self.allocation_flags = claripy.BVS("AllocationFlags", 1)

        # User fields
        self.user_iosb = claripy.BVS("UserIosb", address_size)
        self.user_event = claripy.BVS("UserEvent", address_size)
        self.overlay = claripy.BVS("Overlay", address_size * 2)
        self.cancel_routine = claripy.BVS("CancelRoutine", address_size)
        self.user_buffer = claripy.BVS("UserBuffer", address_size)

        # Kernel fields. Following fields are part of the Tail.Overlay struct
        # Concretize the current_stack_location field since it's used to lookup
        # the current IRP stack location.
        self.driver_context = claripy.BVS("DriverContext", address_size * 4)
        self.thread = claripy.BVS("Thread", address_size)
        self.auxiliary_buffer = claripy.BVS("AuxiliaryBuffer", address_size)
        self.list_entry = claripy.BVS("ListEntry", address_size * 2)
        self.current_stack_location = claripy.BVV(1, address_size)

    def packed(self):
        return [
            self.type,
            self.size,
            self.mdl_address,
            self.flags,
            self.associated_irp,
            self.thread_list_entry,
            self.io_status_status,
            self.io_status_information,
            self.requestor_mode,
            self.pending_returned,
            self.stack_count,
            self.current_location,
            self.cancel,
            self.cancel_irql,
            self.apc_environment,
            self.allocation_flags,
            self.user_iosb,
            self.user_event,
            self.overlay,
            self.cancel_routine,
            self.user_buffer,
            self.driver_context,
            self.thread,
            self.auxiliary_buffer,
            self.list_entry,
            self.current_stack_location]


def swap32(n):
    return struct.unpack("<I", struct.pack(">I", n))[0]


def find_ioctls(bv, dispatch_device_control):
    """Symbolically explore the dispatch function to find IOCTLs"""
    proj = angr.Project(bv.file.filename, auto_load_libs=False)

    # Create a call state with a symbolic IRP
    sirp = SymbolicIrp(bv.arch.address_size)
    siosl = SymbolicDeviceControlIoStackLocation(bv.arch.address_size)
    irp = sirp.packed() + siosl.packed()

    cc = SimCCMicrosoftAMD64(proj.arch)
    state = proj.factory.call_state(dispatch_device_control, irp, cc=cc, ret_addr=0xdeadbeef,
                                    add_options={angr.options.UNICORN})

    # Run until all states finish
    print "running..."
    start = time.time()
    simgr = proj.factory.simgr(state)
    while len(simgr.active) > 0:
        simgr.explore(find=0xdeadbeef)
    stop = time.time()
    print "done. Took", stop - start, "seconds"

    print simgr

    for s in simgr.found:
        #print s.simplify()
        try:
            code = swap32(s.solver.eval_one(siosl.io_control_code))
            print "[+]", code
            if s.regs.rax.concrete:
                print "[+]   ret =", hex(s.solver.eval(s.regs.rax))
        except angr.SimValueError as err:
            print s.simplify(), s.regs.rax

    print 'done'
