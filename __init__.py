#!/usr/bin/env python2

r"""Windows Driver Analyzer Binary Ninja Plugin

This plugin can be used within the Binary Ninja GUI or standalone with the
commercial or enterprise version to detect IRP dispatch routines and valid
IOCTL codes in Windows kernel drivers.

TODO:
 - Function detection for ThreadCreateNotify, ProcessCreateNotify, Workitems, IoCsqInitialize, etc.
 - Recursively follow calls from DriverEntry for code that initializes the DriverObject when
   finding dispatch routines. We currently only search DriverEntry.
"""

from __future__ import print_function
import argparse
import os
import sys

from binaryninja import BinaryViewType, BackgroundTaskThread, PluginCommand

if sys.platform == "win32":
    sys.path.append(r"C:\Python27\Lib\site-packages")

import analyze

class LabelDriverDispatchRoutinesTask(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Labeling Driver Dispatch Routines", can_cancel=True)
        self.bv = bv

    def run(self):
        self.bv.begin_undo_actions()
        a = analyze.Analysis(self.bv)
        a.label_driver_dispatch_routines()
        self.bv.commit_undo_actions()
        self.bv.update_analysis()


class LabelCallbackRoutinesTask(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Labeling Callback Routines", can_cancel=True)
        self.bv = bv

    def run(self):
        self.bv.begin_undo_actions()
        a = analyze.Analysis(self.bv)
        a.label_callback_routines()
        self.bv.commit_undo_actions()
        self.bv.update_analysis()


class FindIoctlsTask(BackgroundTaskThread):
    def __init__(self, bv, function=None):
        BackgroundTaskThread.__init__(self, "Finding IOCTLs", can_cancel=True)
        self.bv = bv
        if function:
            self.function = function.start
        else:
            self.function = None

    def run(self):
        self.bv.begin_undo_actions()
        a = analyze.Analysis(self.bv)
        a.find_ioctls(self.function)
        self.bv.commit_undo_actions()
        self.bv.update_analysis()


def label_driver_dispatch_routines(bv):
    t = LabelDriverDispatchRoutinesTask(bv)
    t.start()


def label_callback_routines(bv):
    t = LabelCallbackRoutinesTask(bv)
    t.start()


def find_ioctls(bv, function=None):
    t = FindIoctlsTask(bv, function)
    t.start()


def cmdline_main():
    parser = argparse.ArgumentParser(description="Auto-detect IRP Dispatch routines and IOCTLs.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-i", "--ioctls", action="store_true", default=False,
                        help="Detect supported IOCTL control codes.")
    parser.add_argument("driver", help="Windows driver to analyze.")

    args = parser.parse_args()

    if not os.path.isfile(args.driver):
        print("[-] '{:s}' is not a file".format(args.driver), file=sys.stderr)
        return 1

    # TODO: This line always returns None
    bv = BinaryViewType["PE"].open(args.driver)

    analysis = analyze.Analysis(bv)
    analysis.label_driver_dispatch_routines()
    if args.ioctls:
        analysis.find_ioctls()


if __name__ == "__main__":
    cmdline_main()
else:
    PluginCommand.register(
        "Label Driver Dispatch Routines", "Label driver dispatch routines for IRPs and other callbacks",
        action=label_driver_dispatch_routines)
    #PluginCommand.register(
    #    "Label Callback Routines", "Label callback routines used in common kernel APIs",
    #    action=label_callback_routines)
    PluginCommand.register(
        "Find IOCTLs [global]", "Find supported IOCTLs and generate CTL_CODE macros",
        action=find_ioctls)
    PluginCommand.register_for_function(
        "Find IOCTLs [current function]", "Find supported IOCTLs and generate CTL_CODE macros",
        action=find_ioctls)
