#!/usr/bin/env python2

"""
TODO:
 - Function detection for FastIO, ThreadCreateNotify, ProcessCreateNotify, Workitems,
   IoCsqInitialize, etc.
"""

import sys
if sys.platform == "win32":
    sys.path.append(r"C:\Python27\Lib\site-packages")
else:
    sys.path.append(r"/usr/local/lib/python2.7/dist-packages")

from binaryninja import BinaryViewType, BackgroundTaskThread, PluginCommand

import analyze


class BackgroundAnalyzer(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Analyzing Driver", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        bv.begin_undo_actions()
        analyze.label_all(bv)
        bv.commit_undo_actions()
        bv.update_analysis()


def main(bv):
    t = BackgroundAnalyzer(bv)
    t.start()


if __name__ == "__main__":
    bv = BinaryViewType["PE"].open(sys.argv[1])
    main(bv)
else:
    PluginCommand.register("Analyze Driver", "Name dispatch functions and find valid IOCTLs",
                           action=main)
