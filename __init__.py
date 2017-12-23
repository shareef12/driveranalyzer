#!/usr/bin/env python2

"""
TODO:
Determine supported IOCTLs (support switch or branch on IOCTL code).
Regenerate header files with CTL_CODE macro definitions.
"""

import sys

from binaryninja import BinaryViewType, BackgroundTaskThread

import analyze


class BackgroundAnalyzer(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "Labeling driver dispatch routines", can_cancel=True)
        self.bv = bv

    def run(self):
        bv = self.bv
        bv.begin_undo_actions()
        analyze.label_all(bv)
        bv.commit_undo_actions()
        bv.update_analysis()


def main(bv):
    #t = BackgroundAnalyzer(bv)
    #t.start()
    bv.begin_undo_actions()
    analyze.label_all(bv)
    bv.commit_undo_actions()
    bv.update_analysis()


if __name__ == "__main__":
    bv = BinaryViewType["PE"].open(sys.argv[1])
    main(bv)
