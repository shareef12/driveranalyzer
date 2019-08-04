# Windows Driver Analyzer (v0.1.0)

Author: **shareef12**
_Find IRP dispatch routines and valid IOCTLs in a Windows kernel driver_


## Description:

This plugin will try to find and label IRP dispatch routines through data-flow
analysis of the DriverEntry routine. Additionally, this helper plugin will
attempt to identify valid IOCTL control codes that the driver supports.
Handler code for detected IOCTLs will be labeled, and CTL_CODE macros will be
generated.


## Installation Instructions

### Windows



### Linux


## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * 1822


## Required Dependencies

The following dependencies are required for this plugin:

 * pip - angr


## License

This plugin is released under a MIT license.


## Metadata Version

2
