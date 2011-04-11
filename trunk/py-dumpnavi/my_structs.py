#!/usr/bin/python
'''
DumpNAVI port by aznoohwee85

Structs and code sniplets based on bysin's DumpNAVI project
http://www.linuxkiddies.com/bysin/navi/

bysin's DumpNAVi uses code snipplets from Willem Jan Hengeveld <itsme@xs4all.nl>.

This program is used to modify Acura/Honda navigation systems by dumping and
modifying system files contained on the DVD.

ChangeLog:
April 1st - Experimental release; only file listing confirmed to work.
April 6th - Limited file extraction support (test all file extraction with option -e a)
            Update file currently not implemented
------------------------------------------------------

Copyright (c) 2011 <aznoohwee85>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

'''

import sys, struct, os
from ctypes import *
from struct import *

FILEATTR_COMPRESS_MODULE = 4096 #really?? i'll have to doublecheck this somehow..
FILEATTR_COMPRESS = 2048
FILEATTR_HIDDEN = 4
FILEATTR_READONLY = 2
FILEATTR_SYSTEM = 1

ROM_EXTRA = 9

IMAGE_DOS_SIGNATURE               = 0x5A4D
IMAGE_FILE_RELOCS_STRIPPED        = 0x0001
IMAGE_SCN_CNT_CODE                = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA    = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA  = 0x00000080
IMAGE_SCN_COMRPESSED              = 0x00002000

doscode = pack('<64B', 0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 
                       0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
                       0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 
                       0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
                       0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 
                       0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
                       0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 
                       0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

STD_EXTRA = 16
EXP = 0
IMP = 1
RES = 2
EXC = 3
SEC = 4
FIX = 5
DEB = 6
IMD = 7
MSP = 8
TLS = 9
CBK = 10
RS1 = 11
RS2 = 12
RS3 = 13
RS4 = 14
RS5 = 15

E32OBJNAMEBYTES = 8

ST_TEXT   = 0
ST_DATA   = 1
ST_PDATA  = 2
ST_RSRC   = 3
ST_OTHER  = 4

g_segmentNames = ['.text', '.data', '.pdata', '.rsrc', '.other']
g_segmentNameUsage = [0, 0, 0, 0, 0]

class StructHelper:
  def send(self):
    return buffer(self)[:]

  def receiveSome(self, data):
    fit = min(len(data), sizeof(self))
    memmove(addressof(self), data, fit)

  
class xipHdr(Structure, StructHelper):
  _fields_ = [('magic', c_ubyte*7),
              ('imageaddr', c_uint32),
              ('imagelen', c_uint32)]

  _pack_ = 1  

class ececHdr(Structure, StructHelper):
  _fields_ = [('ECEC', c_ubyte*4),
              ('romhdraddr', c_uint32)]
  def __str__(self):
    return 'romhdraddr: %08X' % (self.romhdraddr)

class romHdr(Structure, StructHelper): 
  _fields_ = [('dllfirst', c_uint32),
              ('dlllast', c_uint32),
              ('physfirst', c_uint32),
              ('physlast', c_uint32),
              ('nummods', c_uint32),
              ('ulRAMStart', c_uint32),
              ('ulRAMFree', c_uint32),
              ('ulRAMEnd', c_uint32),
              ('ulCopyEntries', c_uint32),
              ('ulCopyOffset', c_uint32),
              ('ulProfileLen', c_uint32),
              ('ulProfileOffset', c_uint32),
              ('numfiles', c_uint32),
              ('ulKernelFlags', c_uint32),
              ('ulFSRamPercent', c_uint32),
              ('ulDrivglobStart', c_uint32),
              ('ulDrivglobLen', c_uint32),
              ('usCPUType', c_uint16),
              ('usMiscFlags', c_uint16),
              ('pExtensions', c_uint32),
              ('ulTrackingStart', c_uint32),
              ('ulTrackingLen', c_uint32)]

class blockHdr(Structure, StructHelper):
  _fields_ = [('addr', c_uint32),
              ('length', c_uint32),
              ('chksum', c_uint32)]

class moduleHdr(Structure, StructHelper):
  _fields_ = [('attr', c_uint32),
              ('time', c_uint32),
              ('time2', c_uint32),
              ('size', c_uint32),
              ('fileaddr', c_uint32),
              ('e32offset', c_uint32),
              ('o32offset', c_uint32),
              ('loadoffset', c_uint32)]
  filename = None

  def __str__(self):
    return '%c%c%c%c%10d%10s%22s (ROM 0x%08x)' % (
      'C' if self.attr & FILEATTR_COMPRESS_MODULE else '_',
      'H' if self.attr & FILEATTR_HIDDEN else '_',
      'R' if self.attr & FILEATTR_READONLY else '_',
      'S' if self.attr & FILEATTR_SYSTEM else '_',
      self.size,
      '',
      self.filename,
      self.loadoffset)

class fileHdr(Structure, StructHelper):
  _fields_ = [('attr', c_uint32),
              ('time', c_uint32),
              ('time2', c_uint32),
              ('size', c_uint32),
              ('size2', c_uint32),
              ('fileaddr', c_uint32),
              ('loadoffset', c_uint32)]
  filename = None

  def __str__(self):
    return '%c%c%c%c%10d%10s%22s (ROM 0x%08x)' % (
      'C' if self.attr & FILEATTR_COMPRESS else '_',
      'H' if self.attr & FILEATTR_HIDDEN else '_',
      'R' if self.attr & FILEATTR_READONLY else '_',
      'S' if self.attr & FILEATTR_SYSTEM else '_',
      self.size,
      self.size2,
      self.filename,
      self.loadoffset)  

class e32_info(Structure, StructHelper):
  _fields_ = [('rva', c_uint32),
              ('size', c_uint32)]

class e32_rom(Structure, StructHelper):
  _fields_ = [('e32_objcnt', c_uint16),
              ('e32_imageflags', c_uint16),
              ('e32_entryrva', c_uint32),
              ('e32_vbase', c_uint32),
              ('e32_subsysmajor', c_uint16),
              ('e32_subsysminor', c_uint16),
              ('e32_stackmax', c_uint32),
              ('e32_vsize', c_uint32),
              ('e32_sect14rva', c_uint32),
              ('e32_sect14size', c_uint32),
              ('e32_unit', e32_info*ROM_EXTRA),
              ('e32_subsys', c_uint16)]

class o32_rom(Structure, StructHelper):
  _fields_ = [('o32_vsize', c_uint32),
              ('o32_rva', c_uint32),
              ('o32_psize', c_uint32),
              ('o32_dataptr', c_uint32),
              ('o32_realaddr', c_uint32),
              ('o32_flags', c_uint32)]
  def __str__(self):
    return 'o32_vsize: %08X\no32_rom_flags: %08X' % (self.o32_vsize, self.o32_flags)

class IMAGE_DOS_HEADER(Structure, StructHelper):
  _fields_ = [('e_magic', c_uint16),
              ('e_cblp', c_uint16),
              ('e_cp', c_uint16),
              ('e_crlc', c_uint16),
              ('e_cparhdr', c_uint16),
              ('e_minalloc', c_uint16),
              ('e_maxalloc', c_uint16),
              ('e_ss', c_uint16),
              ('e_sp', c_uint16),
              ('e_csum', c_uint16),
              ('e_ip', c_uint16),
              ('e_cs', c_uint16),
              ('e_lfarlc', c_uint16),
              ('e_ovno', c_uint16),
              ('e_res', c_uint16*4),
              ('e_oemid', c_uint16),
              ('e_oeminfo', c_uint16),
              ('e_res2', c_uint16*10),
              ('e_lfanew', c_long)]


class e32_exe(Structure, StructHelper):
  _fields_ = [('e32_magic', c_byte*4),
              ('e32_cpu', c_uint16),
              ('e32_objcnt', c_uint16),
              ('e32_timestamp', c_uint32),
              ('e32_symtaboff', c_uint32),
              ('e32_symcount', c_uint32),
              ('e32_opthdrsize', c_uint16),
              ('e32_imageflags', c_uint16),
              ('e32_coffmagic', c_uint16),
              ('e32_linkmajor', c_ubyte),
              ('e32_linkminor', c_ubyte),
              ('e32_codesize', c_uint32),
              ('e32_initdsize', c_uint32),
              ('e32_uninitdsize', c_uint32),
              ('e32_entryrva', c_uint32),
              ('e32_codebase', c_uint32),
              ('e32_database', c_uint32),
              ('e32_vbase', c_uint32),
              ('e32_objalign', c_uint32),
              ('e32_filealign', c_uint32),
              ('e32_osmajor', c_uint16),
              ('e32_osminor', c_uint16),
              ('e32_usermajor', c_uint16),
              ('e32_userminor', c_uint16),
              ('e32_subsysmajor', c_uint16),
              ('e32_subsysminor', c_uint16),
              ('e32_res1', c_uint32),
              ('e32_vsize', c_uint32),
              ('e32_hdrsize', c_uint32),
              ('e32_filechksum', c_uint32),
              ('e32_subsys', c_uint16),
              ('e32_dllflags', c_uint16),
              ('e32_stackmax', c_uint32),
              ('e32_stackinit', c_uint32),
              ('e32_heapmax', c_uint32),
              ('e32_heapinit', c_uint32),
              ('e32_res2', c_uint32),
              ('e32_hdrextra', c_uint32),
              ('e32_unit', e32_info*STD_EXTRA)]

class o32_obj(Structure, StructHelper):
  _fields_ = [('o32_name', c_ubyte*E32OBJNAMEBYTES),
              ('o32_vsize', c_uint32),
              ('o32_rva', c_uint32),
              ('o32_psize', c_uint32),
              ('o32_dataptr', c_uint32),
              ('o32_realaddr', c_uint32),
              ('o32_access', c_uint32),
              ('o32_temp3', c_uint32),
              ('o32_flags', c_uint32)]
  _pack_ = 1

  def __str__(self):
    return 'flags: %08X' % (self.o32_flags)
