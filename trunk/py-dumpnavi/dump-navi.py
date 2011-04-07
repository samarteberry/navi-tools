#!/usr/bin/wine c:\\Python27\\python.exe
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
from binascii import *
from optparse import OptionParser
from my_structs import *
from ctypes import *

lzx = windll.CECompress

class dumpNAVI:
  f = None
 
  virtualpos = 0
  blockstartpos = 0
  blocklen = 0

  xiphdr = xipHdr()
  ecechdr = ececHdr()
  romhdr = romHdr()

  def __init__(self, fileName):
    self.f = open(fileName, 'rb')

  def virtualSeek(self, addr):
    self.f.seek(self.blockstart, 0)
    while 1:
      b = blockHdr()
      self.blockstartpos = self.f.tell()
      data = self.f.read(sizeof(blockHdr))
      b.receiveSome(data)
      
      if b.addr == None:
        break

      if addr >= b.addr and addr < b.addr + b.length:
        a = addr - b.addr
        self.f.seek(a, os.SEEK_CUR)
        self.blocklen = b.length - a
        self.virtualpos = addr
        return self.blocklen
      
      self.f.seek(b.length, os.SEEK_CUR)

    self.blocklen = 0
    self.blockstartpos = 0
    self.virtualpos = 0
    return blocklen

  def virtualRead(self, size):
    data = None
    origsize = size
    if self.virtualpos == 0:
      data = self.f.read(size)
      if data == None:
        return None
      return data
    if self.blocklen >= size:
      self.blocklen -= size
      self.virtualpos += size
      data = self.f.read(size)
      if data == None:
        return None
      return data
    data = ''
    while size > 0:
      if self.blocklen > 0:
        if self.blocklen < size:
          a = self.blocklen
        else:
          a = size
        data = data + self.f.read(a)
        if data == None:
          return None
        size = size - a
        self.virtualpos = self.virtualpos + a
      if self.virtualSeek(self.virtualpos) > 0:
        break
    return data

  def readHeader(self):
    self.xiphdr.receiveSome(self.virtualRead(sizeof(xipHdr)))
    
    magic = ''
    for c in self.xiphdr.magic:
      magic += chr(c)
    if magic == 'B000FF\n':
      self.blockstart = self.f.tell()
      return True
    return False

  def readECEC(self):
    if self.virtualSeek(self.xiphdr.imageaddr+0x40) == None:
      return False

    self.ecechdr.receiveSome(self.virtualRead(sizeof(ececHdr)))
    magic = ''
    for c in self.ecechdr.ECEC:
      magic += chr(c)
    if magic == 'ECEC':
      return True
    return False

# need to fix for other file types..
  def readRomHdr(self):
    if self.virtualSeek(self.ecechdr.romhdraddr) == None:
      return False
    self.romhdr = romHdr()
    self.romhdr.receiveSome(self.virtualRead(sizeof(romHdr)))
    return True

  def extractModule(self, module):
    e32hdr = e32_rom()
    o32hdr = []
    pe32 = e32_exe()
    po32 = o32_obj()
    dos = IMAGE_DOS_HEADER()
    newe32off = headersize = filesize = size = None
    o32hdroff = [] 
    print 'Extracting %s ...' % module.filename
    if options.PATH == None:
      path = options.FILE + '.d'
    else:
      path = options.PATH

    if os.path.exists(path) == False:
      os.mkdir(path)

    fname = path + '/' + module.filename

    r = open(fname, 'w+b')
    if r is None:
      print 'Unable to open %s' % name
      return 0
      
    if self.virtualSeek(module.e32offset) == None:
      print 'Unable to locate e32offset'
      return 0
      
    e32hdr.receiveSome(self.virtualRead(sizeof(e32_rom)))
            
    if self.virtualSeek(module.o32offset) == None:
      print 'Unable to locate o32offset'
      return 0

    for j in range(e32hdr.e32_objcnt):
      o = o32_rom()
      data = self.virtualRead(sizeof(o32_rom))
      o.receiveSome(data)
      o32hdr.append(o)
      
    dos.e_magic = IMAGE_DOS_SIGNATURE
    dos.e_cblp = 0x90
    dos.e_cp = 3
    dos.e_cparhdr = 0x4
    dos.e_maxalloc = 0xffff
    dos.e_sp = 0xb8
    dos.e_lfarlc = 0x40
    dos.e_lfanew = 0xc0
      
    r.write(dos.send())
    r.write(doscode)
    r.seek(0x40, os.SEEK_CUR)
    newe32off = r.tell()
      
    pe32.e32_magic[0] = ord('P')
    pe32.e32_magic[1] = ord('E')
    # sets the CPU type, possibly not necessary
    pe32.e32_cpu = 0x0300
    pe32.e32_objcnt = e32hdr.e32_objcnt
      
    t = module.time
    t <<= 32
    t |= module.time2
    t /= 10000000
    t -= 11644473600
      
    pe32.e32_timestamp = t
    pe32.e32_symtaboff = 0
    pe32.e32_symcount = 0
    pe32.e32_opthdrsize = 0xe0
    pe32.e32_imageflags = e32hdr.e32_imageflags | IMAGE_FILE_RELOCS_STRIPPED
    pe32.e32_coffmagic = 0x10b
    pe32.e32_linkmajor = 6
    pe32.e32_linkminor = 1
      
    pe32.e32_codesize = 0
    pe32.o32_initdsize = 0
    pe32.e32_uninitdsize = 0
    pe32.e32_entryrva = 0

    # fixed an indexing bug... not sure what the implications are yet
    for j in range(e32hdr.e32_objcnt):
        if o32hdr[j].o32_flags & IMAGE_SCN_CNT_CODE:
          pe32.e32_codesize += o32hdr[j].o32_vsize
        
        if o32hdr[j].o32_flags & IMAGE_SCN_CNT_INITIALIZED_DATA:
          pe32.e32_initdsize += o32hdr[j].o32_vsize

        if o32hdr[j].o32_flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
          pe32.e32_uninitdsize += o32hdr[j].o32_vsize
    
    pe32.e32_entryrva = e32hdr.e32_entryrva
    
    for j in range(e32hdr.e32_objcnt):
      if o32hdr[j].o32_flags & IMAGE_SCN_CNT_CODE:
        pe32.e32_codebase = o32hdr[j].o32_vsize
        break

    for j in range(e32hdr.e32_objcnt):
      if o32hdr[j].o32_flags & IMAGE_SCN_CNT_INITIALIZED_DATA:
        pe32.e32_datasize = o32hdr[j].o32_vsize
        break

    pe32.e32_vbase = e32hdr.e32_vbase
    pe32.e32_objalign = 0x1000
    pe32.e32_filealign = 0x200
    pe32.e32_osmajor = 4
    pe32.e32_osminor = 0
    pe32.e32_subsysmajor = e32hdr.e32_subsysmajor
    pe32.e32_subsysminor = e32hdr.e32_subsysminor
    pe32.e32_vsize = e32hdr.e32_vsize
    pe32.e32_filechksum = 0
    pe32.e32_subsys = e32hdr.e32_subsys
    pe32.e32_stackmax = e32hdr.e32_stackmax
    pe32.e32_stackinit = 0x1000
    pe32.e32_heapmax = 0x100000
    pe32.e32_heapinit = 0x1000
    pe32.e32_hdrextra = STD_EXTRA

    pe32.e32_unit[EXP] = e32hdr.e32_unit[EXP]
    pe32.e32_unit[IMP] = e32hdr.e32_unit[IMP]
    pe32.e32_unit[RES] = e32hdr.e32_unit[RES]
    pe32.e32_unit[EXC] = e32hdr.e32_unit[EXC]
    pe32.e32_unit[SEC] = e32hdr.e32_unit[SEC]
    pe32.e32_unit[IMD] = e32hdr.e32_unit[IMD]
    pe32.e32_unit[MSP] = e32hdr.e32_unit[MSP]
    pe32.e32_unit[RS4].rva = e32hdr.e32_sect14rva
    pe32.e32_unit[RS4].size = e32hdr.e32_sect14size
    
    r.write(pe32.send())

    # write o32 header
    for j in range(e32hdr.e32_objcnt):
      segtype = None
      o32hdroff.append(r.tell())
      
      if e32hdr.e32_unit[RES].rva == o32hdr[j].o32_rva and e32hdr.e32_unit[RES].size == o32hdr[j].o32_vsize:
        segtype = ST_RSRC
      elif e32hdr.e32_unit[EXC].rva == o32hdr[j].o32_rva and e32hdr.e32_unit[EXC].size == o32hdr[j].o32_vsize:
        segtype = ST_PDATA
      elif o32hdr[j].o32_flags & IMAGE_SCN_CNT_CODE:
        segtype = ST_TEXT
      elif o32hdr[j].o32_flags & IMAGE_SCN_CNT_INITIALIZED_DATA:
        segtype = ST_DATA
      elif o32hdr[j].o32_flags & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
        segtype = ST_PDATA
      else:
        segtype = ST_OTHER
      
      if g_segmentNameUsage[segtype]:
        n = c_char_p('%s%ld' % (g_segmentNames[segtype], g_segmentNameUsage[segtype]))
        memmove(addressof(po32.o32_name), addressof(n), sizeof(n))
      else:
        n = c_char_p('%s' % g_segmentNames[segtype])
        memmove(addressof(po32.o32_name), addressof(n), sizeof(n)) # not that safe, but the sizes are fixed..

      g_segmentNameUsage[segtype] += 1
      
      po32.o32_vsize = o32hdr[j].o32_vsize
      po32.o32_rva = o32hdr[j].o32_rva
      po32.o32_psize = 0
      po32.o32_dataptr = 0
      po32.o32_realaddr = 0
      po32.o32_access = 0
      po32.o32_temp3 = 0
      po32.o32_flags = o32hdr[j].o32_flags & ~0x2000
      r.write(po32.send())

    size = r.tell()

    # write alignment
    if size % 200:
      r.seek(0x200 - (size % 0x200), os.SEEK_CUR)
    headersize = r.tell()
    
    for j in range(e32hdr.e32_objcnt):
      dataofslist = datalenlist = o32hdr[j].o32_psize
      dataofslist = r.tell()
      buf = ''
      if self.virtualSeek(o32hdr[j].o32_dataptr) == None:
        print 'Unable to read block file'
        return 0
      buf = self.virtualRead(o32hdr[j].o32_psize)
      if o32hdr[j].o32_flags & 0x2000:
        out = outlen = 0
        outlen = lzx.CEDecompress(buf, o32hdr[j].o32_psize, out, o32hdr[j].o32_vsize, 0, 1, 4096)
        if outlen < 0:
          print 'Error in CEDecompress()'
        else:
          r.write(out)
        datalenlist = outlen
      else:
        r.write(buf)
      size = r.tell()
      if size % 0x200:
        r.seek(0x200 - (size % 0x200), os.SEEK_CUR)
        r.write(buffer(c_ulong(datalenlist))[:])
        r.write(buffer(c_ulong(dataofslist))[:])
    r.seek(0, os.SEEK_END)
    filesize = r.tell()
    r.seek(newe32off+0x54, os.SEEK_SET)
    r.write(buffer(c_ulong(headersize))[:])
    r.seek(filesize, os.SEEK_SET)
    r.close()
    return 1

  def updateModule(self, name):
    pass
     
  def readModules(self):
    if self.virtualSeek(self.ecechdr.romhdraddr+sizeof(romHdr)) == None:
      print 'Unable to read block file\n'
      return 0
    
    self.modules = []
    for i in range(self.romhdr.nummods):
      m = moduleHdr()
      data = self.virtualRead(sizeof(moduleHdr))
      m.receiveSome(data)
      self.modules.append(m)
    self.files = []
    
    for module in self.modules:
      if self.virtualSeek(module.fileaddr) == None:
        print 'Unable to read block file\n'
        return 0
      
      name = ''
      n = self.f.read(1)
      while not n == '\00':
        name = name + n
        n = self.f.read(1)
      module.filename = name
  
    if options.LIST:
      for module in self.modules:
        print module

    if options.EXTRACT is not None:
      if options.EXTRACT[0] == 'a':
        for module in self.modules:
          self.extractModule(module)
      else:
        for module in self.modules:
          for fn in options.EXTRACT:
            if fn == module.filename:
              self.extractModule(module)

def main():
  navi = dumpNAVI(options.FILE)
  
  if not navi.readHeader():
    print 'Invalid XIP file\n'
    return 0
  
  if not navi.readECEC():
    print 'Invalid ECEC header\n'
    return 0
  
  if not navi.readRomHdr():
    print 'Invalid ROM header\n'
    return 0
  
  navi.readModules()
    
def splitArgs(option, opt_str, value, parser):
  assert value is None
  done = 0
  value = []
  rargs = parser.rargs
  while rargs:
    arg = rargs[0]

    if ((arg[:2] == '--' and len(arg) > 2) or
      (arg[:1] == '-' and len(arg) > 1 and arg[1] != '-')):
      break
    else:
      value.append(arg)
      del rargs[0]
    setattr(parser.values, option.dest, value)


if __name__ == '__main__':
  parser = OptionParser()
  parser.add_option('-l', '--list', action='store_true', dest='LIST')
  parser.add_option('-e', '--extract', dest='EXTRACT',  action='callback', callback=splitArgs)
  parser.add_option('-u', '--update', action='store_true', dest='UPDATE')
  parser.add_option('-o', '--output', action='store', type='string', dest='PATH')
  parser.add_option('-f', '--file', action='store', type='string', dest='FILE')
  (options, args) = parser.parse_args()
  if options.FILE == None:
    parser.print_help()
  else:
    main()

