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

Notes:
Should work fine with python on Windows but I haven't tested it.

Works well with wine and python 2.7 installed through wine on linux..
The wine dependency is really just to call the CEDecompress function (which ATM has not been tested)

Various bugs have been fixed here and there.  Let me know how this works.
