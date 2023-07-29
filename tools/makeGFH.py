#!/usr/bin/env python

import os
import sys
import struct
import datetime
from os.path import join

arguments = len(sys.argv) - 1
if arguments!=1:
	exit("Error Input Paramiter")

def makeHDR( dat ):   
    bin = dat.replace(".bin", "HDR.bin")
	
    dst = open(bin, "wb")
    arr = [0x4D, 0x4D, 0x4D, 0x01, 0x40, 0x00, 0x00, 0x00, 0x46, 0x49, 0x4C, 0x45, 0x5F, 0x49, 0x4E, 0x46]
    data = bytearray(arr)
    dst.write(data) 
    arr = [0x4F, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x70, 0x07, 0x00, 0x00, 0xB0, 0x2D, 0x10] #MC60
    data = bytearray(arr)
    dst.write(data) 
    
    src_size = os.stat( dat ).st_size + 64 #+64
    #print( "APPLICATIN SIZE: ", src_size + 64, " bytes" )
    dst.write( struct.pack('<i', src_size) ) # write size 

    arr = [                        0xFF, 0xFF, 0xFF, 0xFF, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    data = bytearray(arr)
    dst.write(data)     
    arr = [0x40, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    data = bytearray(arr)
    dst.write(data)   

    src = open(dat, "rb")
    dst.write( src.read() )

    src.close()
    dst.close()  

def makeCFG( dat ): 
    cfg = dat.replace(".bin", ".cfg")
    src_name = os.path.basename(sys.argv[1])
    src_name = src_name.replace(".bin", "HDR.bin\n")
    f = open(cfg, "w")
    f.write(src_name)
    f.close
    

src_size = os.stat( sys.argv[1] ).st_size + 64
src_name = os.path.basename(sys.argv[1])
makeHDR(sys.argv[1])
makeCFG(sys.argv[1])
print ("File Name %s" % (src_name))
print ("File Generate %s Byte" % (src_size))
