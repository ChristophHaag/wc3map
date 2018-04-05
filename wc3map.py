#!/usr/bin/env python3

import sys
import w3xmpq

if len(sys.argv) < 2:
    print("Usage: " + sys.argv[0] + " map.w3x")
    filename = "Evolution Tag 2.48a.w3x"
    #filename = "(2)Circumvention.w3x"
else:
    filename = sys.argv[1]

w3x = w3xmpq.W3X(filename)
