import sys


def bytes_to_int_le(bytes):  # https://coderwall.com/p/x6xtxq/convert-bytes-to-int-or-int-to-bytes-in-python
    result = 0
    for b in reversed(bytes):  # reversed because in little endian smallest byte comes first
        result = result * 256 + int(b)
    return result


def read_string(binary, start):
    ret = ""
    cnt = start
    byte = binary[cnt]
    while byte != 0:
        ret += chr(byte)
        cnt += 1
        byte = binary[cnt]
    return ret, cnt


class W3X():
    #MPQ = None  # slice of the file that represents only the MPQ archive

    def __init__(self, w3xfile):
        with open(w3xfile, "rb") as f:
            binary = f.read()
        header = binary[0:512]
        headerstart = header[0:4].decode("UTF-8")

        if not headerstart == "HM3W":
            print("Only w3x supported! Header must start with HM3W but was " + headerstart)
            sys.exit(1)

        mapname, end = read_string(binary, 4 + 1 * 4)  # 4 bytes HM3W + 1 4byte int
        print("Map name: " + mapname)

        self.MPQ = binary[512:]
        MPQ = self.MPQ

        MPQINFO = MPQ[3:4]
        if MPQINFO == str.encode('\x1A'):
            print(MPQ[:4], "means: MPQ header follows")
        else:
            print("MPQ Shunt? TODO!")

        print("MPQ len", len(MPQ))

        self.MPQHEADERSIZE = bytes_to_int_le(MPQ[4:8])
        print("MPQ header size: {} byte".format(self.MPQHEADERSIZE))

        self.MPQARCHIVESIZE = bytes_to_int_le(MPQ[8:12])
        print("MPQ archive size: {} byte = {} kilobyte = {} megabyte".format(self.MPQARCHIVESIZE, self.MPQARCHIVESIZE / 1024,
                                                                             self.MPQARCHIVESIZE / 1024 / 1024))

        self.FORMATVERSION = bytes_to_int_le(MPQ[12:14])
        print("MPQ format version: {}".format(self.FORMATVERSION))

        self.BLOCKSIZE = bytes_to_int_le(MPQ[14:16])
        print("MPQ block size: {}".format(self.BLOCKSIZE))

        self.HASHTABLEPOS = bytes_to_int_le(MPQ[16:20])
        print("MPQ hash table pos: {}".format(self.HASHTABLEPOS))

        self.BLOCKTABLEPOS = bytes_to_int_le(MPQ[20:24])
        print("MPQ block table pos: {}".format(self.BLOCKTABLEPOS))

        self.HASHTABLESIZE = bytes_to_int_le(MPQ[24:28])
        print("MPQ hash table size: {}".format(self.HASHTABLESIZE))

        self.BLOCKTABLESIZE = bytes_to_int_le(MPQ[28:32])
        print("MPQ block table size: {}".format(self.BLOCKTABLESIZE))

        print("After header", MPQ[32:1000])
