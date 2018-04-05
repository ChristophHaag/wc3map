import sys
import mpyq_functions


FILE_DOESNOTEXIST = "Does not exist"
FILE_DELETED = "Deleted"
FILE_OK = "OK"


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

        #print("After header", MPQ[32:1000])

        print("Read hashtable from", self.HASHTABLEPOS, "to", self.HASHTABLEPOS + self.HASHTABLESIZE)
        self.hashtable_list = HashTable(MPQ[self.HASHTABLEPOS:self.HASHTABLEPOS + self.HASHTABLESIZE])

        #listfile = self.hashtable_list.get_hash_table_entry("(listfile)")
        #print("list file:", listfile)
        for file in w3xfiles:
            hashfile = self.hashtable_list.get_hash_table_entry(file)
            if hashfile:
                print("Found file in hash table: " + file)


class HashTable():  # not actually a hashtable
    def __init__(self, bytearr):
        self.hashtable_list = []
        self.bytearr = bytearr
        self.read_hashtable()

    def read_hashtable(self):
        HASHTABLEENTRYSIZE = 16

        key = mpyq_functions._hash('(hash table)', 'TABLE')

        hashtable_data = mpyq_functions._decrypt(self.bytearr, key)

        filecount = 0
        offset = 0
        while offset < len(self.bytearr):
            entry = HashTableEntry(hashtable_data[offset:offset + HASHTABLEENTRYSIZE])
            if entry.status == FILE_OK:
                filecount += 1
            self.hashtable_list.append(entry)
            #print("Hash entry at offset", offset, ":",  entry)
            offset += HASHTABLEENTRYSIZE
        print("Successfully read hash table with {} file entries".format(filecount))

    def get_hash_table_entry(self, filename):
        """Get the hash table entry corresponding to a given filename."""
        hash_a = mpyq_functions._hash(filename, 'HASH_A')
        hash_b = mpyq_functions._hash(filename, 'HASH_B')
        for entry in self.hashtable_list:
            #print(entry.Name1, hash_a, entry.Name2, hash_b)
            if entry.Name1 == hash_a and entry.Name2 == hash_b:
                return entry

class HashTableEntry():
    def __init__(self, bytearr):
        self.Name1 = bytes_to_int_le(bytearr[0:4])
        self.Name2 = bytes_to_int_le(bytearr[4:8])
        self.locale = bytes_to_int_le(bytearr[8:10])
        self.platform = bytes_to_int_le(bytearr[10:12])
        self.blockindex = bytes_to_int_le(bytearr[12:16])
        if self.blockindex == int("0xFFFFFFFF", 0):
            self.status = FILE_DOESNOTEXIST
        elif self.blockindex == int("0xFFFFFFFE", 0):
            self.status = FILE_DELETED
        else:
            self.status = FILE_OK

    def __str__(self):
        return "{}.{}, locale: {}, platform: {}, blockindex: {}, status: {}".format(self.Name1, self.Name2, self.locale, self.platform, self.blockindex, self.status)

w3xfiles = [
    '(signature)',
    '(attributes)',
    'war3map.w3e',
    'war3map.w3i',
    'war3map.wtg',
    'war3map.wct',
    'war3map.wts',
    'war3map.j',
    'war3map.shd',
    'war3mapMap.blp',
    'war3mapMap.b00',
    'war3mapMap.tga',
    'war3mapPreview.tga',
    'war3map.mmp',
    'war3mapPath.tga',
    'war3map.wpm',
    'war3map.doo',
    'war3mapUnits.doo',
    'war3map.w3r',
    'war3map.w3c',
    'war3map.w3s',
    'war3map.w3u',
    'war3map.w3t',
    'war3map.w3a',
    'war3map.w3b',
    'war3map.w3d',
    'war3map.w3q',
    'war3mapMisc.txt',
    'war3mapSkin.txt',
    'war3mapExtra.txt',
    'war3map.imp'
]
