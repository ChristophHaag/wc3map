import sys
import os.path

import mpyq_functions


FILE_DOESNOTEXIST = "Does not exist"
FILE_DELETED = "Deleted"
FILE_OK = "OK"

BLOCKFLAGS = {
    "MPQ_FILE_IMPLODE": 0x00000100, 	# File is compressed using PKWARE Data compression library
    "MPQ_FILE_COMPRESS": 0x00000200, 	# File is compressed using combination of compression methods
    "MPQ_FILE_ENCRYPTED": 0x00010000, 	# The file is encrypted
    "MPQ_FILE_FIX_KEY": 0x00020000, 	# The decryption key for the file is altered according to the position of the file in the archive
    "MPQ_FILE_PATCH_FILE": 0x00100000, 	# The file contains incremental patch for an existing file in base MPQ
    "MPQ_FILE_SINGLE_UNIT": 0x01000000, 	# Instead of being divided to 0x1000-bytes blocks, the file is stored as single unit
    "MPQ_FILE_DELETE_MARKER": 0x02000000, 	# File is a deletion marker, indicating that the file no longer exists. This is used to allow patch archives to delete files present in lower-priority archives in the search chain. The file usually has length of 0 or 1 byte and its name is a hash
    "MPQ_FILE_SECTOR_CRC": 0x04000000, 	# File has checksums for each sector (explained in the File Data section). Ignored if file is not compressed or imploded.
    "MPQ_FILE_EXISTS": 0x80000000 	# Set if file exists, reset when the file was deleted
}

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

    def get_filelist(self, mapname):
        filelistname = mapname + "_filelist.txt"
        if os.path.isfile(filelistname):
            return [line.rstrip() for line in open(filelistname, "r").readlines()]
        else:
            print("First run, trying all filenames from filelists, this can take a couple of seconds...")
            print("(If you don't have it, download it from http://www.zezula.net/download/listfiles.zip and extract in the wc3map dir)")
            found = []
            with open(filelistname, "w") as f:
                for name in w3xfiles:
                    hashfile = self.hashtable.get_hashtable_entry(name)
                    if hashfile:
                        found.append(name.rstrip())
                        f.write(name + "\n")

                with open("listfiles/Warcraft III.txt", "r") as f2:
                    for line in f2.readlines():
                        name = line.rstrip()
                        hashfile = self.hashtable.get_hashtable_entry(name)
                        if hashfile and name not in found:
                            found.append(name.rstrip())
                            f.write(name + "\n")
                with open("listfiles/Warcraft III Maps.txt", "r") as f2:
                    for line in f2.readlines():
                        name = line.rstrip()
                        hashfile = self.hashtable.get_hashtable_entry(name)
                        if hashfile and name not in found:
                            found.append(name.rstrip())
                            f.write(name + "\n")
            print("found and wrote", len(found), "filenames to ", filelistname)
            return found

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
        self.hashtable = HashTable(MPQ[self.HASHTABLEPOS:self.HASHTABLEPOS + self.HASHTABLESIZE])

        print("Read block table from", self.BLOCKTABLEPOS, "to", self.BLOCKTABLEPOS + self.BLOCKTABLESIZE)
        self.blocktable = BlockTable(MPQ[self.BLOCKTABLEPOS:self.BLOCKTABLEPOS + self.BLOCKTABLESIZE])

        #listfile = self.hashtable_list.get_hash_table_entry("(listfile)")
        #print("list file:", listfile)
        found_files = []
        for file in self.get_filelist(w3xfile):
            # print("Trying name " + file)
            hashfile = self.hashtable.get_hashtable_entry(file)
            if hashfile:
                hashfile.filename = file
                found_files.append(hashfile)
                print("Found file in hash table:", hashfile)
            else:
                print("Did not find", file)

        for hashentry in self.hashtable.get_as_list():
            if hashentry.status in (FILE_DOESNOTEXIST, FILE_DELETED):
                # print("DOES NOT EXIST:", hashentry)
                continue
            blockentry = self.blocktable.get_blocktable_entry(hashentry.blockindex)
            print("File in hash table:", hashentry, end=" ")
            if not blockentry:
                print("... blockentry", hashentry.blockindex, "missing")
                continue
            for flagname, flagvalue in BLOCKFLAGS.items():
                if blockentry.flags & flagvalue:
                    print(flagname, end=", ")
            print()
            if blockentry.compressedsize == 0:
                print("Compressed size is 0!")
                continue
            if blockentry.flags & BLOCKFLAGS["MPQ_FILE_ENCRYPTED"]:
                print("Encrypted file!! TODO!!")
                continue
            file_data = MPQ[blockentry.filepos:blockentry.filepos + blockentry.compressedsize]
            print("Compressed data", file_data)
            uncompressed = mpyq_functions.decompress(file_data)
            print("Uncompressed data", uncompressed)

class BlockTable():
    def __init__(self, bytearr):
        self.blocktable_list = []
        self.bytearr = bytearr
        self.read_blocktable()

    def read_blocktable(self):
        BLOCKTABLEENTRYSIZE = 16

        key = mpyq_functions._hash('(block table)', 'TABLE')

        blocktable_data = mpyq_functions._decrypt(self.bytearr, key)

        blockentrycount = 0
        offset = 0
        while offset < len(self.bytearr):
            entry = BlockTableEntry(blocktable_data[offset:offset + BLOCKTABLEENTRYSIZE])
            self.blocktable_list.append(entry)
            #print("Hash entry at offset", offset, ":",  entry)
            offset += BLOCKTABLEENTRYSIZE
            blockentrycount += 1
        print("Successfully read block table with {} entries".format(blockentrycount))

    def get_blocktable_entry(self, blockindex):
        if blockindex >= len(self.blocktable_list):
            print("Block index", blockindex, "too big, only have", len(self.blocktable_list), "entries")
            return None
        entry = self.blocktable_list[blockindex]
        #print("Entry:", entry)
        return entry


class BlockTableEntry():
    def __init__(self, bytearr):
        self.filepos = bytes_to_int_le(bytearr[0:4])
        self.compressedsize = bytes_to_int_le(bytearr[4:8])
        self.uncompressedsize = bytes_to_int_le(bytearr[8:12])
        self.flags = bytes_to_int_le(bytearr[12:16])

    def __str__(self):
        return "BLOCKENTRY(Pos: {}, compressed: {}, uncompressed: {}, flags: {})".format(self.filepos, self.compressedsize, self.uncompressedsize, self.flags)


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

    def get_hashtable_entry(self, filename):
        """Get the hash table entry corresponding to a given filename."""
        hash_a = mpyq_functions._hash(filename, 'HASH_A')
        hash_b = mpyq_functions._hash(filename, 'HASH_B')
        for entry in self.hashtable_list:
            #print(entry.Name1, hash_a, entry.Name2, hash_b)
            if entry.Name1 == hash_a and entry.Name2 == hash_b:
                return entry

    def get_as_list(self):
        return self.hashtable_list


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
        self.filename = ""

    def __str__(self):
        return "HASHENTRY({}: {}.{}, locale: {}, platform: {}, blockindex: {}, status: {})".format(self.filename, self.Name1, self.Name2, self.locale, self.platform, self.blockindex, self.status)

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
    'war3map.imp',
    'war3map.wgt'  # maybe?
]
