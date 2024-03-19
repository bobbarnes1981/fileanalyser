import sys

if len(sys.argv) < 2:
    print('Usage: analyser <pathtofile>')
    exit()

path = sys.argv[1]

class header():
    def __init__(self, name, length, converter=False):
        self.name = name
        self.length = length
        self.converter = converter
    def get_length(self):
        if isinstance(self.length, int):
            return self.length
        return sizes[self.length]
    def get_value(self, bytes):
        if self.converter:
            return self.converter(bytes)
        return bytes

sizes = {
    'byte': 1,
    'word': 2,
    'dword': 4,
    'qword': 8,
}

machines = {
    '8664': 'IMAGE_FILE_MACHINE_AMD64',
    '014C': 'IMAGE_FILE_MACHINE_I386',
}

def convertlittleendianbytesint(bytes):
    c = 0
    total = 0
    for b in bytes:
        total+=b<<c
        c+=8
    return total

def convertlittleendianbyteshex(bytes):
    output = ''
    for b in bytes:
        output = "{0:02X}{1}".format(b, output)
    return output

def convertlittleendianbytesmachine(bytes):
    return machines[convertlittleendianbyteshex(bytes)]

dosfile = [
    # MZ
    header('signature', 'word'),
    header('extrabytes', 'word'),
    header('pages', 'word', convertlittleendianbytesint),
    header('relocationItems', 'word'),
    header('headerSize', 'word', convertlittleendianbytesint),
    header('minimumAllocation', 'word'),
    header('maximumAllocation', 'word'),
    header('initialSS', 'word'),
    header('initialSP', 'word'),
    header('checksum', 'word'),
    header('initialIP', 'word'),
    header('initialCS', 'word'),
    header('relocationTable', 'word'),
    header('overlay', 'word'),
    # PE info
    header('reserved', 'qword'),
    header('oemIdentifier', 'word'),
    header('oemInfo', 'word'),
    header('reserved', 20),
    header('peHeaderStart', 'dword', convertlittleendianbytesint),
    # PE header
    header('signature', 'dword'),
    header('machine', 'word', convertlittleendianbytesmachine)
]

print(path)

with open(path, mode='rb') as file:
    contents = file.read()

offset = 0
for h in dosfile:
    l = h.get_length()
    val = h.get_value(contents[offset:offset+l])
    print("{0:02X} {1} {2}: {3}".format(offset, l, h.name, val))
    offset+=l

    if h.name =='peHeaderStart':
        offset = val
        print("{0:02X}".format(offset))