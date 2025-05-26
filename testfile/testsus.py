import os
import struct

def generate_suspicious_pe():
    folder = "testfolder"
    os.makedirs(folder, exist_ok=True)

    def write_pe_file(filename, is_dll=False):
        # MZ header
        mz_header = b'MZ' + b'\x90' * 58 + struct.pack('<I', 0x80)

        # PE header
        pe_signature = b'PE\x00\x00'
        # Characteristics flag: 0x0102 for EXE, 0x2102 for DLL
        characteristics = b'\x02\x01' if not is_dll else b'\x02\x21'
        file_header = b'\x4C\x01' + b'\x01\x00' + b'\x00' * 12 + b'\xE0\x00' + characteristics
        optional_header = b'\x0B\x01' + b'\x00' * 222

        section_header = (
            b'.text\x00\x00\x00' +
            struct.pack('<I', 0x1000) +
            struct.pack('<I', 0x1000) +
            struct.pack('<I', 0x200) +
            struct.pack('<I', 0x400) +
            b'\x00' * 16 +
            struct.pack('<I', 0xE0000020)
        )

        section_data = os.urandom(0x200)

        with open(filename, "wb") as f:
            f.write(mz_header)
            f.seek(0x80)
            f.write(pe_signature)
            f.write(file_header)
            f.write(optional_header)
            f.write(section_header)
            f.seek(0x400)
            f.write(section_data)

        print(f"🚨 Suspicious {'DLL' if is_dll else 'EXE'} created: {filename}")

    # Generate suspicious.exe
    write_pe_file(os.path.join(folder, "suspicious.exe"), is_dll=False)

    # Generate suspicious.dll
    write_pe_file(os.path.join(folder, "suspicious.dll"), is_dll=True)

generate_suspicious_pe()
