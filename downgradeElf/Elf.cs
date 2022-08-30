using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace downgradeElf
{
    /// <summary>
    /// downgrade_elf.py (c) flatz
    /// https://twitter.com/flat_z/status/1284499782946390019
    /// </summary>
    public class Elf
    {
        public static byte[] ElfData = new byte[] { };
        public static readonly uint MAGIC = 0x464C457F; // \x7F E L F

        public static Header elfHdr;
        public static List<ElfPHdr.ProgramHeader> progHdrs { get; private set; }
        public static List<ElfSHdr.SectionHeader> sectHdrs { get; private set; }

        public static bool CheckMAGIC() => BitConverter.ToUInt32(ElfData, 0) == MAGIC;

        public static byte[] Load(string filePath)
        {
            try
            {
                FileInfo fi = new FileInfo(filePath);

                long fileSize = fi.Length;
                Array.Resize(ref ElfData, (int)fileSize);

                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read)) fs.Read(ElfData, 0, (int)fileSize);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("error: unable to load elf file, {0}", ex);
            }

            return ElfData;
        }

        public static bool Parse(bool verbose = false)
        {
            byte[] data = new byte[SizeEhdr];
            Buffer.BlockCopy(Elf.ElfData, 0, data, 0, data.Length);
            if (data.Length != SizeEhdr) return WriteLineError("error: unable to read header");

            string errMsg = "";
            elfHdr = Utils.BytesToStruct<Header>(data);

            if (verbose)
                Console.WriteLine(
                    "\n   **Elf head info**\n" +
                    " Head position: {0:X}~{1:X}\n" +
                    " Magic        : 0x{2:X}\n" +
                    " Class        : {3}\n" +
                    " Data         : {4}\n" +
                    " Version      : {5}\n" +
                    " OS           : {6}\n" +
                    " Type         : 0x{7:X}\n" +
                    " Machine      : {8}\n" +
                    " Segment start: 0x{9:X}\n" +
                    " Header size  : 0x{10:X}\n" +
                    " Segment size : {11} Bytes\n" +
                    " Segment count: {12}\n",
                    0, (uint)SizeEhdr - 1, elfHdr.magic, elfHdr.cls, elfHdr.encoding, elfHdr.legacyVersion, elfHdr.osAbi,
                    elfHdr.type_, elfHdr.machine, elfHdr.phdrOffset, elfHdr.ehdrSize, elfHdr.phdrSize, elfHdr.phdrCount);

            if (elfHdr.magic != MAGIC) errMsg = string.Format("error: invalid magic: 0x{0:X8}", elfHdr.magic);
            else if (elfHdr.encoding != EDATA.DATA2LSB) errMsg = string.Format("error: unsupported encoding: 0x{0:X2}", elfHdr.encoding);
            else if (elfHdr.legacyVersion != ELV.CURRENT) throw new Exception(string.Format("Unsupported version: 0x{0:X}", elfHdr.version));
            else if (elfHdr.cls != ECLASS.CLASS64) errMsg = string.Format("error: unsupported class: 0x{0:X2}", elfHdr.cls);
            else if (elfHdr.type_ != EType.SCE_EXEC && elfHdr.type_ != EType.SCE_DYNEXEC && elfHdr.type_ != EType.SCE_DYNAMIC) errMsg = string.Format("error: unsupported type: 0x{0:X4}", (uint)elfHdr.type_);
            else if (elfHdr.machine != EMachine.X86_64) errMsg = string.Format("error: unexpected machine: 0x{0:X}", elfHdr.machine);
            else if (elfHdr.ehdrSize != SizeEhdr) errMsg = string.Format("error: invalid elf header size: 0x{0:X}", elfHdr.ehdrSize);
            else if (elfHdr.phdrSize > 0 && elfHdr.phdrSize != ElfPHdr.SizePhdr) errMsg = string.Format("error: invalid program header size: 0x{0:X}", elfHdr.phdrSize);
            else if (elfHdr.shdrSize > 0 && elfHdr.shdrSize != ElfSHdr.SizeSHdr) errMsg = string.Format("error: invalid section header size: 0x{0:X}", elfHdr.shdrSize);

            if (errMsg.Length > 0) return WriteLineError(errMsg);

            int pHdrOffset = 0;
            progHdrs = new List<ElfPHdr.ProgramHeader>();
            for (int idx = 0; idx < elfHdr.phdrCount; idx++)
            {
                pHdrOffset = (int)elfHdr.phdrOffset + idx * elfHdr.phdrSize;
            ElfPHdr.ProgramHeader pHdr = ElfPHdr.GetPHdr(Elf.ElfData, pHdrOffset);

                if (verbose) Console.Write("Segment{0:00}({1:X4}~{2:X4}) Offset:{3:X8} +{4,-8:X} (memSz: {5:X8}) Type:{6:X8}({7}) \n",
                        idx, pHdrOffset, pHdrOffset + elfHdr.phdrSize - 1, pHdr.offset, pHdr.fileSize, pHdr.memSize, (uint)pHdr.type_, pHdr.type_);

                if (pHdr.offset == 0) return WriteLineError("error: unable to load program header #{0}", idx);

                progHdrs.Add(pHdr);
            }
            sectHdrs = new List<ElfSHdr.SectionHeader>();
            //if (elfHdr.shdrSize > 0)
            //{
            //    for (int idx = 0; idx < elfHdr.shdrCount; idx++)
            //    {
            //        ElfSHdr.SectionHeader shdr = ElfSHdr.GetSHdr(data, (int)elfHdr.shdrOffset + idx * elfHdr.shdrSize);
            //        if (shdr.offset == 0) return WriteLineError("error: unable to load section header #{0}", idx);
            //        sectHdrs.Add(shdr);
            //    }
            //}

            var exInfoOffset = Utils.AlignUp((ulong)(pHdrOffset + ElfPHdr.SizePhdr), 0x10);
            byte[] dataExInfo = new byte[SizeExInfo];
            Buffer.BlockCopy(ElfData, (int)exInfoOffset, dataExInfo, 0, dataExInfo.Length);
            var exInfo = Utils.BytesToStruct<ExInfo>(dataExInfo);

            if (verbose)
                Console.WriteLine(
                    "\n   **Elf Extended info**\n" +
                    " Head position: {0:X}~{1:X}\n" +
                    " Paid         : 0x{2:X}\n" +
                    " Ptype        : {3}\n" +
                    " AppVersion   : {4:X}\n" +
                    " FwVersion    : {5:X}\n" +
                    " Digest       : {6:X}\n",
                    exInfoOffset, exInfoOffset + (uint)SizeExInfo - 1, exInfo.paid, exInfo.ptype, exInfo.appVersion, exInfo.fwVersion, BitConverter.ToString(exInfo.digest).Replace("-", ""));

            return true;
        }

        public static bool SaveHdr()
        {
            byte[] elfHdrData = Utils.StructToBytes(elfHdr, SizeEhdr);

            if (elfHdrData.Length != SizeEhdr) return WriteLineError("error: unable to save header");

            Buffer.BlockCopy(elfHdrData, 0, ElfData, 0, elfHdrData.Length);

            for (int idx = 0; idx < progHdrs.Count; idx++)
            {
                ElfPHdr.ProgramHeader progHdr = progHdrs[idx];
                if (!ElfPHdr.Save(ElfData, (int)elfHdr.phdrOffset + idx * elfHdr.phdrSize, progHdr))
                    return WriteLineError("error: unable to save program header #{0}", idx);
            }
            for (int idx = 0; idx < sectHdrs.Count; idx++)
            {
                ElfSHdr.SectionHeader shdr = sectHdrs[idx];
                if (!ElfSHdr.Save(ElfData, (int)elfHdr.shdrOffset + idx * elfHdr.shdrSize, shdr))
                    return WriteLineError("error: unable to save section header #{0}", idx);
            }
            return true;
        }

        public static bool WriteLineError(string format, params object[] arg)
        {
            Console.Error.WriteLine(format, arg);
            return false;
        }

        public static ElfPHdr.ProgramHeader? GetPhdrByType(ElfPHdr.PhdrType type)
        {
            for (int idx = 0; idx < progHdrs.Count; idx++)
            {
                ElfPHdr.ProgramHeader progHdr = progHdrs[idx];
                if (progHdr.type_ == type) return progHdr;
            }
            return null;
        }

        /// <summary>
        /// FMT = "<4s5B6xB2HI3QI6H", calcsize:64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct Header
        {
        public UInt32 magic;
            public ECLASS cls;
            public EDATA encoding;
            public ELV legacyVersion;
            public EOSABI osAbi;
            public byte abiVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] padBytes;
            public byte nidentSize;
            public EType type_;
            public EMachine machine;
            public EVersion version;
            public UInt64 entry;       // Entry point virtual address
            public UInt64 phdrOffset;  // Program header table file offset
            public UInt64 shdrOffset;  // Section header table file offset
            public UInt32 flags;
            public UInt16 ehdrSize;
            public UInt16 phdrSize;
            public UInt16 phdrCount;
            public UInt16 shdrSize;
            public UInt16 shdrCount;
            public UInt16 shdrStrtableIdx;
        }

        /// <summary>
        /// SizeOF:64, Extended Info for Signed ELF
        /// https://github.com/OpenOrbis/create-fself/blob/master/pkg/fself/FSELF.go
        /// https://www.psxhax.com/threads/ps2-game-backups-on-ps4-hen-4-05-make_fself-py-update-by-flat_z.3541
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ExInfo
        {
            public UInt64 paid;          //program authentication id
            public PTYPE ptype;          //program type
            public UInt64 appVersion;    //application version
            public UInt64 fwVersion;     //firmware version
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] digest; //sha256 digest
        }

        /// <summary>
        /// calcsize:20
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ProgramParam
        {
            public UInt32 paramSize;
            public UInt32 padVar1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] paramMagic;
            public UInt32 padVar2;
            public UInt32 sdkVersion;
        }

        /// <summary>
        /// FMT = "<QQ", calcsize:16
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct Dynamic
        {
            public DTag tag;   // entry tag
            public UInt64 val; // entry value, union { UInt64 d_val; UInt64 d_ptr; } d_un;
        }

        /// <summary>
        /// FMT = "<QLLq", calcsize:24
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct Relocation
        {
            public UInt64 addr;      // Location at which to apply the action
            public RTYPES info;      // type of relocation
            public UInt32 sym;       // index of relocation
            public Int64 addend;     // Constant addend used to compute value
        }

        /// <summary>
        /// FMT = "<IBBHQQ", calcsize:24
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct Symbol
        {
            public UInt32 name;  // Symbol name, index in string tbl
            public STInfo info;  // Type and binding attributes
            public byte other;   // No defined meaning, 0
            public UInt16 shndx; // Associated section index
            public UInt64 value; // Value of the symbol
            public UInt64 size;  // Associated symbol size
        }

        /// <summary>
        /// SizeOF:64
        /// </summary>
        public static readonly int SizeEhdr = Marshal.SizeOf(typeof(Header));
        /// <summary>
        /// SizeOF:64
        /// </summary>
        public static readonly int SizeExInfo = Marshal.SizeOf(typeof(ExInfo));
        /// <summary>
        /// SizeOF:20
        /// </summary>
        public static readonly int SizeProgParam = Marshal.SizeOf(typeof(ProgramParam));
        /// <summary>
        /// SizeOF:16 structFmt = '<QQ';
        /// </summary>
        public static readonly int sizeDynamic = Marshal.SizeOf(typeof(Dynamic));
        /// <summary>
        /// SizeOF:24 structFmt = '<QLLq';
        /// </summary>
        public static readonly int sizeRela = Marshal.SizeOf(typeof(Relocation));
        /// <summary>
        /// SizeOF:24 structFmt = '<IBBHQQ';
        /// </summary>
        public static readonly int sizeSymbol = Marshal.SizeOf(typeof(Symbol));

        public enum ECLASS : byte
        {
            CLASSNONE = 0, // EI_CLASS
            CLASS32   = 1,
            CLASS64   = 2,
            CLASSNUM  = 3,
        }

        public enum EDATA : byte
        {
            DATANONE = 0, // e_ident[EI_DATA]
            DATA2LSB = 1,
            DATA2MSB = 2,
        }

        public enum ELV : byte
        {
            NONE    = 0, // e_version
            CURRENT = 1,
            NUM     = 2,
        }

        public enum EOSABI : byte
        {
            NONE    = 0,
            LINUX   = 3,
            FREEBSD = 9, // e_ident[IE_OSABI]
        }

        /// <summary>
        /// These constants define the different elf file types
        /// SCE-specific definitions for e_type
        /// </summary>
        public enum EType : UInt16
        {
            NONE            = 0,
            REL             = 1,
            EXEC            = 2,
            DYN             = 3,
            CORE            = 4,
            LOPROC          = 0xff00,
            HIPROC          = 0xffff,

            SCE_EXEC        = 0xFE00, // SCE Executable file
            SCE_REPLAY_EXEC = 0xFE01,
            SCE_RELEXEC     = 0xFE04, // SCE Relocatable Executable file
            SCE_STUBLIB     = 0xFE0C, // SCE SDK Stubs
            SCE_DYNEXEC     = 0xFE10, // SCE EXEC_ASLR
            SCE_DYNAMIC     = 0xFE18, // Unused
            SCE_PSPRELEXEC  = 0xFFA0, // Unused (PSP ELF only)
            SCE_PPURELEXEC  = 0xFFA4, // Unused (SPU ELF only)
            SCE_UNK         = 0xFFA5, // Unknown
        }

        /// <summary>
        /// These constants define the various ELF target machines
        /// </summary>
        public enum EMachine : UInt16
        {
            NONE        = 0,
            M32         = 1,
            SPARC       = 2,
            E386        = 3,
            E68K        = 4,
            E88K        = 5,
            E486        = 6, // Perhaps disused
            E860        = 7,

            MIPS        = 8,  // MIPS R3000 (officially, big-endian only)
            MIPS_RS4_BE = 10, // MIPS R4000 big-endian
            PARISC      = 15, // HPPA
            SPARC32PLUS = 18, // Sun's "v8plus"
            PPC         = 20, // PowerPC
            PPC64       = 21, // PowerPC64
            SH          = 42, // SuperH
            SPARCV9     = 43, // SPARC v9 64-bit
            IA_64       = 50, // HP/Intel IA-64
            X86_64      = 62, // AMD x86-64
            S390        = 22, // IBM S/390
            CRIS        = 76, // Axis Communications 32-bit embedded processor
            V850        = 87, // NEC v850
            M32R        = 88, // Renesas M32R
            H8_300      = 46, // Renesas H8/300,300H,H8S

            ALPHA       = 0x9026,
            CYGNUS_V850 = 0x9080, // Bogus old v850 magic number, used by old tools. 
            CYGNUS_M32R = 0x9041, // Bogus old m32r magic number, used by old tools. 
            S390_OLD    = 0xA390, // This is the old interim value for S/390 architecture
            FRV         = 0x5441, // Fujitsu FR-V
        }

        public enum EVersion : UInt32
        {
            NONE    = 0, // EI_VERSION
            CURRENT = 1,
            NUM     = 2,
        }

        /// <summary>
        /// ExInfo::ptype
        /// </summary>
        public enum PTYPE : UInt64
        {
            FAKE          = 0x1,
            NPDRM_EXEC    = 0x4,
            NPDRM_DYNLIB  = 0x5,
            SYSTEM_EXEC   = 0x8,
            SYSTEM_DYNLIB = 0x9, // including Mono binaries
            HOST_KERNEL   = 0xC,
            SEC_MODULE    = 0xE,
            SEC_KERNEL    = 0xF,
        }

        /// <summary>
        /// Tag for SCE string table size
        /// </summary>
        public enum DTag : UInt64
        {
            NULL                     = 0,
            NEEDED                   = 1,
            PLTRELSZ                 = 2,
            PLTGOT                   = 3,
            HASH                     = 4,
            STRTAB                   = 5,
            SYMTAB                   = 6,
            RELA                     = 7,
            RELASZ                   = 8,
            RELAENT                  = 9,
            STRSZ                    = 10,
            SYMENT                   = 11,
            INIT                     = 12,
            FINI                     = 13,
            SONAME                   = 14,
            RPATH                    = 15,
            SYMBOLIC                 = 16,
            REL                      = 17,
            RELSZ                    = 18,
            RELENT                   = 19,
            PLTREL                   = 20,
            DEBUG                    = 21,
            TEXTREL                  = 22,
            JMPREL                   = 23,
            LOPROC                   = 0x70000000,
            HIPROC                   = 0x7FFFFFFF,
            // Tag for SCE string table size
            SCE_IDTABENTSZ           = 0x61000005,
            SCE_FINGERPRINT          = 0x61000007,
            SCE_ORIGINAL_FILENAME    = 0x61000009,
            SCE_MODULE_INFO          = 0x6100000D,
            SCE_NEEDED_MODULE        = 0x6100000F,
            SCE_MODULE_ATTR          = 0x61000011,
            SCE_EXPORT_LIB           = 0x61000013,
            SCE_IMPORT_LIB           = 0x61000015,
            SCE_EXPORT_LIB_ATTR      = 0x61000017,
            SCE_IMPORT_LIB_ATTR      = 0x61000019,
            SCE_STUB_MODULE_NAME     = 0x6100001D,
            SCE_STUB_MODULE_VERSION  = 0x6100001F,
            SCE_STUB_LIBRARY_NAME    = 0x61000021,
            SCE_STUB_LIBRARY_VERSION = 0x61000023,
            SCE_HASH                 = 0x61000025,
            SCE_PLTGOT               = 0x61000027,
            SCE_JMPREL               = 0x61000029,
            SCE_PLTREL               = 0x6100002B,
            SCE_PLTRELSZ             = 0x6100002D,
            SCE_RELA                 = 0x6100002F,
            SCE_RELASZ               = 0x61000031,
            SCE_RELAENT              = 0x61000033,
            SCE_STRTAB               = 0x61000035,
            SCE_STRSZ                = 0x61000037,
            SCE_SYMTAB               = 0x61000039,
            SCE_SYMENT               = 0x6100003B,
            SCE_HASHSZ               = 0x6100003D,
            SCE_SYMTABSZ             = 0x6100003F,
        }

        /// <summary>
        /// type of relocation
        /// </summary>
        public enum RTYPES : UInt32
        {
            AMD64_default   = 0x00,
            AMD64_64        = 0x01,
            AMD64_PC32      = 0x02,
            AMD64_GOT32     = 0x03,
            AMD64_PLT32     = 0x04,
            AMD64_COPY      = 0x05,
            AMD64_GLOB_DAT  = 0x06,
            AMD64_JUMP_SLOT = 0x07,
            AMD64_RELATIVE  = 0x08,
            AMD64_GOTPCREL  = 0x09,
            AMD64_32        = 0x0A,
            AMD64_32S       = 0x0B,
            AMD64_16        = 0x0C,
            AMD64_PC16      = 0x0D,
            AMD64_8         = 0x0E,
            AMD64_PC8       = 0x0F,
            AMD64_DTPMOD64  = 0x10,
            AMD64_DTPOFF64  = 0x11,
            AMD64_TPOFF64   = 0x12,
            AMD64_TLSGD     = 0x13,
            AMD64_TLSLD     = 0x14,
            AMD64_DTPOFF32  = 0x15,
            AMD64_GOTTPOFF  = 0x16,
            AMD64_TPOFF32   = 0x17,
            AMD64_PC64      = 0x18,
            AMD64_GOTOFF64  = 0x19,
            AMD64_GOTPC32   = 0x1A,
        }

        /// <summary>
        /// Symbol Information
        /// This info is needed when parsing the symbol table
        /// TYPES: info & 0xF (NOTYPE, OBJECT, FUNC, SECTION, FILE, COMMON, TLS)
        /// BINDS: info >> 4 (LOCAL, GLOBAL, WEAK)
        /// </summary>
        public enum STInfo : byte
        {
            LOCAL_NONE      = 0x0,
            LOCAL_OBJECT    = 0x1,
            LOCAL_FUNCTION  = 0x2,
            LOCAL_SECTION   = 0x3,
            LOCAL_FILE      = 0x4,
            LOCAL_COMMON    = 0x5,
            LOCAL_TLS       = 0x6,

            GLOBAL_NONE     = 0x10,
            GLOBAL_OBJECT   = 0x11,
            GLOBAL_FUNCTION = 0x12,
            GLOBAL_SECTION  = 0x13,
            GLOBAL_FILE     = 0x14,
            GLOBAL_COMMON   = 0x15,
            GLOBAL_TLS      = 0x16,

            WEAK_NONE       = 0x20,
            WEAK_OBJECT     = 0x21,
            WEAK_FUNCTION   = 0x22,
            WEAK_SECTION    = 0x23,
            WEAK_FILE       = 0x24,
            WEAK_COMMON     = 0x25,
            WEAK_TLS        = 0x26,
        }
    }
}