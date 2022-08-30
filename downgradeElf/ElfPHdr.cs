using System;
using System.Runtime.InteropServices;

namespace downgradeElf
{
    public class ElfPHdr
    {
        public static ProgramHeader GetPHdr(byte[] elfData, int pHdrOffset)
        {
            byte[] progHdrData = new byte[SizePhdr];
            Buffer.BlockCopy(elfData, pHdrOffset, progHdrData, 0, progHdrData.Length);
            if (progHdrData.Length != SizePhdr) return new ProgramHeader { };

            ProgramHeader progHdr = Utils.BytesToStruct<ProgramHeader>(progHdrData);

            return progHdr;
        }

        public static bool Save(byte[] elfData, int pHdrOffset, ProgramHeader progHdr)
        {
            byte[] progHdrData = Utils.StructToBytes(progHdr, SizePhdr);
            if (progHdrData.Length != SizePhdr) return false;

            Buffer.BlockCopy(progHdrData, 0, elfData, pHdrOffset, progHdrData.Length);

            return true;
        }

        /// <summary>
        /// FMT = "<2I6Q", calcsize:56
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct ProgramHeader
        {
            public PhdrType type_;
            public PhdrFlag flags;
            public UInt64 offset;   // Segment file offset
            public UInt64 vaddr;    // Segment virtual address
            public UInt64 paddr;    // Segment physical address
            public UInt64 fileSize; // Segment size in file
            public UInt64 memSize;  // Segment size in memory
            public UInt64 align;    // Segment alignment, file & memory
        }

        /// <summary>
        /// SizeOF:56
        /// </summary>
        public static readonly int SizePhdr = Marshal.SizeOf(typeof(ProgramHeader));

        /// <summary>
        /// Program Segment Type
        /// These constants are for the segment types stored in the image headers
        /// </summary>
        public enum PhdrType : UInt32
        {
            NULL            = 0x0,
            LOAD            = 0x1,
            DYNAMIC         = 0x2,
            INTERP          = 0x3,
            NOTE            = 0x4,
            SHLIB           = 0x5,
            PHDR            = 0x6,
            TLS             = 0x7,                  // Thread local storage segment
            LOOS            = 0x60000000,           // OS-specific
            HIOS            = 0x6fffffff,           // OS-specific
            LOPROC          = 0x70000000,
            HIPROC          = 0x7fffffff,
            SCE_RELA        = LOOS,                 // .rela No +0x1000000 ?
            SCE_DYNLIBDATA  = LOOS + 0x1000000,     // .sce_special
            SCE_PROCPARAM   = LOOS + 0x1000001,     // .sce_process_param
            SCE_MODULEPARAM = LOOS + 0x1000002,
            SCE_RELRO       = LOOS + 0x1000010,     // .data.rel.ro
            SCE_COMMENT     = LOOS + 0xfffff00,     // .sce_comment
            SCE_VERSION     = LOOS + 0xfffff01,     // .sce_version
            GNU_EH_FRAME    = LOOS + 0x474E550,     // .eh_frame_hdr
            GNU_STACK       = LOOS + 0x474e551,
        }

        /// <summary>
        /// These constants define the permissions on sections in the program header, p_flags
        /// </summary>
        public enum PhdrFlag : UInt32
        {
            X  = 0x1,
            W  = 0x2,
            R  = 0x4,
            RX = R | X,
            RW = R | W,
        }
    }
}