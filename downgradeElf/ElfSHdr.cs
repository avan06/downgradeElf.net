using System;
using System.Runtime.InteropServices;

namespace downgradeElf
{
    public class ElfSHdr
    {
        public static SectionHeader GetSHdr(byte[] elfData, int shdrOffset)
        {
            byte[] sHdrData = new byte[SizeSHdr];
            Buffer.BlockCopy(elfData, shdrOffset, sHdrData, 0, sHdrData.Length);
            if (sHdrData.Length != SizeSHdr) return new SectionHeader { };

            SectionHeader sectHdr = Utils.BytesToStruct<SectionHeader>(sHdrData);

            return sectHdr;
        }

        public static bool Save(byte[] elfData, int shdrOffset, SectionHeader sectHdr)
        {
            byte[] sectHdrData = Utils.StructToBytes(sectHdr, SizeSHdr);
            if (sectHdrData.Length != SizeSHdr) return false;

            Buffer.BlockCopy(sectHdrData, 0, elfData, shdrOffset, sectHdrData.Length);

            return true;
        }

        public static readonly int SizeSHdr = Marshal.SizeOf(typeof(SectionHeader));

        /// <summary>
        /// FMT = "<2I4Q2I2Q", calcsize:64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SectionHeader
        {
            public UInt32 name;      // Section name, index in string tbl
            public UInt32 type;      // Type of section
            public UInt64 flags;     // Miscellaneous section attributes
            public UInt64 addr;      // Section virtual addr at execution
            public UInt64 offset;    // Section file offset
            public UInt64 size;      // Size of section in bytes
            public UInt32 link;      // Index of another section
            public UInt32 info;      // Additional section information
            public UInt64 align;     // Section alignment
            public UInt64 entrySize; // Entry size if section holds table
        }
    }
}