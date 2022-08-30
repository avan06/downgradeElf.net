using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;

namespace downgradeElf
{
    public class Utils
    {
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int memcmp(byte[] b1, byte[] b2, Int64 count);

        /// <summary>
        /// Comparing two byte arrays
        /// https://stackoverflow.com/a/1445405
        /// Validate buffers are the same length.
        /// This also ensures that the count does not exceed the length of either buffer.  
        /// </summary>
        /// <param name="b1"></param>
        /// <param name="b2"></param>
        /// <returns></returns>
        public static bool BytesCompare(byte[] b1, byte[] b2) => b1.Length == b2.Length && memcmp(b1, b2, b1.Length) == 0;

        public static T BytesToStruct<T>(byte[] data) where T : struct
        {
            T result = default;
            GCHandle handle = default;
            try
            {
                handle = GCHandle.Alloc(data, GCHandleType.Pinned);
                result = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            }
            catch { }
            finally { if (handle.IsAllocated) handle.Free(); }

            return result;
        }

        public static byte[] StructToBytes<T>(T structure, int SizeOF) where T : struct
        {
            IntPtr ptr = default;
            byte[] data = default;
            try
            {
                ptr = Marshal.AllocHGlobal(SizeOF);
                data = new byte[SizeOF];
                Marshal.StructureToPtr(structure, ptr, true);
                Marshal.Copy(ptr, data, 0, SizeOF);
            }
            catch { }
            finally { Marshal.FreeHGlobal(ptr); }

            return data;
        }

        /// <summary>
        /// Big-endian UInt64 from 4 bytes
        /// swap the bits using bit shift operations:
        /// https://stackoverflow.com/a/3294698
        /// </summary>
        public static UInt32 SwapEndianness(UInt32 x) =>
            ((x & 0x000000FF) << 24) +  // First byte
            ((x & 0x0000FF00) << 8) +   // Second byte
            ((x & 0x00FF0000) >> 8) +   // Third byte
            ((x & 0xFF000000) >> 24);   // Fourth byte

        public static UInt64 AlignUp(UInt64 x, UInt64 alignment) => x + (alignment - 1) & ~(alignment - 1);

        public static bool CheckSdkVersion(string sdkVersion)
        {
            if (sdkVersion.Length != 10) return false;

            var parts = sdkVersion.Split(new char[] { '.' }, 3);
            if (parts.Length != 3) return false;

            var lengths = new List<int> { 2, 3, 3 };
            for (int idx = 0; idx < parts.Length; idx++)
            {
                var part = parts[idx];
                if (part.Length != lengths[idx]) return false;
            }

            return true;
        }

        public static string StringifySdkVersion(UInt32 major, UInt32 minor, UInt32 patch) => string.Format("{0:x2}.{1:x3}.{2:x3}", major, minor, patch);

        // SDK version have 001 in "patch" field
        public static (UInt32 major, UInt32 minor, UInt32 patch) ParseSdkVersion(UInt32 sdkVersion)
        {
            var major = sdkVersion >> 24;
            var minor = (sdkVersion >> 12) & 0xFFF;
            var patch = sdkVersion & 0xFFF;

            return (major, minor, patch);
        }

        public static (UInt32 major, UInt32 minor, UInt32 patch) UnstringifySdkVersion(string sdkVersion)
        {
            var parts = sdkVersion.Split(new char[] { '.' }, 3);
            var major = UInt32.Parse(parts[0], NumberStyles.HexNumber);
            var minor = UInt32.Parse(parts[1], NumberStyles.HexNumber);
            var patch = UInt32.Parse(parts[2], NumberStyles.HexNumber);
            return (major, minor, patch);
        }

        public static UInt32 BuildSdkVersion(UInt32 major, UInt32 minor, UInt32 patch) => (major & 0xFF) << 24 | (minor & 0xFFF) << 12 | patch & 0xFFF;

        public static ((ulong Old, ulong New) Value, (byte[] Old, byte[] New) Bytes, int ValueSize, int MinSegmentsIndex) GetReplacement((ulong Val, ulong VaddrDiff) value)
        {
            var newVal = value.Val - value.VaddrDiff;
            byte[] oldBytes = BitConverter.GetBytes(value.Val);
            byte[] newBytes = BitConverter.GetBytes(newVal);

            int replacementValueSize = Marshal.SizeOf(typeof(UInt64));
            int replacementMinSegmentsIndex = 0;

            return ((value.Val, newVal), (oldBytes, newBytes), replacementValueSize, replacementMinSegmentsIndex);
        }

        public static List<((ulong Old, ulong New) Value, (byte[] Old, byte[] New) Bytes, int ValueSize, int MinSegmentsIndex)> GetReplacements(List<(ulong Val, ulong VaddrDiff)> values)
        {
            var result = new List<((ulong Old, ulong New) Value, (byte[] Old, byte[] New) Bytes, int ValueSize, int MinSegmentsIndex)>();
            List<UInt64> replacementsValList = new List<UInt64>();
            foreach (var value in values)
            {
                if (replacementsValList.Contains(value.Val)) continue;

                result.Add(GetReplacement(value));
                replacementsValList.Add(value.Val);
            }
            return result;
        }
    }
}