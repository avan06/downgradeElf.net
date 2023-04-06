using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using static downgradeElf.Argparse;

namespace downgradeElf
{
    internal class Program
    {
        private static Argparse InitArgparse(string description)
        {
            Argparse parser = new Argparse(description);

            parser.Add("input", "old file", true);
            parser.Add("output", "new file, add \"_new\" to the end of the input filename when the output is not specified");
            parser.Add("--sdk-version", "wanted sdk version, leave 0(empty) for no patching\n" +
                " 05.050.001: usually used when converting sdk version", "0");

            parser.Add("--patch-memhole", "patch memhole options:\n" +
                " 0: don't patch,\n" +
                " 1: extend the memory size of the segment to fill the memhole,\n" +
                " 2: move the segments after the memhole backwards", "1", false, true);
            parser.Add("--patch-memhole-references", "patch memhole references options(this option is used when patch-memhole is 2):\n" +
                " 0: don't patch memory hole segments bytes\n" +
                " 1: patch memory hole segments bytes\n" +
                " 2: patch memory hole segments bytes that the bits from their end up to the replacement value bytes amount aren't 0\n" +
                " 3: patch memory hole segments bytes with addresses that aren't a multiply of 8", "1", false, true);

            parser.Add("--verbose|-v", "detailed printing", ActionEnum.StoreTrue);
            parser.Add("--dry-run", "if inserted then nothing will be written to the output file", ActionEnum.StoreTrue);
            parser.Add("--overwrite", "overwrite input file when the output path is not specified", ActionEnum.StoreTrue);
            parser.Add("--not-patch-program-headers", "not patch program headers", ActionEnum.StoreTrue);
            parser.Add("--not-patch-dynamic-section", "not patch dynamic section when patch-memhole is 2", ActionEnum.StoreTrue);
            parser.Add("--not-patch-relocation-section", "not patch relocation section when patch-memhole is 2", ActionEnum.StoreTrue);
            parser.Add("--not-patch-symbol-table", "not patch symbol table when patch-memhole is 2", ActionEnum.StoreTrue);
            parser.Add("--not-patch-elf-header", "not patch elf header", ActionEnum.StoreTrue);

            parser.ParseArgs();

            return parser;
        }

        private static void Main(string[] args)
        {
            var parser = InitArgparse("Elf downgrader tool");
            Dictionary<string, Argument> argDict = parser.Arguments();
            bool verbose                    = argDict["--verbose"].Value == "true";
            bool dryRun                     = argDict["--dry-run"].Value == "true";
            bool overwrite                  = argDict["--overwrite"].Value == "true";
            bool notPatchProgramHeaders     = argDict["--not-patch-program-headers"].Value == "true";
            bool notPatchDynamicSection     = argDict["--not-patch-dynamic-section"].Value == "true";
            bool notPatchRelocationSection  = argDict["--not-patch-relocation-section"].Value == "true";
            bool notPatchSymbolTable        = argDict["--not-patch-symbol-table"].Value == "true";
            bool notPatchElfHeader          = argDict["--not-patch-elf-header"].Value == "true";
            /// <summary>
            /// 0: don't patch
            /// 1: extend the memory size of the segment to fill the memhole
            /// 2: move the segments after the memhole backwards
            /// </summary>
            int.TryParse(argDict["--patch-memhole"].Value, out int patchMemhole);
            /// <summary>
            /// patch memhole references options:
            /// 0: don't patch memory hole segments bytes
            /// 1: patch memory hole segments bytes
            /// 2: patch memory hole segments bytes that the bits from their end up to the replacement value bytes amount aren't 0
            /// 3: patch memory hole segments bytes with addresses that aren't a multiply of 8
            /// </summary>
            int.TryParse(argDict["--patch-memhole-references"].Value, out int patchMemholeReferences);

            string inputFilePath = argDict["input"].Value;
            if (!File.Exists(inputFilePath)) parser.Error(string.Format("invalid input file: {0}", inputFilePath));

            string outputFilePath = argDict["output"].Value;
            if (outputFilePath == "")
            {
                string extension = Path.GetExtension(inputFilePath);
                string inputPathWithoutExt = inputFilePath.Substring(0, inputFilePath.Length - extension.Length);
                if (overwrite)
                {
                    File.Copy(inputFilePath, inputFilePath + ".bak", true);
                    outputFilePath = inputFilePath;
                }
                else inputPathWithoutExt += "_new";
                outputFilePath = inputPathWithoutExt + extension;
            }
            else File.Copy(inputFilePath, outputFilePath, true);

            string sdkVersion = argDict["--sdk-version"].Value;
            if (sdkVersion != "0" && !Utils.CheckSdkVersion(sdkVersion)) parser.Error(string.Format("bad sdk version: {0}", sdkVersion));

            Console.WriteLine("processing elf file: {0}\n", outputFilePath);

            Elf.Load(inputFilePath);
            if (!Elf.CheckMAGIC()) parser.Error("error: invalid elf file format", false);
            if (!Elf.Parse(verbose)) parser.Error("error: unable to load elf file", false);

            ElfPHdr.PhdrType neededType = 0;
            string paramMagic = "";
            uint newSdkVersion = 0;

            /// Fixing proc/module param structure.
            if (Elf.elfHdr.type_ == Elf.EType.SCE_EXEC || Elf.elfHdr.type_ == Elf.EType.SCE_DYNEXEC)
            {
                neededType = ElfPHdr.PhdrType.SCE_PROCPARAM;
                paramMagic = "ORBI";
                Console.WriteLine("executable file detected, type:{0}\n", Elf.elfHdr.type_);
            }
            else if (Elf.elfHdr.type_ == Elf.EType.SCE_DYNAMIC)
            {
                neededType = ElfPHdr.PhdrType.SCE_MODULEPARAM;
                paramMagic = Encoding.UTF8.GetString(new byte[] { 0xBF, 0xF4, 0x13, 0x3C });
                Console.WriteLine("module file detected, type:{0}", Elf.elfHdr.type_);
            }
            else parser.Error("error: unsupported elf type", false);

            if (sdkVersion != "0")
            {
                (uint major, uint minor, uint patch) = Utils.UnstringifySdkVersion(sdkVersion);
                newSdkVersion = Utils.BuildSdkVersion(major, minor, patch);
                var newSdkVersionStr = Utils.StringifySdkVersion(major, minor, patch);
                Console.WriteLine("wanted sdk version: {0}\n", newSdkVersionStr);
            }
            Console.WriteLine("searching for {0} param segment...\n", neededType == ElfPHdr.PhdrType.SCE_PROCPARAM ? "proc" : "module");

            var pHdrVar = Elf.GetPhdrByType(neededType);
            if (pHdrVar == null) Console.WriteLine("warning: param segment not found (elf from old sdk?)");
            else
            {
                Console.WriteLine("parsing param structure...\n");
                ElfPHdr.ProgramHeader progHdr = (ElfPHdr.ProgramHeader)pHdrVar;
                byte[] pHdrFile = new byte[progHdr.fileSize];
                Buffer.BlockCopy(Elf.ElfData, (int)progHdr.offset, pHdrFile, 0, pHdrFile.Length);
                if (pHdrFile.Length != (int)progHdr.fileSize) parser.Error("error: insufficient data read", false);

                Elf.ProgramParam progFile = Utils.BytesToStruct<Elf.ProgramParam>(pHdrFile);
                if (progFile.paramSize < 0x14) parser.Error("error: param structure is too small", false);
                if (Encoding.UTF8.GetString(progFile.paramMagic) != paramMagic) parser.Error(string.Format("error: unexpected elf param structure format:{0}, the correct param should be BF-F4-13-3C.", BitConverter.ToString(progFile.paramMagic)), false);

                (uint oldMajor, uint oldMinor, uint oldPatch) = Utils.ParseSdkVersion(progFile.sdkVersion);
                string oldSdkVersionStr = Utils.StringifySdkVersion(oldMajor, oldMinor, oldPatch);
                Console.WriteLine("detect sdk version: {0}\n", oldSdkVersionStr);

                if (newSdkVersion != 0 && progFile.sdkVersion > newSdkVersion)
                {
                    Console.WriteLine("patching param structure, Offset: {0:X}\n", (int)progHdr.offset + 0x10);
                    if (!dryRun)
                    {
                        byte[] newSdkVersionBytes = BitConverter.GetBytes(newSdkVersion);
                        Buffer.BlockCopy(newSdkVersionBytes, 0, Elf.ElfData, (int)progHdr.offset + 0x10, newSdkVersionBytes.Length);
                    }
                    Console.WriteLine("patched param structure\n");
                }
            }

            /// Removing memory holes in PHDRs.
            /// Prevents error on old kernel versions: uncontiguous RELRO and DATA segments
            if (newSdkVersion < 0x06000000) // less than 6.00 fw
            {
                List<(int idx, ElfPHdr.ProgramHeader seg)> segments = new List<(int idx, ElfPHdr.ProgramHeader seg)>();

                bool patchMemholeReferencesEnable = patchMemholeReferences == 1;
                bool patchMemholeReferencesPatchRestBytesNotZeroes = patchMemholeReferences == 2;
                bool patchMemholeReferencesPatchNot8Multiply = patchMemholeReferences == 3;

                for (int idx = 0; idx < Elf.progHdrs.Count; idx++)
                {
                    ElfPHdr.ProgramHeader progHdr = Elf.progHdrs[idx];
                    if (progHdr.type_ != ElfPHdr.PhdrType.LOAD && progHdr.type_ != ElfPHdr.PhdrType.SCE_RELRO) continue;
                    if (progHdr.type_ == ElfPHdr.PhdrType.LOAD && progHdr.flags == ElfPHdr.PhdrFlag.RX) continue; //Console.WriteLine("skipping text segment...");

                    //Console.WriteLine("type:0x{0:X} vaddr:0x{1:X} paddr:0x{2:X} fileSize:0x{3:X} memSize:0x{4:X} align:0x{5:X}", progHdr.type_, progHdr.vaddr, progHdr.paddr, progHdr.fileSize, progHdr.memSize, progHdr.align));
                    segments.Add((idx, progHdr));
                }

                for (int idx = 0; idx < Elf.progHdrs.Count; idx++)
                {
                    ElfPHdr.ProgramHeader progHdr = Elf.progHdrs[idx];
                    if (segments.Contains((idx, progHdr))) continue;
                    foreach ((int segIdx, ElfPHdr.ProgramHeader seg) in segments)
                    {
                        if (seg.paddr != progHdr.paddr && seg.vaddr != progHdr.vaddr) continue;
                        segments.Add((idx, progHdr));
                        break;
                    }
                }

                segments.Sort((pHdr1, pHdr2) =>
                { //segs.sort(key=lambda x: (x.vaddr, -(x.vaddr + x.memSize)))
                    int result = pHdr1.seg.vaddr.CompareTo(pHdr2.seg.vaddr);
                    if (result != 0) return result;

                    long vaddr1Len = (long)(pHdr1.seg.vaddr + pHdr1.seg.memSize);
                    long vaddr2Len = (long)(pHdr2.seg.vaddr + pHdr2.seg.memSize);

                    result = vaddr1Len.CompareTo(vaddr2Len) * -1;
                    return result;
                });

                for (int idx = 1; idx < segments.Count; idx++)
                {
                    ElfPHdr.ProgramHeader seg = segments[idx].seg;
                    ElfPHdr.ProgramHeader preSeg = segments[idx - 1].seg;
                    if (seg.vaddr < preSeg.vaddr ||
                        seg.vaddr + seg.memSize > preSeg.vaddr + preSeg.memSize ||
                        seg.type_ != preSeg.type_) continue;
                    //Console.WriteLine("removing seg vaddr:0x{0:X} memSize:0x{1:X}", seg.vaddr, seg.memSize));
                    //Console.WriteLine("  previous seg vaddr:0x{0:X} memSize:0x{1:X}", preSeg.vaddr, preSeg.memSize));
                    segments.RemoveAt(idx);
                }

                ElfPHdr.ProgramHeader dynamicPH = default;
                ElfPHdr.ProgramHeader dynlibDataPH = default;

                int dynamicTableCount = 0;
                ulong dynamicTableAddr = 0;
                int relaTableCount = 0;
                ulong relaTableAddr = 0;
                ulong relaTableSize = 0;
                int symTableCount = 0;
                ulong symTableAddr = 0;
                ulong symTableSize = 0;
                if ((!notPatchDynamicSection || !notPatchRelocationSection || !notPatchSymbolTable) && patchMemhole == 2)
                {
                    foreach (ElfPHdr.ProgramHeader progHdr in Elf.progHdrs)
                    {
                        if (progHdr.type_ == ElfPHdr.PhdrType.DYNAMIC) dynamicPH = progHdr;
                        else if (progHdr.type_ == ElfPHdr.PhdrType.SCE_DYNLIBDATA) dynlibDataPH = progHdr;
                    }
                    if (dynamicPH.type_.Equals(ElfPHdr.PhdrType.NULL)) parser.Error("An error occurred, as the ELF is not a valid OELF!", false);

                    dynamicTableCount = (int)dynamicPH.memSize / Elf.sizeDynamic;

                    dynamicTableAddr = dynamicPH.offset;
                    relaTableAddr    = dynlibDataPH.offset;
                    symTableAddr     = dynlibDataPH.offset;
                }
                ulong firstSegmentVirtualAddress = Elf.progHdrs[0].vaddr;

                if ((!notPatchRelocationSection || !notPatchSymbolTable) && patchMemhole == 2)
                {
                    for (int dIdx = 0; dIdx < dynamicTableCount; dIdx++)
                    {
                        var dynaBytes = new byte[Elf.sizeDynamic];
                        Buffer.BlockCopy(Elf.ElfData, (int)dynamicPH.offset + dIdx * Elf.sizeDynamic, dynaBytes, 0, Elf.sizeDynamic);
                        var dyna = Utils.BytesToStruct<Elf.Dynamic>(dynaBytes);
                        //Console.WriteLine(" Tag:{0,-20} Val:{1,20:X}", dyna.tag, dyna.val);
                        if (dyna.tag      == Elf.DTag.SCE_JMPREL) relaTableAddr   += dyna.val;
                        else if (dyna.tag == Elf.DTag.SCE_PLTRELSZ) relaTableSize += dyna.val;
                        else if (dyna.tag == Elf.DTag.SCE_RELASZ) relaTableSize   += dyna.val;
                        else if (dyna.tag == Elf.DTag.SCE_SYMTAB) symTableAddr    += dyna.val;
                        else if (dyna.tag == Elf.DTag.SCE_SYMTABSZ) symTableSize  += dyna.val;
                    }

                    relaTableCount = (int)relaTableSize / Elf.sizeRela;
                    symTableCount = (int)symTableSize / Elf.sizeSymbol;
                }

                //(c) flatz version, removing memory holes
                //for (int sIdx = 0; sIdx < segments.Count - 1; sIdx++)
                //{
                //    var segment = segments[sIdx];
                //    var nextSegment = segments[sIdx + 1];
                //    var memSizeAligned = Utils.AlignUp(segment.memSize, 0x4000);
                //    if (segment.vaddr + memSizeAligned >= nextSegment.vaddr) continue;
                //    segment.memSize = nextSegment.vaddr - segment.vaddr;
                //    segments[sIdx] = segment;
                //    hasChanges = true;
                //}

                if (segments.Count > 1)
                {
                    List<(ulong Val, ulong VaddrDiff)> dValValues    = new List<(ulong Val, ulong VaddrDiff)>();
                    List<(ulong Val, ulong VaddrDiff)> rAddrValues   = new List<(ulong Val, ulong VaddrDiff)>();
                    List<(ulong Val, ulong VaddrDiff)> rAddendValues = new List<(ulong Val, ulong VaddrDiff)>();
                    List<(ulong Val, ulong VaddrDiff)> stValueValues = new List<(ulong Val, ulong VaddrDiff)>();
                    for (int sIdxA = 0; sIdxA < segments.Count - 1; sIdxA++)
                    {
                        var segment = segments[sIdxA];
                        var nextSegment = segments[sIdxA + 1];
                        var memSizeAligned = Utils.AlignUp(segment.seg.memSize, 0x4000);

                        if (segment.seg.vaddr + memSizeAligned >= nextSegment.seg.vaddr) continue;

                        ulong oldMemSize  = segment.seg.memSize;
                        ulong oldPaddr    = nextSegment.seg.paddr;
                        ulong oldVaddr    = nextSegment.seg.vaddr;
                        var paddrMemSize  = nextSegment.seg.memSize;
                        var vaddrMemSize  = nextSegment.seg.memSize;  // ida shows virtual address;
                        var paddrFileSize = nextSegment.seg.fileSize;
                        var vaddrFileSize = nextSegment.seg.fileSize;

                        ulong newMemSize = 0;
                        ulong newPaddr   = 0;
                        ulong newVaddr   = 0;
                        ulong paddrEnd   = 0;
                        ulong vaddrEnd   = 0;
                        ulong paddrDiff  = 0;
                        ulong vaddrDiff  = 0;
                        Console.WriteLine("\nfound a memhole between: 0x{0:X8} ~ 0x{1:X8} (not including the last address)", segment.seg.vaddr + memSizeAligned, nextSegment.seg.vaddr);

                        if (notPatchProgramHeaders || patchMemhole == 0)
                        {
                            newMemSize = oldMemSize;
                            newPaddr = oldPaddr;
                            newVaddr = oldVaddr;

                            paddrEnd = oldPaddr + paddrMemSize - 1;
                            vaddrEnd = oldVaddr + vaddrMemSize - 1;
                        }
                        else
                        { // program headers patching;
                            Console.WriteLine("\npatching program headers");
                            if (patchMemhole == 1)
                            {
                                newMemSize = oldVaddr - segment.seg.vaddr;
                                newPaddr = oldPaddr;
                                newVaddr = oldVaddr;

                                paddrEnd = oldPaddr + paddrMemSize - 1;
                                vaddrEnd = oldVaddr + vaddrMemSize - 1;

                                segment.seg.memSize = newMemSize;
                                segments[sIdxA] = segment;
                            }
                            else if (patchMemhole == 2)
                            {
                                newMemSize = memSizeAligned;
                                newPaddr = segment.seg.paddr + newMemSize;
                                newVaddr = segment.seg.vaddr + newMemSize;

                                segment.seg.memSize = newMemSize;
                                segments[sIdxA] = segment;

                                paddrDiff = oldPaddr - newPaddr;
                                vaddrDiff = oldVaddr - newVaddr;

                                nextSegment.seg.paddr = newPaddr;
                                nextSegment.seg.vaddr = newVaddr;
                                segments[sIdxA + 1] = nextSegment;

                                if (segments.Count > sIdxA + 2)
                                {
                                    for (int sIdxB = sIdxA + 2; sIdxB < segments.Count; sIdxB++)
                                    {
                                        bool found = false;
                                        var segB = segments[sIdxB];
                                        if (oldPaddr == segB.seg.paddr)
                                        {
                                            found = true;
                                            segB.seg.paddr = newPaddr;
                                            segments[sIdxB] = segB;
                                        }
                                        if (oldVaddr == segB.seg.vaddr)
                                        {
                                            found = true;
                                            segB.seg.vaddr = newVaddr;
                                            segments[sIdxB] = segB;
                                        }
                                        if (segB.seg.memSize > paddrMemSize)
                                        {
                                            found = true;
                                            paddrMemSize = segB.seg.memSize;
                                        }
                                        if (segB.seg.memSize > vaddrMemSize)
                                        {
                                            found = true;
                                            vaddrMemSize = segB.seg.memSize;
                                        }
                                        if (segB.seg.fileSize > paddrFileSize)
                                        {
                                            found = true;
                                            paddrFileSize = segB.seg.fileSize;
                                        }
                                        if (segB.seg.fileSize > vaddrFileSize)
                                        {
                                            found = true;
                                            vaddrFileSize = segB.seg.fileSize;
                                        }
                                        if (!found) break;
                                    }
                                }

                                paddrEnd = oldPaddr + paddrMemSize - 1;
                                vaddrEnd = oldVaddr + vaddrMemSize - 1;

                                for (int phdrsIdx = 0; phdrsIdx < Elf.progHdrs.Count; phdrsIdx++)
                                {
                                    ElfPHdr.ProgramHeader progHdr = Elf.progHdrs[phdrsIdx];
                                    if (progHdr.paddr <= oldPaddr && progHdr.vaddr <= oldVaddr) continue;
                                    if (progHdr.paddr > oldPaddr) progHdr.paddr -= paddrDiff;
                                    if (progHdr.vaddr > oldVaddr) progHdr.vaddr -= vaddrDiff;
                                    if (progHdr.paddr + progHdr.memSize - 1 > paddrEnd) paddrEnd = progHdr.paddr + progHdr.memSize - 1;
                                    if (progHdr.vaddr + progHdr.memSize - 1 > vaddrEnd) vaddrEnd = progHdr.vaddr + progHdr.memSize - 1;
                                    Elf.progHdrs[phdrsIdx] = progHdr;
                                }
                            }

                            if (verbose)
                            {
                                Console.WriteLine("Memory Size: {0:X8} => {1:X8}", oldMemSize, newMemSize);
                                Console.WriteLine("Address:     {0:X8} => {1:X8}", oldPaddr, newPaddr);
                            }
                            Console.WriteLine("\npatched program headers\n");
                        }

                        if (!notPatchDynamicSection && patchMemhole == 2)
                        { // dynamic section patching
                            Console.WriteLine("patching dynamic section");
                            if (dynamicTableCount == 0) Console.WriteLine("  couldn't find the dynamic section");
                            else
                            {
                                Console.WriteLine("Found dynamic section, entries: {0}", dynamicTableCount);
                                for (int dIdx = 0; dIdx < dynamicTableCount; dIdx++)
                                {
                                    var dynaBytes = new byte[Elf.sizeDynamic];
                                    var dynaOffset = (int)dynamicTableAddr + dIdx * Elf.sizeDynamic;
                                    Buffer.BlockCopy(Elf.ElfData, dynaOffset, dynaBytes, 0, Elf.sizeDynamic);
                                    var dyna = Utils.BytesToStruct<Elf.Dynamic>(dynaBytes);
                                    if (dyna.tag == Elf.DTag.SCE_JMPREL || dyna.tag == Elf.DTag.SCE_PLTRELSZ || dyna.tag == Elf.DTag.SCE_RELASZ || dyna.tag == Elf.DTag.SCE_SYMTAB) continue;
                                    if (dyna.val < oldVaddr || dyna.val > vaddrEnd) continue;

                                    dValValues.Add((dyna.val, vaddrDiff));
                                    dyna.val -= vaddrDiff;
                                    if (!dryRun)
                                    {
                                        var newDynaBytes = Utils.StructToBytes(dyna, Elf.sizeDynamic);
                                        Buffer.BlockCopy(newDynaBytes, 0, Elf.ElfData, dynaOffset, Elf.sizeDynamic);
                                    }
                                    if (verbose)
                                    {
                                        Console.Write("Entry: {0,-8}", dIdx + 1); //Console.Write("Tag: 0x{0}\t", dyna.tag);
                                        Console.Write("Value: 0x{0:X8} => 0x{1:X8}\t", dyna.val + vaddrDiff, dyna.val);
                                        Console.Write("Offset: 0x{0:X8}\n", dynaOffset);
                                    }
                                }
                                Console.WriteLine("\npatched dynamic section\n");
                            }
                        }

                        if (!notPatchRelocationSection && patchMemhole == 2)
                        { // relocation section patching;
                            Console.WriteLine("patching relocation section");
                            if (relaTableCount == 0) Console.WriteLine("  couldn't find the relocation section");
                            else
                            {
                                Console.WriteLine("Found relocation section, entries: {0}", relaTableCount);
                                for (int rIdx = 0; rIdx < relaTableCount; rIdx++)
                                {
                                    var relaBytes = new byte[Elf.sizeRela];
                                    var relaOffset = (int)relaTableAddr + rIdx * Elf.sizeRela;
                                    Buffer.BlockCopy(Elf.ElfData, relaOffset, relaBytes, 0, Elf.sizeRela);
                                    var rela = Utils.BytesToStruct<Elf.Relocation>(relaBytes);

                                    var oldRAddr = rela.addr;
                                    var oldRAddend = rela.addend;
                                    string rType = rela.info.ToString("X");

                                    foreach (Elf.RTYPES relaType in (Elf.RTYPES[])Enum.GetValues(typeof(Elf.RTYPES))) if (rela.info == relaType) rType = relaType.ToString();

                                    if (rela.addr >= oldVaddr && rela.addr <= vaddrEnd)
                                    {
                                        rAddrValues.Add((rela.addr, vaddrDiff));
                                        rela.addr -= vaddrDiff;
                                    }
                                    if (rela.addend >= (long)oldVaddr && rela.addend <= (long)vaddrEnd)
                                    {
                                        rAddendValues.Add(((ulong)rela.addend, vaddrDiff));
                                        rela.addend -= (long)vaddrDiff;
                                    }
                                    if (oldRAddr != rela.addr || oldRAddend != rela.addend)
                                    {
                                        if (verbose)
                                        {
                                            Console.Write("Entry: {0,-8}", rIdx + 1);
                                            if (oldRAddr != rela.addr) Console.Write("Address: 0x{0:X8} => 0x{1:X8} ", oldRAddr, rela.addr);
                                            if (oldRAddend != rela.addend) Console.Write("Addend: 0x{0:X8} => 0x{1:X8} ", oldRAddend, rela.addend);
                                            Console.Write("Offset: 0x{0:X8}\n", relaOffset);
                                            //Console.WriteLine("Symbol: 0x{0:X8}\t", rela.sym);
                                        }
                                        if (!dryRun)
                                        {
                                            var newRelaBytes = Utils.StructToBytes(rela, Elf.sizeRela);
                                            Buffer.BlockCopy(newRelaBytes, 0, Elf.ElfData, relaOffset, Elf.sizeRela);
                                        }
                                    }
                                }
                                Console.WriteLine("\npatched relocation section\n");
                            }
                        }

                        if (!notPatchSymbolTable && patchMemhole == 2)
                        {
                            Console.WriteLine("\npatching symbol table");
                            if (symTableCount == 0) Console.WriteLine("  couldn't find the symbol table");
                            else
                            {
                                Console.WriteLine("Found symbol table, entries: {0}", symTableCount);
                                for (int sIdx = 0; sIdx < symTableCount; sIdx++)
                                {
                                    var symbolBytes = new byte[Elf.sizeSymbol];
                                    var symbolOffset = (int)symTableAddr + sIdx * Elf.sizeSymbol;
                                    Buffer.BlockCopy(Elf.ElfData, symbolOffset, symbolBytes, 0, Elf.sizeSymbol);
                                    var sym = Utils.BytesToStruct<Elf.Symbol>(symbolBytes);
                                    if (sym.value < oldVaddr || sym.value > vaddrEnd) continue;

                                    stValueValues.Add((sym.value, vaddrDiff));
                                    sym.value -= vaddrDiff;

                                    if (!dryRun)
                                    {
                                        var newSymBytes = Utils.StructToBytes(sym, Elf.sizeSymbol); //newStructData = pack(structFmt, st_name, st_info, stOther, stShndx, newStValue, st_size)
                                        Buffer.BlockCopy(newSymBytes, 0, Elf.ElfData, symbolOffset, Elf.sizeSymbol);
                                    }

                                    if (verbose)
                                    {
                                        Console.Write("Entry: {0,-8}", sIdx + 1);
                                        Console.Write("Addend: 0x{0:X8} => 0x{0:X8} ", sym.value + vaddrDiff, sym.value);
                                        Console.Write("Size: 0x{0:X4}\tOffset:0x{1:x8}\n", sym.size, symbolOffset);
                                        //Console.WriteLine("Ndx: {0}\t", sym.shndx);
                                        //Console.WriteLine("Name: {0}\t", sym.name);
                                        //Console.WriteLine("Info: {0}\t", sym.info);
                                        //Console.WriteLine("Other: {0}\t", sym.other);
                                    }
                                }
                                Console.WriteLine("\npatched symbol table\n");
                            }
                        }

                        var stValueReplacementsUse = true;
                        var rAddendReplacementsUse = true;
                        var dValReplacementsUse    = true; // suggested not to use, doesn't appear to be necessary
                        var rAddrReplacementsUse   = true; // suggested not to use, not tested enough, but appears to just cause problems && be not needed

                        if (patchMemholeReferencesEnable && patchMemhole == 2)
                        { // memory hole references patching
                            Console.WriteLine("\npatching memory hole references between the segment before the memory hole to the segment after the memory hole && its file size");
                            // might be that it's segment before memhole to after its file size && segment after memhole to after its file size
                            // but we don't do 2 ranges, so instead we do segment before memhole to the segment after the memhole && its file size

                            var structSize = (int)(newVaddr + vaddrFileSize - segment.seg.vaddr);

                            List<(ulong Val, ulong VaddrDiff)> values = new List<(ulong Val, ulong VaddrDiff)>();
                            if (stValueReplacementsUse) values.AddRange(stValueValues);
                            if (rAddendReplacementsUse) values.AddRange(rAddendValues);
                            if (dValReplacementsUse) values.AddRange(dValValues);
                            if (rAddrReplacementsUse) values.AddRange(rAddrValues);
                            var replacements = Utils.GetReplacements(values);

                            Console.WriteLine("Found memory hole references section, entries: {0}", structSize);

                            if (replacements.Count > 0)
                            {
                                var offset = (int)segment.seg.offset;
                                var segmentBytes = new byte[structSize];
                                Buffer.BlockCopy(Elf.ElfData, offset, segmentBytes, 0, segmentBytes.Length);

                                List<byte> newSegmentList = new List<byte>();
                                var safeMinBytesSize = (int)nextSegment.seg.vaddr;
                                var safeMinBytesCount = (int)Math.Ceiling(Math.Log(safeMinBytesSize, 0x00000100));
                                var safeMinBytesEstimatedCount = (int)Math.Pow(2, Math.Ceiling(Math.Log(safeMinBytesCount, 2)));

                                var safeMaxBytesSize = (int)nextSegment.seg.vaddr + (int)vaddrMemSize - 1;
                                var safeMaxBytesCount = (int)Math.Ceiling(Math.Log(safeMaxBytesSize, 0x00000100));
                                var safeMaxBytesEstimatedCount = (int)Math.Pow(2, Math.Ceiling(Math.Log(safeMaxBytesCount, 2)));

                                var replacementsMinValue = nextSegment.seg.vaddr;
                                var replacementsMaxValue = nextSegment.seg.vaddr + vaddrMemSize - 1;

                                int sIdx = 0;
                                bool found = false;
                                while (sIdx <= structSize - 1)
                                {
                                    var currentIdx = 0;
                                    long currentValue = 0;
                                    for (int currentValueSize = safeMinBytesEstimatedCount; currentValueSize <= safeMaxBytesEstimatedCount; currentValueSize++)
                                    {
                                        if (sIdx > structSize - currentValueSize) break;

                                        while (currentIdx < currentValueSize)
                                        {
                                            currentValue += (int)Math.Pow(0x00000100, currentIdx * segmentBytes[sIdx + currentIdx]);
                                            currentIdx++;
                                        }
                                        if (currentValue < (long)replacementsMinValue || currentValue > (long)replacementsMaxValue) continue;

                                        for (int idx = 0; idx < replacements.Count; idx++)
                                        {
                                            var replacement = replacements[idx];
                                            var newReplacementMinSegmentsIndex = replacement.MinSegmentsIndex;
                                            if (sIdx >= replacement.MinSegmentsIndex && currentValueSize <= replacement.ValueSize)
                                            {
                                                bool errorFound = false;
                                                for (int bytesIdx = 0; bytesIdx < currentValueSize; bytesIdx++)
                                                {
                                                    if (segmentBytes[sIdx + bytesIdx] == replacement.Bytes.Old[bytesIdx]) continue;

                                                    errorFound = true;
                                                    break;
                                                }
                                                if (!errorFound)
                                                {
                                                    for (int bytesIdx1 = currentValueSize; bytesIdx1 < replacement.ValueSize; bytesIdx1++)
                                                    {
                                                        if (replacement.Bytes.Old[bytesIdx1] == 0) continue;

                                                        errorFound = true;
                                                        break;
                                                    }
                                                    if (!errorFound) newReplacementMinSegmentsIndex = sIdx + currentValueSize;
                                                }
                                            }
                                            if (newReplacementMinSegmentsIndex != replacement.MinSegmentsIndex)
                                            {
                                                bool errorFound = false;
                                                if (sIdx > structSize - (uint)replacement.ValueSize) errorFound = true;
                                                else
                                                {
                                                    for (int bytesIdx = currentValueSize; bytesIdx < replacement.ValueSize; bytesIdx++)
                                                    {
                                                        if (segmentBytes[sIdx + (uint)bytesIdx] == 0) continue;

                                                        errorFound = true;
                                                        break;
                                                    }
                                                }
                                                if (!errorFound) found = true;
                                                else
                                                {
                                                    errorFound = false;
                                                    if (patchMemholeReferencesPatchRestBytesNotZeroes)
                                                    {
                                                        found = true;
                                                        Console.WriteLine("Patching memory hole segments bytes that the bits from their end up to the replacement value bytes amount aren't 0");
                                                    }
                                                    else Console.WriteLine("Skipped patch for memory hole segments bytes that the bits from their end up to the replacement value bytes amount aren't 0");
                                                }
                                                if (found)
                                                {
                                                    found = false;
                                                    if ((sIdx + (long)segment.seg.vaddr) % 8 != 0) errorFound = true;
                                                    if (errorFound)
                                                    {
                                                        if (patchMemholeReferencesPatchNot8Multiply)
                                                        {
                                                            found = true;
                                                            Console.WriteLine("Patching memory hole segments bytes with an address that isn't a multiply of 8");
                                                        }
                                                        else Console.WriteLine("Skipped patch for memory hole segments bytes with an address that isn't a multiply of 8");
                                                    }
                                                    else found = true;

                                                }

                                                string section;
                                                if (dValValues.Count > 0 && dValValues.Contains(replacement.Value)) section = "dynamic values";
                                                else if (rAddrValues.Count > 0 && rAddrValues.Contains(replacement.Value)) section = "relocation addresses";
                                                else if (rAddendValues.Count > 0 && rAddendValues.Contains(replacement.Value)) section = "relocation addresses";
                                                else section = "symbol values";
                                                if (found)
                                                {
                                                    replacement.MinSegmentsIndex = newReplacementMinSegmentsIndex;
                                                    replacements[idx] = replacement;
                                                    // not going for all of the replacement value size, because we don't want to change the structure
                                                    // of the original data (in case it's not zeroes, we might accept it if using the
                                                    // patch memhole references patch rest bytes not zeroes flag, so whether it's zeroes or not it doesn't matter by here
                                                    // && we ain't gonna change stuff we don't need to)
                                                    for (int bytesIdx = 0; bytesIdx < currentValueSize; bytesIdx++) newSegmentList.Add(replacement.Bytes.New[bytesIdx]);

                                                    if (verbose)
                                                    {
                                                        Console.Write("Entry: {0,-8}", sIdx + 1);
                                                        Console.Write("Address: 0x{0:X8} ", sIdx + (long)segment.seg.vaddr);
                                                        Console.Write("Value: 0x{0:X8} => 0x{1:X8}\t", replacement.Value.Old, replacement.Value.New);
                                                        Console.Write("Section: 0x{0:X4}\n", section);
                                                    }
                                                }
                                                else if (verbose)
                                                {
                                                    Console.Write("Entry: {0,-8}", sIdx + 1);
                                                    Console.Write("Address: 0x{0:X8} ", sIdx + (long)segment.seg.vaddr);
                                                    Console.Write("Value: 0x{0:X8}\t", replacement.Value.Old);
                                                    Console.Write("Section: 0x{0:X4}\n", section);
                                                }
                                            }

                                            if (found)
                                            {
                                                // going forward in current value size && not in replacement value size
                                                // because it might be smaller && contain data afterwards
                                                sIdx += currentValueSize;
                                                break;
                                            }
                                        }
                                        if (found) break;
                                    }
                                    if (found) found = false;
                                    else
                                    {
                                        newSegmentList.Add(segmentBytes[sIdx]);
                                        sIdx += 1;
                                    }
                                }

                                if (!dryRun)
                                {
                                    byte[] newStructData = newSegmentList.ToArray();
                                    Buffer.BlockCopy(newStructData, 0, Elf.ElfData, offset, newStructData.Length);
                                }
                            }
                            Console.WriteLine("\npatched memory hole references\n");
                        }

                        Console.WriteLine("\nFirst Segment Virtual Address: {0:X8}", firstSegmentVirtualAddress);
                        Console.WriteLine("Segment Before Memory Hole Virtual Address: {0:X8}", segment.seg.vaddr);
                        Console.WriteLine("Segment After Memory Hole Unmapped Virtual Address: {0:X8}", nextSegment.seg.vaddr);
                        Console.WriteLine("Segment After Memory Hole Mapped Virtual Address: {0:X8}", newVaddr);
                        // Console.WriteLine("Segment After Memory Hole File Size: {0:X8}", SegmentAfterMemHole_FileSize);
                        Console.WriteLine("Segment After Memory Hole Memory Size: {0:X8}", vaddrMemSize);
                    }
                }

                foreach ((int idx, ElfPHdr.ProgramHeader seg) in segments) Elf.progHdrs[idx] = seg;
            }

            Console.WriteLine("\nsearching for version segment");

            pHdrVar = Elf.GetPhdrByType(ElfPHdr.PhdrType.SCE_VERSION);
            if (pHdrVar != null && (ElfPHdr.ProgramHeader)pHdrVar is ElfPHdr.ProgramHeader pHdr && pHdr.fileSize > 0 && newSdkVersion > 0)
            {
                Console.WriteLine("found version segment, parsing library list");

                bool hasChanges = false;
                ulong offset = 0;
                while (offset < pHdr.fileSize)
                {
                    var current = pHdr.offset + ++offset;
                    var length = Elf.ElfData[current - 1];
                    if (length == 0)
                    {
                        Console.WriteLine("value of the version segment is empty");
                        break;
                    }

                    var data = new byte[length];
                    Buffer.BlockCopy(Elf.ElfData, (int)current, data, 0, data.Length);
                    var idx = Array.IndexOf(data, (byte)':');
                    if (idx == -1) parser.Error("error: unexpected library list entry format for version section", false);
                    if (length - idx - 1 is int oldVerLen && oldVerLen != sizeof(UInt32)) parser.Error("error: unexpected library list entry format for version section", false); //struct.calcsize('I')

                    string name = Encoding.UTF8.GetString(data, 0, idx);
                    var oldSdkVersionBytes = new byte[oldVerLen];
                    Buffer.BlockCopy(data, idx + 1, oldSdkVersionBytes, 0, oldSdkVersionBytes.Length);

                    Array.Reverse(oldSdkVersionBytes);
                    uint oldSdkVersion = BitConverter.ToUInt32(oldSdkVersionBytes, 0);
                    (uint oldMajor, uint oldMinor, uint oldPatch) = Utils.ParseSdkVersion(oldSdkVersion);
                    string oldSdkCersionStr = Utils.StringifySdkVersion(oldMajor, oldMinor, oldPatch);
                    if (verbose) Console.WriteLine("{0,-30} (detect sdk version: {1})", name, oldSdkCersionStr);

                    if (oldSdkVersion > newSdkVersion)
                    {
                        if (!dryRun)
                        {
                            byte[] newSdkVersionBytes = BitConverter.GetBytes(Utils.SwapEndianness(newSdkVersion));
                            Buffer.BlockCopy(newSdkVersionBytes, 0, Elf.ElfData, (int)current + name.Length + 1, newSdkVersionBytes.Length);
                        }
                        hasChanges = true;
                    }
                    offset += length;
                }

                if (hasChanges && verbose) Console.WriteLine("\npatched sdk versions in library list");
                Console.WriteLine("parsed library list");
            }
            else if (verbose) Console.WriteLine("\nversion segment not found\n");

            if (!notPatchElfHeader)
            {
                /// Fixing section headers.
                Console.WriteLine("\npatching elf header");

                /// Prevents error in orbis-bin:
                ///   Section header offset (XXX) exceeds file size (YYY).
                Elf.elfHdr.shdrOffset = 0;
                Elf.elfHdr.shdrCount = 0;
                Console.WriteLine("patched elf header\n");
            }

            if (!Elf.SaveHdr()) parser.Error("error: unable to save elf file");
            using (FileStream fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.ReadWrite, FileShare.Read))
                fs.Write(Elf.ElfData, 0, Elf.ElfData.Length);

            Console.WriteLine("\nfinished patching:{0}\n", outputFilePath);
        }
    }
}