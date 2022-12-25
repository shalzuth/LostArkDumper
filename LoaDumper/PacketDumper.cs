using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Gee.External.Capstone;
using LoaDumper;

namespace LoaDumper
{
    public class PacketDumper
    {
        static String FasmPath = "";
        static String IdaPath = "";
        static IntPtr hProcess;
        static Gee.External.Capstone.X86.CapstoneX86Disassembler disassembler = CapstoneDisassembler.CreateX86Disassembler(Gee.External.Capstone.X86.X86DisassembleMode.Bit64);
        public class DumpedClass
        {
            public IntPtr ParseOffset;
            public String Name;
            public List<ReadOp> OpList = new List<ReadOp>();
            public Boolean OnlyReadsList;
        }
        static Dictionary<UInt64, DumpedClass> Dumped = new Dictionary<UInt64, DumpedClass>();
        public class ReadOp
        {
            public UInt64 dumpedClass;
            public UInt64 structOff;
            public String Name;
            public String Rename;
            public String Op;
            public Boolean If;
            public Boolean For;
            public Boolean List;
            public Boolean ReadsList;
        }
        public static String GetReadName(UInt64 dumpedClass)
        {
            GetReadInfo(dumpedClass, out String readType, out _, out String name, out _, out bool customName);
            return readType;
        }
        public static void GetReadInfo(UInt64 dumpedClass, out String readType, out String readCommand, out String name, out UInt64 size, out Boolean customName)
        {
            customName = false;
            readType = "err";
            readCommand = "err";
            name = "err";
            size = dumpedClass;
            if (dumpedClass == 1)
            {
                readType = "Byte";
                readCommand = "reader.ReadByte()";
                name = "b";
            }
            else if (dumpedClass == 2)
            {
                readType = "UInt16";
                readCommand = "reader.ReadUInt16()";
                name = "u16";
            }
            else if (dumpedClass == 4)
            {
                readType = "UInt32";
                readCommand = "reader.ReadUInt32()";
                name = "u32";
            }
            else if (dumpedClass == 8)
            {
                readType = "UInt64";
                readCommand = "reader.ReadUInt64()";
                name = "u64";
            }
            else if (dumpedClass == Dumped.First(d => d.Value.Name == "PackedInt").Key)
            {
                readType = "Int64";
                readCommand = "reader.ReadPackedInt()";
                name = "p64";
                size = 8;
            }
            else if (dumpedClass == Dumped.First(d => d.Value.Name == "SimpleInt").Key)
            {
                readType = "UInt64";
                readCommand = "reader.ReadSimpleInt()";
                name = "s64";
                size = 8;
            }
            else if (dumpedClass == Dumped.First(d => d.Value.Name == "String").Key)
            {
                readType = "String";
                readCommand = "reader.ReadString()";
                name = "str";
                size = 16;
            }
            else if (dumpedClass == Dumped.First(d => d.Value.Name == "Flag").Key)
            {
                readType = "UInt64";
                readCommand = "reader.ReadFlag()";
                name = "flag";
                size = 16;
            }
            else if (dumpedClass == Dumped.First(d => d.Value.Name == "PackedValues").Key)
            {
                readType = "List<Object>";
                readCommand = "reader.ReadPackedValues(1, 1, 4, 4, 4, 3, 6)";
                name = "packed";
                size = 16;
            }
            else if (dumpedClass < 0x1000)
            {
                readType = "Byte[]";
                readCommand = "reader.ReadBytes(" + dumpedClass + ")";
                name = "bytearray";
            }
            else if (dumpedClass < 0x1100)
            {
                readType = "Byte[]";
                readCommand = "reader.ReadBytes(" + (dumpedClass - 0x1000) + ")";
                name = "bytearray";
            }
            else if (Dumped[dumpedClass].OnlyReadsList)
            {
                GetReadInfo(Dumped[dumpedClass].OpList[1].dumpedClass, out String subReadType, out String subReadCommand, out String subName, out size, out customName);
                readType = "List<" + subReadType + ">";
                readCommand = "reader.ReadList<" + subReadType + ">()";
                if (subReadType == "Byte[]") readCommand = "reader.ReadList<" + subReadType + ">(" + Dumped[dumpedClass].OpList[1].dumpedClass + ")";
                if (Dumped[dumpedClass].OpList[1].dumpedClass > 0x1000)
                    name = char.ToLower(subReadType[0]) + subReadType.Substring(1) + "s";
                else name = subName + "list";
            }
            else
            {
                customName = true;
                size = 0;
                readType = Dumped[dumpedClass].Name;
                foreach (var o in Dumped[dumpedClass].OpList)
                {
                    GetReadInfo(o.dumpedClass, out _, out _, out _, out UInt64 subSize, out _);
                    size += subSize;
                }
                readCommand = "reader.Read<" + Dumped[dumpedClass].Name + ">()";
                name = char.ToLower(readType[0]) + readType.Substring(1);
            }
        }
        public static void DumpClass(DumpedClass cl, Region region, out String baseClass, out String regionClass)
        {
            var privateClass = new StringBuilder();
            privateClass.AppendLine("using System;");
            privateClass.AppendLine("using System.Collections.Generic;");
            privateClass.AppendLine("namespace LostArkLogger");
            privateClass.AppendLine("{");
            privateClass.AppendLine("    public class " + cl.Name + " : Packet");
            privateClass.AppendLine("    {");
            var classHeader = new StringBuilder();
            classHeader.AppendLine("using System;");
            classHeader.AppendLine("using System.Collections.Generic;");
            classHeader.AppendLine("namespace LostArkLogger");
            classHeader.AppendLine("{");
            classHeader.AppendLine("    public partial class " + cl.Name);
            classHeader.AppendLine("    {");
            var baseClassSb = new StringBuilder(classHeader.ToString());
            baseClassSb.AppendLine("        public " + cl.Name + "(BitReader reader)");
            baseClassSb.AppendLine("        {");
            foreach (var r in new List<String> { "Steam", "Korea" })
                //foreach (var r in new List<String> { "Steam" })
                baseClassSb.AppendLine("            if (Properties.Settings.Default.Region == Region." + r + ") " + r + "Decode(reader);");
            //baseClassSb.AppendLine("            if (Properties.Settings.Default.Region == Region." + r + ") " + "SteamDecode(reader);");
            var properties = new StringBuilder();
            var regionClassSb = new StringBuilder(classHeader.ToString());
            regionClassSb.AppendLine("        public void " + region + "Decode(BitReader reader)");
            regionClassSb.AppendLine("        {");
            //foreach(var op in cl.OpList)
            cl.OpList.Where(o => !String.IsNullOrEmpty(o.Rename)).ToList().ForEach(o => o.Name = o.Rename);
            var ordered = cl.OpList.OrderBy(o => String.IsNullOrEmpty(o.Rename)).ThenByDescending(o => o.dumpedClass).ThenBy(o => o.Name).ToList();
            //var fieldCount = 0;
            //ordered.Where(o=> String.IsNullOrEmpty(o.Rename)).ToList().ForEach(o => o.Name = "field" + fieldCount++);
            /*foreach (var group in ordered.Where(o => String.IsNullOrEmpty(o.Rename)).GroupBy(o => o.dumpedClass))
            {
                var fieldCount = 0;
                GetReadInfo(group.First().dumpedClass, out String readType, out String readCommand, out String name, out UInt64 size);
                if (group.Count() > 1)
                    group.ToList().ForEach(o => o.Name = name + "_" + fieldCount++);
                else
                    group.First().Name = name;
            }*/

            //foreach (var group in ordered.Where(o => String.IsNullOrEmpty(o.Rename) && !GetReadType(o.dumpedClass).Contains("Byte[]")).GroupBy(o => GetReadType(o.dumpedClass)))
            foreach (var group in ordered.Where(o => String.IsNullOrEmpty(o.Rename)).GroupBy(o => GetReadName(o.dumpedClass)))
            {
                var fieldCount = 0;
                GetReadInfo(group.First().dumpedClass, out String readType, out String readCommand, out String name, out UInt64 size, out bool customName);
                //if (group.First().dumpedClass < 0x20000 || readType.Contains("Byte[]"))
                if (!customName)
                    group.ToList().ForEach(o => o.Name = name + "_" + fieldCount++);
                else
                    group.ToList().ForEach(o => o.Name = name);
            }/*
            var bacount = 0;
            {
                var fieldCount = 0;
                var bytearrays = ordered.Where(o => String.IsNullOrEmpty(o.Rename) && GetReadType(o.dumpedClass).Contains("List<Byte[]"));
                foreach (var ba in bytearrays)
                {
                    GetReadInfo(ba.dumpedClass, out String readType, out String readCommand, out String name, out UInt64 size);
                    ba.Name = name + "_" + fieldCount++;
                }
            }
            bacount = 0;
            {
                var fieldCount = 0;
                var bytearrays = ordered.Where(o => String.IsNullOrEmpty(o.Rename) && GetReadType(o.dumpedClass).Contains("Byte[]"));
                foreach (var ba in bytearrays)
                {
                    GetReadInfo(ba.dumpedClass, out String readType, out String readCommand, out String name, out UInt64 size);
                    ba.Name = name + "_" + fieldCount++;
                }
            }
            /*foreach (var group in ordered.Where(o => String.IsNullOrEmpty(o.Rename)).GroupBy(o => o.Name))
            {
                var fieldCount = 0;
                if (group.Count() > 1)
                    group.ToList().ForEach(o => o.Name = o.Name + "_" + fieldCount++);
            }*/
            if (cl.OpList.Any(o => o.List)) cl.OpList.First().Name = "num";
            for (var i = 0; i < cl.OpList.Count; i++)
            {
                var op = cl.OpList[i];
                GetReadInfo(op.dumpedClass, out String readType, out String readCommand, out String name, out UInt64 size, out bool customName);
                if (op.List)
                    regionClassSb.AppendLine("            " + (op.List ? "    " : "") + op.Name + ".Add(" + readCommand + ");");
                else
                    regionClassSb.AppendLine("            " + (op.List ? "    " : "") + op.Name + " = " + readCommand + ";");
                if (op.If) regionClassSb.AppendLine("            if (" + op.Name + " == 1)");
                if (op.If) regionClassSb.Append("    ");
                if (op.Name == "num") regionClassSb.AppendLine("            for(var i = 0; i < num; i++)");
                if (op.Name == "num") regionClassSb.AppendLine("            {");
            }
            for (var i = 0; i < ordered.Count; i++)
            {
                var op = ordered[i];
                var structoff = "//" + op.structOff;
                structoff = "";
                GetReadInfo(op.dumpedClass, out String readType, out String readCommand, out String name, out UInt64 size, out bool customName);
                if (op.List)
                    properties.AppendLine("        public List<" + readType + "> " + op.Name + " = new List<" + readType + ">();" + structoff);
                else
                    properties.AppendLine("        public " + readType + " " + op.Name + ";" + structoff);
            }
            if (cl.OpList.Any(o => o.List)) regionClassSb.AppendLine("            }");

            baseClassSb.AppendLine("        }");
            baseClassSb.Append(properties.ToString());
            baseClassSb.AppendLine("    }");
            baseClassSb.AppendLine("}");
            regionClassSb.AppendLine("        }");
            regionClassSb.AppendLine("    }");
            regionClassSb.AppendLine("}");
            baseClass = baseClassSb.ToString();
            regionClass = regionClassSb.ToString();
        }
        public static void ParseFunc(Byte[] bytes, IntPtr getPacket, String packetName)
        {
            var dumpClass = new DumpedClass { ParseOffset = getPacket, Name = packetName };
            if (Dumped.ContainsKey((UInt64)getPacket)) return;
            Dumped.Add((UInt64)getPacket, dumpClass);
            var fieldNum = 0;
            var fieldNumPerType = new Dictionary<String, int>();
            var structCounter = 1;
            //Console.WriteLine("opcode : " + opcode.ToString("X") + " : " + opcodeToName[opcode]);
            var readSize = 0u;
            var structOff = 0u;
            //var instructions = disassembler.Disassemble();
            var instructions = disassembler.Disassemble(bytes);
            var bodyParser = new StringBuilder();
            var properties = new StringBuilder();
            var list = false;
            for (var i = 0; i < instructions.Length; i++)
            //foreach (var instruction in instructions)
            {
                var instruction = instructions[i];
                //Console.WriteLine(instruction.Mnemonic + " " + instruction.Operand);
                if (instruction.Mnemonic == "mov" && instruction.Operand.StartsWith("r8d"))
                {
                    if (readSize != 0)
                        Console.WriteLine("mov failed!!!!");
                    if (instruction.Bytes.Length == 6)
                        readSize = BitConverter.ToUInt32(instruction.Bytes, 2);
                }
                if (instruction.Mnemonic == "imul" && instruction.Operand.StartsWith("r8d"))
                {
                    if (readSize != 0)
                        Console.WriteLine("imul failed!!!!");
                    if (instruction.Bytes.Length == 4)
                        readSize = instruction.Bytes[3];
                }
                if (instruction.Mnemonic == "movsx" && instruction.Operand.StartsWith("r8"))
                {
                    if (readSize != 0)
                        Console.WriteLine("movsx failed!!!!");
                    readSize = 1;
                }
                if (instruction.Mnemonic == "shl" && instruction.Operand.StartsWith("r8d"))
                {
                    if (readSize == 0)
                        Console.WriteLine("shl failed!!!!");
                    //if (instruction.Bytes.Length == 4)
                    readSize = (uint)((int)readSize << (int)instruction.Details.Operands[1].Immediate); // need to multiply still
                }
                if (instruction.Mnemonic == "lea" && instruction.Operand.StartsWith("r8d, [rbp"))
                {
                    if (readSize != 0)
                        Console.WriteLine("lea1 failed!!!!");
                    if (instruction.Bytes.Length == 4)
                        readSize = (UInt32)instruction.Details.Displacement;
                }
                if (instruction.Mnemonic == "lea" && instruction.Operand.StartsWith("r8d, [rcx"))
                {
                    if (readSize != 0)
                        Console.WriteLine("lea2 failed!!!!");
                    if (instruction.Operand.Contains("rcx + rcx*2"))
                        readSize = 3;
                    else if (instruction.Operand.Contains("rcx + rcx]"))
                        readSize = 2;
                    else readSize = 1;
                }
                if (instruction.Mnemonic == "lea" && (instruction.Operand.StartsWith("rcx") || instruction.Operand.StartsWith("rdx") || instruction.Operand.StartsWith("r9")) && !instruction.Operand.Contains("rsp"))
                {
                    if (structOff != 0) Console.WriteLine("lea failed!!!!");
                    structOff = (uint)instruction.Details.Displacement;
                }
                if (instruction.Mnemonic == "add" && instruction.Operand.StartsWith("rcx"))
                {
                    if (structOff != 0) Console.WriteLine("mov struct off failed!!!!");
                    structOff = (uint)instruction.Details.Displacement;
                }
                if (instruction.Mnemonic + " " + instruction.Operand == "add r8d, r8d")
                {
                    Console.WriteLine("werid struct");
                    readSize = 2;
                }
                if ((instruction.Mnemonic == "jmp" && instruction.Operand.StartsWith("qword"))
                    || (instruction.Mnemonic == "call" && instruction.Operand.StartsWith("qword")))
                {
                    if (readSize == 0)
                    {
                        list = true;
                        readSize += 1;
                        Console.Write("");
                    }
                    dumpClass.OpList.Add(new ReadOp { dumpedClass = readSize, Name = "field" + fieldNum++, List = list, structOff = structOff });
                    readSize = 0;
                    structOff = 0;
                }
                else if (instruction.Mnemonic == "jmp" && i == 1)
                {
                    var callAddr = (Int64)UInt64.Parse(instruction.Operand.Substring(2), System.Globalization.NumberStyles.HexNumber);
                    var getSubstruct = (IntPtr)((int)getPacket + callAddr - 0x1000);

                    if (!Dumped.ContainsKey((UInt64)getSubstruct))
                    {
                        var pktParseBytes = sigScan.m_vDumpedRegion.Skip((int)getSubstruct).Take(0x2000).ToArray();
                        ParseFunc(pktParseBytes, (IntPtr)getSubstruct, packetName + "_" + getSubstruct.ToString("X"));// "Struct" + Dumped.Count); // "Sub" + packetName);//
                        //ParseFunc(pktParseBytes, (IntPtr)getSubstruct, packetName + "_genStruct");// "Struct" + Dumped.Count); // "Sub" + packetName);//
                    }

                    dumpClass.OpList.Add(new ReadOp { dumpedClass = (UInt64)getSubstruct, Name = "field" + fieldNum++, List = list, structOff = structOff });
                    structOff = 0;
                }

                else if (instruction.Mnemonic == "call")
                {
                    var callAddr = (Int64)UInt64.Parse(instruction.Operand.Substring(2), System.Globalization.NumberStyles.HexNumber);
                    var getSubstruct = (IntPtr)((int)getPacket + callAddr - 0x1000);

                    if (!Dumped.ContainsKey((UInt64)getSubstruct))
                    {
                        var pktParseBytes = sigScan.m_vDumpedRegion.Skip((int)getSubstruct).Take(0x2000).ToArray();
                        //ParseFunc(pktParseBytes, (IntPtr)getSubstruct, packetName + "_" + structCounter++);// "Struct" + Dumped.Count); // "Sub" + packetName);//
                        ParseFunc(pktParseBytes, (IntPtr)getSubstruct, packetName + "_" + getSubstruct.ToString("X"));// "Struct" + Dumped.Count); // "Sub" + packetName);//
                        //ParseFunc(pktParseBytes, (IntPtr)getSubstruct, packetName + "_genStruct");// "Struct" + Dumped.Count); // "Sub" + packetName);//
                    }
                    dumpClass.OpList.Add(new ReadOp { dumpedClass = (UInt64)getSubstruct, Name = "field" + fieldNum++, List = list, structOff = structOff });
                    structOff = 0;
                }

                if (instruction.Mnemonic == "cmp" && instruction.Details.Operands.Length == 2 &&
                    ((instruction.Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Immediate && instruction.Details.Operands[1].Immediate > 1)
                    || (instruction.Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Immediate && instruction.Details.Operands[1].Immediate > 1)))
                {
                    fieldNum--;
                    list = true;
                }
                else if (instruction.Mnemonic == "cmp" && instruction.Details.Operands.Length == 2 && instruction.Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Immediate && instruction.Details.Operands[1].Immediate == 1)
                {
                    fieldNum--;
                    dumpClass.OpList.Last().If = true;
                }
                else if (instruction.Mnemonic == "cmp")
                {
                    if (list == false)
                    {
                        fieldNum--;
                        list = true;
                    }
                }
                if (instruction.Mnemonic == "ret")
                    break;
                if (instruction.Mnemonic == "int3")
                    break;
            }
            if (dumpClass.OpList.Count == 2 && dumpClass.OpList[0].dumpedClass == 2 && dumpClass.OpList.Any(o => o.List == true))
                dumpClass.OnlyReadsList = true;
            //if (dumpClass.Name.Contains("genStruct")) dumpClass.Name = dumpClass.Name.Replace("genStruct", dumpClass.OpList.Max(a=>a.structOff).ToString("X"));
        }
        static Process process;
        static SigScan sigScan;
        public static Dictionary<String, Dictionary<UInt64, String>> fieldRenames = new Dictionary<string, Dictionary<ulong, string>>();
        public class PartialByte
        {
            public uint offset;
            public uint size;
            public string name;
        }
        static List<ReadOp> SplitByteArray(List<PartialByte> named, uint byteArrayOffset, uint byteArraySize)
        {
            var readOps = new List<ReadOp>();
            var ordered = named.OrderBy(n => n.offset).ToList();
            var currentOffset = byteArrayOffset;
            while (true)
            {
                //if (ordered[0].offset > currentOffset)
                {
                    readOps.Add(new ReadOp { structOff = currentOffset - byteArrayOffset, dumpedClass = 0x1000 + ordered[0].offset - currentOffset, Name = "field" + readOps.Count });
                    currentOffset = ordered[0].offset;
                }
                //else
                {
                    readOps.Add(new ReadOp { structOff = ordered[0].offset, dumpedClass = ordered[0].size, Rename = ordered[0].name });
                    currentOffset += ordered[0].size;
                    if (ordered.Count == 1)
                    {
                        // if (currentOffset < byteArraySize)
                        readOps.Add(new ReadOp { structOff = ordered[0].offset + ordered[0].size, dumpedClass = 0x1000 + byteArrayOffset + byteArraySize - currentOffset, Name = "field" + readOps.Count });
                        break;
                    }
                    ordered = ordered.Skip(1).ToList();
                }
            }
            return readOps;
        }
        public static String Dump(String savePath, String gameDir, Region region, out String blowfish, out String aes)
        {
            var nameToOpcode = new Dictionary<String, UInt32>();
            var nameToSize = new Dictionary<String, UInt32>();
            var nameToHandler = new Dictionary<String, IntPtr>();
            var nameToGetOpcode = new Dictionary<String, UInt64>();
            aes = "";
            blowfish = "";
            disassembler.EnableInstructionDetails = true;
            disassembler.DisassembleSyntax = DisassembleSyntax.Intel;
            var sb = new StringBuilder();
            sb.AppendLine("using System;");
            sb.AppendLine("namespace LostArkLogger");
            sb.AppendLine("{");
            sb.AppendLine("    public enum OpCodes_" + region + " : UInt16");
            sb.AppendLine("    {");
            //var orig = File.ReadAllBytes(@"C:\Users\Downloads\lostark\lostark.exe");
            //var process = Process.Start(@"C:\Program Files (x86)\Steam\steamapps\common\Lost Ark\Binaries\Win64\LOSTARK.exe", "-launch_from_dev_launcher -AuthKey=");
            if (region == Region.Korea) process = Process.Start(gameDir + @"Binaries\Win64\LOSTARKkr.exe", "-launch_from_dev_launcher -AuthKey=");
            else process = Process.Start(gameDir + @"Binaries\Win64\LOSTARK.exe", "-launch_from_dev_launcher -AuthKey=");
            //var process = Process.GetProcessesByName("Launch_Game")[0];
            hProcess = OpenProcess(0xFFFF, false, process.Id);
            var nops = Enumerable.Range(0, 0x50).Select(s => (byte)0x90).ToArray();

            var orig = new Byte[4];
            ReadProcessMemory(hProcess, (IntPtr)(process.MainModule.BaseAddress + 0x10000), orig, 4, out _);
            while (true) // wait for some code exec
            {
                var negOne = new Byte[4];
                ReadProcessMemory(hProcess, (IntPtr)(process.MainModule.BaseAddress + 0x10000), negOne, 4, out _);
                if (!negOne.SequenceEqual(orig)) break;
                Thread.Sleep(50);
            }
            Thread.Sleep(1500);
            NtSuspendProcess(hProcess);
            sigScan = new SigScan(process, process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            Func<IntPtr, IntPtr> GetFuncStart = new Func<IntPtr, IntPtr>((IntPtr a) => {
                for (var i = 0; i < 0x2000; i++)
                {
                    //if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0xcc && sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i - 1] == 0xcc)
                    if (((sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i - 1] == 0xcc && (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i - 2] == 0xcc || sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i - 2] == 0xc3)) || sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i - 1] == 0xc3) && ((UInt64)a - (UInt64)sigScan.Address - (UInt64)i) % 0x10 == 0
                    && sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] != 0xc2 && sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] != 0 && sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] != 0xff)
                    {
                        if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0xf3) continue;
                        if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0xfe) continue;
                        if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0x4d) continue;
                        if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0x17) continue;
                        if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0x51) continue;
                        if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0x48 && sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i + 1] == 0x83) continue;
                        if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0x48 && sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i + 1] == 0x81) continue;
                        if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0x48 && sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i + 1] == 0x8D) continue;
                        if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0x48 && sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i + 1] == 0xC1) continue;
                        if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0x4) continue;
                        if (sigScan.m_vDumpedRegion[(int)((UInt64)a - (UInt64)sigScan.Address) - i] == 0x48)
                        {
                            Console.WriteLine("found valid func!");
                        }
                        return (IntPtr)((UInt64)a - (UInt64)i);
                    }
                }
                return IntPtr.Zero;
            });
            Func<String, IntPtr> GetFuncFromString = new Func<String, IntPtr>((String a) =>
            {
                var stringAddr = sigScan.FindPatterns(BitConverter.ToString(Encoding.Unicode.GetBytes(a)).Replace("-", " "), process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize)[0];
                for (var i = 0; i < sigScan.Size; i++)
                {
                    if ((sigScan.m_vDumpedRegion[i] == 0x48 || sigScan.m_vDumpedRegion[i] == 0x4c) && sigScan.m_vDumpedRegion[i + 1] == 0x8d)
                    {
                        var jmpTo = BitConverter.ToInt32(sigScan.m_vDumpedRegion, i + 3);
                        var addr = sigScan.Address + i + jmpTo + 7;
                        if (addr == stringAddr)
                        {
                            return GetFuncStart((IntPtr)((UInt64)i + (UInt64)sigScan.Address));
                        }
                    }
                }
                return IntPtr.Zero;
            });
            Func<IntPtr, IntPtr> GetXrefToFunc = new Func<IntPtr, IntPtr>((IntPtr a) =>
            {
                for (var i = 0; i < sigScan.Size; i++)
                {
                    if (sigScan.m_vDumpedRegion[i] == 0xe8)
                    {
                        var jmpTo = BitConverter.ToInt32(sigScan.m_vDumpedRegion, i + 1);
                        var addr = sigScan.Address + i + jmpTo + 5;
                        if (addr == a)
                        {
                            return (IntPtr)((UInt64)i + (UInt64)sigScan.Address);
                        }
                    }
                }
                return IntPtr.Zero;
            });
            Func<IntPtr, List<IntPtr>> GetXrefsToFunc = new Func<IntPtr, List<IntPtr>>((IntPtr a) =>
            {
                var xrefs = new List<IntPtr>();
                for (var i = 0; i < sigScan.Size; i++)
                {
                    if (sigScan.m_vDumpedRegion[i] == 0xe8)
                    {
                        var jmpTo = BitConverter.ToInt32(sigScan.m_vDumpedRegion, i + 1);
                        var addr = sigScan.Address + i + jmpTo + 5;
                        if (addr == a)
                        {
                            xrefs.Add((IntPtr)((UInt64)i + (UInt64)sigScan.Address));
                            //return (IntPtr)((UInt64)i + (UInt64)sigScan.Address);
                        }
                    }
                }
                //return IntPtr.Zero;
                return xrefs;
            });
            Func<String, Int32, IntPtr> GetFuncFromStringOffset = new Func<String, Int32, IntPtr>((String a, Int32 offset) =>
            {
                var stringAddrs = sigScan.FindPatterns(BitConverter.ToString(Encoding.Unicode.GetBytes(a)).Replace("-", " "), process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                if (stringAddrs.Count() == 0) return IntPtr.Zero;
                var stringAddr = stringAddrs.Count() == 1 ? stringAddrs[0] : stringAddrs.First(a => (UInt64)a % 0x10 == 0);
                //stringAddr = (IntPtr)(stringAddr+(int)offset);
                stringAddr += offset;
                if ((UInt64)stringAddr % 0x10 != 0) stringAddr += 8;
                for (var i = 0; i < sigScan.Size; i++)
                {
                    if (sigScan.m_vDumpedRegion[i] == 0x48 && sigScan.m_vDumpedRegion[i + 1] == 0x8d)
                    {
                        var jmpTo = BitConverter.ToInt32(sigScan.m_vDumpedRegion, i + 3);
                        var addr = sigScan.Address + i + jmpTo + 7;
                        if (addr == stringAddr)
                        {
                            return GetFuncStart((IntPtr)((UInt64)i + (UInt64)sigScan.Address));
                        }
                    }
                }
                return IntPtr.Zero;
            });
            Func<int, int> ParsePreviousCommand = new Func<int, int>((int a) =>
            {
                //var off = (UInt16)a - (UInt16)sigScan.Address;
                var off = a;
                if (sigScan.m_vDumpedRegion[off - 3] == 0x49 && sigScan.m_vDumpedRegion[off - 2] == 0x8b && sigScan.m_vDumpedRegion[off - 1] == 0xd0)
                {
                    return 3;
                }
                if (sigScan.m_vDumpedRegion[off - 5] == 0xe9 && sigScan.m_vDumpedRegion[off - 1] == 0xff)
                {
                    return 5;
                }
                if (sigScan.m_vDumpedRegion[off - 6] == 0x0f && sigScan.m_vDumpedRegion[off - 5] == 0x85 && sigScan.m_vDumpedRegion[off - 1] == 0)
                {
                    return 6;
                }
                if (sigScan.m_vDumpedRegion[off - 6] == 0x81 && sigScan.m_vDumpedRegion[off - 5] == 0xfa && sigScan.m_vDumpedRegion[off - 1] == 0)
                {
                    return 6;
                }
                if (sigScan.m_vDumpedRegion[off - 2] == 0x7f)
                {
                    return 2;
                }
                if (sigScan.m_vDumpedRegion[off - 2] == 0x74)
                {
                    return 2;
                }
                return 0;
            });
            Func<IntPtr, UInt16> GetOpcodeFromHandler = new Func<IntPtr, ushort>((IntPtr a) =>
            {
                var toIda = (UInt64)a - (UInt64)process.MainModule.BaseAddress;
                for (var i = 0; i < sigScan.Size; i++)
                {
                    if (sigScan.m_vDumpedRegion[i] == 0xe9)
                    {
                        var jmpTo = BitConverter.ToInt32(sigScan.m_vDumpedRegion, i + 1);
                        var addr = sigScan.Address + i + jmpTo + 5;
                        if (addr == a)
                        {
                            for (var j = i % 0x10; j < 0x1000; j += 0x10)
                            {
                                if (((sigScan.m_vDumpedRegion[i - j - 2] == 0xc3 || sigScan.m_vDumpedRegion[i - j - 2] == 0xcc) && sigScan.m_vDumpedRegion[i - j - 1] == 0xcc) || sigScan.m_vDumpedRegion[i - j - 1] == 0xc3)
                                {
                                    var jmpTable = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip(i - j).Take(0x1000).ToArray());//.Reverse().SkipWhile(k => k.Address == i - j);
                                    var jmpToHandler = jmpTable.First(k => k.Address == j + 0x1000);
                                    UInt64 curValue = (UInt64)0;
                                    for (var jmps = 0; jmps < jmpTable.Length; jmps++)
                                    {
                                        if (jmpTable[jmps].Mnemonic == "cmp" && jmpTable[jmps].Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Immediate)
                                        {
                                            curValue = (UInt64)jmpTable[jmps].Details.Operands[1].Immediate;
                                            for (var jmps2 = jmps + 1; jmps2 < jmpTable.Length; jmps2++)
                                            {
                                                if (jmpTable[jmps2].Mnemonic == "jmp" || jmpTable[jmps2].Mnemonic == "je")
                                                {
                                                    if (jmpTable[jmps2].Mnemonic == "jmp")
                                                    {
                                                        if (jmpTable[jmps2].Address == j + 0x1000) return (UInt16)curValue;
                                                    }
                                                    else if (jmpTable[jmps2].Mnemonic == "je")
                                                    {
                                                        var index = jmpTable.TakeWhile(k => k.Address != jmpTable[jmps2].Details.Operands[0].Immediate).Count();
                                                        for (var jmps3 = index; jmps3 < jmpTable.Length; jmps3++)
                                                        {
                                                            if (jmpTable[jmps3].Mnemonic == "jmp")
                                                            {
                                                                if (jmpTable[jmps3].Address == j + 0x1000) return (UInt16)curValue;
                                                                //Console.WriteLine("found it " + jmps3);
                                                                break;
                                                            }
                                                        }

                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    var reversed = jmpTable.TakeWhile(k => k.Address != j + 0x1000).Reverse().ToList();
                                    var jmpAddr = reversed[0].Address;
                                    var jmpLabel = jmpTable.FirstOrDefault(k => k.Mnemonic == "je" && k.Details.Operands[0].Immediate == jmpAddr);
                                    if (jmpLabel == null)
                                    {
                                        jmpAddr = reversed[1].Address;
                                        jmpLabel = jmpTable.FirstOrDefault(k => k.Mnemonic == "je" && k.Details.Operands[0].Immediate == jmpAddr);
                                    }
                                    if (jmpLabel == null && reversed[2].Details.Operands.Length >= 2 && reversed[2].Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Immediate)
                                    {
                                        return (UInt16)reversed[2].Details.Operands[1].Immediate;
                                    }
                                    if (jmpLabel == null)
                                    {
                                        var qq = reversed.FirstOrDefault(o => o.Mnemonic == "cmp");
                                        if (qq != null)
                                            return (UInt16)reversed.First(o => o.Mnemonic == "cmp").Details.Operands[1].Immediate;
                                    }
                                    if (jmpLabel == null) continue;
                                    var beforeCmp = jmpTable.TakeWhile(k => k.Address != jmpLabel.Address).Reverse().TakeWhile(k => k.Mnemonic != "cmp");
                                    var subVal = beforeCmp.Where(k => k.Mnemonic == "sub").Sum(a => a.Details.Operands[1].Immediate);
                                    if (subVal > 0x100) return (UInt16)subVal;
                                    var cmpBranch = jmpTable.TakeWhile(k => k.Address != jmpLabel.Address).Reverse().First(k => k.Mnemonic == "cmp");
                                    var opcode = cmpBranch.Details.Operands[1].Immediate;
                                    return (UInt16)opcode;
                                }
                            }
                            //break;
                        }
                        if (addr == a)
                        {
                            var byteDist = ParsePreviousCommand(i);
                            if (byteDist == 3)
                            {
                                var jmpDest = i - byteDist;
                                var asm = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip(i - byteDist).Take(2).ToArray());
                                var prev = i - byteDist;
                                while (true)
                                {
                                    var offset = ParsePreviousCommand(prev);
                                    prev = prev - offset;
                                    asm = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip(prev).Take(offset).ToArray());
                                    if (offset == 2)
                                    {
                                        if (prev + sigScan.m_vDumpedRegion[prev + 1] + 2 == jmpDest)
                                        {
                                            offset = ParsePreviousCommand(prev);
                                            prev = prev - offset;
                                            asm = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip(prev).Take(offset).ToArray());
                                            return (UInt16)asm[0].Details.Operands[1].Immediate;
                                        }
                                    }
                                    if (offset == 0) break;
                                }
                            }
                            break;
                        }
                    }
                }
                return 0;
            });
            Func<IntPtr, UInt16> GetOpcodeFromHandlerBest = new Func<IntPtr, ushort>((IntPtr a) =>
            {
                for (var i = 0; i < sigScan.Size; i++)
                {
                    if (sigScan.m_vDumpedRegion[i] == 0x48 && sigScan.m_vDumpedRegion[i + 1] == 0x8d && sigScan.m_vDumpedRegion[i + 2] == 0x0d)
                    {
                        var lea = BitConverter.ToInt32(sigScan.m_vDumpedRegion, i + 3);
                        var addr = sigScan.Address + i + lea + 7;
                        if (addr == a)
                        {
                            var leaRef = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip(i).Take(0x200).ToArray());
                            var opcode = leaRef.First(j => j.Mnemonic == "mov" && j.Operand.StartsWith("edx")).Details.Operands[1].Immediate;
                            return (UInt16)opcode;
                        }
                    }
                }
                return 0;
            });
            Func<IntPtr, IntPtr> GetVtableFromCtor = new Func<IntPtr, IntPtr>((IntPtr a) =>
            {
                var ctor = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)a - (Int64)sigScan.Address)).Take(0x1000).ToArray());
                for (var i = 0; i < ctor.Length; i++)
                {
                    if (ctor[i].Mnemonic == "lea" && ctor[i].Operand.StartsWith("rax"))
                    {
                        var lea = BitConverter.ToInt32(sigScan.m_vDumpedRegion, (int)((Int64)a - (Int64)sigScan.Address + ctor[i].Address - 0x1000 + 3));
                        var vTableStart = sigScan.Address + (int)((Int64)a - (Int64)sigScan.Address + ctor[i].Address - 0x1000 + 7) + lea;
                        return vTableStart;
                    }
                }
                return IntPtr.Zero;
            });
            Func<IntPtr, String> GetAsmForFunc = new Func<IntPtr, String>((IntPtr a) =>
            {
                var sb = new StringBuilder();
                var func = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)a - (Int64)sigScan.Address)).Take(0x1000).ToArray());
                for (var i = 0; i < func.Length; i++)
                {
                    var aa = func[i];
                    var line = "";
                    if (aa.Mnemonic.StartsWith("nop") && aa.Address == 0x1244)
                        Console.WriteLine("adfba");
                    if (func[i].Mnemonic.StartsWith("j"))
                    {
                        var fs = aa.ToString();
                        line = func[i].Mnemonic + " 0x" + (0x400000 + func[i].Details.Operands[0].Immediate).ToString("X");// + " // " + BitConverter.ToString(func[i].Bytes));
                    }
                    else if (func[i].Mnemonic.StartsWith("nop"))
                    {
                        for (var j = 0; j < func[i].Bytes.Length; j++)
                            line = "nop";//// + " : " + BitConverter.ToString(func[i].Bytes));
                    }
                    else
                        line = func[i].Mnemonic + " " + func[i].Operand.Replace("ptr ", "").Replace("xmmword ", "");// + " // " + BitConverter.ToString(func[i].Bytes));
                    // rep stosb byte [rdi], al  // remove this
                    if (line.Contains("gs:")) line = line.Replace("[", "").Replace("]", "").Replace("gs", "ptr gs");
                    if (line.Contains("movabs")) line = line.Replace("movabs", "mov");
                    sb.AppendLine(line);
                    if (func[i].Mnemonic.StartsWith("ret")) break;
                }
                return sb.ToString();
            });
            Func<IntPtr, String> GetPsuedocode = new Func<IntPtr, String>((IntPtr a) =>
            {
                var asm = GetAsmForFunc(a);
                asm = "format pe64 console\nuse64\nentry start\nsection '.text' code readable executable\nstart:\n" + asm;
                File.WriteAllText("temp.asm", asm);
                var asmGen = Process.Start(FasmPath + "FASM.EXE", "temp.asm temp.exe");
                while (!asmGen.HasExited) Thread.Sleep(15);
                var psuedoGen = Process.Start(IdaPath + "idat64.exe", "-Ohexrays:-new:-nosave:temp:start -A temp.exe");
                while (!psuedoGen.HasExited) Thread.Sleep(150);
                var psuedoCode = File.ReadAllText("temp.c");
                File.Delete("temp.c");
                File.Delete("temp.exe");
                File.Delete("temp.exe.i64");
                File.Delete("temp.asm");
                return psuedoCode;
            });
            Func<IntPtr, UInt16> GetOpcodeFromVtable = new Func<IntPtr, UInt16>((IntPtr a) =>
            {
                var addr = (int)(BitConverter.ToInt64(sigScan.m_vDumpedRegion, (int)((Int64)a - (Int64)sigScan.Address) + 8) - (Int64)sigScan.Address);
                var ops = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip(addr).Take(0x100).ToArray());
                var moveax = ops.First(o => o.Mnemonic == "mov");
                return (UInt16)moveax.Details.Operands[1].Immediate;
            });
            var versionCheckSize = sigScan.FindPatterns("48 83 C8 FF 66 83 7C 41 ? ? 48 8D 40 01 75 F4 8B 89 ? ? ? ? 83 C1 16 8D 04 41 C3", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            var versionCheckSizeRef = sigScan.FindPatterns(BitConverter.ToString(BitConverter.GetBytes((UInt64)versionCheckSize[0])).Replace("-", " "), process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            var pktTable = (UInt64)versionCheckSizeRef[0] - (UInt64)sigScan.Address - 16;

            var statusEffectParse = GetFuncFromStringOffset("AddBuffOverCount ID", -0xF0 + 0x50);

            var possibleDmg = sigScan.FindPatterns("E8 ? ? ? ?", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            //var possibleDmg = sigScan.FindPatterns("48 ? ? E8 ? ? ? ? FF ? 48", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            var skillMove = GetFuncStart(GetXrefToFunc(GetFuncFromStringOffset("sys.squarehole.announce_new_registration", 0x60 + 5 * 0x50)));
            var skillMove2 = sigScan.FindPatterns("48 8B C4 55 41 54 41 55 41 56 41 57 48 8D 68 B1 48 81 EC ? ? ? ? 48 C7 45 ? ? ? ? ? 48 89 58 08 48 89 70 10 48 89 78 18 45 0F", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            var abSkillMove = sigScan.FindPatterns("40 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 48 C7 44 24 ? ? ? ? ? 48 89 9C 24 ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 45 0F", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            //var abSkillMove = sigScan.FindPatterns("40 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? B8 ? ? ? ? E8 ? ? ? ? 48 2B E0 48 C7 44 24 ? ? ? ? ? 48 89 9C 24 ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 45 0F B6 E1 45 8B E8 4C 8B", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            foreach (var d in possibleDmg)
            {
                //var jmpTo = BitConverter.ToInt32(sigScan.m_vDumpedRegion, (int)((UInt64)d - (UInt64)sigScan.Address) + 4);
                var jmpTo = BitConverter.ToInt32(sigScan.m_vDumpedRegion, (int)((UInt64)d - (UInt64)sigScan.Address) + 1);
                var addr = IntPtr.Zero + (int)((UInt64)d - (UInt64)sigScan.Address) + jmpTo + 5;
                if (addr == (IntPtr)((UInt64)skillMove - (UInt64)sigScan.Address))
                    nameToHandler["PKTSkillDamageNotify"] = GetFuncStart(d);
                if (addr == (IntPtr)((UInt64)abSkillMove[0] - (UInt64)sigScan.Address))
                    nameToHandler["PKTSkillDamageAbnormalMoveNotify"] = GetFuncStart(d);
            }
            nameToHandler["PKTCounterAttackNotify"] = GetFuncFromStringOffset("TopHudSecureURL", 0 - 0x48 - 0x50 * 5);
            nameToHandler["PKTInitEnv"] = GetFuncFromStringOffset("Logout\0", 0x10);
            /*var proj = GetFuncFromStringOffset("ProjectilePos too near", -0x50);
            if (proj == IntPtr.Zero) nameToHandler["PKTNewProjectile"] = GetFuncStart(sigScan.FindPatterns("40 57 48 83 EC 30 48 C7 44 24 ? ? ? ? ? 48 89 5C 24 ? 48 89 74 24 ? 48 8B DA 48 83 62 ? fe", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize)[0]);
            else nameToHandler["PKTNewProjectile"] = GetFuncStart(GetXrefToFunc(proj));*/
            var proj = GetFuncFromStringOffset("ProjectilePos too near", -0x50);
            if (proj == IntPtr.Zero) nameToHandler["PKTNewProjectile"] = nameToHandler["PKTNewProjectile"] = GetFuncStart(GetXrefsToFunc(GetFuncFromStringOffset("ProjectileManager", 0x30 + 3 * 0x50))[1]);
            else nameToHandler["PKTNewProjectile"] = GetFuncStart(GetXrefToFunc(proj));

            //nameToHandler["PKTStatusEffectAddNotify"] = GetFuncStart(GetXrefToFunc(GetFuncFromStringOffset("AddBuffOverCount ID", -0xF0)));
            nameToHandler["PKTStatusEffectAddNotify"] = GetFuncStart(GetXrefToFunc(statusEffectParse));
            nameToHandler["PKTAuthTokenResult"] = GetFuncStart(sigScan.FindPatterns("6B C2 64 33 DB", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize)[0]);
            nameToHandler["PKTSkillStartNotify"] = GetFuncFromString("SkillSyncCheck,"); //  40 57 48 83 EC 60 48 C7 44 24 ? ? ? ? ? 48 89 5C 24 ? 48 8B FA 48 8B D9 48 85 D2 75 07 33 C0 E9
            nameToHandler["PKTSkillStageNotify"] = GetFuncStart(sigScan.FindPatterns("88 8D ? ? ? ? 0F B7 88 ? ? ? ? 66 89 8D ? ? ? ? 0F B6 80 ? ? ? ? 88 85 ? ? ? ? 0F B7 87 ? ? ? ? 66 89 85 ? ? ? ? 0F B6 87 ? ? ? ? 88 85 ? ? ? ? 0F B7 87", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize)[0]); //  40 57 48 83 EC 60 48 C7 44 24 ? ? ? ? ? 48 89 5C 24 ? 48 8B FA 48 8B D9 48 85 D2 75 07 33 C0 E9
            nameToHandler["PKTInitPC"] = GetFuncFromStringOffset("sys.pcselect.error_testserver_enter_condition", 0x100);
            nameToHandler["PKTStatusEffectRemoveNotify"] = GetFuncStart(GetXrefToFunc(GetFuncFromStringOffset("AddBuffOverCount ID", 0x80 + 2 * 0x50)));

            foreach (var handler in nameToHandler) nameToOpcode[handler.Key] = GetOpcodeFromHandlerBest(handler.Value);

            nameToHandler["PKTNewNpc"] = GetFuncFromString("RECV > PKTNewNpc\0");
            nameToHandler["PKTNewNpcSummon"] = GetFuncFromString("RECV > PKTNewNpcSummon");
            //nameToHandler["PKTStatChangeOriginNotify"] = GetFuncFromStringOffset("LocalPlayer is not die but HP Change to 0", 0x60);
            //   nameToHandler["PKTStatChangeOriginNotify"] = GetFuncFromStringOffset("LocalPlayer is not die but HP Change to 0", 0xB0 + 0x50);
            //nameToHandler["PKTNewPC2"] = GetFuncStart(sigScan.FindPatterns("40 56 57 41 56 48 83 EC 50 48 C7 44 24 ? ? ? ? ? 48 89 5C 24 ? 48 89 AC 24 ? ? ? ? 48 8B DA 4C 8B F1 48 8B CA E8", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize)[0]);
            //nameToHandler["PKTDeathNotify"] = GetFuncStart(sigScan.FindPatterns("48 8B 46 ? 48 3B 46 ? 74 05 48 85 C0 75 32 F3 0F 10 15 ? ? ? ? F3 0F 10 45 ? F3 0F 59 C2 F3 0F 11 45", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize)[0]);
            nameToHandler["PKTNewPC"] = GetFuncStart(GetXrefToFunc(GetFuncFromStringOffset("RECV > PKTNewNpc\0", -9 * 0x50)));
            nameToHandler["PKTDeathNotify"] = GetFuncStart(GetXrefToFunc(GetFuncFromStringOffset("sys.common.localplayer_instant_revive", -5 * 0x50)));
            nameToHandler["PKTRemoveObject"] = GetFuncFromString("Inter,");
            //nameToHandler["PKTRaidResult"] = GetFuncStart(sigScan.FindPatterns("48 85 D2 75 07 33 C0 E9", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize)[0]);
            nameToHandler["PKTRaidResult"] = GetFuncFromStringOffset("sys.raid.result_failure_braveheart", -0x50);
            nameToHandler["PKTRaidBossKillNotify"] = GetFuncFromStringOffset("Sys.raid.abyss_vote_passed_massage", -6 * 0x50);
            nameToHandler["PKTTriggerBossBattleStatus"] = GetFuncFromStringOffset("Sys.raid.abyss_vote_passed_massage", -5 * 0x50);
            nameToHandler["PKTTriggerStartNotify"] = GetFuncFromStringOffset("(%lld)", -7 * 0x50);
            var ttdsbf = GetFuncFromStringOffset("sys.party.leave_has_pkshield_1", 0x40 + 2 * 0x50);
            var pp = GetXrefToFunc(GetFuncFromStringOffset("sys.party.leave_has_pkshield_1", 0x40 + 2 * 0x50));
            nameToHandler["PKTPartyStatusEffectAddNotify"] = GetFuncStart(GetXrefToFunc(GetFuncFromStringOffset("sys.party.leave_has_pkshield_1", 0x40 + 2 * 0x50)));
            nameToHandler["PKTPartyStatusEffectRemoveNotify"] = GetFuncStart(GetXrefToFunc(GetFuncFromStringOffset("sys.party.leave_has_pkshield_1", 0x40 + 6 * 0x50)));
            foreach (var handler in nameToHandler) if (!nameToOpcode.ContainsKey(handler.Key)) nameToOpcode[handler.Key] = GetOpcodeFromHandler(handler.Value);
            foreach (var op in nameToOpcode)
            {
                if (op.Value == 0)
                    Console.WriteLine("failed : " + op.Key);
            }
            //nameToHandler["PKTNewNpcSummon"] = GetFuncFromString("RECV > PKTNewNpcSummon");
            //nameToOpcode["PKTNewNpcSummon"] = 0x22BE;

            var nto = nameToOpcode.OrderBy(b => b.Key);
            foreach (var ntokv in nto) sb.AppendLine("        " + ntokv.Key + " = 0x" + ntokv.Value.ToString("X") + ",");

            var pktHandlerInit2 = sigScan.FindPatterns("75 15 48 8D 54 24 ? 48 8D 4D 90 E8 ? ? ? ? 90 41 8D 5E 01 EB 32 48 C7 44 24", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            var pktHandlerInit = sigScan.FindPatterns("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8B F9 48 8D 0D ? ? ? ? 49 8B F0 8B DA E8", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            var readPackedInt = sigScan.FindPatterns("48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 83 EC 20 48 8B 02 4C 8B F2 48 8D 51 08 48 8B D9 41 B8 ? ? ? ? 49 8B CE FF 50 18 44 0F B6 43", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            var readFlags = sigScan.FindPatterns("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B 02 48 8B FA 48 8D 51 1F 48 8B E9 41 B8", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            var readString = sigScan.FindPatterns("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 33 ED 48 8B DA 48 8B F9 66 89 29 48 8B 02 44 8D 45 02 48 8D 54 24 ? 48 8B CB 66 89 6C 24 ? FF 50 18 8B F0 0F B7 44 24 ? 66 83 F8 14 77 21 4C", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            var readSimpleInt = sigScan.FindPatterns("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B 02 48 8B F2 48 8B D9 48 8B D1 41 B8 ? ? ? ? 48 8B CE FF 50 18 44 8B 0B 45 8B C1 8B F8 41 81 E0 ? ? ? ? 41 81 F8 1F 08", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            var readSomePackedValues = sigScan.FindPatterns("48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8B 02 48 8B FA 48 8D 51 17 48 8B E9 41 B8", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            Dumped.Add((UInt64)((Int64)readString[0] - (Int64)sigScan.Address), new DumpedClass { Name = "String" });
            Dumped.Add((UInt64)((Int64)readPackedInt[0] - (Int64)sigScan.Address), new DumpedClass { Name = "PackedInt" });
            Dumped.Add((UInt64)((Int64)readFlags[0] - (Int64)sigScan.Address), new DumpedClass { Name = "Flag" });
            Dumped.Add((UInt64)((Int64)readSimpleInt[0] - (Int64)sigScan.Address), new DumpedClass { Name = "SimpleInt" });
            foreach (var p in readSomePackedValues)
            {
                Dumped.Add((UInt64)((Int64)p - (Int64)sigScan.Address), new DumpedClass { Name = "PackedValues" });
            }

            var pktVtable0 = BitConverter.ToUInt64(sigScan.m_vDumpedRegion, (int)pktTable);
            //foreach (var pkt in dumpStructs)
            foreach (var pktkv in nameToOpcode)
            {
                if (pktkv.Key == "PKTAuthTokenResult") continue;
                if (pktkv.Key == "PKTRaidResult") continue;
                if (pktkv.Key == "PKTRaidBossKillNotify") continue;
                if (pktkv.Key == "PKTInitEnv")
                {
                }
                if (pktkv.Key == "PKTTriggerBossBattleStatus") continue;
                var possGetOpcodes = sigScan.FindPatterns("B8 " + BitConverter.ToString(BitConverter.GetBytes((UInt32)pktkv.Value)).Replace("-", " ") + " C3 CC CC", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                if (possGetOpcodes.Count() == 0)
                    Console.WriteLine("couldn't find!!");
                foreach (var getOpcodeRef in possGetOpcodes)
                {
                    var pktVtable = sigScan.FindPatterns((BitConverter.ToString(BitConverter.GetBytes(pktVtable0)) + "-" + BitConverter.ToString(BitConverter.GetBytes((UInt64)getOpcodeRef))).Replace("-", " "), process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);

                    var pktParse = BitConverter.ToUInt64(sigScan.m_vDumpedRegion, (int)((Int64)pktVtable[0] - (Int64)sigScan.Address + 24));
                    var pktParseBytes = sigScan.m_vDumpedRegion.Skip((int)((Int64)pktParse - (Int64)sigScan.Address)).Take(0x1000).ToArray();
                    Console.WriteLine(pktkv.Key + " : " + (pktParse - (UInt64)sigScan.Address).ToString("X") + " : " + pktkv.Value.ToString("X"));
                    ParseFunc(pktParseBytes, (IntPtr)(pktParse - (UInt64)sigScan.Address), pktkv.Key);
                }
                //var getOpcodeRef = nameToGetOpcode[pkt];
                //var pktStringRef = sigScan.FindPatterns(BitConverter.ToString(Encoding.Unicode.GetBytes(pkt + "\0")).Replace("-"," "), process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //avar getOpcodeRef = BitConverter.ToUInt64(sigScan.m_vDumpedRegion, (int)((Int64)pktStringRef[0] - (Int64)sigScan.Address) - 0x20);
            }
            var parsedSubStructs = 0;
            if (nameToOpcode.ContainsKey("PKTInitPC"))
            {
                //var handler = sigScan.FindPatterns("4C 8B C0 BA " + BitConverter.ToString(BitConverter.GetBytes((UInt32)nameToOpcode["PKTInitPC"])).Replace("-", " ") + " 48 8B CF", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var leaPkt = (Int64)handler[0] - (Int64)sigScan.Address - 0x22;
                //var handlerOffset = leaPkt + BitConverter.ToInt32(sigScan.m_vDumpedRegion, (int)leaPkt + 3) + 7;
                //var handlerFunc = (uint)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)handlerOffset).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret").Reverse().First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("rdx")).Details.Displacement;
                //var myIdAddr = sigScan.FindPatterns("4C 8B A6 ? ? ? ? 48 8D 15 ? ? ? ? 48 8D 8E ? ? ? ? FF 15 ? ? ? ? 48 85 C0", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var funcStart = GetFuncStart(myIdAddr);
                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTInitPC");
                //var procInitPc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)myIdAddr[0] - (Int64)sigScan.Address)).Take(0x1000).ToArray());
                var fullInitPc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)nameToHandler["PKTInitPC"] - (Int64)sigScan.Address)).Take(0x1000).ToArray());
                var floats = fullInitPc.Where(i => i.Mnemonic == "movss" && i.Operand.StartsWith("xmm1") && i.Operand.Contains("rsi")).ToList();
                var words = fullInitPc.Where(i => i.Mnemonic == "movzx" && i.Operand.StartsWith("eax") && i.Operand.Contains(" word")).ToList();
                //var id = (UInt32)procInitPc.First().Details.Displacement;
                var id = (UInt32)fullInitPc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("r12")).Details.Displacement;
                var nameId = (UInt32)fullInitPc.First(i => i.Mnemonic == "lea" && i.Operand.StartsWith("rcx")).Details.Displacement;
                //var nameId = (UInt32)procInitPc[2].Details.Displacement;
                var gearLevel = (UInt32)floats[0].Details.Displacement;
                var classId = (UInt32)words[0].Details.Displacement;
                var level = (UInt32)words[2].Details.Displacement;
                cl.Value.OpList.First(c => c.structOff == id).Rename = "PlayerId";
                cl.Value.OpList.First(c => c.dumpedClass == Dumped.First(d => d.Value.Name == "String").Key).Rename = "Name";
                //cl.Value.OpList.First(c => c.structOff == nameId).Rename = "Name";
                cl.Value.OpList.First(c => c.structOff == gearLevel).Rename = "GearLevel";
                cl.Value.OpList.First(c => c.structOff == classId).Rename = "ClassId";


                var byteArray = cl.Value.OpList.First(o => o.dumpedClass > 100 && o.dumpedClass < 200);
                var bIndex = cl.Value.OpList.IndexOf(byteArray);
                cl.Value.OpList.InsertRange(bIndex, SplitByteArray(new List<PartialByte> { new PartialByte { name = "Level", size = 2, offset = level } }, (uint)byteArray.structOff, (uint)byteArray.dumpedClass));
                cl.Value.OpList.Remove(byteArray);
            }
            if (nameToOpcode.ContainsKey("PKTInitEnv"))
            {
                /*var handler = sigScan.FindPatterns("4C 8B C0 BA " + BitConverter.ToString(BitConverter.GetBytes((UInt32)nameToOpcode["PKTInitEnv"])).Replace("-", " ") + " 48 8B CF", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                var leaPkt = (Int64)handler[0] - (Int64)sigScan.Address - 0x22;
                var handlerOffset = leaPkt + BitConverter.ToInt32(sigScan.m_vDumpedRegion, (int)leaPkt + 3) + 7;*/
                var handlerFunc = (uint)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)nameToHandler["PKTInitEnv"] - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret").Reverse().First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("rdx")).Details.Displacement;
                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTInitEnv");
                cl.Value.OpList.First(c => c.structOff == handlerFunc).Rename = "PlayerId";
            }
            if (nameToOpcode.ContainsKey("PKTSkillDamageNotify"))
            {
                var handlerFunc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)nameToHandler["PKTSkillDamageNotify"] - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret").Reverse().ToList();//
                var skillins = handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("r8d"));
                var skillOp = (uint)skillins.Details.Displacement;
                var stuff = handlerFunc.Select(s => s.Address.ToString("X") + " : " + s.Mnemonic + " " + s.Operand);
                var effectOp2 = handlerFunc[handlerFunc.IndexOf(skillins) - 3];
                //var effectOp = (uint)handlerFunc[handlerFunc.IndexOf(skillins) + 4].Details.Displacement;
                //var effectOp = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("ecx")).Details.Displacement;
                //var effectOp = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("ecx") && i.Details.Displacement > 0).Details.Displacement;
                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTSkillDamageNotify");
                cl.Value.OpList.First(c => c.structOff == skillOp).Rename = "SkillId";
                //cl.Value.OpList.First(c => c.structOff == effectOp).Rename = "SkillEffectId";
                cl.Value.OpList.First(c => c.dumpedClass == 4 && String.IsNullOrEmpty(c.Rename)).Rename = "SkillEffectId";
                cl.Value.OpList.First(c => c.dumpedClass == 8).Rename = "SourceId";

                var skillDmgEvents = Dumped[cl.Value.OpList.First(c => c.dumpedClass > 0x1000).dumpedClass];
                var skillDmgEvent = Dumped[skillDmgEvents.OpList.First(c => c.dumpedClass > 0x1000).dumpedClass];
                skillDmgEvent.Name = "SkillDamageEvent";

                //var parseSkillDmg = sigScan.FindPatterns("41 83 E6 07 B9 ? ? ? ? E8 ? ? ? ? 83 F8 01 0F", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var qq = GetFuncFromString("sys.squarehole.announce_new_registration");
                // var qq = GetFuncFromStringOffset("sys.squarehole.announce_new_registration", 0x1f0);

                var dmgParge = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)GetFuncFromStringOffset("sys.squarehole.announce_new_registration", 0x1f0) - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => !i.Mnemonic.StartsWith("ret"));
                var parseStart = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)GetFuncFromStringOffset("sys.squarehole.announce_new_registration", 0x1f0) - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).SkipWhile(o => o.Mnemonic != "cmp" || !o.Operand.StartsWith("dword") || !o.Operand.EndsWith("0")).ToList();
                var mod = (uint)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)GetFuncFromStringOffset("sys.squarehole.announce_new_registration", 0x1f0) - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).SkipWhile(o => o.Mnemonic != "movzx" || !o.Operand.StartsWith("ecx")).ToList()[0].Details.Displacement;
                var dmgs = dmgParge.Where(i => i.Mnemonic.StartsWith("mov") && i.Operand.StartsWith("rax") && skillDmgEvent.OpList.Count(o => o.structOff == (UInt64)i.Details.Displacement - 8 && o.dumpedClass == (UInt64)readPackedInt[0] - (UInt64)sigScan.Address) > 0).ToList();//.GroupBy(i => i.Details.Displacement).OrderBy(i => i.Count()).First().First().Details.Displacement;

                skillDmgEvent.OpList.First(c => c.structOff == (uint)dmgs[0].Details.Displacement - 8).Rename = "MaxHp";
                skillDmgEvent.OpList.First(c => c.structOff == (uint)dmgs[1].Details.Displacement - 8).Rename = "CurHp";
                skillDmgEvent.OpList.First(c => c.structOff == (uint)dmgs[2].Details.Displacement - 8).Rename = "Damage"; /* var d2 = dmgParge.Where(i => i.Mnemonic.StartsWith("mov") && i.Mnemonic.StartsWith("rax") && skillDmgEvent.OpList.Count(o => o.structOff == (UInt64)i.Details.Displacement - 8 && o.dumpedClass == (UInt64)readPackedInt[0] - (UInt64)sigScan.Address) > 0).GroupBy(i => i.Details.Displacement).OrderBy(i => i.Count());

                 //var mod = (uint)parseStart[0].Details.Displacement;
                 var damageInfos = 0;
                 for(var i = 0; i < parseStart.Count - 3; i++)
                 {
                     if (parseStart[i].Mnemonic == "mov" && parseStart[i + 2].Mnemonic == "mov" && parseStart[i + 4].Mnemonic == "mov" && parseStart[i].Operand.StartsWith("rax") && parseStart[i + 2].Operand.StartsWith("rax") && parseStart[i + 4].Operand.StartsWith("rax"))
                     {
                         skillDmgEvent.OpList.Last(c => c.structOff == (uint)parseStart[i].Details.Displacement - 8).Rename = "MaxHp";
                         skillDmgEvent.OpList.Last(c => c.structOff == (uint)parseStart[i + 2].Details.Displacement - 8).Rename = "CurHp";
                         skillDmgEvent.OpList.Last(c => c.structOff == (uint)parseStart[i + 4].Details.Displacement - 8).Rename = "Damage";
                         break;
                     }
                 }
                 var dmgs = parseStart.Where(o => o.Mnemonic == "mov" && o.Operand.StartsWith("rax")).ToList();*/
                //skillDmgEvent.OpList.Last(c => c.structOff == (uint)dmgs[6].Details.Displacement).Rename = "TargetId";
                skillDmgEvent.OpList.Last(c => c.dumpedClass == 8).Rename = "TargetId";
                skillDmgEvent.OpList.Last(c => c.structOff == mod).Rename = "Modifier";
            }
            if (nameToOpcode.ContainsKey("PKTSkillDamageAbnormalMoveNotify"))
            {
                var handlerFunc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)nameToHandler["PKTSkillDamageAbnormalMoveNotify"] - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret").Reverse();
                var skillOp = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("r8d")).Details.Displacement;
                var effectOp = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("eax") && i.Details.Displacement > 0).Details.Displacement;
                //var effectOp = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("rcx") && i.Details.Displacement > 0).Details.Displacement;
                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTSkillDamageAbnormalMoveNotify");
                cl.Value.OpList.First(c => c.structOff == skillOp).Rename = "SkillId";
                cl.Value.OpList.First(c => c.structOff == effectOp).Rename = "SkillEffectId";
                cl.Value.OpList.First(c => c.dumpedClass == 8).Rename = "SourceId";
                var skillDmgEvents = Dumped[cl.Value.OpList.First(c => c.dumpedClass > 0x1000).dumpedClass];
                var skillDmgMoveEvents = Dumped[skillDmgEvents.OpList.First(c => c.dumpedClass > 0x1000).dumpedClass];
                skillDmgMoveEvents.Name = "SkillDamageMoveEvent";
            }
            if (nameToOpcode.ContainsKey("PKTNewProjectile"))
            {
                //var handler = sigScan.FindPatterns("4C 8B C0 BA " + BitConverter.ToString(BitConverter.GetBytes((UInt32)nameToOpcode["PKTNewProjectile"])).Replace("-", " ") + " 48 8B CF", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var leaPkt = (Int64)handler[0] - (Int64)sigScan.Address - 0x22;
                //var handlerOffset = leaPkt + BitConverter.ToInt32(sigScan.m_vDumpedRegion, (int)leaPkt + 3) + 7;
                //var handlerFunc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)handlerOffset).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret").Reverse().First(i => i.Mnemonic == "call");
                //var callAddr = (Int64)UInt64.Parse(handlerFunc.Operand.Substring(2), System.Globalization.NumberStyles.HexNumber);
                //var parseProjFunc = (IntPtr)((int)handlerOffset + callAddr - 0x1000);

                var parseProjFunc = GetFuncFromStringOffset("ProjectileManager", 0x28 + 4 * 0x50);
                if (parseProjFunc == IntPtr.Zero) parseProjFunc = GetFuncFromStringOffset("QuestIds[{0}] QuestId[{1}]", -6 * 0x50);
                if (parseProjFunc == IntPtr.Zero) parseProjFunc = GetFuncFromStringOffset("Projectile CheckInvalidTargetPos_AimPos", 0xe0 + 3 * 0x50);

                //var idaaaa = 0x7FF788B70000 + ((UInt64)parseProjFunc);
                var idaaaa = 0x7FF7C8CB0000 + ((UInt64)parseProjFunc - (UInt64)sigScan.Address);
                //var handlerFunc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)nameToHandler["PKTNewProjectile"] - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret").Reverse().First(i => i.Mnemonic == "call");
                //var callAddr = (Int64)UInt64.Parse(handlerFunc.Operand.Substring(2), System.Globalization.NumberStyles.HexNumber);
                //var parseProjFunc = (IntPtr)((int)((UInt64)nameToHandler["PKTNewProjectile"] - (UInt64)sigScan.Address) + callAddr - 0x1000);
                var funcAsm = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)parseProjFunc - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).ToList();
                //var ops = funcAsm.Where(i => i.Mnemonic == "mov" && i.Operand.StartsWith("r") && (i.Operand.Contains("[rdx") || i.Operand.Contains("[rdx"))).ToList();
                var ops2 = funcAsm.Where(i => i.Mnemonic == "mov" && i.Operand.StartsWith("eax")).ToList();
                //var ownerId = (UInt64)ops.First(i => i.Operand.StartsWith("rdi")).Details.Displacement; // ops[0] works too
                var ops = new List<Gee.External.Capstone.X86.X86Instruction>();
                for (var i = 0; i < funcAsm.Count - 3; i++)
                {
                    if (!(funcAsm[i].Mnemonic == "jmp" || funcAsm[i].Mnemonic == "je") && funcAsm[i + 1].Mnemonic == "mov" && (funcAsm[i + 1].Operand.StartsWith("r") || funcAsm[i + 1].Operand.StartsWith("e")) && funcAsm[i + 1].Operand.Contains("[rdx"))
                    {
                        ops.Add(funcAsm[i + 1]);
                        if (ops.Count == 3)
                            break;
                    }
                }
                var ownerId = (UInt64)ops[0].Details.Displacement;// works too
                var projId = (UInt64)ops[1].Details.Displacement;
                var skillEffect = (UInt64)ops[2].Details.Displacement;

                var skillId = 0ul;
                for (var i = 0; i < funcAsm.Count - 2; i++)
                {
                    if (funcAsm[i].Mnemonic.Contains("call") && funcAsm[i + 2].Operand.StartsWith("eax"))
                    {
                        skillId = (UInt64)funcAsm[i + 2].Details.Displacement;
                        break;
                    }
                }
                //var skillId = (UInt64)funcAsm.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("eax") && i.Operand.Contains("eax, dword ptr [rsi")).Details.Displacement;
                var extras = funcAsm.Where(i => i.Mnemonic == "movzx" && i.Operand.StartsWith("eax")).ToList();
                var skillLevel = (UInt64)extras[1].Details.Displacement;
                var tripods = (UInt64)extras[2].Details.Displacement;
                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTNewProjectile");
                var projInfo = Dumped[cl.Value.OpList.First(c => c.dumpedClass > 0x1000).dumpedClass];
                projInfo.Name = "ProjectileInfo";
                //cl.Value.OpList.First(o => o.dumpedClass == (UInt64)projInfo.ParseOffset).Rename = "Info";
                projInfo.OpList.First(c => c.structOff == projId).Rename = "ProjectileId";
                projInfo.OpList.First(c => c.structOff == ownerId).Rename = "OwnerId";
                projInfo.OpList.First(c => c.structOff == skillLevel).Rename = "SkillLevel";
                projInfo.OpList.First(c => c.structOff == tripods).Rename = "Tripods";
                projInfo.OpList.First(c => c.structOff == skillId).Rename = "SkillId";
                projInfo.OpList.First(c => c.structOff == skillEffect).Rename = "SkillEffect";
            }
            if (nameToOpcode.ContainsKey("PKTNewNpc"))
            {
                var newNpc = Dumped.FirstOrDefault(c => c.Value.Name == "PKTNewNpc");
                var npcStruct = Dumped[newNpc.Value.OpList.First(c => c.dumpedClass > 0x1000).dumpedClass];
                npcStruct.Name = "NpcStruct";
                //newNpc.Value.OpList.First(o => o.dumpedClass == (UInt64)npcStruct.ParseOffset).Name = "npc";
                var PKTNewNpcId = GetFuncFromStringOffset("RECV > PKTNewNpc\0", -4 * 0x50);
                //var PKTNewNpcNetId = GetFuncFromStringOffset("RECV > PKTNewNpc\0", -5 * 0x50);
                var PKTNewNpcNetId = GetFuncFromString("RECV > PKTNewNpc\0");
                var disasm = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)PKTNewNpcId - (Int64)sigScan.Address + 0x1A)).Take(0x1000).ToArray());
                var npcId = (UInt32)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)PKTNewNpcNetId - (Int64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => !i.Mnemonic.StartsWith("ret")).Where(i => i.Mnemonic.StartsWith("mov") && npcStruct.OpList.Count(o => o.structOff == (UInt64)i.Details.Displacement && o.dumpedClass == 4) > 0).GroupBy(i => i.Details.Displacement).OrderBy(i => i.Count()).First().First().Details.Displacement;

                //var npcId = (UInt32)disasm.TakeWhile(i => !(i.Mnemonic == "mov" && i.Operand.StartsWith("edx"))).Reverse().ToArray()[0].Details.Displacement;
                //var parseProjFunc = GetFuncFromStringOffset("QuestIds[{0}] QuestId[{1}]", -0x1e0);
                //var PKTNewNpcId = sigScan.FindPatterns("49 8B 06 45 8B CC 4C", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize); // 48 8B 07 45 8B CC 4C
                //var PKTNewNpcNetId = sigScan.FindPatterns("44 88 44 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 C7 45 ? ? ? ? ? 48 89 9C 24 ? ? ? ? 49 8B F1 4C 8B F2 4C 8B E9", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var npcId = (UInt32)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)PKTNewNpcId[0] - (Int64)sigScan.Address + 0x1A)).Take(0x10).ToArray())[0].Details.Displacement;
                // var netId = (UInt32)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)PKTNewNpcNetId - (Int64)sigScan.Address)).Take(0x1000).ToArray()).First(i=> i.Mnemonic == "mov" && i.Operand.StartsWith("r1")).Details.Displacement;
                var netId = (UInt16)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)PKTNewNpcNetId - (Int64)sigScan.Address)).Take(0x1000).ToArray()).Where(i => i.Mnemonic.StartsWith("mov") && npcStruct.OpList.Count(o => o.structOff == (UInt64)i.Details.Displacement && o.dumpedClass == 8) > 0).GroupBy(i => i.Details.Displacement).First(i => i.Key > 0).First().Details.Displacement;
                //var netIdasdf = (UInt32)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)PKTNewNpcNetId - (Int64)sigScan.Address)).Take(0x1000).ToArray()).Where(i=> i.Mnemonic.StartsWith("mov") && npcStruct.OpList.Count(o=>o.structOff == (UInt64)i.Details.Displacement && o.dumpedClass == 8) > 0).GroupBy(i=>i.Details.Displacement).Where(i=>i.Count() == 6).First().First().Details.Displacement;
                //var netId = (UInt32)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)PKTNewNpcNetId - (Int64)sigScan.Address)).Take(0x1000).ToArray()).First(i=> i.Mnemonic.StartsWith("mov") && npcStruct.OpList.Count(o=>o.structOff == (UInt64)i.Details.Displacement && o.dumpedClass == 8)>0).Details.Displacement;
                //if (npcStruct.OpList.Count(c => c.structOff == npcId) == 0)  npcId = (UInt32)disasm.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("esi")).Details.Displacement;
                var tests = npcStruct.OpList.Where(c => c.dumpedClass == 8);
                npcStruct.OpList.First(c => c.structOff == npcId).Rename = "NpcType";
                npcStruct.OpList.First(c => c.structOff == netId).Rename = "NpcId";
            }
            if (nameToOpcode.ContainsKey("PKTNewPC"))
            {
                var newPc = Dumped.FirstOrDefault(c => c.Value.Name == "PKTNewPC");
                var pcStruct = Dumped[newPc.Value.OpList.First(c => c.dumpedClass > 0x1000 && newPc.Value.OpList.Count(c2 => c2.If && c2.Name == c.Name) == 0).dumpedClass];
                pcStruct.Name = "PCStruct";
                pcStruct.OpList.Where(c => c.dumpedClass > 0x1000 && Dumped[c.dumpedClass].OpList.Count == 3).ToList().ForEach(o => Dumped[o.dumpedClass].Name = "SkillRunes");
                //newPc.Value.OpList.First(o => o.dumpedClass == (UInt64)pcStruct.ParseOffset).Name = "playerCharacter";
                var PKTNewPCId = GetFuncFromString("OtherPetPCDeserial");
                //var PKTNewPCId = sigScan.FindPatterns("C7 80 ? ? ? ? ? ? ? ? 48 8B 86 ? ? ? ? 48 89 44 24 ? 44 8B B6 ? ? ? ? 48 8B 07 48 8B CF FF 90", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var PKTNewPCId = sigScan.FindPatterns("C7 80 ? ? ? ? ? ? ? ? 48 8B 06 ? ? ? ? ? 44 8B B6 ? ? ? ? ", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var equippedItems = sigScan.FindPatterns("48 8D 8F ? ? ? ? 48 8D", PKTNewPCId[0], 0x500);
                var pcStructParse = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)PKTNewPCId - (Int64)sigScan.Address)).Take(0x1000).ToArray());
                //var PKTNewPCName = sigScan.FindPatterns("48 8D B1 ? ? ? ? 48 8B D6", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var PKTNewPCName = sigScan.FindPatterns("48 8D B1 ? ? ? ? 48 ? ? ? ? ? ? ? ? ? E8 ? ? ? ? 48 8D 8F ? ? ? ? 48 8B D6 E8 ? ? ? ?", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var PKTNewPCName = sigScan.FindPatterns("FF 15 ? ? ? ? 48 85 C0 74 04 66 44 89 38 49 8D 95", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //if (PKTNewPCName.Count == 0) PKTNewPCName = sigScan.FindPatterns("FF 15 ? ? ? ? 48 85 C0 74 04 66 44 89 38 49 8B D5", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var PKTNewPCClass = sigScan.FindPatterns("FF 50 18 48 8B 03 0F B7 97 ? ? ? ? 48 8B CB FF 50 20 48 8D 97", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //foreach(var s in new String[2] { "FF 50 18 48 8B 03 0F B7 97 ? ? ? ? 48 8B", "FF 50 18 48 8B 03 0F B7 57" })

                var parserAddr = sigScan.FindPatterns("48 8B C4 57 41 54 41 55 41 56 41 57 48 83 EC 60 48 C7 40 ? ? ? ? ? 48 89 58 10 48 89 68 18 48 89 70 20 49 8B F8 48 8B E9 4C 8B 1A 8B 99", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                var parserPsuedo = GetPsuedocode(parserAddr[0]);
                foreach (var s in new String[] { })
                {
                    //var PKTNewPCClass = sigScan.FindPatterns("FF 50 18 48 8B 03 0F B7 97 ? ? ? ? 48 8B", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                    //var PKTNewPCClass = sigScan.FindPatterns("FF 50 18 48 8B 03 0F B7 57", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);

                    //var qq = GetPsuedocode(nameToHandler["PKTInitEnv"]);
                    var PKTNewPCClass = sigScan.FindPatterns(s, process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                    var found = false;
                    foreach (var pcclass in PKTNewPCClass)
                    {
                        //var playerId2 = BitConverter.ToUInt32(disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)PKTNewPCId - (Int64)sigScan.Address + 10)).Take(0x10).ToArray())[0].Bytes, 3);
                        var playerIdParser = pcStructParse.SkipWhile(i => !(i.Mnemonic == "mov" && i.Operand.StartsWith("dword")));
                        var playerId = (uint)playerIdParser.ToArray()[1].Details.Displacement;
                        pcStruct.OpList.First(c => c.structOff == playerId).Rename = "PlayerId";
                        var PKTNewPCName = GetFuncFromStringOffset("OtherPetSummonChange", 0x30);
                        var nameParse = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)PKTNewPCName - (Int64)sigScan.Address)).Take(0x1000).ToArray());
                        for (var i = 0; i < nameParse.Length; i++)
                        {
                            if (nameParse[i].Mnemonic == "lea" && nameParse[i].Operand.StartsWith("rcx") && !nameParse[i].Operand.Contains("rbp") && nameParse[i + 1].Mnemonic == "call" && pcStruct.OpList.Count(pc => pc.structOff == (ulong)nameParse[i].Details.Displacement) == 1)
                            {
                                var name = (UInt32)nameParse[i].Details.Displacement;
                                pcStruct.OpList.First(c => c.structOff == name).Rename = "Name";
                                break;
                            }
                        }
                        if (pcStruct.OpList.Count(c => c.Rename == "Name") == 0)
                        {
                            if (pcStruct.OpList.Count(c => c.dumpedClass == (UInt64)readString[0] - (UInt64)sigScan.Address) == 1)
                                pcStruct.OpList.First(c => c.dumpedClass == (UInt64)readString[0] - (UInt64)sigScan.Address).Rename = "Name";
                            else
                                throw new Exception("");
                        }
                        //pcStruct.OpList.First(c => c.dumpedClass == (UInt64)readString[0] - (UInt64)sigScan.Address && String.IsNullOrEmpty(c.Rename)).Rename = "Guild";
                        var important = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)pcclass - (Int64)sigScan.Address - 10)).Take(0x1000).ToArray());
                        var partyIdAsm = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)pcclass - (Int64)sigScan.Address - 10 - 0xe)).Take(0x1000).ToArray());
                        var classId = (uint)important[0].Details.Displacement;
                        var partyId = (uint)partyIdAsm[0].Details.Displacement;
                        var level = (uint)important[4].Details.Displacement;
                        var gearLevel = (uint)important.Where(o => o.Mnemonic.StartsWith("movss") && o.Operand.StartsWith("xmm1")).ToList()[1].Details.Displacement;
                        try
                        {
                            pcStruct.OpList.First(c => c.structOff == classId).Rename = "ClassId";
                            pcStruct.OpList.First(c => c.structOff == level).Rename = "Level";
                            pcStruct.OpList.First(c => c.structOff == gearLevel).Rename = "GearLevel";
                            pcStruct.OpList.First(c => c.structOff == partyId).Rename = "PartyId";
                            found = true;
                            break;
                        }
                        catch
                        {

                        }
                    }
                    if (found) break;
                }

                /*for (var i = 0; i < pcStructParse.Length - 8; i++)
                {
                    //if (pcStructParse[i].Mnemonic == "mov" && pcStructParse[i+1].Mnemonic == "lea" && pcStructParse[i+2].Mnemonic == "mov" && pcStructParse[i+3].Mnemonic == "xor" && pcStructParse[i+4].Mnemonic == "mov" && pcStructParse[i+5].Mnemonic == "mov" && pcStructParse[i+6].Mnemonic == "call")
                    if (pcStructParse[i].Mnemonic == "mov" && pcStructParse[i+1].Mnemonic == "lea" && pcStructParse[i+2].Mnemonic == "mov" && pcStructParse[i+3].Mnemonic == "xor" && pcStructParse[i+4].Mnemonic == "mov" && pcStructParse[i+5].Mnemonic == "mov")
                    {
                        var itemInfo = (uint)pcStructParse[i + 1].Details.Displacement;
                        pcStruct.OpList.First(c => c.structOff == itemInfo).Rename = "EquippedItems";
                        var itemInfoClass = Dumped[Dumped[pcStruct.OpList.First(c => c.structOff == itemInfo).dumpedClass].OpList[1].dumpedClass];
                        itemInfoClass.Name = "ItemInfo";
                        //var itemInfoParse = sigScan.FindPatterns("48 89 5C 24 ? 48 89 7C 24 ? 0F B7 02 33 FF 4C 8B DA 66 89 01 48 8B D9 44 0F B7 D7 66 3B 3A 0F 8D ? ? ? ? 66 66 66 0F 1F 84 00 ? ? ? ? 4D 0F BF C2 49 C1 E0 06 4B 8D 04 18 4D 8D 0C 18 44 0F B7 C7", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                        //var itemInfoParse = sigScan.FindPatterns("0F B7 48 2E 66 41 89 49 ? 0F B6 48 31 41 88 49 31 84 C9 74 08 0F B6 48 30 41 88 49 30", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                        //var itemInfoParse = sigScan.FindPatterns("49 C1 E0 06 4B 8D 04 18 4D 8D 0C 18", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                        var itemInfoParse = sigScan.FindPatterns("? C1 E0 06 ? 8D 04 18 ? 8D 0C 18", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                        //var itemInfoOff = (UInt32)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)itemInfoParse[0] - (Int64)sigScan.Address)).Take(0x100).ToArray()).SkipWhile(i=>i.Mnemonic != "jl").TakeWhile(i=>i.Mnemonic != "ret").Last(i=>i.Mnemonic == "movzx").Details.Displacement;
                        var itemInfoOff =0x3eu;
                        //var itemInfoOff = (UInt32)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)itemInfoParse[0] - (Int64)sigScan.Address)).Take(0x10).ToArray())[0].Details.Displacement;
                        //var op = itemInfoClass.OpList.First(c => c.structOff == itemInfoOff - 2);
                        var op = itemInfoClass.OpList.First();
                        if (op.dumpedClass != 2) op = itemInfoClass.OpList.First(c => c.dumpedClass == 2);
                        op.Rename = "Level";
                        break;
                    }
                }*/
                {
                    var possibleStructs = pcStruct.OpList.Where(p => p.dumpedClass > 0x2000 && Dumped[p.dumpedClass].OpList.Count == 2).ToList();
                    var tt = possibleStructs.Select(l => Dumped[l.dumpedClass]).ToList();
                    var itemInfoClassAddrs = possibleStructs.Where(p => possibleStructs.Count(p2 => Dumped[p2.dumpedClass].OpList[1].dumpedClass == Dumped[p.dumpedClass].OpList[1].dumpedClass) == 2);
                    var itemInfoClassAddr = Dumped[itemInfoClassAddrs.First().dumpedClass].OpList[1].dumpedClass;
                    //var itemInfoClassAddr = pcStruct.OpList.First(p => p.dumpedClass > 0x1000 && p.dumpedClass != Dumped.First().Key && pcStruct.OpList.Count(p2 => p2.dumpedClass == p.dumpedClass) == 2).dumpedClass;
                    var itemInfoClass = Dumped[itemInfoClassAddr];
                    // var itemInfoClass = Dumped[Dumped[pcStruct.OpList.First(c => c.structOff == itemInfo).dumpedClass].OpList[1].dumpedClass];
                    itemInfoClass.Name = "ItemInfo";
                    //var itemInfoParse = sigScan.FindPatterns("48 89 5C 24 ? 48 89 7C 24 ? 0F B7 02 33 FF 4C 8B DA 66 89 01 48 8B D9 44 0F B7 D7 66 3B 3A 0F 8D ? ? ? ? 66 66 66 0F 1F 84 00 ? ? ? ? 4D 0F BF C2 49 C1 E0 06 4B 8D 04 18 4D 8D 0C 18 44 0F B7 C7", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                    //var itemInfoParse = sigScan.FindPatterns("0F B7 48 2E 66 41 89 49 ? 0F B6 48 31 41 88 49 31 84 C9 74 08 0F B6 48 30 41 88 49 30", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                    //var itemInfoParse = sigScan.FindPatterns("49 C1 E0 06 4B 8D 04 18 4D 8D 0C 18", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                    //var itemInfoParse = sigScan.FindPatterns("? C1 E0 06 ? 8D 04 18 ? 8D 0C 18", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                    //var itemInfoOff = (UInt32)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)itemInfoParse[0] - (Int64)sigScan.Address)).Take(0x100).ToArray()).SkipWhile(i=>i.Mnemonic != "jl").TakeWhile(i=>i.Mnemonic != "ret").Last(i=>i.Mnemonic == "movzx").Details.Displacement;
                    //var itemInfoOff = 0x3eu;
                    //var itemInfoOff = (UInt32)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)itemInfoParse[0] - (Int64)sigScan.Address)).Take(0x10).ToArray())[0].Details.Displacement;
                    //var op = itemInfoClass.OpList.First(c => c.structOff == itemInfoOff - 2);
                    var op = itemInfoClass.OpList.First();
                    if (op.dumpedClass != 2) op = itemInfoClass.OpList.First(c => c.dumpedClass == 2);
                    op.Rename = "Level";
                    pcStruct.OpList.First(c => c.dumpedClass == itemInfoClassAddrs.First().dumpedClass).Rename = "EquippedItems";
                }
                /*
                for (var i = 0; i < pcStructParse.Length - 8; i++)
                {
                    if (pcStructParse[i].Mnemonic == "mov" && pcStructParse[i+1].Mnemonic == "mov" && pcStructParse[i+2].Mnemonic == "xor" && pcStructParse[i+3].Mnemonic == "mov" && pcStructParse[i+4].Mnemonic == "mov" && pcStructParse[i+5].Mnemonic == "mov" && pcStructParse[i+6].Mnemonic == "call")
                    {
                        var itemInfo = (uint)pcStructParse[i + 1].Details.Displacement;
                        pcStruct.OpList.First(c => c.structOff == itemInfo).Rename = "EquippedItems";
                        
                        break;
                    }
                }*/
                //Dumped[pcStruct.OpList.First(c => c.dumpedClass > 0x1000 && Dumped[c.dumpedClass].OpList.Count == 3).dumpedClass].Name = "SkillRunes";
                //var itemInfo = Dumped[pcStruct.OpList.First(o => (o.dumpedClass != ((UInt64)readString[0] - (UInt64)sigScan.Address)) && o.dumpedClass > 0x1000 && pcStruct.OpList.Count(oo => oo.dumpedClass == o.dumpedClass) == 2).dumpedClass];
                //itemInfo.Name = "Equipment";
            }
            if (nameToOpcode.ContainsKey("PKTStatChangeOriginNotify"))
            {
                var structs = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)nameToHandler["PKTStatChangeOriginNotify"] - (Int64)sigScan.Address)).Take(0x1000).ToArray()).SkipWhile(i => i.Mnemonic != "movzx").Skip(1).SkipWhile(i => i.Mnemonic != "movzx").Where(i => i.Mnemonic == "lea" && i.Operand.StartsWith("r")).ToList();
                var id = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)nameToHandler["PKTStatChangeOriginNotify"] - (Int64)sigScan.Address)).Take(0x1000).ToArray()).SkipWhile(i => i.Mnemonic != "movzx").Skip(1).SkipWhile(i => i.Mnemonic != "movzx").Where(i => i.Mnemonic == "mov" && i.Operand.StartsWith("rdx")).ToList();

                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTStatChangeOriginNotify");
                var statPairList = cl.Value.OpList.First(c => c.structOff == (uint)structs[0].Details.Displacement);
                statPairList.Rename = "StatPairList";
                cl.Value.OpList.First(c => c.structOff != statPairList.structOff && c.dumpedClass == statPairList.dumpedClass).Rename = "StatPairChangedList";
                //cl.Value.OpList.First(c => c.structOff == (uint)structs[1].Details.Displacement).Rename = "StatPairChangedList";
                cl.Value.OpList.First(c => c.structOff == (uint)id[0].Details.Displacement).Rename = "ObjectId";
                var c = Dumped[cl.Value.OpList.First(c => c.dumpedClass > 0x1000).dumpedClass];
                c.Name = "StatPair";
                c.OpList.First(c => c.dumpedClass > 0x1000).Rename = "Value";
                c.OpList.First(c => c.dumpedClass == 1).Rename = "StatType";
            }
            if (nameToOpcode.ContainsKey("PKTStatusEffectAddNotify"))
            {
                var handlerFunc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)nameToHandler["PKTStatusEffectAddNotify"] - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret");
                var objectId = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.Contains("[rdx")).Details.Displacement;
                var effectOp = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("ecx")).Details.Displacement;
                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTStatusEffectAddNotify");
                cl.Value.OpList.First(c => c.structOff == objectId).Rename = "ObjectId";
                cl.Value.OpList.First(c => c.dumpedClass == 1).Rename = "New";
                var buffClassField = cl.Value.OpList.First(c => c.dumpedClass > 0x1000);
                //var hasBuffField = cl.Value.OpList.First(c=>c.Name)
                var c = Dumped[buffClassField.dumpedClass];
                c.Name = "StatusEffectData";
                var buffClassFieldstructOff = buffClassField.structOff + 0;// 0x18;// 0x18; // hack
                //var buffClassFieldstructOff = buffClassField.structOff + 0x18;// 0x18; // hack
                /*var callSubParse = handlerFunc.SkipWhile(i => i.Mnemonic == "mov" && i.Operand.StartsWith("rcx, rdi")).ToList();
                var callAddr = (Int64)UInt64.Parse(callSubParse[1].Operand.Substring(2), System.Globalization.NumberStyles.HexNumber);
                var parseProjFunc = (IntPtr)((int)handlerOffset + callAddr - 0x1000);
                var projId = (UInt64)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)parseProjFunc).Take(0x1000).ToArray()).First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("r15")).Details.Displacement;*/

                var buffClass = statusEffectParse;// sigScan.FindPatterns("83 F8 01 0F 85 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? F2 0F 5C F0", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                if (region == Region.Steam)
                {
                    var buffClasss = sigScan.FindPatterns("83 F8 01 0F 85 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? F2 0F 5C F0", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                    var buffClass2 = buffClasss[0];
                    buffClass = buffClasss[0];
                }

                var disasm = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)buffClass - (Int64)sigScan.Address)).Take(0x1000).ToArray());
                // steam
                var buffOffsets64 = disasm.Where(i => i.Mnemonic == "mov" && i.Details.Operands.Length == 2 && i.Details.Operands[0].Type == Gee.External.Capstone.X86.X86OperandType.Register && i.Details.Operands[0].Size == 8 && i.Details.Operands[0].Register.Name.StartsWith("r") && i.Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Memory && i.Details.Operands[1].Memory.Base != null && i.Details.Operands[1].Memory.Base.Name.StartsWith("r") && !i.Details.Operands[1].Memory.Base.Name.StartsWith("rip")).ToList();
                if (region == Region.Korea) buffOffsets64 = disasm.Where(i => i.Mnemonic == "mov" && i.Details.Operands.Length == 2 && i.Details.Operands[0].Type == Gee.External.Capstone.X86.X86OperandType.Register && i.Details.Operands[0].Size == 8 && i.Details.Operands[0].Register.Name.StartsWith("r") && i.Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Memory && i.Details.Operands[1].Memory.Base != null && i.Details.Operands[1].Memory.Base.Name.StartsWith("r") && i.Details.Operands[1].Memory.Base.Name.StartsWith("rsi")).ToList();

                var buffOffsets = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)buffClass - (Int64)sigScan.Address)).Take(0x1000).ToArray()).Where(i => i.Mnemonic == "mov" && !i.Operand.StartsWith("byte ptr") && !i.Operand.StartsWith("word ptr") && !i.Operand.StartsWith("qword ptr")).ToList();
                //var buffOffsets64 = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)buffClass[0] - (Int64)sigScan.Address)).Take(0x1000).ToArray()).Where(i => i.Mnemonic == "mov" && i.Details.Operands[0].Size == 8 && i.Details.Displacement > 0 && !i.Operand.StartsWith("byte ptr") && !i.Operand.StartsWith("word ptr") && !i.Operand.StartsWith("qword ptr")).ToList();
                var buffOffsets32 = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)buffClass - (Int64)sigScan.Address)).Take(0x1000).ToArray()).Where(i => i.Mnemonic == "mov" && i.Details.Operands[0].Size == 4 && i.Details.Displacement > 0 && !i.Operand.StartsWith("byte ptr") && !i.Operand.StartsWith("word ptr") && !i.Operand.StartsWith("qword ptr") && i.Details.Operands[0].Type == Gee.External.Capstone.X86.X86OperandType.Register).ToList();
                var buffOffsets8 = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)buffClass - (Int64)sigScan.Address)).Take(0x1000).ToArray()).Where(i => i.Mnemonic == "movzx" && i.Details.Displacement > 0 && !i.Operand.StartsWith("byte ptr") && !i.Operand.StartsWith("word ptr") && !i.Operand.StartsWith("qword ptr")).ToList();
                var buffOffsets2 = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)buffClass - (Int64)sigScan.Address)).Take(0x1000).ToArray()).SkipWhile(i => !i.Mnemonic.StartsWith("cmp") && !i.Operand.StartsWith("byte ptr") && !i.Operand.StartsWith("word ptr") && !i.Operand.StartsWith("qword ptr")).First();
                //c.OpList.First(c => (uint)(buffClassFieldstructOff + c.structOff) == buffOffsets64[0].Details.Displacement).Rename = "InstanceId";
                //c.OpList.First(c => (uint)(buffClassFieldstructOff + c.structOff) == buffOffsets64[0].Details.Displacement).Rename = "InstanceId";
                c.OpList.First(c => c.dumpedClass == 8 && (uint)(buffClassFieldstructOff + c.structOff) == buffOffsets64.First(b => b.Details.Displacement == (uint)(buffClassFieldstructOff + c.structOff))?.Details?.Displacement).Rename = "InstanceId";
                c.OpList.First(c => c.Rename != "InstanceId" && c.dumpedClass == 8 && (uint)(buffClassFieldstructOff + c.structOff) == buffOffsets64.First(b => b.Details.Displacement == (uint)(buffClassFieldstructOff + c.structOff))?.Details?.Displacement).Rename = "SourceId";
                //c.OpList.First(c => (uint)(buffClassFieldstructOff + c.structOff) == buffOffsets64[1].Details.Displacement).Rename = "SourceId";
                var valueField = c.OpList.First(c => c.dumpedClass == 0x10);
                c.OpList.First(c => c.structOff == valueField.structOff + 16).Rename = "hasValue";
                valueField.Rename = "Value";
                //c.OpList.First(c => (uint)(buffClassField.structOff + c.structOff) == buffOffsets[2].Details.Displacement).Name = "Level";
                //c.OpList.First(c => (uint)(buffClassFieldstructOff + c.structOff) == buffOffsets[3].Details.Displacement).Rename = "StartTime";
                c.OpList.First(c => (uint)(buffClassFieldstructOff + c.structOff) == buffOffsets32[0].Details.Displacement).Rename = "EffectInstanceId";
                c.OpList.First(c => (uint)(buffClassFieldstructOff + c.structOff) == buffOffsets32[1].Details.Displacement).Rename = "StatusEffectId";
                c.OpList.First(c => (uint)(buffClassFieldstructOff + c.structOff) == buffOffsets8[0].Details.Displacement).Rename = "SkillLevel";

                // c.OpList.First(c => c.structOff == (uint)((int)buffClassField.structOff + buffOffsets[7].Details.Displacement)).Name = "Level";
                //c.OpList.First(c => c.structOff == (uint)((int)buffClassField.structOff + buffOffsets2.Details.Displacement)).Name = "BuffId";
            }
            if (nameToOpcode.ContainsKey("PKTCounterAttackNotify"))
            {
                var idaAddr = (UInt64)nameToHandler["PKTCounterAttackNotify"] - (UInt64)sigScan.Address;
                var handlerFunc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)nameToHandler["PKTCounterAttackNotify"] - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret");
                var sourceTarget = handlerFunc.SkipWhile(i => !(i.Mnemonic == "mov" && i.Operand.StartsWith("rbx,"))).Take(2).ToArray();
                var objRegs = handlerFunc.Where(i => i.Mnemonic == "mov" && i.Details.Operands.Length == 2 && i.Details.Operands[0].Type == Gee.External.Capstone.X86.X86OperandType.Register && i.Details.Operands[0].Size == 8 && i.Details.Operands[0].Register.Name.StartsWith("r") && i.Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Memory && i.Details.Operands[1].Memory.Base != null && i.Details.Operands[1].Memory.Base.Name.StartsWith("r") && !i.Details.Operands[1].Memory.Base.Name.StartsWith("rip")).ToList();

                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTCounterAttackNotify");
                var byteArray = cl.Value.OpList.First();

                var source = objRegs.First(o => o.Details.Operands[0].Size == 8 && (ulong)o.Details.Displacement >= byteArray.structOff && (ulong)o.Details.Displacement < (byteArray.structOff + byteArray.dumpedClass - 8)).Details.Displacement;
                var target = objRegs.First(o => o.Details.Displacement != source && o.Details.Operands[0].Size == 8 && (ulong)o.Details.Displacement >= byteArray.structOff && (ulong)o.Details.Displacement <= (byteArray.structOff + byteArray.dumpedClass - 8)).Details.Displacement;
                cl.Value.OpList = SplitByteArray(new List<PartialByte> { new PartialByte { name = "TargetId", size = 8, offset = (uint)target }, new PartialByte { name = "SourceId", size = 8, offset = (uint)source } }, (uint)byteArray.structOff, (uint)byteArray.dumpedClass);
            }
            if (nameToOpcode.ContainsKey("PKTSkillStartNotify"))
            {
                var handlerFunc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)nameToHandler["PKTSkillStartNotify"] - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret");
                var skillId = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("ecx, dword ptr [rbx +")).Details.Displacement;
                var source = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("rdi")).Details.Displacement;
                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTSkillStartNotify");
                cl.Value.OpList.First(c => c.structOff == source).Rename = "SourceId";
                cl.Value.OpList.First(c => c.structOff == skillId).Rename = "SkillId";
            }
            if (nameToOpcode.ContainsKey("PKTSkillStageNotify"))
            {
                var handlerFunc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)nameToHandler["PKTSkillStageNotify"] - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret");
                var source = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("r14")).Details.Displacement;
                var sources = handlerFunc.Where(i => i.Mnemonic == "mov" && i.Operand.StartsWith("eax")).ToList();
                var skillId = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("eax") && i.Operand.Contains("rsi")).Details.Displacement;
                var stage = (uint)handlerFunc.First(i => i.Mnemonic == "movsx" && i.Operand.StartsWith("eax") && i.Operand.Contains("rsi")).Details.Displacement;

                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTSkillStageNotify");
                var byteArray = cl.Value.OpList.First();
                cl.Value.OpList = SplitByteArray(new List<PartialByte> { new PartialByte { name = "SourceId", size = 8, offset = source }, new PartialByte { name = "SkillId", size = 4, offset = skillId }, new PartialByte { name = "Stage", size = 1, offset = stage } }, (uint)byteArray.structOff, (uint)byteArray.dumpedClass);
            }
            if (nameToOpcode.ContainsKey("PKTDeathNotify"))
            {
                var handlerFunc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((UInt64)nameToHandler["PKTDeathNotify"] - (UInt64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret");
                //var handler = sigScan.FindPatterns("4C 8B C0 BA " + BitConverter.ToString(BitConverter.GetBytes((UInt32)nameToOpcode["PKTDeathNotify"])).Replace("-", " ") + " 48 8B CF", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var handler = GetFuncStart(sigScan.FindPatterns("48 8B 46 ? 48 3B 46 ? 74 05 48 85 C0 75 32 F3 0F 10 15 ? ? ? ? F3 0F 10 45 ? F3 0F 59 C2 F3 0F 11 45", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize)[0]);
                //var handlerFunc = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)handler - (Int64)sigScan.Address)).Take(0x1000).ToArray()).TakeWhile(i => i.Mnemonic != "ret");
                var target = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("rbx") && i.Operand.Contains("word")).Details.Displacement;
                var source = (uint)handlerFunc.First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("rax") && i.Operand.Contains("rsi")).Details.Displacement;

                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTDeathNotify");
                cl.Value.OpList.First(c => c.structOff == target).Rename = "TargetId";
                cl.Value.OpList.First(c => c.structOff == source).Rename = "SourceId";
            }
            if (nameToOpcode.ContainsKey("PKTNewNpcSummon"))
            {
                //var summonOwner = sigScan.FindPatterns("81 3D ? ? ? ? ? ? ? ? 0F 8E ? ? ? ? 48 8B 0D ? ? ? ? 48 85 C9 41 0F 94 C6 41 F7 DE 49 63 C6 48 23 C6 48 0B C1 F7 80", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                //var summonOwner = sigScan.FindPatterns("FF 15 ? ? ? ? 41 39 ? ? ? ? ? 0F 84 ? ? ? ? 49 8B", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
                var summonOwner = nameToHandler["PKTNewNpcSummon"];// GetFuncFromString("ScouterDroneNpcId");

                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTNewNpcSummon");
                var byteArray = cl.Value.OpList.First(i => i.dumpedClass > 1 && i.dumpedClass < 0x100);
                var disasm = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)summonOwner - (Int64)sigScan.Address)).Take(0x1000).ToArray());
                var objRegs = disasm.Where(i => i.Mnemonic == "mov" && i.Details.Operands.Length == 2 && i.Details.Operands[0].Type == Gee.External.Capstone.X86.X86OperandType.Register && i.Details.Operands[0].Register.Name.StartsWith("r") && i.Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Memory && i.Details.Operands[1].Memory.Base != null && i.Details.Operands[1].Memory.Base.Name.StartsWith("r") && !i.Details.Operands[1].Memory.Base.Name.StartsWith("rip")).ToList();

                //var summon = (uint)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)summonOwner - (Int64)sigScan.Address)).Take(0x1000).ToArray()).First(i => i.Mnemonic == "mov" && (UInt64)i.Details.Displacement >= byteArray.structOff && (UInt64)i.Details.Displacement < byteArray.structOff + byteArray.dumpedClass).Details.Displacement;
                var summons = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)summonOwner - (Int64)sigScan.Address)).Take(0x1000).ToArray()).Where(i => i.Mnemonic == "mov" && i.Operand.StartsWith("rdx") && (Int64)i.Details.Displacement >= 0);
                //var summon = (UInt32)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)summonOwner - (Int64)sigScan.Address)).Take(0x1000).ToArray()).First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("rdx") && (Int64)i.Details.Displacement >= 0 && (UInt64)i.Details.Displacement < byteArray.dumpedClass).Details.Displacement;
                //var summon = (UInt32)disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)summonOwner - (Int64)sigScan.Address)).Take(0x1000).ToArray()).First(i => i.Mnemonic == "mov" && i.Operand.StartsWith("r") && (Int64)i.Details.Displacement >= (Int64)byteArray.structOff && (UInt64)i.Details.Displacement < byteArray.structOff + byteArray.dumpedClass).Details.Displacement;
                var summon = (uint)byteArray.structOff + (uint)objRegs[0].Details.Displacement;
                var newOps = cl.Value.OpList.TakeWhile(i => i != byteArray).ToList();
                newOps.AddRange(SplitByteArray(new List<PartialByte> { new PartialByte { name = "OwnerId", size = 8, offset = summon - 0x18 } }, (uint)byteArray.structOff, (uint)byteArray.dumpedClass));
                newOps.AddRange(cl.Value.OpList.SkipWhile(i => i != byteArray).Skip(1));
                cl.Value.OpList = newOps;
            }
            if (nameToOpcode.ContainsKey("PKTTriggerStartNotify"))
            {
                var handler = nameToHandler["PKTTriggerStartNotify"];
                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTTriggerStartNotify");
                var disasm = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)handler - (Int64)sigScan.Address)).Take(0x1000).ToArray());
                //var objReg = disasm.FirstOrDefault(i => i.Mnemonic == "mov" && i.Details.Operands.Length == 2 && i.Details.Operands[1].Register.Name == "rdx")?.Details.Operands[0].Register.Name;
                var objReg = disasm.FirstOrDefault(i => i.Mnemonic == "mov" && i.Details.Operands.Length == 2 && i.Details.Operands[0].Type == Gee.External.Capstone.X86.X86OperandType.Register && i.Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Register && i.Details.Operands[1].Register.Name == "rdx");//?.Details.Operands[0].Register.Name;
                var regName = objReg == null ? "rdx" : objReg.Details.Operands[0].Register.Name;
                //var objReg2 = disasm.First(i => i.Mnemonic == "mov" && i.Details.Operands.Length == 2 && i.Details.Operands[0].Type == Gee.External.Capstone.X86.X86OperandType.Register && i.Details.Operands[0].Register.Name == "ecx" && i.Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Memory && i.Details.Operands[1].Memory.Base.Name == regName);
                var objRegs = disasm.Where(i => i.Mnemonic == "mov" && i.Details.Operands.Length == 2 && i.Details.Operands[0].Type == Gee.External.Capstone.X86.X86OperandType.Register && i.Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Memory && i.Details.Operands[1].Memory.Base != null && i.Details.Operands[1].Memory.Base.Name == regName).ToList();

                cl.Value.OpList.First(c => c.structOff == (uint)objRegs[1].Details.Displacement).Rename = "TriggerUnitIndex"; // a9, 9d [0]
                cl.Value.OpList.First(c => c.structOff == (uint)objRegs[2].Details.Displacement).Rename = "ActorId"; // ad
                cl.Value.OpList.First(c => c.structOff == (uint)objRegs[3].Details.Displacement).Rename = "Signal"; // 13f
            }
            if (nameToOpcode.ContainsKey("PKTStatusEffectRemoveNotify"))
            {
                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTStatusEffectRemoveNotify");
                cl.Value.OpList.First(c => c.dumpedClass > 0x2000).Rename = "InstanceIds";
                cl.Value.OpList.First(c => c.dumpedClass == 1).Rename = "Reason";
                cl.Value.OpList.First(c => c.dumpedClass == 8).Rename = "ObjectId";
            }
            if (nameToOpcode.ContainsKey("PKTPartyStatusEffectAddNotify"))
            {
                var handler = nameToHandler["PKTPartyStatusEffectAddNotify"];
                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTPartyStatusEffectAddNotify");
                var disasm = disassembler.Disassemble(sigScan.m_vDumpedRegion.Skip((int)((Int64)handler - (Int64)sigScan.Address)).Take(0x1000).ToArray());
                var objRegs = disasm.Where(i => i.Mnemonic == "mov" && i.Details.Operands.Length == 2 && i.Details.Operands[0].Type == Gee.External.Capstone.X86.X86OperandType.Register && i.Details.Operands[0].Register.Name.StartsWith("r") && i.Details.Operands[1].Type == Gee.External.Capstone.X86.X86OperandType.Memory && i.Details.Operands[1].Memory.Base != null && i.Details.Operands[1].Memory.Base.Name.StartsWith("r") && !i.Details.Operands[1].Memory.Base.Name.StartsWith("rip")).ToList();

                cl.Value.OpList.First(c => c.dumpedClass == 8 && c.structOff == (uint)objRegs[0].Details.Displacement).Rename = "PartyId";
                cl.Value.OpList.Last(c => c.dumpedClass == 8 && String.IsNullOrEmpty(c.Rename)).Rename = "PlayerIdOnRefresh";
            }
            if (nameToOpcode.ContainsKey("PKTPartyStatusEffectRemoveNotify"))
            {
                var cl = Dumped.FirstOrDefault(c => c.Value.Name == "PKTPartyStatusEffectRemoveNotify");
                if (cl.Key > 0)
                {
                    cl.Value.OpList.First(c => c.dumpedClass == 8).Rename = "PartyId";
                    cl.Value.OpList.First(c => c.dumpedClass > 8).Rename = "StatusEffectIds";

                }
            }

            foreach (var cl in Dumped)
            {
                if ((int)cl.Value.ParseOffset > 0)
                {
                    if (cl.Value.OnlyReadsList) continue;
                    if (cl.Value.Name.Contains("_"))
                    {
                        GetReadInfo((UInt64)cl.Value.ParseOffset, out _, out _, out _, out UInt64 size, out bool customName);
                        cl.Value.Name = "sub" + cl.Value.Name.Substring(0, cl.Value.Name.IndexOf("_")) + size;
                    }
                }
            }
            foreach (var cl in Dumped)
            {
                if ((int)cl.Value.ParseOffset > 0)
                {
                    if (cl.Value.OnlyReadsList) continue;
                    DumpClass(cl.Value, region, out String baseClass, out String regionClass);
                    if (savePath.Contains("Headlost"))
                    {
                        File.WriteAllText(savePath + @"Packets\Steam\" + cl.Value.Name + ".cs", baseClass);
                    }
                    else
                    {
                        File.WriteAllText(savePath + @"Packets\Base\" + cl.Value.Name + ".cs", baseClass);
                        File.WriteAllText(savePath + @"Packets\" + region + @"\" + cl.Value.Name + ".cs", regionClass);
                    }
                }
            }

            aes = "";
            blowfish = "";


            var aesSigs = sigScan.FindPatterns("4C 8D 05 ? ? ? ? 41 8D 51 41 48 8D 0D ? ? ? ? FF 15 ? ? ? ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 84 C0 74 78 45 33 D2 4C 39 15 ? ? ? ? 76 60", process.MainModule.BaseAddress, process.MainModule.ModuleMemorySize);
            foreach (var aesSig in aesSigs)
            {
                var lea = new Byte[7];
                ReadProcessMemory(hProcess, aesSig, lea, lea.Length, out _);
                var stringOffset = aesSig + BitConverter.ToInt32(lea, 3) + lea.Length;
                var stringBytes = new Byte[0x100];
                ReadProcessMemory(hProcess, stringOffset, stringBytes, stringBytes.Length, out _);
                var unicodeBytes = new UInt16[0x80];
                Buffer.BlockCopy(stringBytes, 0, unicodeBytes, 0, stringBytes.Length);
                var lookingForVictory = Encoding.UTF8.GetString(unicodeBytes.TakeWhile(b => b != 0).Select(b => (Byte)b).ToArray());
                if (lookingForVictory.Contains("VictoryCrestLearnType"))
                {
                    var cmp = new Byte[7];
                    ReadProcessMemory(hProcess, aesSig + 0x2b, cmp, cmp.Length, out _);
                    var aesOffset = aesSig + 0x2b + BitConverter.ToInt32(cmp, 3) + cmp.Length + 8;
                    var aesBytes = new Byte[0x10];
                    ReadProcessMemory(hProcess, aesOffset, aesBytes, aesBytes.Length, out _);
                    aes = BitConverter.ToString(aesBytes).Replace("-", "");
                    break;
                }

            }

            NtResumeProcess(hProcess);
            CloseHandle(hProcess);
            process.Kill();
            sb.AppendLine("    }");
            sb.AppendLine("}");
            return sb.ToString();
        }
        [DllImport("kernel32")] static extern IntPtr OpenProcess(Int32 dwDesiredAccess, Boolean bInheritHandle, Int32 dwProcessId);
        [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("ntdll")] static extern Int32 NtCreateSection(out IntPtr sectionHandle, Int32 DesiredAccess, IntPtr objectAttributes, ref Int32 MaximumSize, UInt32 SectionPageProtection, Int32 AllocationAttributes, IntPtr fileHandle);
        [DllImport("ntdll")] static extern void NtResumeProcess(IntPtr processHandle);
        [DllImport("ntdll")] static extern void NtSuspendProcess(IntPtr processHandle);
        [DllImport("ntdll")] static extern Int32 NtUnmapViewOfSection(IntPtr processHandle, IntPtr baseAddress);
        [DllImport("ntdll")] static extern Int32 NtMapViewOfSection(IntPtr sectionHandle, IntPtr processHandle, ref IntPtr baseAddress, UIntPtr ZeroBits, Int32 commitSize, out Int32 SectionOffset, ref Int32 ViewSize, UInt32 InheritDisposition, Int32 allocationType, UInt32 win32Protect);

        [DllImport("kernel32")] static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32")] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, Int32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")] static extern IntPtr VirtualQueryEx(IntPtr handle, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION64 lpBuffer, UInt32 dwLength);
        [DllImport("kernel32")] static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

        [DllImport("kernel32")] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, Byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, Byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION64
        {
            public IntPtr BaseAddress;
            public ulong AllocationBase;
            public int AllocationProtect;
            public int __alignment1;
            public ulong RegionSize;
            public int State;
            public int Protect;
            public int Type;
            public int __alignment2;
        }
    }
}
