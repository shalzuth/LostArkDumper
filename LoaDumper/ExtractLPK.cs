using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LoaDumper
{
    internal class ExtractLPK
    {
        static void DumpAll(SQLiteConnection connect, String k, Dictionary<String, String> d, String language = "")
        {
            using (SQLiteCommand fmd = connect.CreateCommand())
            {
                fmd.CommandType = System.Data.CommandType.Text;
                fmd.CommandText = @"SELECT * FROM GameMsg" + language + " WHERE KEY LIKE '%" + k + "%'";
                var r = fmd.ExecuteReader();
                while (r.Read())
                {
                    d.Add(Convert.ToString(r["KEY"]), Convert.ToString(r["MSG"]));
                }
            }
        }
        public static Byte[] Dump(String lpkPath, String blowfish, String aes, String fileToDump = "")
        {
            //var lpkPath = @"C:\Program Files (x86)\Steam\steamapps\common\Lost Ark\EFGame\config.lpk";// args[0];
            //lpkPath = @"C:\Program Files (x86)\Steam\steamapps\common\Lost Ark\EFGame\data.lpk";// args[0];
            //lpkPath = @"C:\Program Files (x86)\Steam\steamapps\common\Lost Ark\EFGame\ReleasePC\Packages\0G1MAN0P84NX8I1MZZESXGZ.upk";// args[0];
            // lpkPath = @"C:\Program Files (x86)\Steam\steamapps\common\Lost Ark\EFGame\leveldata2.lpk";// args[0];

            using var fileStream = new FileStream(lpkPath, FileMode.Open, FileAccess.Read);
            using var binaryReader = new BinaryReader(fileStream);
            var numFiles = binaryReader.ReadInt32();
            const int entrySize = 528;
            var entriesSize = numFiles * entrySize;
            var dataOffset = entriesSize + 8;

            var bytes = binaryReader.ReadBytes(entriesSize);
            var bf = new Blowfish(Encoding.UTF8.GetBytes(blowfish)) { NonStandard = false, CompatMode = true };
            var decryptedBytes = bf.Decrypt_ECB(bytes);
            using var binaryReader2 = new BinaryReader(new MemoryStream(decryptedBytes));

            for (var i = 1; i <= numFiles; i++)
            {
                var fileNameLength = binaryReader2.ReadInt32();
                var fileName = new string(binaryReader2.ReadChars(fileNameLength));
                var filePath = new string(fileName).Replace("\\..\\", "").TrimStart('\\');
                var fileInfo = new FileInfo(Path.Combine("Output", filePath));
                binaryReader2.BaseStream.Seek(entrySize * i, SeekOrigin.Begin);
                binaryReader2.BaseStream.Seek(-12, SeekOrigin.Current);
                var rawSize = binaryReader2.ReadInt32();
                var encryptedSize = binaryReader2.ReadInt32();
                var compressedSize = binaryReader2.ReadInt32();

                binaryReader.BaseStream.Seek(dataOffset, SeekOrigin.Begin);
                dataOffset += encryptedSize;
                if (!filePath.Contains(fileToDump)) continue;
                if (fileToDump == "") continue;
                var encryptedBytes = binaryReader.ReadBytes(encryptedSize);
                if (compressedSize != 0)
                {
                    var decryptedFileData = bf.Decrypt_ECB(encryptedBytes);
                    var compressedStream = new MemoryStream(decryptedFileData);
                    using var decompressor = new ZLibStream(compressedStream, CompressionMode.Decompress);
                    var finalStream = new MemoryStream();
                    decompressor.CopyTo(finalStream);
                    return finalStream.ToArray();
                }
                else
                {
                    using var a = Aes.Create();
                    a.KeySize = 256;
                    a.BlockSize = 128;
                    a.Mode = CipherMode.CBC;
                    a.Padding = PaddingMode.None;
                    a.Key = SHA256.HashData(Encoding.ASCII.GetBytes(Convert.ToHexString(GetDbKey(fileInfo.Name, aes)).ToLower()));
                    a.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                    var blockOffset = 0;
                    var blockCount = encryptedSize / 1024;
                    for (var j = 0; j < blockCount; j++)
                    {
                        using var dec = a.CreateDecryptor();
                        dec.TransformBlock(encryptedBytes, blockOffset, 1024, encryptedBytes, blockOffset);
                        blockOffset += 1024;
                    }
                    return encryptedBytes;
                }
            }
            Console.WriteLine("err");
            return new Byte[0];
        }

        static byte[] GetDbKey(string fileName, string key)
        {
            var fileNameWithoutExtension = Path.GetFileNameWithoutExtension(fileName);
            fileNameWithoutExtension = fileNameWithoutExtension[(fileNameWithoutExtension.IndexOf('_') + 1)..];
            Console.WriteLine(fileNameWithoutExtension);
            var hashedName = MD5.HashData(Encoding.Unicode.GetBytes(fileNameWithoutExtension));
            //var xorKey = Convert.FromHexString("1069d88738c5c75f82b44a1f0a382762");
            //var xorKey = Convert.FromHexString("ee36ace0d87a9eaea565e6884a058b63");
            //var xorKey = Convert.FromHexString("6310ba0b09cac5e67474c324052bbf48");
            var xorKey = Convert.FromHexString(key);
            for (var i = 0; i < hashedName.Length; i++) hashedName[i] ^= xorKey[15 - i];
            Array.Reverse(hashedName, 0, hashedName.Length);
            return hashedName;
        }
        public static void ExtractDb(String basePath, Region region2, String installDir, String blowfish, String aes)
        {
            var region = region2.ToString();
            //File.WriteAllBytes("EFTable_Item.db", new DumpStaticFile().Dump("EFTable_Item.db"));
            var regionPad = region2 == Region.Korea ? "kr" : "";
            File.WriteAllBytes("EFTable_GameMsg" + region + ".db", Dump(installDir + @"EFGame\data2" + regionPad + ".lpk", blowfish, aes, "EFTable_GameMsg.db"));
            var englishDict = new Dictionary<string, string>();
            var language = "";
            if (region2 == Region.Steam) language = "_English";
            using (SQLiteConnection connect = new SQLiteConnection(@"Data Source=EFTable_GameMsg" + region + ".db"))
            {
                connect.Open();
                DumpAll(connect, "tip.name.monster", englishDict, language);
                //DumpAll(connect, "tip.name.ability");
                DumpAll(connect, "tip.name.skill_", englishDict, language);
                //DumpAll(connect, "tip.name.skillbuff_", englishDict);
            }
            File.WriteAllBytes(basePath + "Resources\\GameMsg" + language + ".bin", ObjectSerialize.Serialize(englishDict));

            //if (region2 != Region.Korea) return;

            File.WriteAllBytes("EFTable_Npc" + region + ".db", Dump(installDir + @"EFGame\data2.lpk", blowfish, aes, "EFTable_Npc.db"));
            var npc = new Dictionary<string, Tuple<String, String>>();
            using (SQLiteConnection connect = new SQLiteConnection(@"Data Source=EFTable_Npc" + region + ".db"))
            {
                connect.Open();
                using (SQLiteCommand fmd = connect.CreateCommand())
                {
                    fmd.CommandType = System.Data.CommandType.Text;
                    fmd.CommandText = @"SELECT * FROM Npc";
                    var r = fmd.ExecuteReader();
                    while (r.Read())
                    {
                        npc.Add(Convert.ToString(r["PrimaryKey"]), new Tuple<string, string>(Convert.ToString(r["Name"]), Convert.ToString(r["Comment"])));
                    }
                }
            }
            File.WriteAllBytes(basePath + "Resources\\Npc.bin", ObjectSerialize.Serialize(npc));

            File.WriteAllBytes("EFTable_Skill" + region + ".db", Dump(installDir + @"EFGame\data2.lpk", blowfish, aes, "EFTable_Skill.db"));
            var skill = new Dictionary<int, String[]>();
            using (SQLiteConnection connect = new SQLiteConnection(@"Data Source=EFTable_Skill" + region + ".db"))
            {
                connect.Open();
                using (SQLiteCommand fmd = connect.CreateCommand())
                {
                    fmd.CommandType = System.Data.CommandType.Text;
                    fmd.CommandText = @"SELECT * FROM Skill GROUP BY PrimaryKey";
                    var r = fmd.ExecuteReader();
                    while (r.Read())
                    {
                        skill.Add(int.Parse(Convert.ToString(r["PrimaryKey"])), new string[] { Convert.ToString(r["Name"]), Convert.ToString(r["Comment"]), Convert.ToString(r["LearnClass"]), Convert.ToString(r["Icon"]), Convert.ToString(r["IconIndex"]) });
                    }
                }
            }
            File.WriteAllBytes(basePath + "Resources\\Skill.bin", ObjectSerialize.Serialize(skill));

            File.WriteAllBytes("EFTable_SkillEffect" + region + ".db", Dump(installDir + @"EFGame\data2.lpk", blowfish, aes, "EFTable_SkillEffect.db"));
            var skillEffect = new Dictionary<int, String>();
            using (SQLiteConnection connect = new SQLiteConnection(@"Data Source=EFTable_SkillEffect" + region + ".db"))
            {
                connect.Open();
                using (SQLiteCommand fmd = connect.CreateCommand())
                {
                    fmd.CommandType = System.Data.CommandType.Text;
                    fmd.CommandText = @"SELECT * FROM SkillEffect GROUP BY PrimaryKey";
                    var r = fmd.ExecuteReader();
                    while (r.Read())
                    {
                        skillEffect.Add(int.Parse(Convert.ToString(r["PrimaryKey"])), Convert.ToString(r["Comment"]));
                    }
                }
            }
            File.WriteAllBytes(basePath + "Resources\\SkillEffect.bin", ObjectSerialize.Serialize(skillEffect));

            File.WriteAllBytes("EFTable_SkillBuff" + region + ".db", Dump(installDir + @"EFGame\data2.lpk", blowfish, aes, "EFTable_SkillBuff.db"));
            var skillBuff = new Dictionary<uint, String>();
            using (SQLiteConnection connect = new SQLiteConnection(@"Data Source=EFTable_SkillBuff" + region + ".db"))
            {
                connect.Open();
                using (SQLiteCommand fmd = connect.CreateCommand())
                {
                    fmd.CommandType = System.Data.CommandType.Text;
                    fmd.CommandText = @"SELECT * FROM SkillBuff GROUP BY PrimaryKey";
                    var r = fmd.ExecuteReader();
                    while (r.Read())
                    {
                        if (!skillBuff.ContainsKey(uint.Parse(Convert.ToString(r["PrimaryKey"]))))
                            skillBuff.Add(uint.Parse(Convert.ToString(r["PrimaryKey"])), Convert.ToString(r["Comment"]));
                    }
                }
            }
            File.WriteAllBytes(basePath + "Resources\\SkillBuff.bin", ObjectSerialize.Serialize(skillBuff));
        }
    }
}
