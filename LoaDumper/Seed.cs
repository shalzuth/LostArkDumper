using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace LoaDumper
{
    internal class Seed
    {
        static String rsaXml = "<RSAKeyValue><Modulus>rSVaV7qT/PmGpW9SRyWA/ulsdpxvcjgJLkeNYx0ageMBgscDGMswWk2V9DnxKYyfzT9eoQvC3xNCa1qFHRkFBSTfjqETcW40mNdcmPQmYtUBpNg1pp4uBfXF8LAtetm7wp5XI6KgYShtg+83vh0hU6yIqlBilSDpl7jAv7nru1OX0hhDIaKerhYZZv9GEXDUJmJkoN1araejriOlDS9u1uAUHKGHCSmje+zSolJG/C1Ut7kViWl5xoNtoNRUcKP8Io0MGJKKg3hxgLDktjZFjev5I7MaZDCg9VnrC4DaKKeyJ6aREFjRU3phR7RDJRcuwZLTCTdd9thuIIZPugxiuQ==</Modulus><Exponent>AQAB</Exponent><P>1v2WeN/Mq5z60F4rlwub6HRotLdIk5h12J5NXlC155UpQoecSpkzwHyAvxR36/rhDKbsWYhMlyilI4t5sAZylDa+XoMpea4tUCxhESqWX4DNRu8gmyXBVHkRFbfK/BgpWcoBnKuy2YadM0howGoS72Q6Dc02WYynRxOSloB6qwc=</P><Q>zixoZeek9SF4npPMwRPp2vQWqKZGhhNZ1azrKHCeNNeAOiTx+YHUiL07jPQYGjJkE0kLLv0WFGH0IMkyhHnAES6m4MEzL3DhuL+2AuOt2bxKMAgX4ZqAKuGd25uSwaABa+lHJqRVwa06On5VoUtUSaXhyPbl7E1kIkIN4fDSVD8=</Q><DP>Plulhn/bfLd2pHN8Dz6lxSHmsOwsl+rz25Xm+QFOEdLY+dwdwCF5uk4ihcnpEsBdAG92RG3dUUbPx2SQMjdcipLqWr2OjSWxLP0CVplUrnTMldOMUJP95IONKhB6Ru63J70JBKlkoeWCuTo6b/0Uau1WTWSFbCn45wvNS+wOKIc=</DP><DQ>lXMXUhcyOgbDOqAEokjfEbox2pp9MJ9CVWN9KtlHtSIpbvxs8uIrv9r8Gdauyf6REHG4S51lrey7XDC8D895bHsWuIETq2X2GUfOlhWYZebZGCwls4GdOnhFR3VkUjq8DQ8SZm5lQ3lgZhpB1COYu7IlEtn2HO6UkUi0a3132V0=</DQ><InverseQ>aHJdGTSXWGVxs4SXlDdtXhnNf7nonSn7nIuxovcZ0C+jQkV9EuksM9Ap1flpDYt1ynn8rIg2Xju0eREoIU9yP/lq/Ji0Uwcoq3HBD3+/uOQuxqHM0lsern4Gr53F17sF2mCbkzJAx6CbrjYv8AiumWl13lDeGtLUOFRMX5StW4Q=</InverseQ><D>mgq7X4WNF+nfktuBde613xRI/RWcSR/1ewkJjv5bkOcndvQbmzlaoVyZZpkOJ4sGuRIB3IGcM97snpoAB600vCjcBAbmR2pmvPwNU78TT6Z2OfRpdv0PsRnBqqrzK3L/CtzYZcnPqeDP3is7ipZcChdb1zqBGnAXonYqdeixAwybOFau41bm9QXhZRBvLWWWlXmgAo9iYoOBuym24IIVxo0fGgTo7PcbV/vYJH+gLPSF0JowHT74yHFBoJGqKL6NDuiT4NC24CCvfFWEP4am0lreHThRe4HKgdJPLTV/ncxmifjSjqBOJsNQpJEcqcMAduMS+WBriWQVOXZWnFA56Q==</D></RSAKeyValue>";
        public static Byte[] GetXorTable(String region)
        {
            var client = new TcpClient();
            if (region == "Steam") client.Connect(IPAddress.Parse("52.44.176.195"), 6010); // us
            if (region == "Korea") client.Connect(IPAddress.Parse("110.45.233.75"), 6010); // kr
            var stream = client.GetStream();
            using (var rsa = new RSACryptoServiceProvider(2048) { PersistKeyInCsp = false })
            {
                rsa.FromXmlString(rsaXml);
                var base64 = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                var cert = "-----BEGIN RSA PUBLIC KEY-----\n";
                for (var i = 0; i < base64.Length; i += 64) cert += base64.Substring(i, Math.Min(64, base64.Length - i)) + "\n";
                cert += "-----END RSA PUBLIC KEY-----\n";

                var packet = BitConverter.GetBytes((UInt16)0).ToList(); // packet length
                packet.AddRange(BitConverter.GetBytes((UInt16)1)); // opcode
                packet.Add(0); // uncompressed
                packet.Add(0); // unencrypted
                packet.AddRange(BitConverter.GetBytes((UInt64)0)); // counter
                packet.AddRange(BitConverter.GetBytes((UInt64)0)); // rand
                packet.AddRange(BitConverter.GetBytes(cert.Length));
                packet.AddRange(Encoding.UTF8.GetBytes(cert));
                var packetBytes = packet.ToArray();
                Array.Copy(BitConverter.GetBytes(packet.Count), packetBytes, 2);
                stream.Write(packetBytes, 0, packetBytes.Length);
            }
            {
                var buf = new byte[client.ReceiveBufferSize];
                var n = stream.Read(buf, 0, buf.Length);
                if (BitConverter.ToUInt16(buf) != n) throw new Exception("bad packet length");
                if (BitConverter.ToUInt16(buf, 2) != 2) throw new Exception("bad packet opcode");
                if (buf[5] != 0) throw new Exception("bad packet encryption");
                if (buf[4] == 2) buf = IronSnappy.Snappy.Decode(buf.Take(n).Skip(6).ToArray()).Skip(16).ToArray();

                var tableSize = 0x100;
                var xorTable = Enumerable.Range(0, tableSize).Select(s => (Byte)s).ToList();
                var seedBytes = BitConverter.GetBytes(BitConverter.ToUInt32(buf, 0));
                var o = (Byte)0;
                for (var i = 0; i < tableSize; i++)
                {
                    var index = xorTable[i];
                    o = (Byte)(seedBytes[i % 4] + index + o);
                    var tempSwap = xorTable[o];
                    xorTable[o] = index;
                    xorTable[i] = tempSwap;
                }

                return xorTable.ToArray();
            }
        }
    }
}
