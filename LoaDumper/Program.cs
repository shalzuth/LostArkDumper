using System.Net;
using LoaDumper;


var basePath = @"C:\Users\" + Environment.UserName + @"\Documents\GitHub\LostArkLogger\LostArkLogger\";
var steam = Region.Korea;
steam = Region.Steam;
HardCodes(steam, out String installDir, out String blowfish, out String aes);
DumpInfo(basePath, steam, installDir, blowfish, aes);

static void DumpInfo(String basePath, Region region, String installDir, String blowfish, String aes)
{
    File.WriteAllText(basePath + @"Packets\OpCodes_" + region + ".cs", PacketDumper.Dump(basePath, installDir, region, out String blowfish2, out String aes2));
    var regionPad = region == Region.Korea ? "kr" : "";
    File.WriteAllBytes(basePath + @"Resources\" + "oodle_state_" + region + ".bin", ObjectSerialize.Compress(ExtractLPK.Dump(installDir + @"EFGame\data1" + regionPad + ".lpk", blowfish, aes, "oodle_state.bin")));
    File.WriteAllBytes(basePath + @"Resources\" + "xor_" + region + ".bin", ObjectSerialize.Compress(Seed.GetXorTable(region.ToString())));
    ExtractLPK.ExtractDb(basePath, region, installDir, blowfish, aes);
}
static void HardCodes(Region region, out String installDir, out String blowfish, out String aes)
{
    installDir = blowfish = aes = "";
    if (region == Region.Steam) installDir = @"F:\Games\SteamLibrary\steamapps\common\Lost Ark\";
    if (region == Region.Steam) installDir = @"C:\Program Files (x86)\Steam\steamapps\common\Lost Ark\";
    if (region == Region.Korea) installDir = @"F:\Games\Games\LOSTARK\";
    if (region == Region.Korea) installDir = @"C:\Program Files (x86)\Steam\steamapps\common\Lost Ark\\";
    if (region == Region.Russia) installDir = @"F:\Games\LOSTARK\";
    //if (region == "jp") installDir = @"F:\Games\Games\LOSTARK\";
    if (region == Region.Steam) blowfish = @"83657ea6ffa1e671375c689a2e99a598";
    if (region == Region.Korea) blowfish = @"287f1d85be26e55a1d994e9e1bfd0df1";
    if (region == Region.Russia) blowfish = @"a7f33db20dfb711a16d5d3dd3d4cef4d";
    //if (region == "jp") blowfish = @"c66e7c755883b5a92227b6c1c71c1d94";
    if (region == Region.Steam) aes = @"1069d88738c5c75f82b44a1f0a382762";
    if (region == Region.Korea) aes = @"6ce3db2fbe338fba87edf2abf6453bfa";
    if (region == Region.Russia) aes = @"ee36ace0d87a9eaea565e6884a058b63";
    //if (region == "jp") aes = @"fail";
}
static void DLKorea()
{
    // post https://patchapi.onstove.com/apiv1/get_live_version
    // http://la.cdn.stovegame.net/stove/live/game/dpms_45/v542/plist.json
    // https://la.cdn.stovegame.net/stove/live/game/dpms_45/v543/3.gz // LostArk.exe
    // https://la.cdn.stovegame.net/stove/live/game/dpms_45/v543/4.gz // data.lpk
    var url = "https://patchapi.onstove.com/apiv1/get_live_version";
    var handler = new HttpClientHandler();
    handler.Proxy = new WebProxy("", 3128);
    handler.Proxy.Credentials = new NetworkCredential("", "");
    var httpClient = new HttpClient(handler);
    var request = new HttpRequestMessage(HttpMethod.Post, url);
    request.Content = new FormUrlEncodedContent(new List<KeyValuePair<string, string>> { new KeyValuePair<string, string>("service_code", "45") });// new StringContent(content);
    var response = httpClient.Send(request);
    var res = response.Content.ReadAsStringAsync().Result;
    var versionInfoUrl = res.Substring(res.IndexOf("http"));
    versionInfoUrl = versionInfoUrl.Substring(0, versionInfoUrl.IndexOf("json") + 4);

    var kr = new WebClient();
    //kr.Proxy = new WebProxy("", 80);
    kr.Proxy = handler.Proxy;

    var latestVersions = kr.DownloadString(versionInfoUrl);
    var exe = latestVersions.Substring(latestVersions.IndexOf("LOSTARK.exe"), 0x100).Split("|", StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    var data = latestVersions.Substring(latestVersions.IndexOf("/data.lpk"), 0x100).Split("|", StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    if (!File.Exists("LostArk_" + exe[1] + "_" + exe[2] + ".exe"))
        kr.DownloadFile("http://la.cdn.stovegame.net/stove/live/game/dpms_45/v" + exe[1] + "/" + exe[2] + ".gz", "LostArk_" + exe[1] + "_" + exe[2] + ".exe");
    if (!File.Exists("data_" + data[1] + "_" + data[2] + ".lpk"))
        kr.DownloadFile("http://la.cdn.stovegame.net/stove/live/game/dpms_45/v" + data[1] + "/" + data[2] + ".gz", "data_" + data[1] + "_" + data[2] + ".lpk");
    //var plist = kr.DownloadString("http://la.cdn.stovegame.net/stove/live/game/dpms_45/v542/plist.json");
}