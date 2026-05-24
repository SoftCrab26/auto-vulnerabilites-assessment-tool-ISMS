using Model.Vcode;

Dictionary<Enum, string> rawConfig = new Dictionary<Enum, string>();
foreach (VCode.Linux vcode in Enum.GetValues(typeof(VCode.Linux)))
{
    rawConfig[vcode] = "s";
}
VulnScanner vulnScanner= new VulnScanner();

vulnScanner.Scan(rawConfig);