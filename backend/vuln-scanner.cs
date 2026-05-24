
class VulnScanner{
    public List<VulnResult> Scan(
        Dictionary<Enum, string> rawConfigs)
    {
        var results =
            new List<VulnResult>();

        foreach(var item in rawConfigs)
        {
            IAnalyzer analyzer = AnalyzerFactory.Create(item.Key); // item.Key = VCode

            VulnResult result = analyzer.Run(item.Key,item.Value); //item.Value = rawConfig

            results.Add(result);

            Console.WriteLine(result.status);
        }

        return results;
    }
}