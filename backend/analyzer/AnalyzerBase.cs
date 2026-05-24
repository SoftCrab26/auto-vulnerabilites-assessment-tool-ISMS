public abstract class AnalyzerBase : IAnalyzer
{
    public VulnResult Run(Enum VCode, string rawConfig)
    {
        return new VulnResult(VCode, Check(rawConfig), CreateConfigSummary(rawConfig), rawConfig);
    }

    protected abstract Status Check(string rawConfig);
    protected abstract string CreateConfigSummary(string rawConfig);
}