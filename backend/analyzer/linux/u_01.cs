using Model.Vcode;

namespace Analyzer;
class U_01Analyzer : AnalyzerBase
{
    protected override Status Check(string rawConfig)
    {
        return Status.Pass;
    }

    protected override string CreateConfigSummary(string rawConfig)
    {
        return rawConfig;
    }

}