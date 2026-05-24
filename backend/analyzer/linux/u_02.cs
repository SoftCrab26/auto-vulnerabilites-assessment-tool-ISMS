using Model.Vcode;

namespace Analyzer;
class U_02Analyzer : IAnalyzer{
    private Status Check (string rawConfig){
        return Status.Pass;
    }

       public VulnResult Run(Enum VCode, string rawConfig){
        var status = Check(rawConfig);
        
        return new VulnResult(VCode, status ,rawConfig,rawConfig);
    }

}