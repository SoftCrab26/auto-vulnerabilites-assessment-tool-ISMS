using Model.Vcode;

public class VulnResult
{
  
    public Enum VCode {get;set;}
    public Status status {get;set;}
    public string detail{get;set;}
    public string rawConfigDetail {get;set;}

    public VulnResult(Enum vcode, Status status, string detail,string rawConfigDetail){
        this.VCode = vcode;
        this.status = status;
        this.rawConfigDetail = rawConfigDetail;
    }
}