using System.Text.Json.Serialization;

namespace ui.Models
{
    public class GuidelineItem
    {
        [JsonPropertyName("os_type")]
        public string OsType { get; set; } = "Linux"; // Linux, Windows 등

        [JsonPropertyName("code")]
        public string Code { get; set; } = string.Empty; // U-01, U-02 등

        [JsonPropertyName("title")]
        public string Title { get; set; } = string.Empty; // 항목명

        [JsonPropertyName("remediation")]
        public string Remediation { get; set; } = string.Empty; // 기술적 조치 및 가이드라인

        [JsonPropertyName("pass_comment")]
        public string PassComment { get; set; } = string.Empty; // 양호 시 점검현황 멘트

        [JsonPropertyName("fail_comment")]
        public string FailComment { get; set; } = string.Empty; // 취약 시 점검현황 멘트
    }
}
