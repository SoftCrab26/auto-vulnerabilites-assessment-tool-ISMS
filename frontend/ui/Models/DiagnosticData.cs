using System.Text.Json.Serialization;
using System.Collections.Generic;

namespace ui.Models
{
    public class SystemInfo
    {
        [JsonPropertyName("target_os")]
        public string TargetOs { get; set; } = string.Empty;

        [JsonPropertyName("hostname")]
        public string Hostname { get; set; } = string.Empty;

        [JsonPropertyName("ip_address")]
        public string IpAddress { get; set; } = string.Empty;

        [JsonPropertyName("inspection_date")]
        public string InspectionDate { get; set; } = string.Empty;
    }

    public class DiagnosticItem
    {
        [JsonPropertyName("code")]
        public string Code { get; set; } = string.Empty;

        [JsonPropertyName("category")]
        public string Category { get; set; } = string.Empty;

        [JsonPropertyName("title")]
        public string Title { get; set; } = string.Empty;

        [JsonPropertyName("status")]
        public string Status { get; set; } = string.Empty; // Pass, Fail, N/A

        [JsonPropertyName("severity")]
        public string Severity { get; set; } = string.Empty; // High, Medium, Low

        [JsonPropertyName("description")]
        public string Description { get; set; } = string.Empty;

        [JsonPropertyName("evidence")]
        public string Evidence { get; set; } = string.Empty;

        [JsonPropertyName("remediation")]
        public string Remediation { get; set; } = string.Empty;

        [JsonPropertyName("processed_config")]
        public string ProcessedConfig { get; set; } = string.Empty;

        [JsonPropertyName("err_msg")]
        public string ErrMsg { get; set; } = string.Empty;
    }

    public class DiagnosticReport
    {
        public string FilePath { get; set; } = string.Empty;

        [JsonPropertyName("system_info")]
        public SystemInfo SystemInfo { get; set; } = new();

        [JsonPropertyName("diagnostics")]
        public List<DiagnosticItem> Diagnostics { get; set; } = new();
    }

    // Go result.go matching structures
    public class GoMitreAttack
    {
        [JsonPropertyName("tactic")]
        public string Tactic { get; set; } = string.Empty;

        [JsonPropertyName("techniques")]
        public List<string> Techniques { get; set; } = new();

        [JsonPropertyName("mitigations")]
        public List<string> Mitigations { get; set; } = new();
    }

    public class GoCheckResult
    {
        [JsonPropertyName("Code")]
        public string Code { get; set; } = string.Empty;

        [JsonPropertyName("Description")]
        public string Description { get; set; } = string.Empty;

        [JsonPropertyName("Status")]
        public int Status { get; set; } // 0=Good, 1=Vulnerable, 2=Interview, 3=Manual, 4=NotApplicable, 5=Error

        [JsonPropertyName("RawConfig")]
        public string RawConfig { get; set; } = string.Empty;

        [JsonPropertyName("VulnerableConfig")]
        public string VulnerableConfig { get; set; } = string.Empty;

        [JsonPropertyName("ProcessedConfig")]
        public string ProcessedConfig { get; set; } = string.Empty;

        [JsonPropertyName("ErrMsg")]
        public string ErrMsg { get; set; } = string.Empty;

        [JsonPropertyName("MitreAttack")]
        public GoMitreAttack MitreAttack { get; set; } = new();
    }
}
