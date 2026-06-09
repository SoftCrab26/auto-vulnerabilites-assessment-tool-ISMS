using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace Generator
{
    class Program
    {
        static void Main(string[] args)
        {
            string linuxShPath = @"c:\Users\khkim\source\repos\SoftCrab26\auto-vulnerabilites-assessment-tool-ISMS\scripts\linux.sh";
            string outputDir = @"c:\Users\khkim\source\repos\SoftCrab26\auto-vulnerabilites-assessment-tool-ISMS\frontend\ui\test_data";

            if (!Directory.Exists(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            var lines = File.ReadAllLines(linuxShPath, Encoding.UTF8);
            var items = new List<(string Code, string Description)>();

            var regex = new Regex(@"^#\s*(U-\d{2})\s*(.*)$");

            foreach (var line in lines)
            {
                var match = regex.Match(line.Trim());
                if (match.Success)
                {
                    string code = match.Groups[1].Value;
                    string desc = match.Groups[2].Value.Trim();
                    items.Add((code, desc));
                }
            }

            // Ensure unique
            var uniqueItems = new Dictionary<string, string>();
            foreach (var item in items)
            {
                if (!uniqueItems.ContainsKey(item.Code))
                {
                    uniqueItems[item.Code] = item.Description;
                }
            }

            string[] hostnames = { "WEB-PROD-LIN01", "DB-REPL-LIN02", "MAIL-GATE-LIN03", "APP-API-LIN04", "BASTION-LIN05" };
            var rand = new Random();

            for (int h = 0; h < 5; h++)
            {
                var diagnostics = new List<object>();

                foreach (var kvp in uniqueItems)
                {
                    int statusVal = rand.Next(0, 3); // 0, 1, 2
                    if (statusVal == 2) statusVal = 4; // 0=Good, 1=Vulnerable, 4=NotApplicable

                    string vulnerableConfig = "";
                    string rawConfig = $"Check output: cat /etc/example_config for {kvp.Value}";
                    string processedConfig = "Config status: processed";

                    if (statusVal == 1)
                    {
                        vulnerableConfig = $"문제점: {kvp.Value} 관련 취약한 설정이 감지되었습니다.\n상세 내용: 권한 설정 오류 또는 불필요한 기능이 활성화 상태입니다.";
                    }

                    var mitreAttack = new
                    {
                        tactic = "Initial Access",
                        techniques = new[] { "T1078", "T1133" },
                        mitigations = new[] { "M1042" }
                    };

                    diagnostics.Add(new
                    {
                        Code = kvp.Key,
                        Description = kvp.Value,
                        Status = statusVal,
                        RawConfig = rawConfig,
                        VulnerableConfig = vulnerableConfig,
                        ProcessedConfig = processedConfig,
                        ErrMsg = "",
                        MitreAttack = mitreAttack
                    });
                }

                var options = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(diagnostics, options);

                string outputPath = Path.Combine(outputDir, $"linux_result_{h + 1}.json");
                File.WriteAllText(outputPath, json, Encoding.UTF8);
            }

            Console.WriteLine($"Generated 5 JSON test data files in: {outputDir}");
        }
    }
}
