using System;
using System.IO;
using System.Text.Json;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Runtime.InteropServices;

namespace Generator
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
        public string Status { get; set; } = string.Empty;

        [JsonPropertyName("severity")]
        public string Severity { get; set; } = string.Empty;

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
        public int Status { get; set; }

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

    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                string testDataDir = @"c:\Users\khkim\source\repos\SoftCrab26\auto-vulnerabilites-assessment-tool-ISMS\frontend\ui\test_data";
                string templatePath = @"c:\Users\khkim\source\repos\SoftCrab26\auto-vulnerabilites-assessment-tool-ISMS\frontend\ui\ReportExample\1. UNIX_서버_취약점진단_상세결과보고서.xlsx";
                string outputDir = @"c:\Users\khkim\source\repos\SoftCrab26\auto-vulnerabilites-assessment-tool-ISMS\scratch";

                var reports = new List<DiagnosticReport>();
                var files = Directory.GetFiles(testDataDir, "*.json");

                foreach (var file in files)
                {
                    string fileBaseName = Path.GetFileNameWithoutExtension(file);
                    if (fileBaseName.IndexOf("unknown_host", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        continue;
                    }

                    var jsonString = File.ReadAllText(file);
                    var report = ParseJsonReport(jsonString, file);
                    if (report != null)
                    {
                        reports.Add(report);
                    }
                }

                var osGroups = reports.GroupBy(r => string.IsNullOrEmpty(r.SystemInfo.TargetOs) ? "UNIX" : r.SystemInfo.TargetOs.Trim().ToUpper());

                foreach (var group in osGroups)
                {
                    string osType = group.Key;
                    string baseFileName = $"{osType}_서버_취약점진단_상세결과보고서_TEST";
                    string outputPath = GetUniqueFilePath(outputDir, baseFileName, ".xlsx");

                    Console.WriteLine($"Generating report for {osType} -> {outputPath}...");
                    GenerateExcelDetailedReport(templatePath, outputPath, group.ToList(), osType);
                    
                    Console.WriteLine("Verifying generated report file...");
                    if (VerifyGeneratedExcel(outputPath))
                    {
                        Console.WriteLine("VERIFICATION SUCCESS: Report opened cleanly and charts are intact.");
                    }
                    else
                    {
                        Console.WriteLine("VERIFICATION FAILED: Report is corrupted or charts are missing!");
                    }
                    Console.WriteLine($"Generated successfully.");
                }

                Console.WriteLine("=== TARGETS SHEET FORMAT CHECK ===");
                string checkPath = Path.Combine(outputDir, "LINUX_서버_취약점진단_상세결과보고서_TEST.xlsx");
                Type? checkExcelType = Type.GetTypeFromProgID("Excel.Application");
                dynamic checkExcel = Activator.CreateInstance(checkExcelType!)!;
                dynamic checkWb = checkExcel.Workbooks.Open(checkPath);
                dynamic checkWs = checkWb.Worksheets["점검대상"];
                for (int r = 6; r <= 16; r++)
                {
                    dynamic rng = checkWs.Cells[r, 2]; // B열
                    Console.WriteLine($"Row {r} | Hostname: {rng.Value} | BgColor: {rng.Interior.Color} | FontSize: {rng.Font.Size} | FontName: {rng.Font.Name}");
                }
                Console.WriteLine("=== SECURITY SHEET FORMAT CHECK ===");
                dynamic checkWsSec = checkWb.Worksheets["보안수준 통계"];
                for (int r = 35; r <= 46; r++)
                {
                    dynamic rngVal = checkWsSec.Cells[r, 2]; // B열
                    dynamic rngStyle = checkWsSec.Cells[r, 1]; // A열 (장비 타입 스타일)
                    Console.WriteLine($"Row {r} | Hostname: {rngVal.Value} | A-BgColor: {rngStyle.Interior.Color} | A-FontSize: {rngStyle.Font.Size} | A-FontName: {rngStyle.Font.Name}");
                }

                checkWb.Close(SaveChanges: false);
                checkExcel.Quit();
                Marshal.ReleaseComObject(checkWb);
                Marshal.ReleaseComObject(checkExcel);

                Console.WriteLine("ALL REPORTS COMPLETED.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error occurred: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }

        static DiagnosticReport? ParseJsonReport(string jsonString, string filename)
        {
            try
            {
                var report = JsonSerializer.Deserialize<DiagnosticReport>(jsonString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (report != null && report.Diagnostics != null && report.Diagnostics.Count > 0)
                {
                    report.FilePath = filename;
                    return report;
                }
            }
            catch { }

            try
            {
                var goResults = JsonSerializer.Deserialize<List<GoCheckResult>>(jsonString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (goResults != null && goResults.Count > 0)
                {
                    return ConvertGoResultsToReport(goResults, filename);
                }
            }
            catch { }

            return null;
        }

        static DiagnosticReport ConvertGoResultsToReport(List<GoCheckResult> goResults, string filename)
        {
            var report = new DiagnosticReport { FilePath = filename };
            string fileBaseName = Path.GetFileNameWithoutExtension(filename);
            
            // 파일명에서 호스트명 및 IP 추출 (형식: hostname_IP)
            string hostname = "UNKNOWN";
            string ipAddress = "0.0.0.0";
            
            int underscoreIdx = fileBaseName.LastIndexOf('_');
            if (underscoreIdx > 0)
            {
                hostname = fileBaseName.Substring(0, underscoreIdx);
                ipAddress = fileBaseName.Substring(underscoreIdx + 1);
            }
            else
            {
                hostname = fileBaseName;
            }

            report.SystemInfo = new SystemInfo
            {
                TargetOs = "Linux",
                Hostname = hostname,
                IpAddress = ipAddress,
                InspectionDate = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
            };

            foreach (var goRes in goResults)
            {
                string statusStr = goRes.Status switch
                {
                    0 => "Pass",
                    1 => "Fail",
                    4 => "N/A",
                    2 => "N/A",
                    3 => "N/A",
                    5 => "Fail",
                    _ => "N/A"
                };

                report.Diagnostics.Add(new DiagnosticItem
                {
                    Code = goRes.Code,
                    Category = "기타",
                    Title = goRes.Description,
                    Status = statusStr,
                    Severity = "Medium",
                    Description = goRes.Description,
                    Evidence = $"[검출된 설정값 (ProcessedConfig)]\n{goRes.ProcessedConfig}\n\n[진단 로그 / 설정 원본 (RawConfig)]\n{goRes.RawConfig}" + 
                               (!string.IsNullOrEmpty(goRes.ErrMsg) ? $"\n\n[오류 메시지]\n{goRes.ErrMsg}" : ""),
                    Remediation = "",
                    ProcessedConfig = goRes.ProcessedConfig,
                    ErrMsg = goRes.ErrMsg
                });
            }

            return report;
        }

        static void GenerateExcelDetailedReport(string templatePath, string outputPath, List<DiagnosticReport> osReports, string osType)
        {
            File.Copy(templatePath, outputPath, true);

            Type? excelType = Type.GetTypeFromProgID("Excel.Application");
            if (excelType == null)
            {
                throw new Exception("Excel is not installed on this system.");
            }

            dynamic excel = Activator.CreateInstance(excelType)!;
            dynamic? wb = null;

            try
            {
                excel.Visible = false;
                excel.DisplayAlerts = false;

                wb = excel.Workbooks.Open(outputPath);

                // 1. 표지 시트 날짜 업데이트
                dynamic wsCover = wb.Worksheets["표지"];
                if (wsCover != null)
                {
                    wsCover.Range("H19").Value = DateTime.Now.ToString("yyyy.MM.");
                }

                // 2. 점검대상 시트 처리
                dynamic wsTargets = wb.Worksheets["점검대상"];
                if (wsTargets != null)
                {
                    int hostCount = osReports.Count;
                    if (hostCount > 1)
                    {
                        dynamic row7 = wsTargets.Rows[7];
                        row7.Copy();
                        for (int i = 0; i < hostCount - 1; i++)
                        {
                            wsTargets.Rows[8].Insert();
                        }
                        excel.CutCopyMode = false;
                    }

                    for (int i = 0; i < hostCount; i++)
                    {
                        int r = 7 + i;
                        var rep = osReports[i];

                        wsTargets.Cells[r, 1].Formula = @"=HYPERLINK(""["" & MID(CELL(""filename""),SEARCH(""["",CELL(""filename""))+1, SEARCH(""]"",CELL(""filename""))-SEARCH(""["",CELL(""filename""))-1) & ""]'요약 통계'!"" & ADDRESS(4,ROW()+5,1,TRUE),ROW()-6)";
                        wsTargets.Cells[r, 2].Value = rep.SystemInfo.Hostname;
                        wsTargets.Cells[r, 3].Value = rep.SystemInfo.TargetOs;
                        wsTargets.Cells[r, 4].Value = rep.SystemInfo.IpAddress;
                        wsTargets.Cells[r, 5].Value = "";
                        wsTargets.Cells[r, 6].Value = "";
                        wsTargets.Cells[r, 7].Value = "";
                        wsTargets.Cells[r, 8].Value = "";
                        wsTargets.Cells[r, 9].Formula = $"=IF(AND(SUM(F{r}:H{r})>=8, SUM(F{r}:H{r})<=9), \"1등급\", IF(AND(SUM(F{r}:H{r})>=6, SUM(F{r}:H{r})<=7), \"2등급\", IF(AND(SUM(F{r}:H{r})>=3, SUM(F{r}:H{r})<=5), \"3등급\", \"\")))";
                    }
                }

                // 3. 요약 통계 시트 처리
                dynamic wsSummary = wb.Worksheets["요약 통계"];
                if (wsSummary != null)
                {
                    int hostCount = osReports.Count;
                    if (hostCount > 1)
                    {
                        dynamic colL = wsSummary.Columns[12]; // L열
                        for (int i = 0; i < hostCount - 1; i++)
                        {
                            colL.Copy();
                            dynamic nextCol = wsSummary.Columns[13 + i];
                            nextCol.Insert(Shift: -4161); // xlShiftToRight = -4161
                        }
                        excel.CutCopyMode = false;
                    }

                    for (int i = 0; i < hostCount; i++)
                    {
                        int colNum = 12 + i;
                        string colLetter = GetColumnLetter(colNum);

                        wsSummary.Cells[4, colNum].Formula = @"=HYPERLINK(""["" & MID(CELL(""filename""),SEARCH(""["",CELL(""filename""))+1, SEARCH(""]"",CELL(""filename""))-SEARCH(""["",CELL(""filename""))-1) & ""]'"" & INDIRECT(ADDRESS(COLUMN()-5,2,1,TRUE,""점검대상"")) & ""'!A1"",INDIRECT(ADDRESS(COLUMN()-5,2,1,TRUE,""점검대상"")))";

                        for (int r = 6; r <= 72; r++)
                        {
                            wsSummary.Cells[r, colNum].Formula = $"=IFERROR(INDIRECT(ADDRESS(ROW()+22,15,1,TRUE,{colLetter}$4)),\"\")";
                        }

                        wsSummary.Cells[73, colNum].Formula = $"=COUNTIF({colLetter}6:{colLetter}72,\"양호\")+COUNTIF({colLetter}6:{colLetter}72,\"취약\")+COUNTIF({colLetter}6:{colLetter}72,\"부분만족\")+COUNTIF({colLetter}6:{colLetter}72,\"N/A\")";

                        for (int r = 75; r <= 78; r++)
                        {
                            wsSummary.Cells[r, colNum].Formula = $"=COUNTIF({colLetter}$6:{colLetter}$72,$J{r})";
                        }

                        for (int r = 80; r <= 91; r++)
                        {
                            wsSummary.Cells[r, colNum].Formula = $"=COUNTIFS($D$6:$D$72,$I${r},{colLetter}$6:{colLetter}$72,$J{r})";
                        }
                    }
                }

                // 4. 보안수준 통계 시트 처리
                dynamic wsSecurity = wb.Worksheets["보안수준 통계"];
                if (wsSecurity != null)
                {
                    int hostCount = osReports.Count;
                    if (hostCount > 1)
                    {
                        dynamic row36 = wsSecurity.Rows[36];
                        row36.Copy();
                        for (int i = 0; i < hostCount - 1; i++)
                        {
                            wsSecurity.Rows[37].Insert();
                        }
                        excel.CutCopyMode = false;
                    }

                    for (int i = 0; i < hostCount; i++)
                    {
                        int r = 36 + i;
                        var rep = osReports[i];

                        wsSecurity.Cells[r, 1].Value = osType.ToUpper();
                        wsSecurity.Cells[r, 2].Formula = $"=INDIRECT(ADDRESS(ROW()-29,2,1,TRUE,\"점검대상\"))";

                        for (int c = 3; c <= 10; c++)
                        {
                            wsSecurity.Cells[r, c].Formula = $"=IFERROR(INDIRECT(ADDRESS(23,COLUMN()+1,1,TRUE,$B{r})),0)";
                        }

                        wsSecurity.Cells[r, 11].Formula = $"=IF(I{r}=0,\"N/A\",((I{r}-J{r})/I{r})*1)";
                    }

                    int totalRow = 36 + hostCount;
                    for (int c = 3; c <= 10; c++)
                    {
                        string colLetter = GetColumnLetter(c);
                        wsSecurity.Cells[totalRow, c].Formula = $"=SUM({colLetter}36:{colLetter}{totalRow-1})";
                    }

                    wsSecurity.Cells[totalRow, 11].Formula = $"=SUM(K36:K{totalRow-1})/(COUNTA(K36:K{totalRow-1})-COUNTIF(K36:K{totalRow-1},\"N/A\"))";
                }

                // 5. 호스트별 상세 시트 복제 및 데이터 주입
                dynamic wsSample = wb.Worksheets["sample"];
                if (wsSample != null)
                {
                    dynamic wsDb = wb.Worksheets["기준 DB"];

                    for (int i = 0; i < osReports.Count; i++)
                    {
                        var rep = osReports[i];
                        string hostname = rep.SystemInfo.Hostname;

                        // 기존 동일 시트 존재 시 삭제
                        try
                        {
                            dynamic existing = wb.Worksheets[hostname];
                            if (existing != null)
                            {
                                existing.Delete();
                            }
                        }
                        catch { }

                        // Duplicate sheet using Excel COM native Copy
                        wsSample.Copy(Before: wsDb);
                        dynamic wsNew = excel.ActiveSheet;
                        wsNew.Name = hostname;

                        // Set Zoom scale to 75% and select Cell A1
                        wsNew.Select();
                        excel.ActiveWindow.Zoom = 75;
                        wsNew.Range("A1").Select();

                        wsNew.Range("C6").Value = rep.SystemInfo.Hostname;
                        wsNew.Range("C7").Value = rep.SystemInfo.IpAddress;

                        for (int r = 28; r <= 94; r++)
                        {
                            string code = wsNew.Cells[r, 3].Text.ToString().Trim();
                            if (string.IsNullOrEmpty(code)) continue;

                            var diag = rep.Diagnostics.FirstOrDefault(d => d.Code.Equals(code, StringComparison.OrdinalIgnoreCase));
                            if (diag != null)
                            {
                                string resultKo = diag.Status.ToUpper() switch
                                {
                                    "PASS" => "양호",
                                    "FAIL" => "취약",
                                    "N/A" => "N/A",
                                    _ => diag.Status
                                };
                                wsNew.Cells[r, 15].Value = resultKo;
                                wsNew.Cells[r, 21].Value = diag.Evidence;

                                // ProcessedConfig가 있으면 운영현황(Q열, 17열)에 입력하고, 
                                // 비어있는 상태에서 ErrMsg가 있으면 ErrMsg를 대신 대입
                                string opStatus = string.Empty;
                                if (!string.IsNullOrEmpty(diag.ProcessedConfig))
                                {
                                    opStatus = diag.ProcessedConfig;
                                }
                                else if (!string.IsNullOrEmpty(diag.ErrMsg))
                                {
                                    opStatus = diag.ErrMsg;
                                }
                                wsNew.Cells[r, 17].Value = opStatus;
                            }
                            else
                            {
                                // 항목 누락 시 점검결과(O열, 15열)를 N/A로 하고 나머지는 비움
                                wsNew.Cells[r, 15].Value = "N/A";
                                wsNew.Cells[r, 17].Value = "";
                                wsNew.Cells[r, 21].Value = "";
                            }
                        }
                    }
                    try
                    {
                        wsSample.Delete();
                    }
                    catch { }
                }

                wb.Save();
            }
            finally
            {
                if (wb != null)
                {
                    wb.Close(SaveChanges: false);
                    Marshal.ReleaseComObject(wb);
                }
                excel.Quit();
                Marshal.ReleaseComObject(excel);
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        static bool VerifyGeneratedExcel(string filePath)
        {
            Type? excelType = Type.GetTypeFromProgID("Excel.Application");
            if (excelType == null) return false;

            dynamic excel = Activator.CreateInstance(excelType)!;
            dynamic? wb = null;
            try
            {
                excel.Visible = false;
                excel.DisplayAlerts = false;

                wb = excel.Workbooks.Open(filePath);
                
                if (wb.Worksheets.Count < 8)
                {
                    wb.Close(SaveChanges: false);
                    return false;
                }

                int totalSheets = wb.Worksheets.Count;
                for (int idx = 7; idx < totalSheets; idx++)
                {
                    dynamic ws = wb.Worksheets[idx];
                    if (ws.Shapes.Count < 2)
                    {
                        wb.Close(SaveChanges: false);
                        return false;
                    }
                }

                wb.Close(SaveChanges: false);
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (wb != null)
                {
                    System.Runtime.InteropServices.Marshal.ReleaseComObject(wb);
                }
                excel.Quit();
                System.Runtime.InteropServices.Marshal.ReleaseComObject(excel);
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        static string GetColumnLetter(int columnNumber)
        {
            int dividend = columnNumber;
            string columnName = String.Empty;
            int modulo;

            while (dividend > 0)
            {
                modulo = (dividend - 1) % 26;
                columnName = Convert.ToChar(65 + modulo).ToString() + columnName;
                dividend = (int)((dividend - modulo) / 26);
            }

            return columnName;
        }

        static string GetUniqueFilePath(string directory, string baseFileNameWithoutExtension, string extension)
        {
            string filePath = Path.Combine(directory, baseFileNameWithoutExtension + extension);
            if (!File.Exists(filePath))
            {
                return filePath;
            }

            int counter = 1;
            while (true)
            {
                filePath = Path.Combine(directory, $"{baseFileNameWithoutExtension} ({counter}){extension}");
                if (!File.Exists(filePath))
                {
                    return filePath;
                }
                counter++;
            }
        }
    }
}
