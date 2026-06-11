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

    public class GuidelineItem
    {
        [JsonPropertyName("os_type")]
        public string OsType { get; set; } = "Linux";

        [JsonPropertyName("code")]
        public string Code { get; set; } = string.Empty;

        [JsonPropertyName("title")]
        public string Title { get; set; } = string.Empty;

        [JsonPropertyName("remediation")]
        public string Remediation { get; set; } = string.Empty;

        [JsonPropertyName("pass_comment")]
        public string PassComment { get; set; } = string.Empty;

        [JsonPropertyName("fail_comment")]
        public string FailComment { get; set; } = string.Empty;
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
        static List<GuidelineItem> Guidelines = new();

        static void Main(string[] args)
        {
            try
            {
                string testDataDir = @"c:\Users\khkim\source\repos\SoftCrab26\auto-vulnerabilites-assessment-tool-ISMS\frontend\ui\test_data";
                string templatePath = @"c:\Users\khkim\source\repos\SoftCrab26\auto-vulnerabilites-assessment-tool-ISMS\frontend\ui\ReportExample\UNIX_서버_취약점진단_상세결과보고서.xlsx";
                string templateRiskPlanPath = @"c:\Users\khkim\source\repos\SoftCrab26\auto-vulnerabilites-assessment-tool-ISMS\frontend\ui\ReportExample\UNIX_서버_위험관리 계획서_양식.xlsm";
                string templateRiskEvalPath = @"c:\Users\khkim\source\repos\SoftCrab26\auto-vulnerabilites-assessment-tool-ISMS\frontend\ui\ReportExample\UNIX_서버_위험_분석_평가표_양식.xlsm";
                string outputDir = @"c:\Users\khkim\source\repos\SoftCrab26\auto-vulnerabilites-assessment-tool-ISMS\scratch";

                string guidelinesPath = Path.Combine(testDataDir, "..", "ReportExample", "guidelines.json");
                if (File.Exists(guidelinesPath))
                {
                    try
                    {
                        string jsonString = File.ReadAllText(guidelinesPath);
                        var items = JsonSerializer.Deserialize<List<GuidelineItem>>(jsonString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                        if (items != null)
                        {
                            Guidelines = items;
                        }
                    }
                    catch { }
                }

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
                    
                    // 1. 상세결과보고서
                    string baseFileName = $"{osType}_서버_취약점진단_상세결과보고서_TEST";
                    string outputPath = GetUniqueFilePath(outputDir, baseFileName, ".xlsx");

                    Console.WriteLine($"Generating detailed report for {osType} -> {outputPath}...");
                    GenerateExcelDetailedReport(templatePath, outputPath, group.ToList(), osType);
                    
                    Console.WriteLine("Verifying generated detailed report file...");
                    if (VerifyGeneratedExcel(outputPath))
                    {
                        Console.WriteLine("VERIFICATION SUCCESS: Detailed report opened cleanly.");
                    }
                    else
                    {
                        Console.WriteLine("VERIFICATION FAILED: Detailed report is corrupted or charts are missing!");
                    }

                    // 2. 위험관리 계획서
                    string baseRiskPlanName = $"{osType}_서버_위험관리_계획서_TEST";
                    string outputRiskPlanPath = GetUniqueFilePath(outputDir, baseRiskPlanName, ".xlsm");

                    Console.WriteLine($"Generating risk plan for {osType} -> {outputRiskPlanPath}...");
                    GenerateExcelRiskReport(templateRiskPlanPath, outputRiskPlanPath, group.ToList(), osType);

                    Console.WriteLine("Verifying generated risk plan file...");
                    if (VerifyGeneratedExcel(outputRiskPlanPath))
                    {
                        Console.WriteLine("VERIFICATION SUCCESS: Risk plan opened cleanly.");
                    }
                    else
                    {
                        Console.WriteLine("VERIFICATION FAILED: Risk plan is corrupted or charts are missing!");
                    }

                    // 3. 위험 분석 평가표
                    string baseRiskEvalName = $"{osType}_서버_위험_분석_평가표_TEST";
                    string outputRiskEvalPath = GetUniqueFilePath(outputDir, baseRiskEvalName, ".xlsm");

                    Console.WriteLine($"Generating risk evaluation for {osType} -> {outputRiskEvalPath}...");
                    GenerateExcelRiskReport(templateRiskEvalPath, outputRiskEvalPath, group.ToList(), osType);

                    Console.WriteLine("Verifying generated risk evaluation file...");
                    if (VerifyGeneratedExcel(outputRiskEvalPath))
                    {
                        Console.WriteLine("VERIFICATION SUCCESS: Risk evaluation opened cleanly.");
                    }
                    else
                    {
                        Console.WriteLine("VERIFICATION FAILED: Risk evaluation is corrupted or charts are missing!");
                    }
                }

                Console.WriteLine("=== DUMPING SECURITY SHEET FORMULAS ===");
                string checkPath = templateRiskPlanPath;
                Type? checkExcelType = Type.GetTypeFromProgID("Excel.Application");
                dynamic checkExcel = Activator.CreateInstance(checkExcelType!)!;
                dynamic checkWb = checkExcel.Workbooks.Open(checkPath);
                dynamic checkWsSec = checkWb.Worksheets["보안수준 통계"];
                List<string> debugFormulas = new List<string>();
                for (int r = 1; r <= 30; r++)
                {
                    for (int c = 1; c <= 15; c++)
                    {
                        dynamic cell = checkWsSec.Cells[r, c];
                        string valStr = cell.Formula.ToString();
                        if (valStr.StartsWith("="))
                        {
                            debugFormulas.Add($"Row {r} Col {c} ({cell.Address}): {valStr}");
                        }
                    }
                }
                File.WriteAllLines(Path.Combine(outputDir, "sec_formulas.txt"), debugFormulas);
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

                // 가이드라인 매칭 시도
                var guide = Guidelines.FirstOrDefault(g => g.OsType.Equals("Linux", StringComparison.OrdinalIgnoreCase) && g.Code.Equals(goRes.Code, StringComparison.OrdinalIgnoreCase));
                
                string passComm = guide != null ? guide.PassComment : "설정이 기준에 부합하여 안전합니다.";
                string failComm = guide != null ? guide.FailComment : "설정이 기준에 미달하여 취약합니다.";
                string baseRemediation = guide != null ? guide.Remediation : "";

                // U열에 들어갈 점검 현황(증적자료) 조립
                string statusSection = string.Empty;
                if (statusStr.Equals("Pass", StringComparison.OrdinalIgnoreCase))
                {
                    statusSection = passComm;
                }
                else if (statusStr.Equals("Fail", StringComparison.OrdinalIgnoreCase))
                {
                    statusSection = failComm;
                }
                else
                {
                    if (goRes.Status == 2)
                    {
                        statusSection = "인터뷰";
                    }
                    else
                    {
                        statusSection = "N/A";
                    }
                }

                string evidenceText = $"{statusSection}\n\n[검출된 설정값 (ProcessedConfig)]\n{goRes.ProcessedConfig}\n\n[진단 로그 / 설정 원본 (RawConfig)]\n{goRes.RawConfig}" + 
                                       (!string.IsNullOrEmpty(goRes.ErrMsg) ? $"\n\n[오류 메시지]\n{goRes.ErrMsg}" : "");

                report.Diagnostics.Add(new DiagnosticItem
                {
                    Code = goRes.Code,
                    Category = "기타",
                    Title = goRes.Description,
                    Status = statusStr,
                    Severity = "Medium",
                    Description = goRes.Description,
                    Evidence = evidenceText,
                    Remediation = baseRemediation,
                    ProcessedConfig = goRes.ProcessedConfig,
                    ErrMsg = goRes.ErrMsg
                });
            }

            return report;
        }

        static void GenerateExcelRiskReport(string templatePath, string outputPath, List<DiagnosticReport> osReports, string osType)
        {
            // 템플릿 파일을 결과 경로로 복사
            File.Copy(templatePath, outputPath, true);

            Type? excelType = Type.GetTypeFromProgID("Excel.Application");
            if (excelType == null)
            {
                throw new Exception("Excel is not installed on this system.");
            }

            dynamic excel = Activator.CreateInstance(excelType)!;
            dynamic? wb = null;

            // 상세결과보고서 템플릿의 기준 DB 정보 로드
            string detailTemplateFileName = "UNIX_서버_취약점진단_상세결과보고서.xlsx";
            string detailTemplatePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ReportExample", detailTemplateFileName);
            if (!File.Exists(detailTemplatePath))
            {
                string searchDir = AppDomain.CurrentDomain.BaseDirectory;
                for (int i = 0; i < 5; i++)
                {
                    string candidate = Path.Combine(searchDir, "ReportExample", detailTemplateFileName);
                    if (File.Exists(candidate))
                    {
                        detailTemplatePath = candidate;
                        break;
                    }
                    var parent = Directory.GetParent(searchDir);
                    if (parent == null) break;
                    searchDir = parent.FullName;
                }
            }

            var dbDict = new Dictionary<string, (string pass, string fail, string na)>(StringComparer.OrdinalIgnoreCase);
            
            dynamic? wbDetail = null;
            try
            {
                wbDetail = excel.Workbooks.Open(detailTemplatePath);
                dynamic wsDetailDb = wbDetail.Worksheets["기준 DB"];
                if (wsDetailDb != null)
                {
                    for (int r = 2; r <= 68; r++)
                    {
                        string code = wsDetailDb.Cells[r, 1].Text.ToString().Trim();
                        if (string.IsNullOrEmpty(code)) continue;
                        string passBase = wsDetailDb.Cells[r, 3].Text.ToString();
                        string failBase = wsDetailDb.Cells[r, 4].Text.ToString();
                        string naBase = wsDetailDb.Cells[r, 5].Text.ToString();
                        dbDict[code] = (passBase, failBase, naBase);
                    }
                }
            }
            catch { }
            finally
            {
                if (wbDetail != null)
                {
                    wbDetail.Close(SaveChanges: false);
                    Marshal.ReleaseComObject(wbDetail);
                }
            }

            try
            {
                excel.Visible = false;
                excel.DisplayAlerts = false;                wb = excel.Workbooks.Open(outputPath);

                // 1. 표지 시트 날짜 업데이트
                dynamic? wsCover = null;
                try
                {
                    wsCover = wb.Worksheets["표지"];
                }
                catch { }

                if (wsCover != null)
                {
                    wsCover.Range("H19").Value = DateTime.Now.ToString("yyyy.MM.");
                }

                int hostCount = osReports.Count;

                // 2. 점검대상 시트 처리
                dynamic wsTargets = wb.Worksheets["점검대상"];
                if (wsTargets != null)
                {
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

                        wsTargets.Cells[r, 2].Value = i + 1; // B열: 일련번호
                        wsTargets.Cells[r, 3].Value = rep.SystemInfo.Hostname; // C열: 호스트명
                        wsTargets.Cells[r, 4].Value = rep.SystemInfo.TargetOs; // D열: 운영체제
                        wsTargets.Cells[r, 5].Value = rep.SystemInfo.IpAddress; // E열: IP 주소
                        wsTargets.Cells[r, 6].Value = ""; // F열: 용도
                        wsTargets.Cells[r, 7].Value = 3; // G열: 중요도 C
                        wsTargets.Cells[r, 8].Value = 3; // H열: 중요도 I
                        wsTargets.Cells[r, 9].Value = 3; // I열: 중요도 A
                        wsTargets.Cells[r, 10].Formula = $"=IF(AND(SUM(G{r}:I{r})>=8, SUM(G{r}:I{r})<=9), \"1등급\", IF(AND(SUM(G{r}:I{r})>=6, SUM(G{r}:I{r})<=7), \"2등급\", IF(AND(SUM(G{r}:I{r})>=3, SUM(G{r}:I{r})<=5), \"3등급\", \"\")))"; // J열: 등급 수식
                    }
                }

                // 3. 잠재위험 및 대응책 DB 시트 처리
                dynamic wsDb = wb.Worksheets["잠재위험 및 대응책 DB"];
                if (wsDb != null)
                {
                    if (hostCount > 1)
                    {
                        dynamic colL = wsDb.Columns[12]; // L열
                        for (int i = 0; i < hostCount - 1; i++)
                        {
                            colL.Copy();
                            dynamic nextCol = wsDb.Columns[13 + i];
                            nextCol.Insert(Shift: -4161); // xlShiftToRight = -4161
                        }
                        excel.CutCopyMode = false;
                    }
                }

                // 4. 보안수준 통계 시트 처리
                dynamic wsSecurity = wb.Worksheets["보안수준 통계"];
                if (wsSecurity != null)
                {
                    if (hostCount > 1)
                    {
                        dynamic row31 = wsSecurity.Rows[31];
                        row31.Copy();
                        for (int i = 0; i < hostCount - 1; i++)
                        {
                            wsSecurity.Rows[32].Insert();
                        }
                        excel.CutCopyMode = false;
                    }

                    for (int i = 0; i < hostCount; i++)
                    {
                        int r = 31 + i;
                        var rep = osReports[i];

                        wsSecurity.Cells[r, 1].Value = osType.ToUpper(); // A열: 장비구분
                        wsSecurity.Cells[r, 2].Formula = $"=점검대상!C{7+i}"; // B열: 호스트명 참조
                    }

                    int totalRow = 31 + hostCount;
                    // 계 (SUM) 행 수식 갱신
                    for (int c = 4; c <= 10; c++)
                    {
                        string colLetter = GetColumnLetter(c);
                        wsSecurity.Cells[totalRow, c].Formula = $"=SUM({colLetter}31:{colLetter}{totalRow-1})";
                    }
                    wsSecurity.Cells[totalRow, 11].Formula = $"=SUM(K31:K{totalRow-1})/(COUNTA(K31:K{totalRow-1})-COUNTIF(K31:K{totalRow-1},\"N/A\"))";

                    // 비율 행 수식 갱신 (비율 행은 totalRow + 1)
                    int avgRow = totalRow + 1;
                    for (int c = 4; c <= 10; c++)
                    {
                        string colLetter = GetColumnLetter(c);
                        wsSecurity.Cells[avgRow, c].Formula = $"=IFERROR({colLetter}{totalRow}/$K${totalRow},\"-\")";
                    }
                    wsSecurity.Cells[avgRow, 11].Formula = $"=IFERROR(SUM(D{avgRow}:J{avgRow}),\"-\")";
                }

                // 5. 호스트별 상세 시트 복제 및 데이터 주입
                dynamic wsSample = wb.Worksheets["sample"];
                if (wsSample != null)
                {
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
                        wsSample.Copy(Before: wsDb); // wsDb (기준 DB) 바로 앞에 삽입
                        dynamic wsNew = excel.ActiveSheet;
                        wsNew.Name = hostname;

                        // Zoom 75% 및 A1 선택
                        wsNew.Select();
                        excel.ActiveWindow.Zoom = 75;
                        wsNew.Range("A1").Select();

                        wsNew.Range("D4").Value = rep.SystemInfo.Hostname;
                        wsNew.Range("D5").Value = rep.SystemInfo.IpAddress;
                        wsNew.Range("H4").Value = rep.SystemInfo.TargetOs;

                        // 21행(U-01)부터 87행(U-67)까지 데이터 주입
                        for (int r = 21; r <= 87; r++)
                        {
                            string code = wsNew.Cells[r, 4].Text.ToString().Trim(); // D열(4)이 항목 코드
                            if (string.IsNullOrEmpty(code)) continue;

                            var diag = rep.Diagnostics.FirstOrDefault(d => d.Code.Equals(code, StringComparison.OrdinalIgnoreCase));
                            if (diag != null)
                            {
                                string resultKo = diag.Status.ToUpper() switch
                                {
                                    "PASS" => "Y",
                                    "FAIL" => "N",
                                    "N/A" => "N/A",
                                    _ => diag.Status
                                };
                                wsNew.Cells[r, 13].Value = resultKo; // M열(13열) 결과: Y / N / N/A

                                // 상세결과보고서의 P열(점검현황) 값 조합하여 기입
                                string statusVal = string.Empty;
                                if (dbDict.TryGetValue(code, out var bases))
                                {
                                    if (diag.Status.Equals("Pass", StringComparison.OrdinalIgnoreCase))
                                    {
                                        statusVal = bases.pass + diag.Evidence;
                                    }
                                    else if (diag.Status.Equals("Fail", StringComparison.OrdinalIgnoreCase))
                                    {
                                        statusVal = bases.fail + diag.Evidence;
                                    }
                                    else // N/A
                                    {
                                        statusVal = bases.na + diag.Evidence;
                                    }
                                }
                                else
                                {
                                    statusVal = diag.Evidence; // fallback
                                }
                                wsNew.Cells[r, 15].Value = statusVal;
                            }
                            else
                            {
                                wsNew.Cells[r, 13].Value = "N/A";
                                wsNew.Cells[r, 15].Value = "";
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

                string ext = Path.GetExtension(filePath).ToLower();
                if (ext == ".xlsm")
                {
                    dynamic wsSec = wb.Worksheets["보안수준 통계"];
                    if (wsSec == null)
                    {
                        wb.Close(SaveChanges: false);
                        return false;
                    }
                    dynamic shapes = wsSec.Shapes;
                    if (shapes == null || shapes!.Count < 2)
                    {
                        wb.Close(SaveChanges: false);
                        return false;
                    }
                }
                else
                {
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
