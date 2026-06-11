using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Collections.Generic;
using ui.Models;
using OfficeOpenXml;

namespace ui.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private ObservableCollection<DiagnosticReport> _reports = new();
        private DiagnosticReport? _selectedReport;
        private string _selectedView = "Dashboard";
        private string _searchText = string.Empty;
        private string _selectedStatusFilter = "전체";
        private DiagnosticItem? _selectedDiagnosticItem;

        // 가이드라인 관리용 필드
        private ObservableCollection<GuidelineItem> _guidelines = new();
        private GuidelineItem? _selectedGuidelineItem;
        private string _selectedGuidelineOs = "Linux";

        // 통계용 필드
        private int _totalHosts;
        private int _totalItems;
        private int _totalPass;
        private int _totalFail;
        private int _totalNa;
        private double _passRate;

        // 보고서 생성 탭 설정 필드
        private bool _exportDetailReport = true;
        private bool _exportSummaryReport = false;
        private bool _exportActionPlan = false;
        private bool _integrateHosts = true;
        private string _exportPath = string.Empty;
        private string _exportLogs = string.Empty;
        private bool _isExporting;
        private int _exportProgress;

        public ObservableCollection<DiagnosticReport> Reports
        {
            get => _reports;
            set => SetProperty(ref _reports, value);
        }

        public DiagnosticReport? SelectedReport
        {
            get => _selectedReport;
            set
            {
                if (SetProperty(ref _selectedReport, value))
                {
                    OnPropertyChanged(nameof(FilteredDiagnostics));
                    SelectedDiagnosticItem = FilteredDiagnostics.FirstOrDefault();
                }
            }
        }

        public string SelectedView
        {
            get => _selectedView;
            set => SetProperty(ref _selectedView, value);
        }

        public string SearchText
        {
            get => _searchText;
            set
            {
                if (SetProperty(ref _searchText, value))
                {
                    OnPropertyChanged(nameof(FilteredDiagnostics));
                }
            }
        }

        public List<string> StatusFilters { get; } = new() { "전체", "양호 (Pass)", "취약 (Fail)", "이행 불가/해당 없음 (N/A)" };

        public string SelectedStatusFilter
        {
            get => _selectedStatusFilter;
            set
            {
                if (SetProperty(ref _selectedStatusFilter, value))
                {
                    OnPropertyChanged(nameof(FilteredDiagnostics));
                }
            }
        }

        public DiagnosticItem? SelectedDiagnosticItem
        {
            get => _selectedDiagnosticItem;
            set => SetProperty(ref _selectedDiagnosticItem, value);
        }

        public IEnumerable<DiagnosticItem> FilteredDiagnostics
        {
            get
            {
                if (SelectedReport == null) return Enumerable.Empty<DiagnosticItem>();

                var query = SelectedReport.Diagnostics.AsEnumerable();

                if (!string.IsNullOrWhiteSpace(SearchText))
                {
                    var text = SearchText.Trim().ToLower();
                    query = query.Where(item =>
                        item.Code.ToLower().Contains(text) ||
                        item.Category.ToLower().Contains(text) ||
                        item.Title.ToLower().Contains(text) ||
                        item.Description.ToLower().Contains(text)
                    );
                }

                if (!string.IsNullOrEmpty(SelectedStatusFilter) && SelectedStatusFilter != "전체")
                {
                    string statusEnglish = SelectedStatusFilter switch
                    {
                        "양호 (Pass)" => "Pass",
                        "취약 (Fail)" => "Fail",
                        "이행 불가/해당 없음 (N/A)" => "N/A",
                        _ => SelectedStatusFilter
                    };
                    query = query.Where(item => item.Status.Equals(statusEnglish, StringComparison.OrdinalIgnoreCase));
                }

                return query.ToList();
            }
        }

        // 통계 프로퍼티
        public int TotalHosts
        {
            get => _totalHosts;
            set => SetProperty(ref _totalHosts, value);
        }

        public int TotalItems
        {
            get => _totalItems;
            set => SetProperty(ref _totalItems, value);
        }

        public int TotalPass
        {
            get => _totalPass;
            set => SetProperty(ref _totalPass, value);
        }

        public int TotalFail
        {
            get => _totalFail;
            set => SetProperty(ref _totalFail, value);
        }

        public int TotalNa
        {
            get => _totalNa;
            set => SetProperty(ref _totalNa, value);
        }

        public double PassRate
        {
            get => _passRate;
            set => SetProperty(ref _passRate, value);
        }

        // 보고서 내보내기 프로퍼티
        public bool ExportDetailReport
        {
            get => _exportDetailReport;
            set => SetProperty(ref _exportDetailReport, value);
        }

        public bool ExportSummaryReport
        {
            get => _exportSummaryReport;
            set => SetProperty(ref _exportSummaryReport, value);
        }

        public bool ExportActionPlan
        {
            get => _exportActionPlan;
            set => SetProperty(ref _exportActionPlan, value);
        }

        public bool IntegrateHosts
        {
            get => _integrateHosts;
            set => SetProperty(ref _integrateHosts, value);
        }

        public string ExportPath
        {
            get => _exportPath;
            set => SetProperty(ref _exportPath, value);
        }

        public string ExportLogs
        {
            get => _exportLogs;
            set => SetProperty(ref _exportLogs, value);
        }

        public bool IsExporting
        {
            get => _isExporting;
            set => SetProperty(ref _isExporting, value);
        }

        public int ExportProgress
        {
            get => _exportProgress;
            set => SetProperty(ref _exportProgress, value);
        }

        // 가이드라인 관리용 프로퍼티
        public ObservableCollection<GuidelineItem> Guidelines
        {
            get => _guidelines;
            set
            {
                if (SetProperty(ref _guidelines, value))
                {
                    OnPropertyChanged(nameof(FilteredGuidelines));
                }
            }
        }

        public GuidelineItem? SelectedGuidelineItem
        {
            get => _selectedGuidelineItem;
            set => SetProperty(ref _selectedGuidelineItem, value);
        }

        public string SelectedGuidelineOs
        {
            get => _selectedGuidelineOs;
            set
            {
                if (SetProperty(ref _selectedGuidelineOs, value))
                {
                    OnPropertyChanged(nameof(FilteredGuidelines));
                    SelectedGuidelineItem = FilteredGuidelines.FirstOrDefault();
                }
            }
        }

        public List<string> GuidelineOsTypes { get; } = new() { "Linux", "Windows" };

        public IEnumerable<GuidelineItem> FilteredGuidelines
        {
            get
            {
                return Guidelines.Where(g => g.OsType.Equals(SelectedGuidelineOs, StringComparison.OrdinalIgnoreCase)).ToList();
            }
        }

        // 커맨드 목록
        public ICommand LoadFilesCommand { get; }
        public ICommand RemoveReportCommand { get; }
        public ICommand SelectViewCommand { get; }
        public ICommand ExportReportCommand { get; }
        public ICommand SelectExportPathCommand { get; }
        public ICommand SaveGuidelinesCommand { get; }

        public MainViewModel()
        {
            // EPPlus 라이선스 설정
            ExcelPackage.License.SetNonCommercialPersonal("SoftCrab26");

            LoadFilesCommand = new RelayCommand(_ => LoadFiles());
            RemoveReportCommand = new RelayCommand(p => RemoveReport(p));
            SelectViewCommand = new RelayCommand(v => SelectedView = v?.ToString() ?? "Dashboard");
            ExportReportCommand = new RelayCommand(_ => ExportReports(), _ => Reports.Count > 0 && !IsExporting);
            SelectExportPathCommand = new RelayCommand(_ => SelectExportPath());
            SaveGuidelinesCommand = new RelayCommand(_ => SaveGuidelines());

            // 기본 출력 디렉터리를 사용자 Downloads 폴더로 설정
            ExportPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

            LoadGuidelines();
            TryLoadSampleData();
        }

        private void LoadFiles()
        {
            var openFileDialog = new Microsoft.Win32.OpenFileDialog
            {
                Multiselect = true,
                Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                foreach (var filename in openFileDialog.FileNames)
                {
                    try
                    {
                        string fileBaseName = Path.GetFileNameWithoutExtension(filename);
                        if (fileBaseName.IndexOf("unknown_host", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            continue;
                        }

                        var jsonString = File.ReadAllText(filename);
                        var report = ParseJsonReport(jsonString, filename);
                        if (report != null)
                        {
                            var existing = Reports.FirstOrDefault(r => r.FilePath == filename);
                            if (existing != null) Reports.Remove(existing);

                            Reports.Add(report);
                        }
                        else
                        {
                            MessageBox.Show($"지원하지 않는 진단 결과 파일 포맷이거나 파일이 손상되었습니다: {Path.GetFileName(filename)}", "오류", MessageBoxButton.OK, MessageBoxImage.Error);
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"파일을 읽는 도중 오류가 발생했습니다: {Path.GetFileName(filename)}\n오류: {ex.Message}", "오류", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }

                if (SelectedReport == null && Reports.Count > 0)
                {
                    SelectedReport = Reports[0];
                }

                UpdateStatistics();
            }
        }

        private DiagnosticReport? ParseJsonReport(string jsonString, string filename)
        {
            try
            {
                // 형식 1: 메타데이터 감싸진 DiagnosticReport
                var report = JsonSerializer.Deserialize<DiagnosticReport>(jsonString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (report != null && report.Diagnostics != null && report.Diagnostics.Count > 0)
                {
                    report.FilePath = filename;
                    return report;
                }
            }
            catch
            {
                // 형식 1 실패 시 형식 2로 진행
            }

            try
            {
                // 형식 2: Go result.go의 []CheckResult 목록 형태
                var goResults = JsonSerializer.Deserialize<List<GoCheckResult>>(jsonString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (goResults != null && goResults.Count > 0)
                {
                    return ConvertGoResultsToReport(goResults, filename);
                }
            }
            catch
            {
                // 파싱 실패
            }

            return null;
        }

        private DiagnosticReport ConvertGoResultsToReport(List<GoCheckResult> goResults, string filename)
        {
            var report = new DiagnosticReport();
            report.FilePath = filename;

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
                // Status 매핑: 0=Good (Pass), 1=Vulnerable (Fail), 4=NotApplicable (N/A)
                // 2=Interview (N/A), 3=Manual (N/A), 5=Error (Fail)
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
                string baseRemediation = guide != null ? guide.Remediation : GetLinuxRemediationGuide(goRes.Code);

                // 조치 가이드 및 상세 구성
                string remediationText = string.Empty;
                if (goRes.MitreAttack != null && !string.IsNullOrEmpty(goRes.MitreAttack.Tactic))
                {
                    remediationText += $"[MITRE ATTACK 정보]\n- Tactic (전술): {goRes.MitreAttack.Tactic}\n- Techniques (기술): {string.Join(", ", goRes.MitreAttack.Techniques)}\n- Mitigations (완화조치): {string.Join(", ", goRes.MitreAttack.Mitigations)}\n\n";
                }

                if (!string.IsNullOrEmpty(goRes.VulnerableConfig))
                {
                    remediationText += $"[취약한 설정 분석 내용]\n{goRes.VulnerableConfig}\n\n";
                }

                remediationText += baseRemediation;

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

                string category = GetLinuxCategory(goRes.Code);
                string severity = GetLinuxSeverity(goRes.Code);

                report.Diagnostics.Add(new DiagnosticItem
                {
                    Code = goRes.Code,
                    Category = category,
                    Title = goRes.Description,
                    Status = statusStr,
                    Severity = severity,
                    Description = goRes.Description,
                    Evidence = evidenceText,
                    Remediation = remediationText,
                    ProcessedConfig = goRes.ProcessedConfig,
                    ErrMsg = goRes.ErrMsg
                });
            }

            return report;
        }

        private string GetLinuxCategory(string code)
        {
            if (string.IsNullOrEmpty(code) || !code.StartsWith("U-")) return "기타 서비스";

            if (int.TryParse(code.Substring(2), out int num))
            {
                if ((num >= 1 && num <= 5) || (num >= 44 && num <= 54))
                    return "계정 관리";
                if ((num >= 6 && num <= 18) || (num >= 55 && num <= 59))
                    return "파일 및 디렉터리 관리";
                if ((num >= 19 && num <= 41) || (num >= 60 && num <= 72))
                    return "서비스 관리";
                if (num == 42 || num == 43)
                    return "패치 및 로그 관리";
            }
            return "기타 서비스";
        }

        private string GetLinuxSeverity(string code)
        {
            if (string.IsNullOrEmpty(code) || !code.StartsWith("U-")) return "Medium";

            if (int.TryParse(code.Substring(2), out int num))
            {
                int[] highItems = { 1, 2, 3, 4, 7, 8, 13, 17, 20, 22, 24, 25, 28, 30, 31, 32, 35, 36, 44, 45, 46, 47, 48, 50, 54, 56, 57, 60, 61, 64, 65, 66, 67 };
                int[] lowItems = { 16, 42, 43, 59 };

                if (highItems.Contains(num)) return "High";
                if (lowItems.Contains(num)) return "Low";
                return "Medium";
            }
            return "Medium";
        }

        private string GetLinuxRemediationGuide(string code)
        {
            return code switch
            {
                "U-01" => "[ISMS-P 조치 가이드]\n/etc/ssh/sshd_config 파일 내 'PermitRootLogin' 설정을 'no'로 명시하고 SSH 서비스를 재시작하십시오.",
                "U-02" => "[ISMS-P 조치 가이드]\n/etc/security/pwquality.conf 및 /etc/pam.d/system-auth 파일에서 최소 길이(10자 이상) 및 문자 혼용(영문 대소문자, 숫자, 특수문자) 규칙을 강제 적용하십시오.",
                "U-03" => "[ISMS-P 조치 가이드]\n/etc/pam.d/system-auth 파일 내 pam_faillock.so 또는 pam_tally2.so 모듈을 설정하여 비밀번호 오입력 시(예: 5회) 계정이 임시 잠금되도록 조치하십시오.",
                "U-04" => "[ISMS-P 조치 가이드]\n섀도우 패스워드 방식을 사용하여 암호화된 비밀번호를 /etc/shadow에 분리 보관하고 해당 파일의 권한을 400 또는 000으로 제한하십시오.",
                "U-05" => "[ISMS-P 조치 가이드]\nPATH 환경변수 내에 '.'(현재 디렉터리)이나 공백이 포함되어 있지 않은지 profile 및 bashrc 파일을 검사하십시오.",
                "U-06" => "[ISMS-P 조치 가이드]\n소유자나 소유그룹이 존재하지 않는 불필요한 파일을 찾아 삭제하거나 적절한 관리자로 소유권을 이전하십시오.",
                "U-07" => "[ISMS-P 조치 가이드]\n/etc/passwd 파일의 쓰기 권한을 제한하여 일반 사용자가 해당 파일을 무단으로 수정하지 못하도록 조치하십시오.",
                "U-08" => "[ISMS-P 조치 가이드]\n/etc/shadow 파일의 읽기 권한을 root 계정으로만 제한하여 패스워드 해시값이 노출되지 않도록 조치하십시오.",
                "U-09" => "[ISMS-P 조치 가이드]\n/etc/hosts 파일의 권한을 600 또는 644로 설정하여 악의적인 사용자가 호스트 IP 매핑을 조작하지 못하게 하십시오.",
                "U-10" => "[ISMS-P 조치 가이드]\n/etc/xinetd.conf 파일 및 /etc/xinetd.d/ 디렉토리의 권한을 제한하여 비인가된 네트워크 서비스가 마음대로 실행되지 못하도록 설정하십시오.",
                "U-11" => "[ISMS-P 조치 가이드]\n/etc/syslog.conf 또는 /etc/rsyslog.conf 로그 설정 파일의 읽기 권한을 제한하여 중요 시스템 로그 설정을 보호하십시오.",
                "U-12" => "[ISMS-P 조치 가이드]\n/etc/services 파일의 권한을 644 이하로 제한하여 포트 서비스 매핑 정보 변조를 방지하십시오.",
                "U-13" => "[ISMS-P 조치 가이드]\n시스템 내 불필요한 SUID/SGID 설정이 적용된 바이너리를 확인하고 권한을 제거하여 권한 상승 공격 위험을 제거하십시오.",
                "U-14" => "[ISMS-P 조치 가이드]\n사용자 환경설정 파일 및 시작 프로그램 스크립트(.profile, .bashrc 등)의 쓰기 권한을 소유자 전용으로 수정하십시오.",
                "U-15" => "[ISMS-P 조치 가이드]\n누구나 쓰기가 가능한 World Writable 파일들을 검사하여 보안에 취약한 스크립트 실행 공격을 미연에 방지하십시오.",
                "U-16" => "[ISMS-P 조치 가이드]\n/dev 디렉토리 아래에 존재하지 않는 가짜 장치 파일이나 불필요한 파일을 주기적으로 검색하여 청소하십시오.",
                "U-17" => "[ISMS-P 조치 가이드]\n사용자 홈 디렉토리 내에 .rhosts 및 /etc/hosts.equiv 설정 파일을 삭제하고 무인증 원격 접속을 허용하지 마십시오.",
                "U-18" => "[ISMS-P 조치 가이드]\n/etc/hosts.allow 및 /etc/hosts.deny 설정을 이용해 인가된 관리자 IP대역에 대해서만 시스템 접근을 허용하십시오.",
                "U-19" => "[ISMS-P 조치 가이드]\n시스템 사용자 세부 정보를 유출할 수 있는 finger 서비스를 비활성화하고 제거하십시오.",
                "U-20" => "[ISMS-P 조치 가이드]\n익명 FTP(Anonymous FTP) 설정을 제거하여 인증되지 않은 익명 사용자의 파일 다운로드/업로드를 통제하십시오.",
                "U-21" => "[ISMS-P 조치 가이드]\nr 계열 서비스(rsh, rlogin, rexec)를 중지하고 암호화된 전송을 제공하는 SSH 서비스로 전면 교체하십시오.",
                "U-22" => "[ISMS-P 조치 가이드]\n/etc/cron.allow 및 /etc/cron.deny 파일을 구성하여 일반 사용자가 주기적 작업을 무단 등록하여 권한 상승 공격을 도모하지 못하도록 제어하십시오.",
                "U-23" => "[ISMS-P 조치 가이드]\necho, discard, daytime, chargen 등 잘 알려진 DoS 유발성 간이 네트워크 서비스들을 서비스 설정에서 주석 처리하거나 종료하십시오.",
                "U-24" => "[ISMS-P 조치 가이드]\n공유 저장소를 사용하지 않는 환경이라면 NFS(Network File System) 관련 대몬 서비스(nfs, rpbind)를 종료하고 비활성화하십시오.",
                "U-25" => "[ISMS-P 조치 가이드]\nNFS 서비스 사용 시 /etc/exports 파일에 root_squash 또는 all_squash 옵션을 명시하여 비인가 사용자가 호스트의 루트 권한을 획득하는 것을 방지하십시오.",
                "U-26" => "[ISMS-P 조치 가이드]\n자동 마운트 서비스(automountd)를 제거하여 비인가된 외장 매체나 디렉토리가 시스템에 무단 연결되지 않도록 조치하십시오.",
                "U-27" => "[ISMS-P 조치 가이드]\n원격 프로시저 호출(RPC) 관련 불필요한 서브 서비스들을 선별하여 종료하십시오.",
                "U-28" => "[ISMS-P 조치 가이드]\n중앙 계정 동기화 시 암호화되지 않은 프로토콜을 사용하는 NIS/NIS+ 서비스를 비활성화하거나 LDAP/Kerberos 등으로 마이그레이션하십시오.",
                "U-29" => "[ISMS-P 조치 가이드]\n인증 없이 파일을 다운로드받을 수 있는 tftp 및 talk 서비스를 설정 파일에서 비활성화하십시오.",
                "U-30" => "[ISMS-P 조치 가이드]\nSendmail 메일 서버 버전을 최신 버전으로 유지하여 알려진 버퍼 오버플로우 등의 원격 코드 실행 취약점을 패치하십시오.",
                "U-31" => "[ISMS-P 조치 가이드]\n/etc/mail/sendmail.cf에서 릴레이 제한 설정을 적용하여 외부 악의적 공격자가 메일 서버를 스팸 중계기로 악용하지 못하게 하십시오.",
                "U-32" => "[ISMS-P 조치 가이드]\n일반 사용자가 sendmail 명령어로 메일 대기 큐를 무단으로 열어보거나 시스템을 혼란하게 하지 못하도록 실행 제한(RestrictQueueRun) 설정을 적용하십시오.",
                "U-33" => "[ISMS-P 조치 가이드]\nBIND DNS 네임서버 버전을 점검하여 최신 보안 패치를 적용하십시오.",
                "U-34" => "[ISMS-P 조치 가이드]\n/etc/named.conf 파일에서 allow-transfer { none; }; 옵션을 지정하여 전체 DNS 영역 전송 요청을 신뢰된 서버로만 한정하십시오.",
                "U-35" => "[ISMS-P 조치 가이드]\n웹서버(Apache) 설정 파일에서 Indexes 옵션을 제거하여 디렉토리 파일 목록이 외부 브라우저에 무단 노출되지 않도록 차단하십시오.",
                "U-36" => "[ISMS-P 조치 가이드]\n웹 프로세스(httpd, nginx 등)가 root 권한이 아닌 별도의 보안이 적용된 전용 시스템 계정(nobody, apache 등)으로 실행되도록 구성하십시오.",
                "U-37" => "[ISMS-P 조치 가이드]\n웹서버 상위 디렉토리 참조 차단 설정을 적용하여 사용자가 URL 경로 조작을 통해 시스템 루트 파일을 들여다보지 못하도록 제한하십시오.",
                "U-38" => "[ISMS-P 조치 가이드]\n웹 루트 홈 디렉토리 내에 개발 중 남겨진 백업 파일(*.bak, *.old) 또는 임시 소스 코드 파일을 정기적으로 청소하십시오.",
                "U-39" => "[ISMS-P 조치 가이드]\n웹서버 설정에서 심볼릭 링크 사용(FollowSymLinks) 기능을 가급적 끄거나 신뢰된 사용자로 한정하여 웹서비스 영역 탈취를 예방하십시오.",
                "U-40" => "[ISMS-P 조치 가이드]\n파일 업로드/다운로드 파일의 크기(LimitRequestBody) 및 확장자 제한을 구현하여 서버 침투 및 웹쉘(Webshell) 공격을 방지하십시오.",
                "U-41" => "[ISMS-P 조치 가이드]\n웹서비스 홈 디렉토리 영역은 OS의 다른 핵심 디렉토리나 데이터 볼륨과 독립된 마운트 파티션으로 분리 운영하십시오.",
                "U-42" => "[ISMS-P 조치 가이드]\n운영체제 및 커널 보안 커뮤니티의 업데이트 권고를 반영하여 주기적인 패치 매니지먼트를 가동하십시오.",
                "U-43" => "[ISMS-P 조치 가이드]\nsyslog 및 인증 보안 로그(/var/log/secure 등)를 주 1회 이상 주기적으로 분석하고 감사 기록을 유지하십시오.",
                _ => "[ISMS-P 조치 가이드]\n주요정보통신기반시설 기술적 취약점 가이드라인을 참조하여 권한 설정 수정, 불필요 서비스 비활성화 또는 패치 적용 등의 조치를 취하십시오."
            };
        }

        private void RemoveReport(object? parameter)
        {
            if (parameter is DiagnosticReport report)
            {
                Reports.Remove(report);
                if (SelectedReport == report)
                {
                    SelectedReport = Reports.FirstOrDefault();
                }
                UpdateStatistics();
            }
        }

        private void SelectExportPath()
        {
            // Simple folder dialog or standard SaveFileDialog
            var saveFileDialog = new Microsoft.Win32.SaveFileDialog
            {
                Title = "보고서 저장 위치 선택",
                Filter = "Excel Files (*.xlsx)|*.xlsx",
                FileName = "Vulnerability_Report_Integrated"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                ExportPath = Path.GetDirectoryName(saveFileDialog.FileName) ?? string.Empty;
            }
        }

        private async void ExportReports()
        {
            if (!ExportDetailReport && !ExportSummaryReport && !ExportActionPlan)
            {
                MessageBox.Show("출력할 보고서 양식을 최소 하나 이상 선택해야 합니다.", "알림", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            IsExporting = true;
            ExportProgress = 0;
            ExportLogs = $"[{DateTime.Now:HH:mm:ss}] 보고서 생성 작업을 시작합니다...\n";

            try
            {
                if (!Directory.Exists(ExportPath))
                {
                    Directory.CreateDirectory(ExportPath);
                }

                // 1. 상세결과보고서 생성 (엑셀 템플릿 데이터 주입)
                if (ExportDetailReport)
                {
                    // Reports를 자산 타입(TargetOs) 별로 그룹화
                    var osGroups = Reports.GroupBy(r => string.IsNullOrEmpty(r.SystemInfo.TargetOs) ? "UNIX" : r.SystemInfo.TargetOs.Trim().ToUpper());
                    int totalGroups = osGroups.Count();
                    int currentGroup = 0;

                    foreach (var group in osGroups)
                    {
                        currentGroup++;
                        string osType = group.Key;
                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}] {osType} 계열 자산 상세결과보고서 생성 중... (총 {group.Count()}개 호스트)\n";

                        // 템플릿 파일 경로 확인
                        string templateFileName = "UNIX_서버_취약점진단_상세결과보고서.xlsx";
                        string templatePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ReportExample", templateFileName);

                        // 만약 로컬 디버그 경로(PreserveNewest)가 아닐 경우 프로젝트 폴더에서 탐색 시도
                        if (!File.Exists(templatePath))
                        {
                            string searchDir = AppDomain.CurrentDomain.BaseDirectory;
                            for (int i = 0; i < 5; i++)
                            {
                                string candidate = Path.Combine(searchDir, "ReportExample", templateFileName);
                                if (File.Exists(candidate))
                                {
                                    templatePath = candidate;
                                    break;
                                }
                                var parent = Directory.GetParent(searchDir);
                                if (parent == null) break;
                                searchDir = parent.FullName;
                            }
                        }

                        if (!File.Exists(templatePath))
                        {
                            throw new FileNotFoundException($"엑셀 상세결과보고서 템플릿 파일을 찾을 수 없습니다: {templateFileName}");
                        }

                        // 결과 파일 이름 결정
                        string cleanOsType = osType.Replace(" ", "_");
                        string baseFileName = $"{cleanOsType}_서버_취약점진단_상세결과보고서_{DateTime.Now:yyyyMMdd}";
                        string outputPath = GetUniqueFilePath(ExportPath, baseFileName, ".xlsx");
                        string outputFileName = Path.GetFileName(outputPath);

                        // 엑셀 생성을 백그라운드 스레드에서 수행
                        await System.Threading.Tasks.Task.Run(() =>
                        {
                            GenerateExcelDetailedReport(templatePath, outputPath, group.ToList(), osType);
                        });

                        // 엑셀 파일 무결성 및 차트(도형) 검증 수행
                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - 생성된 엑셀 파일 검증 중...\n";
                        bool isValid = await System.Threading.Tasks.Task.Run(() => VerifyGeneratedExcel(outputPath));
                        if (isValid)
                        {
                            ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - [검증 완료] 엑셀 무결성 및 차트 정상 확인\n";
                        }
                        else
                        {
                            ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - [경고] 엑셀 파일에 손상 및 차트 유실이 감지되었습니다!\n";
                        }

                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - {osType} 상세보고서 생성 완료: {outputFileName}\n";
                        ExportProgress = (int)((double)currentGroup / totalGroups * 70);
                    }
                }

                // 2. 위험관리 계획서 생성
                if (ExportSummaryReport)
                {
                    var osGroups = Reports.GroupBy(r => string.IsNullOrEmpty(r.SystemInfo.TargetOs) ? "UNIX" : r.SystemInfo.TargetOs.Trim().ToUpper());
                    int totalGroups = osGroups.Count();
                    int currentGroup = 0;

                    foreach (var group in osGroups)
                    {
                        currentGroup++;
                        string osType = group.Key;
                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}] {osType} 계열 자산 위험관리 계획서 생성 중... (총 {group.Count()}개 호스트)\n";

                        // 템플릿 파일 경로 확인
                        string templateFileName = $"{osType}_서버_위험관리 계획서_양식.xlsm";
                        string templatePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ReportExample", templateFileName);

                        if (!File.Exists(templatePath))
                        {
                            // Fallback to UNIX template
                            templateFileName = "UNIX_서버_위험관리 계획서_양식.xlsm";
                            templatePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ReportExample", templateFileName);
                        }

                        if (!File.Exists(templatePath))
                        {
                            string searchDir = AppDomain.CurrentDomain.BaseDirectory;
                            for (int i = 0; i < 5; i++)
                            {
                                string candidate = Path.Combine(searchDir, "ReportExample", templateFileName);
                                if (File.Exists(candidate))
                                {
                                    templatePath = candidate;
                                    break;
                                }
                                var parent = Directory.GetParent(searchDir);
                                if (parent == null) break;
                                searchDir = parent.FullName;
                            }
                        }

                        if (!File.Exists(templatePath))
                        {
                            throw new FileNotFoundException($"위험관리 계획서 템플릿 파일을 찾을 수 없습니다: {templateFileName}");
                        }

                        // 결과 파일 이름 결정
                        string cleanOsType = osType.Replace(" ", "_");
                        string baseFileName = $"{cleanOsType}_서버_위험관리_계획서_{DateTime.Now:yyyyMMdd}";
                        string outputPath = GetUniqueFilePath(ExportPath, baseFileName, ".xlsm");
                        string outputFileName = Path.GetFileName(outputPath);

                        await System.Threading.Tasks.Task.Run(() =>
                        {
                            GenerateExcelRiskReport(templatePath, outputPath, group.ToList(), osType);
                        });

                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - 생성된 파일 검증 중...\n";
                        bool isValid = await System.Threading.Tasks.Task.Run(() => VerifyGeneratedExcel(outputPath));
                        if (isValid)
                        {
                            ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - [검증 완료] 위험관리 계획서 무결성 확인\n";
                        }
                        else
                        {
                            ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - [경고] 위험관리 계획서 파일 검증 실패!\n";
                        }

                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - {osType} 위험관리 계획서 생성 완료: {outputFileName}\n";
                    }
                }

                // 3. 위험 분석 평가표 생성
                if (ExportActionPlan)
                {
                    var osGroups = Reports.GroupBy(r => string.IsNullOrEmpty(r.SystemInfo.TargetOs) ? "UNIX" : r.SystemInfo.TargetOs.Trim().ToUpper());
                    int totalGroups = osGroups.Count();
                    int currentGroup = 0;

                    foreach (var group in osGroups)
                    {
                        currentGroup++;
                        string osType = group.Key;
                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}] {osType} 계열 자산 위험 분석 평가표 생성 중... (총 {group.Count()}개 호스트)\n";

                        // 템플릿 파일 경로 확인
                        string templateFileName = $"{osType}_서버_위험_분석_평가표_양식.xlsm";
                        string templatePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ReportExample", templateFileName);

                        if (!File.Exists(templatePath))
                        {
                            templateFileName = "UNIX_서버_위험_분석_평가표_양식.xlsm";
                            templatePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ReportExample", templateFileName);
                        }

                        if (!File.Exists(templatePath))
                        {
                            string searchDir = AppDomain.CurrentDomain.BaseDirectory;
                            for (int i = 0; i < 5; i++)
                            {
                                string candidate = Path.Combine(searchDir, "ReportExample", templateFileName);
                                if (File.Exists(candidate))
                                {
                                    templatePath = candidate;
                                    break;
                                }
                                var parent = Directory.GetParent(searchDir);
                                if (parent == null) break;
                                searchDir = parent.FullName;
                            }
                        }

                        if (!File.Exists(templatePath))
                        {
                            throw new FileNotFoundException($"위험 분석 평가표 템플릿 파일을 찾을 수 없습니다: {templateFileName}");
                        }

                        string cleanOsType = osType.Replace(" ", "_");
                        string baseFileName = $"{cleanOsType}_서버_위험_분석_평가표_{DateTime.Now:yyyyMMdd}";
                        string outputPath = GetUniqueFilePath(ExportPath, baseFileName, ".xlsm");
                        string outputFileName = Path.GetFileName(outputPath);

                        await System.Threading.Tasks.Task.Run(() =>
                        {
                            GenerateExcelRiskReport(templatePath, outputPath, group.ToList(), osType);
                        });

                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - 생성된 파일 검증 중...\n";
                        bool isValid = await System.Threading.Tasks.Task.Run(() => VerifyGeneratedExcel(outputPath));
                        if (isValid)
                        {
                            ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - [검증 완료] 위험 분석 평가표 무결성 확인\n";
                        }
                        else
                        {
                            ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - [경고] 위험 분석 평가표 파일 검증 실패!\n";
                        }

                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - {osType} 위험 분석 평가표 생성 완료: {outputFileName}\n";
                    }
                }

                ExportProgress = 100;
                ExportLogs += $"[{DateTime.Now:HH:mm:ss}] 모든 보고서 생성이 완료되었습니다. 경로: {ExportPath}\n";
                MessageBox.Show($"모든 보고서가 성공적으로 생성되었습니다.\n저장 경로: {ExportPath}", "완료", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                ExportLogs += $"[{DateTime.Now:HH:mm:ss}] 오류 발생: {ex.Message}\n";
                MessageBox.Show($"보고서 생성 도중 오류가 발생했습니다:\n{ex.Message}", "오류", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                IsExporting = false;
            }
        }

        private void GenerateExcelRiskReport(string templatePath, string outputPath, List<DiagnosticReport> osReports, string osType)
        {
            // 템플릿 파일을 결과 경로로 복사
            File.Copy(templatePath, outputPath, true);

            Type? excelType = Type.GetTypeFromProgID("Excel.Application");
            if (excelType == null)
            {
                throw new Exception("Excel이 설치되어 있지 않습니다.");
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
                    System.Runtime.InteropServices.Marshal.ReleaseComObject(wbDetail);
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
                    wsCover.Range("I21").Value = DateTime.Now.ToString("yyyy.MM.");
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

                // 3. 요약 통계 시트 처리
                dynamic wsSummary = wb.Worksheets["요약 통계"];
                if (wsSummary != null)
                {
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

                        // 4행: 호스트명 참조 수식 주입
                        wsSummary.Cells[4, colNum].Formula = $"=INDIRECT(\"'\"&INDIRECT(\"점검대상!C\"&COLUMN()-5)&\"'!D4\")";

                        // 6~72행 (67개 항목): 상세 시트 M열 결과 참조 수식 주입
                        for (int r = 6; r <= 72; r++)
                        {
                            wsSummary.Cells[r, colNum].Formula = $"=INDIRECT(\"'\"&INDIRECT(\"점검대상!C\"&COLUMN()-5)&\"'!M\"&ROW()+15)";
                        }

                        // 73행 (전체항목 합계 - 배열 수식): N/A 제외 가중치 합
                        wsSummary.Cells[73, colNum].FormulaArray = $"=SUM(IF({colLetter}$6:{colLetter}$72<>\"N/A\",$F$6:$F$72))";

                        // 74행 (위험항목 합계): 취약(N) 가중치 합
                        wsSummary.Cells[74, colNum].Formula = $"=SUMIF({colLetter}$6:{colLetter}$72,\"=N\",$F$6:$F$72)";

                        // 75~77행 (Y, N, N/A 개수)
                        for (int r = 75; r <= 77; r++)
                        {
                            wsSummary.Cells[r, colNum].Formula = $"=COUNTIF({colLetter}$6:{colLetter}$72,$J{r})";
                        }

                        // 80행 (호스트명): =L$4
                        wsSummary.Cells[80, colNum].Formula = $"={colLetter}$4";

                        // 81~87행 (영역별 위험 등급 개수): 상세 시트의 M92~M98 참조
                        for (int r = 81; r <= 87; r++)
                        {
                            wsSummary.Cells[r, colNum].Formula = $"=INDIRECT(\"'\"&INDIRECT(\"점검대상!C\"&COLUMN()-5)&\"'!M\"&ROW()+11)";
                        }
                    }
                }

                // 4. 잠재위험 및 대응책 DB 시트 처리
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

                // 5. 보안수준 통계 시트 처리
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

                        // D~J열: HLOOKUP 공식 입력
                        for (int c = 4; c <= 10; c++)
                        {
                            wsSecurity.Cells[r, c].Formula = $"=HLOOKUP($B{r}, '요약 통계'!$80:$87, {c-2}, 0)";
                        }
                        // K열: 합계 공식 입력
                        wsSecurity.Cells[r, 11].Formula = $"=SUM(D{r}:J{r})";
                    }

                    int totalRow = 31 + hostCount;
                    // 계 (SUM) 행 수식 갱신 (D~K열 전체)
                    for (int c = 4; c <= 11; c++)
                    {
                        string colLetter = GetColumnLetter(c);
                        wsSecurity.Cells[totalRow, c].Formula = $"=SUM({colLetter}31:{colLetter}{totalRow-1})";
                    }

                    // 첫 번째 비율 행 수식 갱신 (비율 행은 totalRow + 1)
                    int avgRow = totalRow + 1;
                    for (int c = 4; c <= 10; c++)
                    {
                        string colLetter = GetColumnLetter(c);
                        wsSecurity.Cells[avgRow, c].Formula = $"=IFERROR({colLetter}{totalRow}/$K${totalRow},\"-\")";
                    }
                    wsSecurity.Cells[avgRow, 11].Formula = $"=IFERROR(SUM(D{avgRow}:J{avgRow}),\"-\")";

                    // 두 번째 비율 행 수식 갱신 (비율 행은 totalRow + 2)
                    int avgRow2 = totalRow + 2;
                    for (int c = 4; c <= 10; c++)
                    {
                        string colLetter = GetColumnLetter(c);
                        wsSecurity.Cells[avgRow2, c].Formula = $"=IFERROR({colLetter}{avgRow}/$K${avgRow},\"-\")";
                    }
                    wsSecurity.Cells[avgRow2, 11].Formula = $"=IFERROR(SUM(D{avgRow2}:J{avgRow2}),\"-\")";
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
                    System.Runtime.InteropServices.Marshal.ReleaseComObject(wb);
                }
                excel.Quit();
                System.Runtime.InteropServices.Marshal.ReleaseComObject(excel);
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        private void GenerateExcelDetailedReport(string templatePath, string outputPath, List<DiagnosticReport> osReports, string osType)
        {
            // 템플릿 파일을 결과 경로로 복사
            File.Copy(templatePath, outputPath, true);

            Type? excelType = Type.GetTypeFromProgID("Excel.Application");
            if (excelType == null)
            {
                throw new Exception("Excel이 설치되어 있지 않습니다.");
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
                    System.Runtime.InteropServices.Marshal.ReleaseComObject(wb);
                }
                excel.Quit();
                System.Runtime.InteropServices.Marshal.ReleaseComObject(excel);
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }

        private bool VerifyGeneratedExcel(string filePath)
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
                    // 호스트별 상세 시트(7번째 시트부터 마지막 바로 직전 시트까지)의 차트(도형) 개수가 2개인지 확인
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

        private string GetColumnLetter(int columnNumber)
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

        private string GetUniqueFilePath(string directory, string baseFileNameWithoutExtension, string extension)
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

        private void TryLoadSampleData()
        {
            try
            {
                string baseDir = AppDomain.CurrentDomain.BaseDirectory;
                string current = baseDir;
                for (int i = 0; i < 5; i++)
                {
                    string testDataPath = Path.Combine(current, "test_data");
                    if (Directory.Exists(testDataPath))
                    {
                        var files = Directory.GetFiles(testDataPath, "*.json");
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
                                Reports.Add(report);
                            }
                        }
                        break;
                    }
                    var parent = Directory.GetParent(current);
                    if (parent == null) break;
                    current = parent.FullName;
                }

                if (Reports.Count > 0)
                {
                    SelectedReport = Reports[0];
                    UpdateStatistics();
                }
            }
            catch
            {
                // Silent fail for sample data
            }
        }

        public void UpdateStatistics()
        {
            TotalHosts = Reports.Count;
            int items = 0;
            int pass = 0;
            int fail = 0;
            int na = 0;

            foreach (var r in Reports)
            {
                foreach (var item in r.Diagnostics)
                {
                    items++;
                    if (item.Status.Equals("Pass", StringComparison.OrdinalIgnoreCase)) pass++;
                    else if (item.Status.Equals("Fail", StringComparison.OrdinalIgnoreCase)) fail++;
                    else na++;
                }
            }

            TotalItems = items;
            TotalPass = pass;
            TotalFail = fail;
            TotalNa = na;

            PassRate = TotalItems > 0 ? Math.Round((double)TotalPass / TotalItems * 100, 1) : 0.0;
        }

        private string GetGuidelinesFilePath()
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string appDir = Path.Combine(localAppData, "ISMS_Analyzer");
            if (!Directory.Exists(appDir))
            {
                try
                {
                    Directory.CreateDirectory(appDir);
                }
                catch { }
            }
            string targetPath = Path.Combine(appDir, "guidelines.json");
            
            if (!File.Exists(targetPath))
            {
                string defaultPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ReportExample", "guidelines.json");
                if (File.Exists(defaultPath))
                {
                    try
                    {
                        File.Copy(defaultPath, targetPath, true);
                    }
                    catch { }
                }
            }
            
            return File.Exists(targetPath) ? targetPath : Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "ReportExample", "guidelines.json");
        }

        private void LoadGuidelines()
        {
            try
            {
                string guidelinesPath = GetGuidelinesFilePath();
                if (File.Exists(guidelinesPath))
                {
                    string jsonString = File.ReadAllText(guidelinesPath);
                    var items = JsonSerializer.Deserialize<List<GuidelineItem>>(jsonString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (items != null)
                    {
                        Guidelines = new ObservableCollection<GuidelineItem>(items);
                    }
                }

                bool updated = false;
                for (int num = 1; num <= 67; num++)
                {
                    string code = $"U-{num:D2}";
                    var existing = Guidelines.FirstOrDefault(g => g.OsType.Equals("Linux", StringComparison.OrdinalIgnoreCase) && g.Code.Equals(code, StringComparison.OrdinalIgnoreCase));
                    if (existing == null)
                    {
                        string title = GetLinuxTitle(code);
                        string remediation = GetLinuxRemediationGuide(code);
                        string passComm = $"{title} 설정이 안전하게 관리되고 있어 양호합니다.";
                        string failComm = $"{title} 설정이 취약하게 관리되고 있거나 비활성화되어 위험합니다.";

                        Guidelines.Add(new GuidelineItem
                        {
                            OsType = "Linux",
                            Code = code,
                            Title = title,
                            Remediation = remediation,
                            PassComment = passComm,
                            FailComment = failComm
                        });
                        updated = true;
                    }
                }

                if (updated)
                {
                    var options = new JsonSerializerOptions 
                    { 
                        WriteIndented = true, 
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Create(System.Text.Unicode.UnicodeRanges.All) 
                    };
                    string jsonString = JsonSerializer.Serialize(Guidelines, options);
                    File.WriteAllText(guidelinesPath, jsonString);
                }

                SelectedGuidelineItem = FilteredGuidelines.FirstOrDefault();
            }
            catch
            {
                // Silent fail
            }
        }

        private void SaveGuidelines()
        {
            try
            {
                string guidelinesPath = GetGuidelinesFilePath();
                var options = new JsonSerializerOptions 
                { 
                    WriteIndented = true, 
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.Create(System.Text.Unicode.UnicodeRanges.All) 
                };
                string jsonString = JsonSerializer.Serialize(Guidelines, options);
                File.WriteAllText(guidelinesPath, jsonString);
                MessageBox.Show("조치 가이드라인 및 점검현황 멘트가 성공적으로 저장되었습니다.", "알림", MessageBoxButton.OK, MessageBoxImage.Information);
                
                OnPropertyChanged(nameof(FilteredGuidelines));
            }
            catch (Exception ex)
            {
                MessageBox.Show($"가이드라인 저장 중 오류가 발생했습니다: {ex.Message}", "오류", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string GetLinuxTitle(string code)
        {
            return code switch
            {
                "U-01" => "root 계정 원격 접속 제한",
                "U-02" => "패스워드 복잡성 설정",
                "U-03" => "계정 잠금 임계값 설정",
                "U-04" => "패스워드 파일 보호",
                "U-05" => "패스 경로 설정",
                "U-06" => "파일 및 디렉터리 소유자 설정",
                "U-07" => "/etc/passwd 파일 소유자 및 권한 설정",
                "U-08" => "/etc/shadow 파일 소유자 및 권한 설정",
                "U-09" => "/etc/hosts 파일 소유자 및 권한 설정",
                "U-10" => "/etc/xinetd.conf 파일 소유자 및 권한 설정",
                "U-11" => "/etc/syslog.conf 파일 소유자 및 권한 설정",
                "U-12" => "/etc/services 파일 소유자 및 권한 설정",
                "U-13" => "SUID, SGID, 설정 파일 및 권한 설정",
                "U-14" => "사용자, 시스템 시작파일 및 환경설정 파일 소유자 및 권한 설정",
                "U-15" => "world writable 파일 점검",
                "U-16" => "/dev에 존재하지 않는 device 파일 점검",
                "U-17" => "$HOME/.rhosts, hosts.equiv 사용 금지",
                "U-18" => "접속 IP 및 포트 제한",
                "U-19" => "Finger 서비스 비활성화",
                "U-20" => "Anonymous FTP 비활성화",
                "U-21" => "r 계열 서비스 비활성화",
                "U-22" => "cron 파일 소유자 및 권한 설정",
                "U-23" => "DoS 유발 서비스 비활성화",
                "U-24" => "NFS 서비스 비활성화",
                "U-25" => "NFS 접근 통제",
                "U-26" => "automountd 비활성화",
                "U-27" => "RPC 서비스 비활성화",
                "U-28" => "NIS, NIS+ 서비스 비활성화",
                "U-29" => "tftp, talk 서비스 비활성화",
                "U-30" => "Sendmail 버전 점검",
                "U-31" => "Spam 메일 릴레이 제한",
                "U-32" => "일반사용자의 Sendmail 실행 방지",
                "U-33" => "DNS 보안 패치",
                "U-34" => "DNS Zone Transfer 설정",
                "U-35" => "웹서비스 디렉토리 리스팅 제거",
                "U-36" => "웹서비스 프로세스 권한 제한",
                "U-37" => "웹서비스 상위 디렉토리 접근 금지",
                "U-38" => "웹서비스 불필요한 파일 제거",
                "U-39" => "웹서비스 링크 파일 사용 금지",
                "U-40" => "웹서비스 파일 업로드 및 다운로드 제한",
                "U-41" => "웹서비스 영역의 분리",
                "U-42" => "최신 패치 적용",
                "U-43" => "로그의 정기적 검토 및 보고",
                _ => "주요 서비스 보안 설정 점검"
            };
        }
    }
}
