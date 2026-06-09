using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Collections.Generic;
using ui.Models;

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

        // 커맨드 목록
        public ICommand LoadFilesCommand { get; }
        public ICommand RemoveReportCommand { get; }
        public ICommand SelectViewCommand { get; }
        public ICommand ExportReportCommand { get; }
        public ICommand SelectExportPathCommand { get; }

        public MainViewModel()
        {
            LoadFilesCommand = new RelayCommand(_ => LoadFiles());
            RemoveReportCommand = new RelayCommand(p => RemoveReport(p));
            SelectViewCommand = new RelayCommand(v => SelectedView = v?.ToString() ?? "Dashboard");
            ExportReportCommand = new RelayCommand(_ => ExportReports(), _ => Reports.Count > 0 && !IsExporting);
            SelectExportPathCommand = new RelayCommand(_ => SelectExportPath());

            ExportPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "VulnerabilityReports");

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
            
            // 파일명에서 호스트명 및 IP 추출/유추
            string hostname = fileBaseName.Replace("linux_result_", "LINUX-SRV-0").ToUpper();
            string lastOctet = fileBaseName.Replace("linux_result_", "");
            if (!int.TryParse(lastOctet, out int ipLast)) ipLast = 10;

            report.SystemInfo = new SystemInfo
            {
                TargetOs = "Linux",
                Hostname = hostname,
                IpAddress = $"192.168.10.{100 + ipLast}",
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

                remediationText += GetLinuxRemediationGuide(goRes.Code);

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
                    Evidence = $"[검출된 설정값 (ProcessedConfig)]\n{goRes.ProcessedConfig}\n\n[진단 로그 / 설정 원본 (RawConfig)]\n{goRes.RawConfig}" + 
                               (!string.IsNullOrEmpty(goRes.ErrMsg) ? $"\n\n[오류 메시지]\n{goRes.ErrMsg}" : ""),
                    Remediation = remediationText
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

                int steps = Reports.Count;
                int currentStep = 0;

                foreach (var report in Reports)
                {
                    currentStep++;
                    ExportLogs += $"[{DateTime.Now:HH:mm:ss}] 호스트 [{report.SystemInfo.Hostname}] 진단 정보 처리 중...\n";
                    
                    // Simulate processing delay
                    await System.Threading.Tasks.Task.Delay(500);

                    if (ExportDetailReport)
                    {
                        string detailName = $"ISMS_Detailed_Report_{report.SystemInfo.Hostname}_{DateTime.Now:yyyyMMdd}.xlsx";
                        string fullPath = Path.Combine(ExportPath, detailName);
                        // Mock writing
                        await File.WriteAllTextAsync(Path.ChangeExtension(fullPath, ".txt"), 
                            $"Hostname: {report.SystemInfo.Hostname}\nOS: {report.SystemInfo.TargetOs}\nIP: {report.SystemInfo.IpAddress}\n" +
                            $"Total Checks: {report.Diagnostics.Count}\n" +
                            $"Pass: {report.Diagnostics.Count(d => d.Status.Equals("Pass", StringComparison.OrdinalIgnoreCase))}\n" +
                            $"Fail: {report.Diagnostics.Count(d => d.Status.Equals("Fail", StringComparison.OrdinalIgnoreCase))}\n" +
                            $"N/A: {report.Diagnostics.Count(d => !d.Status.Equals("Pass", StringComparison.OrdinalIgnoreCase) && !d.Status.Equals("Fail", StringComparison.OrdinalIgnoreCase))}\n");

                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - 취약점 상세 보고서 생성 완료: {detailName}\n";
                    }

                    if (ExportSummaryReport)
                    {
                        string summaryName = $"Executive_Summary_Report_{report.SystemInfo.Hostname}_{DateTime.Now:yyyyMMdd}.xlsx";
                        string fullPath = Path.Combine(ExportPath, summaryName);
                        await File.WriteAllTextAsync(Path.ChangeExtension(fullPath, ".txt"), 
                            $"[요약서] {report.SystemInfo.Hostname}에 대한 보안 취약점 진단 점수가 요약되었습니다.\n");
                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - 임원 보고용 요약 보고서 생성 완료: {summaryName}\n";
                    }

                    if (ExportActionPlan)
                    {
                        string planName = $"Remediation_Action_Plan_{report.SystemInfo.Hostname}_{DateTime.Now:yyyyMMdd}.xlsx";
                        string fullPath = Path.Combine(ExportPath, planName);
                        await File.WriteAllTextAsync(Path.ChangeExtension(fullPath, ".txt"), 
                            $"[조치계획서] 취약항목 {report.Diagnostics.Count(d => d.Status.Equals("Fail", StringComparison.OrdinalIgnoreCase))}건에 대한 기술적 조치방안 조치자 할당 대기 중.\n");
                        ExportLogs += $"[{DateTime.Now:HH:mm:ss}]   - 조치 계획서 생성 완료: {planName}\n";
                    }

                    ExportProgress = (int)((double)currentStep / steps * 100);
                }

                ExportProgress = 100;
                ExportLogs += $"[{DateTime.Now:HH:mm:ss}] 모든 보고서 생성이 완료되었습니다. 경로: {ExportPath}\n";
                MessageBox.Show($"모든 보고서가 성공적으로 생성되었습니다.\n저장 경로: {ExportPath}", "완료", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                ExportLogs += $"[{DateTime.Now:HH:mm:ss}] 오류 발생: {ex.Message}\n";
                MessageBox.Show($"보고서 생성 도중 오류가 발생했습니다: {ex.Message}", "오류", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                IsExporting = false;
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
    }
}
