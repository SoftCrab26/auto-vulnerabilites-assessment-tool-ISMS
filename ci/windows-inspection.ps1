<#
.SYNOPSIS
    windows-inspection.ps1
    Windows 스크립트(.ps1, .bat, .cmd) 대상 위험 명령어 블랙리스트 점검 스크립트

.DESCRIPTION
    점검 항목:
    [1] 디스크 포맷/파티션 삭제 (format, diskpart clean)
    [2] 강제 대량 삭제 (Remove-Item -Recurse -Force, del /f /s /q)
    [3] 원격 다운로드 후 즉시 실행 (IEX(New-Object Net.WebClient).DownloadString / iwr | iex)
    [4] 실행 정책 우회 (-ExecutionPolicy Bypass, Set-ExecutionPolicy Unrestricted)
    [5] 보안 소프트웨어 비활성화 (Defender, 방화벽)
    [6] 계정/권한 조작 (net user /add, 관리자 그룹 추가)
    [7] 레지스트리 삭제/영구 실행 등록 (reg delete, 시작프로그램 등록)
    [8] 로그/이벤트 삭제 (wevtutil cl, Clear-EventLog)

.NOTES
    종료 코드: 위반 발견 시 1, 없으면 0
#>

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..")).Path
Set-Location $repoRoot

Write-Host "==== 🛡️  Windows 위험 명령어 블랙리스트 스캔 시작 ====" -ForegroundColor Cyan
Write-Host "📂 대상 루트: $repoRoot"

$violationFound = $false

# CI 스크립트·의도적 취약 랩/픽스처는 제외한다.
$targetFiles = Get-ChildItem -Path $repoRoot -Recurse -Include *.ps1, *.bat, *.cmd -File |
    Where-Object {
        $_.FullName -notmatch '\\\.git\\' -and
        $_.FullName -notmatch '[\\/]ci[\\/]' -and
        $_.FullName -notmatch '[\\/]test-lab[\\/]' -and
        $_.FullName -notmatch '[\\/]vulnerableEnviorment[\\/]' -and
        $_.FullName -notmatch '[\\/]vulnerableEnvironment[\\/]'
    }

if (-not $targetFiles) {
    Write-Host "ℹ️  검사 대상 .ps1/.bat/.cmd 파일이 없습니다."
    exit 0
}

# 항목: (설명, 정규식 패턴)
$rules = @(
    @{ Desc = "디스크 포맷/파티션 삭제 명령(format, diskpart clean) - 데이터 파괴 위험"
       Pattern = '(?im)^\s*(format\s+[a-z]:|diskpart|clean\b)' },

    @{ Desc = "강제 대량 삭제(Remove-Item -Recurse -Force, del /f /s /q) - 데이터 파괴 위험"
       Pattern = '(?im)(Remove-Item\s+.*-Recurse.*-Force|del\s+/f\s*/s\s*/q|rd\s+/s\s*/q)' },

    @{ Desc = "원격 스크립트 다운로드 후 즉시 실행(IEX, DownloadString, iwr|iex) - 매우 위험"
       Pattern = '(?im)(IEX\s*\(|Invoke-Expression|DownloadString|iwr\s+.*\|\s*iex|curl\s+.*\|\s*iex)' },

    @{ Desc = "PowerShell 실행 정책 우회(ExecutionPolicy Bypass/Unrestricted)"
       Pattern = '(?im)(-ExecutionPolicy\s+(Bypass|Unrestricted)|Set-ExecutionPolicy\s+Unrestricted)' },

    @{ Desc = "Windows Defender/방화벽 비활성화 - 보안 기능 우회"
       Pattern = '(?im)(Set-MpPreference\s+.*-DisableRealtimeMonitoring\s+\$true|Disable-WindowsOptionalFeature|netsh\s+advfirewall\s+set\s+.*state\s+off)' },

    @{ Desc = "계정 추가/관리자 그룹 편입 - 권한 상승 위험"
       Pattern = '(?im)(net\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators\s+.*\s+/add)' },

    @{ Desc = "레지스트리 삭제 또는 시작프로그램(Run 키) 등록"
       Pattern = '(?im)(reg\s+delete|reg\s+add\s+.*\\Run\b)' },

    @{ Desc = "이벤트 로그/감사 기록 삭제 - 흔적 인멸 의심"
       Pattern = '(?im)(wevtutil\s+cl|Clear-EventLog)' }
)

foreach ($file in $targetFiles) {
    Write-Host "🔍 스캔 중: $($file.FullName)"
    $lines = Get-Content -Path $file.FullName

    foreach ($rule in $rules) {
        $matchedLines = @()
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            # 주석 라인 제외 (PowerShell '#', batch 'REM'/'::')
            if ($line -match '^\s*(#|REM\b|::)' ) { continue }
            if ($line -match $rule.Pattern) {
                $matchedLines += "     $($i + 1): $($line.Trim())"
            }
        }

        if ($matchedLines.Count -gt 0) {
            Write-Host "❌ [Violation] $($file.FullName)" -ForegroundColor Red
            Write-Host "   └ 항목: $($rule.Desc)"
            $matchedLines | ForEach-Object { Write-Host $_ }
            $violationFound = $true
        }
    }
}

Write-Host "--------------------------------------------------"
if ($violationFound) {
    Write-Host "🚨 빌드 실패: 블랙리스트에 등록된 위험 명령어가 발견되었습니다." -ForegroundColor Red
    exit 1
} else {
    Write-Host "✅ 빌드 성공: 스크립트 내에 알려진 위험 명령어가 없습니다." -ForegroundColor Green
    exit 0
}
