<#
.SYNOPSIS
    Hentar og formaterer DLP-hendingar (rule matches) frå unified audit log til ein lesbar rapport.

.DESCRIPTION
    Purview sine innebygde DLP-rapportar gir avgrensa fleksibilitet for eigne analysar.
    Dette skriptet søkjer i unified audit log etter DLPRuleMatch-hendingar i ein gitt
    periode, pakkar ut relevante felt frå AuditData-JSON-en (regel, handling, arbeidslast,
    brukar, sensitive informasjonstypar), og eksporterer til CSV.

.PARAMETER StartDate
    Startdato for søket. Standard: 7 dagar tilbake.

.PARAMETER EndDate
    Sluttdato for søket. Standard: no.

.PARAMETER OutFile
    Sti til CSV-fil for output.

.EXAMPLE
    .\Export-PurviewDLPReport.ps1 -StartDate (Get-Date).AddDays(-30) -OutFile dlp-siste-30.csv

.NOTES
    Krev modulen ExchangeOnlineManagement og at kontoen har rolla "View-Only Audit Logs"
    eller tilsvarande i Purview-portalen.
    Unified audit log har normalt inntil 24 timars forseinking for nye hendingar.
#>

[CmdletBinding()]
param(
    [datetime]$StartDate = (Get-Date).AddDays(-7),
    [datetime]$EndDate = (Get-Date),
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    throw "Modulen ExchangeOnlineManagement manglar. Installer med: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
}

Import-Module ExchangeOnlineManagement -ErrorAction Stop

Write-Host "Koplar til Security & Compliance ..." -ForegroundColor Cyan
Connect-ExchangeOnline -ShowBanner:$false

Write-Host "Søkjer i unified audit log frå $StartDate til $EndDate ..." -ForegroundColor Cyan

$alleTreff = @()
$sessionId = [guid]::NewGuid().ToString()

do {
    $batch = Search-UnifiedAuditLog `
        -StartDate $StartDate `
        -EndDate $EndDate `
        -RecordType DLPRuleMatch `
        -SessionId $sessionId `
        -SessionCommand ReturnLargeSet `
        -ResultSize 5000

    if ($batch) { $alleTreff += $batch }
} while ($batch.Count -eq 5000)

Write-Host "Fann $($alleTreff.Count) DLP-hendingar. Pakkar ut detaljar ..." -ForegroundColor Cyan

$rapport = foreach ($hending in $alleTreff) {
    $data = $hending.AuditData | ConvertFrom-Json

    [PSCustomObject]@{
        Tidspunkt          = $data.CreationTime
        Brukar             = $data.UserId
        Arbeidslast        = $data.Workload
        Objekt             = $data.ObjectId
        RegelNamn          = ($data.PolicyDetails.Rules.RuleName -join '; ')
        Handlingar         = ($data.PolicyDetails.Rules.Actions -join '; ')
        SensitiveInfoTypar = ($data.PolicyDetails.Rules.ConditionsMatched.SensitiveInformation.SensitiveType -join '; ')
    }
}

if ($OutFile) {
    $rapport | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    Write-Host "Rapport lagra til $OutFile" -ForegroundColor Green
} else {
    $rapport | Format-Table -AutoSize
}

Disconnect-ExchangeOnline -Confirm:$false
