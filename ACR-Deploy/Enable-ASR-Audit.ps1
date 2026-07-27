# ==============================================================================
# Enable-ASR-Audit.ps1
# Formål: Opprettar OG tildeler ein Intune Device Configuration-policy som set
#         alle 16 standard Attack Surface Reduction-reglar i Audit-modus.
#
#         Brukar den verifiserte CSP-baserte streng-eigenskapen
#         "defenderAttackSurfaceReductionRules"
#         (./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules),
#         IKKJE dei individuelt namngitte eigenskapane (som berre dekkjer eit
#         subsett av reglane og har eit anna, mindre verifisert skjema).
#
#         Kjør etter 7-14 dagar, analyser med Get-ASRStatus.ps1 -Mode Remote
#         (eller Reports > Attack surface reduction rules i Defender-portalen),
#         deretter oppdater til Block der confidence er høg nok.
# ==============================================================================

#requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement

<#
.SYNOPSIS
    Opprettar og tildeler ein Intune ASR-audit-policy for Business Premium-tenantar.

.DESCRIPTION
    Byggjer ein windows10EndpointProtectionConfiguration-profil med alle 16
    standard ASR-reglar sett til Audit (2), oppretter han i Intune via
    Microsoft Graph, og tildeler han til ei valt gruppe (eller alle einingar)
    om du ber om det. Utan tildeling gjer policyen ingenting, sjølv om han
    er oppretta korrekt – det er difor tildeling er ein eigen, eksplisitt
    parameter i staden for noko som skjer automatisk.

    Krev: Microsoft.Graph-modular (Install-Module Microsoft.Graph)
    Rettar: DeviceManagementConfiguration.ReadWrite.All

.PARAMETER PolicyName
    Namn på Intune-policyen

.PARAMETER Description
    Skildring av policyen

.PARAMETER AssignToGroupId
    Object ID til ei Entra-gruppe policyen skal tildelast. Om ikkje sett,
    blir policyen oppretta men IKKJE tildelt – du må tildele han manuelt
    i Intune-portalen (Devices > Configuration > policyen > Assignments)
    før han trer i kraft.

.PARAMETER AssignToAllDevices
    Tildel policyen til alle einingar. Bruk med varsemd – tilrådd berre
    etter at du har testa på ei pilotgruppe fyrst via -AssignToGroupId.

.EXAMPLE
    .\Enable-ASR-Audit.ps1

    Opprettar policyen, men tildeler han ikkje (trygt standardval).

.EXAMPLE
    .\Enable-ASR-Audit.ps1 -AssignToGroupId "11111111-2222-3333-4444-555555555555"

    Opprettar og tildeler policyen til den valde gruppa (t.d. ei pilotgruppe).

.EXAMPLE
    .\Enable-ASR-Audit.ps1 -AssignToAllDevices

    Opprettar og tildeler policyen til alle einingar.
#>

param(
    [string]$PolicyName = "ASR - Audit All Rules (Baseline)",
    [string]$Description = "Set all ASR rules to Audit mode via defenderAttackSurfaceReductionRules. Sjå blogg Del 3.",
    [string]$AssignToGroupId = "",
    [switch]$AssignToAllDevices
)

Connect-MgGraph -Scopes "DeviceManagementConfiguration.ReadWrite.All" -NoWelcome

# --- ASR-REGLAR (Audit = 2) ---
# Verifisert mot learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference (2026-07-27).
# Dei tre reglane blogg-serien (Del 3) tilrår som trygt startpunkt er merkte under.
$ASRRules = [ordered]@{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = 2  # Block abuse of exploited vulnerable signed drivers  <- anbefalt startpunkt
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 2  # Block credential stealing from LSASS                <- anbefalt startpunkt
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 2  # Block persistence through WMI event subscription     <- anbefalt startpunkt
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = 2  # Block Adobe Reader from creating child processes
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 2  # Block all Office applications from creating child processes
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = 2  # Block executable content from email client and webmail
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = 2  # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = 2  # Block execution of potentially obfuscated scripts
    "d3e037e1-3eb8-44c8-a917-57927947596d" = 2  # Block JavaScript or VBScript from launching downloaded executable content
    "3b576869-a4ec-4529-8536-b80a7769e899" = 2  # Block Office applications from creating executable content
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = 2  # Block Office applications from injecting code into other processes
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = 2  # Block Office communication application from creating child processes
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = 2  # Block process creations originating from PSExec and WMI commands
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 2  # Block untrusted and unsigned processes that run from USB
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = 2  # Block Win32 API calls from Office macros
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = 2  # Use advanced protection against ransomware
}

# Bygg CSP-strengen: "GUID1=verdi|GUID2=verdi|..." (dette ER det faktiske formatet
# Policy CSP-en ./Device/Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules forventar)
$RuleString = ($ASRRules.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "|"

$Body = @{
    "@odata.type"                       = "#microsoft.graph.windows10EndpointProtectionConfiguration"
    displayName                         = $PolicyName
    description                         = $Description
    defenderAttackSurfaceReductionRules  = $RuleString
}

# --- OPPRETT POLICY ---
Write-Host "Opprettar Intune-policy '$PolicyName'..." -ForegroundColor Cyan

try {
    $NewPolicy = New-MgDeviceManagementDeviceConfiguration -BodyParameter $Body
    Write-Host "✅ Policy oppretta. Id: $($NewPolicy.Id)" -ForegroundColor Green
} catch {
    Write-Error "Klarte ikkje å opprette policyen: $_"
    return
}

# --- TILDELING ---
if ($AssignToAllDevices) {
    Write-Host "Tildeler til ALLE einingar..." -ForegroundColor Yellow
    $AssignmentTarget = @{ "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget" }
} elseif ($AssignToGroupId) {
    Write-Host "Tildeler til gruppe $AssignToGroupId..." -ForegroundColor Cyan
    $AssignmentTarget = @{
        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
        groupId       = $AssignToGroupId
    }
} else {
    Write-Host "`n⚠️  Ingen tildeling gjort. Policyen er oppretta, men gjeld ingen einingar enno." -ForegroundColor Yellow
    Write-Host "   Tildel han manuelt i Intune-portalen (Devices > Configuration > $PolicyName > Assignments)," -ForegroundColor Gray
    Write-Host "   eller kjør scriptet på nytt med -AssignToGroupId <gruppe-id> eller -AssignToAllDevices." -ForegroundColor Gray
    Write-Host "`nFerdig." -ForegroundColor Green
    return
}

try {
    $AssignmentBody = @{
        assignments = @(
            @{ target = $AssignmentTarget }
        )
    }
    Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/$($NewPolicy.Id)/assign" `
        -Body $AssignmentBody
    Write-Host "✅ Policy tildelt." -ForegroundColor Green
} catch {
    Write-Error "Policyen vart oppretta, men tildelinga feila: $_"
    Write-Host "Tildel han manuelt i Intune-portalen (Devices > Configuration > $PolicyName > Assignments)." -ForegroundColor Yellow
}

Write-Host "`nKjør '.\Get-ASRStatus.ps1 -Mode Remote' etter 7-14 dagar, eller sjå Reports > Attack surface reduction rules i Defender-portalen, for å vurdere enforce." -ForegroundColor Cyan
Write-Host "Merk: Tamper Protection er IKKJE del av denne profilen. Konfigurer det separat under security.microsoft.com > Settings > Endpoints > Advanced features, eller via ein eigen Antivirus-tryggingspolicy i Intune." -ForegroundColor Gray
