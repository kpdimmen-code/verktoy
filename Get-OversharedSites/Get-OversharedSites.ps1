<#
.SYNOPSIS
    Kartlegg SharePoint-nettstadar med potensielt for vide delingsinnstillingar.

.DESCRIPTION
    Hentar delingsnivå (SharingCapability) for alle SharePoint-nettstadar (og valfritt
    OneDrive) i tenanten, og flaggar dei som tillèt ekstern deling eller anonyme lenker.
    Tenkt brukt som eit steg i kartlegginga før Copilot-utrulling: nettstadar med vide
    delingsinnstillingar er dei som lettast lek data via Copilot sine søk på tvers av
    innhald brukaren har tilgang til.

.PARAMETER TenantAdminUrl
    URL til SharePoint-administrasjonssida, t.d. https://contoso-admin.sharepoint.com

.PARAMETER IncludeOneDrive
    Ta med OneDrive for Business-nettstadar i tillegg til vanlege SharePoint-nettstadar.

.PARAMETER OutFile
    Sti til CSV-fil for output. Om ikkje angitt, skriv resultatet til skjermen.

.EXAMPLE
    .\Get-OversharedSites.ps1 -TenantAdminUrl https://contoso-admin.sharepoint.com -OutFile rapport.csv

.NOTES
    Krev modulen Microsoft.Online.SharePoint.PowerShell og SharePoint-administratorrolle.
    Test i eit ikkje-produksjonsmiljø først, sidan Get-SPOSite -Limit All kan ta tid i
    store tenantar.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantAdminUrl,

    [switch]$IncludeOneDrive,

    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Microsoft.Online.SharePoint.PowerShell)) {
    throw "Modulen Microsoft.Online.SharePoint.PowerShell manglar. Installer med: Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser"
}

Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop

Write-Host "Koplar til $TenantAdminUrl ..." -ForegroundColor Cyan
Connect-SPOService -Url $TenantAdminUrl

Write-Host "Hentar nettstadar (kan ta litt tid i store tenantar) ..." -ForegroundColor Cyan
$sites = Get-SPOSite -Limit All -IncludePersonalSite:$IncludeOneDrive

# Delingsnivå sortert frå strengast (0) til mest ope (3)
$risikoNivaa = @{
    'Disabled'                          = 0
    'ExistingExternalUserSharingOnly'   = 1
    'ExternalUserSharingOnly'           = 2
    'ExternalUserAndGuestSharing'       = 3
}

$resultat = $sites | ForEach-Object {
    [PSCustomObject]@{
        Url               = $_.Url
        Title             = $_.Title
        SharingCapability = $_.SharingCapability
        Risikoscore       = $risikoNivaa[$_.SharingCapability.ToString()]
        StorageUsedMB     = $_.StorageUsageCurrent
        Owner             = $_.Owner
    }
} | Where-Object { $_.Risikoscore -ge 2 } | Sort-Object Risikoscore -Descending

if ($resultat.Count -eq 0) {
    Write-Host "Fann ingen nettstadar med ekstern deling utover 'Disabled' eller 'berre eksisterande eksterne brukarar'." -ForegroundColor Green
} else {
    Write-Host "Fann $($resultat.Count) nettstad(ar) med potensielt for vid deling:" -ForegroundColor Yellow
}

if ($OutFile) {
    $resultat | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    Write-Host "Rapport lagra til $OutFile" -ForegroundColor Green
} else {
    $resultat | Format-Table -AutoSize
}

Disconnect-SPOService
