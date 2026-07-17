<#
.SYNOPSIS
    Estimerer kor stor del av innhaldet i SharePoint-nettstadar som har sensitivity labels.

.DESCRIPTION
    Spør SharePoint sin søkeindeks (via Microsoft Graph) etter totalt tal på element og
    tal på element med ein Information Protection-label sett, per nettstad. Gir eit
    prioriteringsgrunnlag for kvar arbeidet med automatisk eller manuell merking bør
    starte – nyttig steg før du stoler på labels som grunnlag for Copilot-tilgangsstyring.

.PARAMETER SiteUrls
    Liste over nettstad-URL-ar som skal sjekkast. Om ikkje angitt, hentar skriptet
    alle nettstadar tenanten har via Graph (kan ta tid i store tenantar).

.PARAMETER OutFile
    Sti til CSV-fil for output.

.EXAMPLE
    .\Test-SensitivityLabelCoverage.ps1 -SiteUrls "https://contoso.sharepoint.com/sites/HR" -OutFile dekning.csv

.NOTES
    Krev Microsoft.Graph-modulen (Sites og Search) og løyvet Sites.Read.All.
    Talet er eit estimat basert på søkeindeksen, ikkje ei fullstendig
    filsystem-gjennomgang – nyleg endra filer kan mangle frå indeksen ei kort stund.
#>

[CmdletBinding()]
param(
    [string[]]$SiteUrls,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Sites)) {
    throw "Modulen Microsoft.Graph manglar. Installer med: Install-Module Microsoft.Graph -Scope CurrentUser"
}

Import-Module Microsoft.Graph.Sites -ErrorAction Stop

Write-Host "Koplar til Microsoft Graph ..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "Sites.Read.All" -NoWelcome

if (-not $SiteUrls) {
    Write-Host "Ingen nettstadar angitt, hentar alle ..." -ForegroundColor Cyan
    $SiteUrls = Get-MgSite -All | Select-Object -ExpandProperty WebUrl
}

function Get-ElementTal {
    param([string]$Kql)

    $sok = @{
        requests = @(@{
            entityTypes = @("driveItem")
            query       = @{ queryString = $Kql }
            size        = 1
        })
    }

    $svar = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/search/query" `
        -Body ($sok | ConvertTo-Json -Depth 6)

    return [int]$svar.value[0].hitsContainers[0].total
}

$rapport = foreach ($url in $SiteUrls) {
    Write-Host "Sjekkar $url ..." -ForegroundColor Cyan
    try {
        $totalt = Get-ElementTal -Kql "path:$url"
        $merkte = Get-ElementTal -Kql "path:$url AND InformationProtectionLabelId:*"

        $dekning = if ($totalt -gt 0) { [math]::Round(($merkte / $totalt) * 100, 1) } else { 0 }

        [PSCustomObject]@{
            Nettstad          = $url
            TotaltTalElement  = $totalt
            MerkteElement     = $merkte
            DekningProsent    = $dekning
        }
    } catch {
        Write-Warning "Kunne ikkje sjekke $url : $_"
    }
}

$rapport = $rapport | Sort-Object DekningProsent

if ($OutFile) {
    $rapport | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    Write-Host "Rapport lagra til $OutFile" -ForegroundColor Green
} else {
    $rapport | Format-Table -AutoSize
}

Disconnect-MgGraph
