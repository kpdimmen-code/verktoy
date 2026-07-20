<#
.SYNOPSIS
  REIN LESETILGANG - ingen endringar vert gjort i tenanten.
  Hentar alle Conditional Access-policyar, named locations, og
  tryggingsrelaterte grunninnstillingar frå ein tenant, og byggjer ein
  ferdig-formatert tekstprompt du kan lime inn til Claude (eller anna LLM)
  for ein full CA-statusanalyse med forbetringsforslag og kritiske manglar.

  Tenkt brukt som kartleggingssteg i ein tryggingsaudit hos kundetenantar.

.VIKTIG - KVAR DETTE KAN KØYRAST
  Interaktiv nettlesarpålogging (device code) - køyr lokalt.

.FØREHANDSKRAV
  - Ingen PowerShell-modular krevst (rein REST).
  - Brukaren treng KUN LESERETTAR: Global Reader, Security Reader, eller
    Conditional Access Administrator/Global Administrator (som òg har
    leserettar). Dette skriptet endrar ingenting.

.PARAMETER TenantId
  Tenant-ID eller domenenamn for kundetenanten som skal kartleggjast.

.PARAMETER OutputPath
  Kor prompt-fila skal lagrast. Default: .\CA-Analysis-Prompt-<tenant>-<dato>.md

.EXAMPLE
  .\Export-CAAnalysisPrompt.ps1 -TenantId "kunde1.onmicrosoft.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [string]$OutputPath
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $color = switch ($Level) { "ERROR" { "Red" }; "WARN" { "Yellow" }; "OK" { "Green" }; "STEP" { "Cyan" }; default { "White" } }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

# ===========================================================================
# 1. Interaktiv pålogging - device code, ingen modular, KUN lesescope
# ===========================================================================
$ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"   # Microsoft Graph Command Line Tools (offisiell public client)
$Scope    = "https://graph.microsoft.com/Policy.Read.All https://graph.microsoft.com/Directory.Read.All https://graph.microsoft.com/Application.Read.All offline_access openid profile"

$deviceCodeResp = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{ client_id = $ClientId; scope = $Scope }

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host $deviceCodeResp.message -ForegroundColor Cyan
Write-Host "=====================================================`n" -ForegroundColor Cyan
Write-Log "Ventar på godkjenning i nettlesaren..." "WARN"

$accessToken = $null
$interval  = [int]$deviceCodeResp.interval
$expiresAt = (Get-Date).AddSeconds([int]$deviceCodeResp.expires_in)

while ((Get-Date) -lt $expiresAt) {
    Start-Sleep -Seconds $interval
    try {
        $tokenResp = Invoke-RestMethod -Method POST `
            -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
            -ContentType "application/x-www-form-urlencoded" `
            -Body @{ grant_type = "urn:ietf:params:oauth:grant-type:device_code"; client_id = $ClientId; device_code = $deviceCodeResp.device_code }
        $accessToken = $tokenResp.access_token
        break
    } catch {
        $err = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($err.error -eq "authorization_pending") { continue }
        elseif ($err.error -eq "authorization_declined") { throw "Pålogginga vart avvist." }
        elseif ($err.error -eq "expired_token") { throw "Koden utløp. Køyr skriptet på nytt." }
        else { throw "Uventa feil under pålogging: $($_.Exception.Message)" }
    }
}
if (-not $accessToken) { throw "Fekk ikkje access token innan tidsavbrot." }

$headers = @{ Authorization = "Bearer $accessToken"; "Content-Type" = "application/json" }
Write-Log "Innlogga OK mot tenant $TenantId." "OK"

function Invoke-Graph {
    param([string]$Method, [string]$Uri, [string]$Body = $null)
    try {
        if ($Body) { return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $Body }
        else { return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers }
    } catch {
        return $null   # Best-effort: manglande løyve skal ikkje stoppe heile kartlegginga
    }
}

# ===========================================================================
# 2. Hent data
# ===========================================================================
Write-Log "`n=== Hentar Conditional Access-policyar ===" "STEP"
$policies = (Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies").value
Write-Log "Fann $($policies.Count) CA-policyar." "OK"

Write-Log "`n=== Hentar Named Locations ===" "STEP"
$namedLocations = (Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations").value
Write-Log "Fann $($namedLocations.Count) named locations." "OK"

Write-Log "`n=== Hentar Security Defaults-status ===" "STEP"
$securityDefaults = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"

Write-Log "`n=== Hentar Authentication Methods policy ===" "STEP"
$authMethodsPolicy = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"

Write-Log "`n=== Hentar organisasjonsinfo ===" "STEP"
$org = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/organization"
$orgName = if ($org.value) { $org.value[0].displayName } else { $TenantId }

# ===========================================================================
# 3. Byggje oppslagstabellar for lesbare namn (best effort - feilar stille)
# ===========================================================================
Write-Log "`n=== Løyser opp ID-ar til lesbare namn (grupper/brukarar/roller/appar) ===" "STEP"

$idNameCache = @{}

# Kjende, faste Microsoft-rolle-template-ID-ar (dei vi har brukt i policyane tidlegare i denne kartlegginga)
$knownRoles = @{
    "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
    "29232cdf-9323-42fd-ade2-1d097af3e4de" = "Exchange Administrator"
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint Administrator"
    "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Administrator"
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
    "158c047a-c907-4556-b7ef-446551a6b5f7" = "Cloud Application Administrator"
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = "Conditional Access Administrator"
    "729827e3-9c14-49f7-bb1b-9608f156bbb8" = "Helpdesk Administrator"
}
$knownApps = @{
    "Office365"            = "Office 365 (heile appsuiten)"
    "All"                  = "Alle skyappar"
    "None"                 = "Ingen appar"
    "MicrosoftAdminPortals"= "Microsoft Admin Portals (samla)"
    "797f4846-ba00-4fd7-ba43-dac1f8f63013" = "Microsoft Azure Management"
    "00000002-0000-0ff1-ce00-000000000000" = "Office 365 Exchange Online"
}

function Resolve-Name {
    param([string]$Id, [string]$Kind)  # Kind: User, Group, Role, App
    if ([string]::IsNullOrWhiteSpace($Id)) { return $Id }
    if ($Id -in @("All","None","GuestsOrExternalUsers")) { return $Id }
    $cacheKey = "$Kind|$Id"
    if ($idNameCache.ContainsKey($cacheKey)) { return $idNameCache[$cacheKey] }

    $resolved = $Id
    switch ($Kind) {
        "Role" {
            if ($knownRoles.ContainsKey($Id)) { $resolved = $knownRoles[$Id] }
            else {
                $r = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$Id"
                if ($r.displayName) { $resolved = $r.displayName }
            }
        }
        "App" {
            if ($knownApps.ContainsKey($Id)) { $resolved = $knownApps[$Id] }
            else {
                $sp = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$Id'&`$select=displayName"
                if ($sp.value.Count -gt 0) { $resolved = $sp.value[0].displayName }
            }
        }
        default {
            $obj = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$Id"
            if ($obj.displayName) { $resolved = $obj.displayName }
            elseif ($obj.userPrincipalName) { $resolved = $obj.userPrincipalName }
        }
    }
    $idNameCache[$cacheKey] = $resolved
    return $resolved
}

function Format-IdList {
    param([array]$Ids, [string]$Kind)
    if (-not $Ids -or $Ids.Count -eq 0) { return "(ingen)" }
    return ($Ids | ForEach-Object { "$(Resolve-Name -Id $_ -Kind $Kind) [$_]" }) -join "; "
}

$locationNameMap = @{}
foreach ($nl in $namedLocations) { $locationNameMap[$nl.id] = $nl.displayName }
function Format-LocationList {
    param([array]$Ids)
    if (-not $Ids -or $Ids.Count -eq 0) { return "(ingen)" }
    return ($Ids | ForEach-Object { if ($locationNameMap.ContainsKey($_)) { "$($locationNameMap[$_]) [$_]" } else { $_ } }) -join "; "
}

# ===========================================================================
# 4. Byggje markdown-seksjon per policy
# ===========================================================================
Write-Log "`n=== Byggjer rapport ===" "STEP"

$policySections = foreach ($p in ($policies | Sort-Object displayName)) {
    $c = $p.conditions
    $g = $p.grantControls
    $s = $p.sessionControls

    $lines = @()
    $lines += "### $($p.displayName)"
    $lines += "- **State**: $($p.state)"
    $lines += "- **Included users**: $(Format-IdList $c.users.includeUsers 'User')"
    $lines += "- **Excluded users**: $(Format-IdList $c.users.excludeUsers 'User')"
    $lines += "- **Included groups**: $(Format-IdList $c.users.includeGroups 'Group')"
    $lines += "- **Excluded groups**: $(Format-IdList $c.users.excludeGroups 'Group')"
    if ($c.users.includeRoles -or $c.users.excludeRoles) {
        $lines += "- **Included roles**: $(Format-IdList $c.users.includeRoles 'Role')"
        $lines += "- **Excluded roles**: $(Format-IdList $c.users.excludeRoles 'Role')"
    }
    $lines += "- **Included applications**: $(Format-IdList $c.applications.includeApplications 'App')"
    $lines += "- **Excluded applications**: $(Format-IdList $c.applications.excludeApplications 'App')"
    if ($c.applications.includeUserActions) {
        $lines += "- **User actions**: $($c.applications.includeUserActions -join '; ')"
    }
    if ($c.platforms) {
        $lines += "- **Platforms include**: $($c.platforms.includePlatforms -join '; ')"
        $lines += "- **Platforms exclude**: $($c.platforms.excludePlatforms -join '; ')"
    }
    if ($c.locations) {
        $lines += "- **Locations include**: $(Format-LocationList $c.locations.includeLocations)"
        $lines += "- **Locations exclude**: $(Format-LocationList $c.locations.excludeLocations)"
    }
    if ($c.devices -and $c.devices.deviceFilter) {
        $lines += "- **Device filter**: mode=$($c.devices.deviceFilter.mode), rule=``$($c.devices.deviceFilter.rule)``"
    }
    $lines += "- **Client app types**: $($c.clientAppTypes -join '; ')"
    if ($g) {
        $lines += "- **Grant controls**: operator=$($g.operator), controls=$($g.builtInControls -join '; ')$(if ($g.authenticationStrength) { ", authStrength=$($g.authenticationStrength.id)" })"
    } else {
        $lines += "- **Grant controls**: (ingen - kun sesjonskontroll)"
    }
    if ($s) {
        $sessionBits = @()
        if ($s.signInFrequency.isEnabled) { $sessionBits += "signInFrequency=$($s.signInFrequency.value) $($s.signInFrequency.type)" }
        if ($s.persistentBrowser.isEnabled) { $sessionBits += "persistentBrowser=$($s.persistentBrowser.mode)" }
        if ($s.cloudAppSecurity.isEnabled) { $sessionBits += "cloudAppSecurity=$($s.cloudAppSecurity.cloudAppSecurityType)" }
        if ($sessionBits.Count -gt 0) { $lines += "- **Session controls**: $($sessionBits -join '; ')" }
    }
    $lines -join "`n"
}

$namedLocationSections = foreach ($nl in ($namedLocations | Sort-Object displayName)) {
    $type = if ($nl.'@odata.type' -like '*countryNamedLocation*') { "Country" } else { "IP" }
    if ($type -eq "Country") {
        "- **$($nl.displayName)** (Country, isTrusted=n/a): $($nl.countriesAndRegions -join ', ')"
    } else {
        $trusted = if ($nl.isTrusted) { "trusted" } else { "ikkje trusted" }
        "- **$($nl.displayName)** (IP, $trusted): $($nl.ipRanges.cidrAddress -join ', ')"
    }
}

# Statistikk
$stateCounts = $policies | Group-Object state | ForEach-Object { "$($_.Name): $($_.Count)" }
$blockPolicies = ($policies | Where-Object { $_.grantControls.builtInControls -contains "block" }).Count
$mfaPolicies   = ($policies | Where-Object { $_.grantControls.builtInControls -contains "mfa" }).Count

# ===========================================================================
# 5. Byggje den ferdige prompten
# ===========================================================================
$dateStr = Get-Date -Format "yyyy-MM-dd HH:mm"

$promptHeader = @"
# Conditional Access - Kartleggingsdata for tryggingsaudit

Du er ein Microsoft Entra ID / Conditional Access-ekspert som bistår med ein
tryggingsaudit av kundetenanten under. Dataen er henta reint (read-only) via
Microsoft Graph og representerer FAKTISK oppsett i tenanten på
eksporttidspunktet.

**Oppdrag**: Analyser heile CA-oppsettet under og gi meg:

1. **Overordna statusvurdering** - kor moden/godt dekt er tenanten frå eit
   Zero Trust-/Conditional Access-perspektiv?
2. **Kritiske manglar** - kva vesentlege scenario/angrepsvektorar er IKKJE
   dekt av noverande policyar (t.d. manglar MFA-dekning, manglar
   legacy-auth-blokkering, manglar device-compliance-krav, manglar
   beskyttelse av admin-roller/portalar, manglar geo-blokkering,
   break-glass-kontoar utan reell beskyttelse, osv.)?
3. **Konkrete forbetringsforslag**, prioritert etter risiko (kritisk / høg /
   middels / lav), med grunngjeving for kvar.
4. **Merk policyar i "report-only" spesielt** - kva bør prioriterast for å
   gå frå report-only til enabled, og kva bør testast meir først?
5. **Konsistens-/konfliktsjekk** - er det policyar som overlappar,
   motseier kvarandre, eller har unødvendig breie/smale unntak?
6. **Vurdering mot Microsoft sine anbefalte baseline-/Zero Trust-policyar**
   og generelle bransjestandardar (NIST, CIS Benchmark for Entra ID der
   relevant).

Svar strukturert med overskrifter for kvart punkt over. Vær konkret - vis
til policynamn og faktiske innstillingar, ikkje berre generiske råd.

---

## Tenant-informasjon

- **Organisasjon**: $orgName
- **Tenant ID**: $TenantId
- **Eksportert**: $dateStr
- **Tal CA-policyar**: $($policies.Count)
- **Fordeling per state**: $($stateCounts -join ' | ')
- **Policyar med "block"-kontroll**: $blockPolicies
- **Policyar med MFA-krav**: $mfaPolicies
- **Security Defaults aktivert**: $(if ($securityDefaults) { $securityDefaults.isEnabled } else { "(kunne ikkje hentast - manglar løyve?)" })
- **Tal named locations**: $($namedLocations.Count)

---

## Conditional Access-policyar (fullstendig detalj)

"@

$promptFooter = @"

---

## Named Locations

$($namedLocationSections -join "`n")

---

## Merknad om datagrunnlaget

- Data er henta med reine LESE-løyve (Policy.Read.All, Directory.Read.All,
  Application.Read.All) - ingenting er endra i tenanten under denne kartlegginga.
- ID-ar som ikkje let seg løyse til namn (t.d. pga. manglande løyve eller
  sletta objekt) står att som rå GUID.
- Authentication Methods-policy og Security Defaults er tatt med som
  kontekst, men er ikkje fullt utbrodert her - spør meg om detaljar om det
  trengst.
"@

$fullPrompt = $promptHeader + ($policySections -join "`n`n") + $promptFooter

# ===========================================================================
# 6. Lagre og vis
# ===========================================================================
if (-not $OutputPath) {
    $safeTenant = ($orgName -replace '[^a-zA-Z0-9]', '')
    $OutputPath = ".\CA-Analysis-Prompt-$safeTenant-$(Get-Date -Format 'yyyyMMdd-HHmmss').md"
}

$fullPrompt | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Log "`nPrompt lagra til: $OutputPath" "OK"
Write-Log "Lengde: $($fullPrompt.Length) teikn." "OK"

try {
    $fullPrompt | Set-Clipboard
    Write-Log "Prompten er òg kopiert til utklippstavla - berre lim rett inn i Claude." "OK"
} catch {
    Write-Log "Klarte ikkje å kopiere til utklippstavle automatisk - opne fila manuelt og kopier innhaldet." "WARN"
}

Write-Host "`nFerdig. Opne fila eller lim inn frå utklippstavla i ein samtale med Claude for full analyse." -ForegroundColor Cyan
