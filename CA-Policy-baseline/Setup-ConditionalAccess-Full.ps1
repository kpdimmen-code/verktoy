<#
.SYNOPSIS
  Fullstendig oppsett av Conditional Access i EIN tenant, interaktivt:
    0. Spør deg VED OPPSTART om dette skal vere ein dry run eller faktisk endring.
    1. Oppretter Named Locations (Z-0 til Z-4 + valfri Z-5-info) - finst
       ei location med same namn frå før, vert han IKKJE rørt/overskrive,
       berre gjenbrukt (id).
    2. Oppretter/gjenbruker standardgruppene CA-policyane refererer til som
       unntak - finst gruppa frå før, vert eksisterande Object ID brukt.
    3. Spør deg interaktivt om Object ID/UPN for break-glass-kontoane -
       vert lagt DIREKTE i excludeUsers på alle relevante policyar, i
       tillegg til å bli lagt til CA-Exclusion-BreakGlass-gruppa.
    4. Oppretter CA-policyane, ALLTID i "enabledForReportingButNotEnforced"
       (report-only). VIKTIG: Om ein policy med namn som startar med same
       CA-nummer (t.d. "CA-001", "CA-008-A") alt finst, vert OPPRETTINGA
       AV DEN POLICYEN HOPPA OVER - ingen duplikat, ingen overskriving av
       ein policy nokon alt har tilpassa.
    5. Skriv ut ein samla rapport til slutt (skjerm + CSV-fil).

.VIKTIG - KVAR DETTE KAN KØYRAST
  Krev interaktiv nettlesarpålogging (device code) - køyr LOKALT, ikkje som
  eit ubetjent Nerdio Azure Runbook.

.FØREHANDSKRAV
  - Ingen PowerShell-modular krevst (rein REST via Invoke-RestMethod).
  - Brukaren som loggar inn må ha Global Administrator, eller kombinasjonen
    Conditional Access Administrator + Groups Administrator + User
    Administrator.

.PARAMETER TenantId
  Tenant-ID eller domenenamn.

.PARAMETER WhatIf
  Valfri. Om denne vert gitt eksplisitt, vert IKKJE det interaktive
  modusvalet vist - skriptet køyrer rett i dry run. Utelat parameteren for
  å bli spurt interaktivt ved oppstart (anbefalt).

.EXAMPLE
  .\Setup-ConditionalAccess-Full.ps1 -TenantId "kunde1.onmicrosoft.com"
  # -> vert spurt om dry run eller faktisk endring

.EXAMPLE
  .\Setup-ConditionalAccess-Full.ps1 -TenantId "kunde1.onmicrosoft.com" -WhatIf
  # -> tvinger dry run utan å spørje
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $color = switch ($Level) { "ERROR" { "Red" }; "WARN" { "Yellow" }; "OK" { "Green" }; "STEP" { "Cyan" }; default { "White" } }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

# ===========================================================================
# 0. Interaktivt modusval (om -WhatIf ikkje alt vart gitt eksplisitt på kommandolinja)
# ===========================================================================
if (-not $PSBoundParameters.ContainsKey('WhatIf')) {
    Write-Host "`n=====================================================" -ForegroundColor Cyan
    Write-Host " Vel køyremodus" -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host " 1) Dry run  - berre vis kva som VILLE blitt gjort, ingen endringar"
    Write-Host " 2) Faktisk endring - opprettar grupper/locations/policyar i Entra ID"
    Write-Host ""

    do {
        $modeChoice = Read-Host "Val (1 eller 2)"
    } while ($modeChoice -notin @("1", "2"))

    $WhatIf = ($modeChoice -eq "1")
}

if ($WhatIf) {
    Write-Log "`nKøyremodus: DRY RUN - ingen endringar vert gjort i Entra ID.`n" "WARN"
} else {
    Write-Log "`nKøyremodus: FAKTISK ENDRING - dette vil opprette objekt i Entra ID.`n" "WARN"
    $confirm = Read-Host "Skriv 'JA' for å stadfeste at du vil fortsette"
    if ($confirm -ne "JA") { Write-Log "Avbrote av brukar." "ERROR"; exit 1 }
}

# ===========================================================================
# 1. Interaktiv pålogging - device code, ingen modular
# ===========================================================================
$ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"   # Microsoft Graph Command Line Tools (offisiell public client)
$Scope    = "https://graph.microsoft.com/Group.ReadWrite.All https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess https://graph.microsoft.com/User.Read.All offline_access openid profile"

$deviceCodeResp = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{ client_id = $ClientId; scope = $Scope }

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host $deviceCodeResp.message -ForegroundColor Cyan
Write-Host "=====================================================`n" -ForegroundColor Cyan
Write-Log "Ventar på godkjenning i nettlesaren (logg inn som Global Admin)..." "WARN"

$accessToken = $null
$interval    = [int]$deviceCodeResp.interval
$expiresAt   = (Get-Date).AddSeconds([int]$deviceCodeResp.expires_in)

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
        $detail = $_.ErrorDetails.Message
        throw "Graph-kall feila ($Method $Uri): $($_.Exception.Message)`n$detail"
    }
}

# Samla rapport - éi rad per objekt, uansett type
$Report = New-Object System.Collections.Generic.List[object]

# ===========================================================================
# 2. NAMED LOCATIONS - skip om namn alt finst (ikkje overskriv)
# ===========================================================================
# MERK - MAL, IKKJE FASIT: Landlistene under er eit fornuftig standardoppsett
# for dei fleste norske/nordiske verksemder, men DIN organisasjon kan ha
# forretningsaktivitet, kundar eller tilsette utanfor det som er føresett
# her. Gå gjennom kvar sone og juster landkodane (ISO 3166-1 alpha-2) før
# de tek dette i bruk i produksjon - spesielt NL-Zone-Home-NordEU (heimesona)
# og eventuelle sanksjons-/eksportkontroll-sensitive land.
# ===========================================================================
Write-Log "`n=== STEG 1: Named Locations ===" "STEP"

$NamedLocations = @(
    @{ displayName = "NL-Zone-Perm-Block";  countriesAndRegions = @("RU","BY","IR","KP","CU","SY","MM") },
    @{ displayName = "NL-Zone-Home-NordEU"; countriesAndRegions = @(
            "NO","SE","DK","FI","IS","AT","BE","BG","HR","CY","CZ","EE","FR","DE","GR","HU","IE","IT",
            "LV","LT","LU","MT","NL","PL","PT","RO","SK","SI","ES","GB","CH","LI"
        )
    },
    @{ displayName = "NL-Zone-Americas"; countriesAndRegions = @("US","CA","MX","BR","AR","CL","CO","PE","EC","BO","PY","UY","GT","CR","PA","JM","DO","TT","VE") },
    @{ displayName = "NL-Zone-APAC";     countriesAndRegions = @("AU","NZ","JP","KR","TW","SG","IN","MY","TH","PH","ID","VN","LK","BD","HK","MO") }, # Kina med vilje utelate
    @{ displayName = "NL-Zone-MEA";      countriesAndRegions = @("AE","SA","QA","KW","BH","OM","IL","JO","TR","EG","MA","TN","DZ","ZA","KE","GH","RW","TZ","NG","LB","IQ") },
    @{ displayName = "NL-Zone-Other-Z5-Informational"; countriesAndRegions = @("CN","PK","AF","KZ","UZ","TM","KG","TJ") }
)

$locationMap = @{}

foreach ($loc in $NamedLocations) {
    $displayName = $loc.displayName
    $existing = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations?`$filter=displayName eq '$displayName'"

    if ($existing.value.Count -gt 0) {
        $id = $existing.value[0].id
        Write-Log "  $displayName -> $id (finst frå før - HOPPAR OVER, ikkje rørt)" "OK"
        $locationMap[$displayName] = $id
        $Report.Add([PSCustomObject]@{ Type = "NamedLocation"; Name = $displayName; Action = "Skipped-AlreadyExists"; Id = $id })
    } else {
        if ($WhatIf) {
            Write-Log "  [DRY RUN] Ville oppretta $displayName" "WARN"
            $locationMap[$displayName] = "<ville-blitt-oppretta>"
            $Report.Add([PSCustomObject]@{ Type = "NamedLocation"; Name = $displayName; Action = "DryRun-WouldCreate"; Id = $null })
        } else {
            $body = @{
                "@odata.type"                     = "#microsoft.graph.countryNamedLocation"
                displayName                       = $displayName
                countryLookupMethod               = "clientIpAddress"
                includeUnknownCountriesAndRegions = $false
                countriesAndRegions               = $loc.countriesAndRegions
            } | ConvertTo-Json -Depth 10
            $new = Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -Body $body
            Write-Log "  $displayName -> $($new.id) (oppretta)" "OK"
            $locationMap[$displayName] = $new.id
            $Report.Add([PSCustomObject]@{ Type = "NamedLocation"; Name = $displayName; Action = "Created"; Id = $new.id })
        }
    }
}

# ===========================================================================
# 3. GRUPPER - skip om namn alt finst
# ===========================================================================
Write-Log "`n=== STEG 2: Grupper ===" "STEP"

$StandardGroups = @(
    @{ Name = "CA-Exclusion-BreakGlass";        Description = "Break-glass-kontoar, ekskludert fra CA-policyar" }
    @{ Name = "CA-Exclusion-ServiceAccounts";   Description = "Godkjende tenestekontoar, ekskludert fra CA-001" }
    @{ Name = "CA-Exclusion-EksternePartnarar"; Description = "Eksterne partnarar med legitimt behov, ekskludert fra CA-005" }
    @{ Name = "CA-Allow-Americas";              Description = "Midlertidig unntak - reise Z-2 (Amerika), maks 45 dagar" }
    @{ Name = "CA-Allow-APAC";                  Description = "Midlertidig unntak - reise Z-3 (APAC), maks 45 dagar" }
    @{ Name = "CA-Allow-MEA";                   Description = "Midlertidig unntak - reise Z-4 (Midt-Austen/Afrika), maks 45 dagar" }
    @{ Name = "CA-Allow-Other";                 Description = "Unntak Z-5 (fangst-alt) - krev CISO/CTO-godkjenning, maks 14 dagar" }
)

$groupMap = @{}

foreach ($g in $StandardGroups) {
    $existing = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($g.Name)'"

    if ($existing.value.Count -gt 0) {
        $id = $existing.value[0].id
        Write-Log "  $($g.Name) -> $id (finst frå før - gjenbrukt, ikkje rørt)" "OK"
        $groupMap[$g.Name] = $id
        $Report.Add([PSCustomObject]@{ Type = "Group"; Name = $g.Name; Action = "Skipped-AlreadyExists"; Id = $id })
    } else {
        if ($WhatIf) {
            Write-Log "  [DRY RUN] Ville oppretta $($g.Name)" "WARN"
            $groupMap[$g.Name] = "<ville-blitt-oppretta>"
            $Report.Add([PSCustomObject]@{ Type = "Group"; Name = $g.Name; Action = "DryRun-WouldCreate"; Id = $null })
        } else {
            $mailNickname = ($g.Name -replace '[^a-zA-Z0-9]', '')
            $body = @{ displayName = $g.Name; description = $g.Description; mailEnabled = $false; mailNickname = $mailNickname; securityEnabled = $true } | ConvertTo-Json
            $new = Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/groups" -Body $body
            Write-Log "  $($g.Name) -> $($new.id) (oppretta)" "OK"
            $groupMap[$g.Name] = $new.id
            $Report.Add([PSCustomObject]@{ Type = "Group"; Name = $g.Name; Action = "Created"; Id = $new.id })
        }
    }
}

# ===========================================================================
# 4. BREAK-GLASS-KONTOAR
# ===========================================================================
Write-Log "`n=== STEG 3: Break-glass-kontoar ===" "STEP"
Write-Host "Skriv inn UPN (t.d. breakglass1@kunde.no) ELLER Object ID (GUID) for kvar" -ForegroundColor Cyan
Write-Host "break-glass-konto som ALLTID skal ekskluderast fra CA-policyane." -ForegroundColor Cyan
Write-Host "Trykk Enter utan tekst når du er ferdig.`n" -ForegroundColor Cyan

$breakGlassUserIds = New-Object System.Collections.Generic.List[string]
$guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

while ($true) {
    $inputVal = Read-Host "Break-glass UPN/Object ID"
    if ([string]::IsNullOrWhiteSpace($inputVal)) { break }
    try {
        $user = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$inputVal`?`$select=id,displayName,userPrincipalName"
        Write-Log "  Funne: $($user.displayName) <$($user.userPrincipalName)> - id: $($user.id)" "OK"
        if (-not $breakGlassUserIds.Contains($user.id)) { $breakGlassUserIds.Add($user.id) }
        $Report.Add([PSCustomObject]@{ Type = "BreakGlassUser"; Name = $user.userPrincipalName; Action = "Registered"; Id = $user.id })
    } catch {
        Write-Log "  Fann ikkje brukar '$inputVal' i tenanten - hoppar over. ($($_.Exception.Message))" "ERROR"
    }
}

if ($breakGlassUserIds.Count -eq 0) {
    Write-Log "INGEN break-glass-kontoar registrert. Policyane vert oppretta UTAN direkte brukar-unntak (berre gruppe-unntak)." "WARN"
} else {
    Write-Log "Registrerte break-glass-kontoar: $($breakGlassUserIds -join ', ')" "OK"
    if (-not $WhatIf -and $groupMap["CA-Exclusion-BreakGlass"] -notlike "<*>") {
        foreach ($uid in $breakGlassUserIds) {
            $memberBody = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$uid" } | ConvertTo-Json
            try {
                Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/groups/$($groupMap['CA-Exclusion-BreakGlass'])/members/`$ref" -Body $memberBody | Out-Null
                Write-Log "  Lagt til $uid i CA-Exclusion-BreakGlass" "OK"
            } catch {
                Write-Log "  Klarte ikkje å leggje $uid til gruppa (kanskje alt medlem): $($_.Exception.Message)" "WARN"
            }
        }
    }
}

$breakGlassArray = @($breakGlassUserIds)

# ===========================================================================
# 5. CA-POLICYAR - HOPP OVER om policy med same CA-nummer-prefiks alt finst
# ===========================================================================
Write-Log "`n=== STEG 4: Conditional Access-policyar (report-only) ===" "STEP"

$RoleIds = @(
    "62e90394-69f5-4237-9190-012177145e10", "194ae4cb-b126-40b2-bd5b-6091b380977d",
    "29232cdf-9323-42fd-ade2-1d097af3e4de", "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
    "fe930be7-5e62-47db-91af-98c3a49a38b1"
)
$PhishingResistantMfaId = "00000000-0000-0000-0000-000000000004"

$bg  = $groupMap["CA-Exclusion-BreakGlass"];       $svc = $groupMap["CA-Exclusion-ServiceAccounts"]
$ext = $groupMap["CA-Exclusion-EksternePartnarar"]
$aAm = $groupMap["CA-Allow-Americas"];             $aAp = $groupMap["CA-Allow-APAC"]
$aMe = $groupMap["CA-Allow-MEA"];                  $aOt = $groupMap["CA-Allow-Other"]
$lPB = $locationMap["NL-Zone-Perm-Block"];         $lHo = $locationMap["NL-Zone-Home-NordEU"]
$lAm = $locationMap["NL-Zone-Americas"];           $lAp = $locationMap["NL-Zone-APAC"]
$lMe = $locationMap["NL-Zone-MEA"]

$Policies = @(
    @{ Prefix = "CA-001"; displayName = "CA-001 - Krev MFA - alle brukarar"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $svc) }
                       applications = @{ includeApplications = @("All") }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("mfa") } },

    @{ Prefix = "CA-002"; displayName = "CA-002 - Sterk MFA - privilegerte roller"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @(); excludeUsers = $breakGlassArray; includeRoles = $RoleIds; excludeGroups = @($bg) }
                       applications = @{ includeApplications = @("All") }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @(); authenticationStrength = @{ id = $PhishingResistantMfaId } } },

    @{ Prefix = "CA-003"; displayName = "CA-003 - Bloker eldre autentisering (Legacy Auth)"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg) }
                       applications = @{ includeApplications = @("All") }; clientAppTypes = @("exchangeActiveSync","other") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-004"; displayName = "CA-004 - Appbeskyttelse - iOS og Android"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg) }
                       applications = @{ includeApplications = @("Office365") }
                       platforms = @{ includePlatforms = @("iOS","android") }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("approvedApplication","compliantApplication") } },

    @{ Prefix = "CA-005"; displayName = "CA-005 - Krev kompatibel einheit - Windows/macOS"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $ext) }
                       applications = @{ includeApplications = @("All") }
                       platforms = @{ includePlatforms = @("windows","macOS") }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("compliantDevice","domainJoinedDevice") } },

    @{ Prefix = "CA-006"; displayName = "CA-006 - Administrasjonsportalar - MFA og kompatibel einheit"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg) }
                       applications = @{ includeApplications = @("MicrosoftAdminPortals","797f4846-ba00-4fd7-ba43-dac1f8f63013","00000002-0000-0ff1-ce00-000000000000") }
                       clientAppTypes = @("all") }
       grantControls = @{ operator = "AND"; builtInControls = @("mfa","compliantDevice") }
       # Merk: "Persistent Browser Session" kan berre brukast på policyar som gjeld
       # "Alle skyappar" (Graph API gir 400 InvalidConditionsForPersistentBrowserSessionMode
       # elles). Sidan CA-006 berre gjeld admin-portalane, kan vi difor IKKJE setje
       # persistentBrowser her - berre signInFrequency. Ønskjer de "aldri persistent
       # nettlesarøkt" generelt, må det leggjast i ein eigen policy som gjeld ALLE appar.
       sessionControls = @{ signInFrequency = @{ value = 4; type = "hours"; isEnabled = $true } } },

    @{ Prefix = "CA-007"; displayName = "CA-007 - Krev MFA ved enhetsregistrering"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg) }
                       applications = @{ includeUserActions = @("urn:user:registerdevice") }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("mfa") } },

    @{ Prefix = "CA-008-A"; displayName = "CA-008-A - Permanent blokk - Hoyrisikostatar (Z-0)"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @() }
                       applications = @{ includeApplications = @("All") }
                       locations = @{ includeLocations = @($lPB) }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-008-B"; displayName = "CA-008-B - Bloker Amerika - Z-2"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $aAm) }
                       applications = @{ includeApplications = @("All") }
                       locations = @{ includeLocations = @($lAm) }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-008-C"; displayName = "CA-008-C - Bloker Asia-Stillehavsregionen - Z-3"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $aAp) }
                       applications = @{ includeApplications = @("All") }
                       locations = @{ includeLocations = @($lAp) }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-008-D"; displayName = "CA-008-D - Bloker Midt-Austen og Afrika - Z-4"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $aMe) }
                       applications = @{ includeApplications = @("All") }
                       locations = @{ includeLocations = @($lMe) }; clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-008-E"; displayName = "CA-008-E - Bloker ovrig verd - Fangst-alt Z-5"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg, $aOt) }
                       applications = @{ includeApplications = @("All") }
                       locations = @{ includeLocations = @("All"); excludeLocations = @($lPB, $lHo, $lAm, $lAp, $lMe) }
                       clientAppTypes = @("all") }
       grantControls = @{ operator = "OR"; builtInControls = @("block") } },

    @{ Prefix = "CA-009"; displayName = "CA-009 - Sesjonskontroll - uadministrerte einheiter"; state = "enabledForReportingButNotEnforced"
       conditions = @{ users = @{ includeUsers = @("All"); excludeUsers = $breakGlassArray; excludeGroups = @($bg) }
                       applications = @{ includeApplications = @("All") }
                       devices = @{ deviceFilter = @{ mode = "include"; rule = '(device.isCompliant -eq False) -and (device.trustType -ne "ServerAD")' } }
                       clientAppTypes = @("all") }
       grantControls = $null
       sessionControls = @{ signInFrequency = @{ value = 8; type = "hours"; isEnabled = $true }; persistentBrowser = @{ mode = "never"; isEnabled = $true } } }
)

Write-Log "CA-008-A ekskluderer break-glass-kontoane dine (viss registrert), sjølv om kravdokumentet opphavleg tilrår FULL blokkering utan unntak for Z-0. Vurder å fjerne manuelt i Entra-portalen om de vil følgje den strengaste tilrådinga." "WARN"

# Hent ALLE eksisterande CA-policyar éin gong (billigare enn eitt kall per policy)
$allExistingPolicies = (Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$select=id,displayName").value

foreach ($p in $Policies) {
    $prefix      = $p.Prefix
    $displayName = $p.displayName

    $match = $allExistingPolicies | Where-Object { $_.displayName -like "$prefix*" } | Select-Object -First 1

    if ($match) {
        Write-Log "  $prefix : HOPPAR OVER - finst alt som '$($match.displayName)' (id: $($match.id))" "WARN"
        $Report.Add([PSCustomObject]@{ Type = "CAPolicy"; Name = $displayName; Action = "Skipped-Duplicate"; Id = $match.id; ExistingName = $match.displayName })
        continue
    }

    if ($WhatIf) {
        Write-Log "  $prefix : [DRY RUN] Ville oppretta '$displayName'" "WARN"
        $Report.Add([PSCustomObject]@{ Type = "CAPolicy"; Name = $displayName; Action = "DryRun-WouldCreate"; Id = $null; ExistingName = $null })
        continue
    }

    $bodyObj = $p | Select-Object * -ExcludeProperty Prefix
    $body = $bodyObj | ConvertTo-Json -Depth 12
    $new = Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Body $body
    Write-Log "  $prefix : Oppretta '$displayName' (id: $($new.id))" "OK"
    $Report.Add([PSCustomObject]@{ Type = "CAPolicy"; Name = $displayName; Action = "Created"; Id = $new.id; ExistingName = $null })
}

# ===========================================================================
# 6. SAMLA RAPPORT
# ===========================================================================
Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host " RAPPORT" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

$Report | Format-Table -AutoSize -Property Type, Name, Action, Id, ExistingName

$created = ($Report | Where-Object { $_.Action -eq "Created" }).Count
$skipped = ($Report | Where-Object { $_.Action -like "Skipped*" }).Count
$dryRun  = ($Report | Where-Object { $_.Action -like "DryRun*" }).Count

Write-Host "`nOppsummering: $created oppretta, $skipped hoppa over (fanst frå før), $dryRun i dry-run-plan.`n" -ForegroundColor Cyan

$reportPath = ".\CA-Setup-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$Report | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
Write-Log "Full rapport lagra til: $reportPath" "OK"

if ($WhatIf) {
    Write-Log "Dette var ein DRY RUN. Ingenting vart faktisk oppretta/endra. Køyr på nytt og vel modus 2 for å publisere." "WARN"
} else {
    Write-Log "Ferdig. Alle nye policyar er publisert i report-only. Overvak sign-in-loggen før de vurderer 'enabled'." "OK"
}
