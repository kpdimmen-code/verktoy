# Test-SensitivityLabelCoverage.ps1

Estimerer kor stor del av innhaldet i SharePoint-nettstadar som har ein sensitivity label sett, ved å spørje søkeindeksen. Gir eit prioriteringsgrunnlag: sorterer nettstadar frå lågast til høgast dekning, så du ser kvar arbeidet bør starte.

## Føresetnader

- PowerShell 5.1 eller 7+
- Modul: `Microsoft.Graph` (spesifikt `Microsoft.Graph.Sites`)
- Løyve: `Sites.Read.All`

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Bruk

```powershell
.\Test-SensitivityLabelCoverage.ps1 -SiteUrls "https://contoso.sharepoint.com/sites/HR" -OutFile "dekning.csv"
```

Utan `-SiteUrls` hentar skriptet alle nettstadar i tenanten:

```powershell
.\Test-SensitivityLabelCoverage.ps1 -OutFile "dekning-alle.csv"
```

## Parametrar

| Parameter | Påkravd | Skildring |
|---|---|---|
| `-SiteUrls` | Nei | Liste over nettstadar. Standard: alle nettstadar i tenanten |
| `-OutFile` | Nei | Filsti for CSV-output, standard: konsoll |

## Kva han gjer

For kvar nettstad spør skriptet SharePoint sin søkeindeks (via Graph search-API) to gonger: éin gong for totalt tal på element, éin gong avgrensa til element med `InformationProtectionLabelId` sett. Reknar ut dekningsprosent og sorterer resultatet med lågast dekning øvst.

## Kjende avgrensingar

- Basert på søkeindeksen, ikkje ei fullstendig filgjennomgang – nyleg opplasta eller endra filer kan mangle frå indeksen i ein kort periode etter endring.
- Store tenantar utan `-SiteUrls` kan gi mange API-kall og ta tid; vurder å køyre mot ei liste med prioriterte nettstadar først.
- Reknar berre element av type `driveItem` (filer i dokumentbibliotek) – listeelement utanfor bibliotek blir ikkje talde med.
