# Export-PurviewDLPReport.ps1

Hentar DLP-hendingar frå unified audit log og formaterer dei til ein CSV-rapport med regel, handling, arbeidslast og sensitiv informasjonstype per hending – nyttig når Purview sine innebygde rapportar ikkje gir fleksibiliteten du treng.

## Føresetnader

- PowerShell 5.1 eller 7+
- Modul: `ExchangeOnlineManagement`
- Rolla "View-Only Audit Logs" (eller høgare) i Purview/Microsoft 365-portalen

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

## Bruk

```powershell
.\Export-PurviewDLPReport.ps1 -StartDate (Get-Date).AddDays(-30) -OutFile "dlp-siste-30-dagar.csv"
```

## Parametrar

| Parameter | Påkravd | Skildring |
|---|---|---|
| `-StartDate` | Nei | Startdato, standard: 7 dagar tilbake |
| `-EndDate` | Nei | Sluttdato, standard: no |
| `-OutFile` | Nei | Filsti for CSV-output, standard: konsoll |

## Kva han gjer

Søkjer i unified audit log etter `DLPRuleMatch`-hendingar, med automatisk paginering for periodar med mange treff. Pakkar ut `AuditData`-JSON-en per hending og hentar ut tidspunkt, brukar, arbeidslast (Exchange/SharePoint/OneDrive/Teams), objekt, regelnamn, utløyste handlingar og kva sensitive informasjonstypar som vart funne.

## Kjende avgrensingar

- Unified audit log kan ha inntil 24 timars forseinking – forvent ikkje sanntidsdata.
- Store søk (månadsvis i store tenantar) kan ta fleire minutt grunna paginering.
- Skjemaet på `AuditData` kan variere noko mellom arbeidslaster; skriptet er testa mot Exchange- og SharePoint-hendingar, juster `ConvertFrom-Json`-parsinga om du ser tomme felt for andre arbeidslaster.
