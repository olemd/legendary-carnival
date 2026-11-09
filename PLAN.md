# lanwatch – prosjektplan

Kontinuerlig agent som holder oversikt over eget lokalnett, oppdager problemer,
svakheter og forbedringsmuligheter, og bruker en lokal LLM til å forklare og
prioritere. Alt kjører lokalt. Ingenting om nettverket forlater det: de eneste
utgående forespørslene henter offentlige versjons- og leverandørlister, og de kan
slås av.

Arbeidsnavn på pakken: `lanwatch`.

## 1. Mål og ikke-mål

Mål
- Automatisk inventar over enheter og tjenester på eget LAN, uten konfigurasjon.
- Oppdage endringer over tid (ny enhet, ny tjeneste, endret oppsett).
- Flagge kjente svakheter i eget oppsett via et sett deterministiske regler.
- Foreslå forbedringer (segmentering, oppdateringer, herding).
- Forklare funn på norsk i klartekst med anbefalt tiltak, via lokal LLM.
- Kontinuerlig vedlikeholdt oversikt over nettet: ett dokument som alltid
  viser nåtilstand (enheter, tjenester, segmenter, åpne funn, siste endringer),
  regenerert etter hver runde, med historikk via git.
- Kjøre ubetjent i måneder på en Linux-boks under `systemd`.
- Sane defaults overalt. Null obligatorisk config for å få verdi.

Ikke-mål
- Angrep av noe slag. Agenten er en revisor av eget nett, ikke et angrepsverktøy.
- Full trafikkinspeksjon (IDS). Krever mirror port, som de fleste routere
  ikke har. Passiv lytting begrenses til broadcast/multicast og egen trafikk.
- Automatisk utbedring. Regler og LLM foreslår, mennesket utfører.
- Skanning utenfor subnettene agenten selv sitter på. Alt annet krever
  eksplisitt allowlist i config.

## 2. Prinsipper, med begrunnelse

1. **Regler finner, LLM forklarer.** Små lokale modeller er upålitelige til å
   *oppdage* problemer fra rådata, men gode til å *formulere*, *klassifisere*
   og *oppsummere*. Alle funn og all severity kommer fra kode. LLM får aldri
   finne på identifikatorer, versjoner eller sårbarheter, kun referere til
   data vi gir den.
2. **Diff er hoveddetektoren.** "Noe nytt dukket opp" fanger mer i praksis enn
   signaturer. Historikk i SQLite er derfor kjernen, ikke et tillegg.
3. **Ikke ødelegg nettet du overvåker.** IoT, printere og gamle embedded-
   enheter tåler lite. Default er konservativ timing, rate limit, ingen
   aggressive prober, og en exclude-liste som er enkel å fylle.
4. **Alt lokalt.** Ollama (eller annet OpenAI-kompatibelt endepunkt) på samme
   maskin eller en annen maskin på LAN.
5. **Lagdelt konfig.** Innebygde defaults → `/etc/lanwatch/config.toml` →
   env `LANWATCH_*` → CLI-flagg. Alt kan overstyres, ingenting må.

## 3. Arkitektur

```
 scheduler (asyncio, kadens per jobb)
    │
    ├─ collectors   eksterne verktøy → typede observasjoner (pydantic)
    │                discovery, service inventory, router/infra-probes
    ▼
 store (sqlite)    devices, snapshots (immutable), services, findings, llm_cache
    ▼
 rules engine      ren Python, input = nå + forrige snapshot, output = Finding
    ▼
 llm layer         Ollama, JSON-schema-output, cachet på input-hash
    ▼
 notify / report   logg + markdown default. Opt-in: ntfy, webhook, e-post,
                   Home Assistant
```

- **collectors/**: én modul per kilde. Alltid timeout og rate limit. Returnerer
  aldri rå tekst oppover.
- **store/**: `sqlite3` direkte med små håndskrevne migrasjoner. Ingen ORM.
  Enhet identifiseres på MAC først, deretter IP + hostname for enheter uten
  synlig MAC.
- **rules/**: en fil per regel, felles interface `evaluate(ctx) -> list[Finding]`.
  Hver regel har id, default severity og kan slås av eller justeres i config.
- **llm/**: tynn klient. Prompt-maler ligger i filer, ikke i kode. Alle kall
  cachet slik at reskanning ikke koster ny inferens.
- **notify/**: kanaler med felles interface (ntfy, webhook, e-post, Home
  Assistant). Alle av som default. Et funn varsles én gang når det åpnes,
  funn fra samme runde batches til én melding, terskel `notify.min_severity`
  (default medium) med mulighet for strengere terskel per kanal. LLM-ens
  énlinjes oppsummering tas med når den finnes. Hver leveranse logges i
  store og vises i web-UI. Home Assistant får i tillegg `sensor.lanwatch_*`
  oppdatert hver runde.
- **overview/**: renderer `overview.md` fra store etter hver runde. Atomisk
  skriving. Valgfri git-commit av overview-katalogen per endring, slik at
  `git log` blir endringshistorikk for nettet. Senere HTML-variant og
  LLM-berikede enhetsbeskrivelser.
- **web/**: FastAPI + Jinja2, server-rendret, ingen JS-bygg. Dashboard, enheter,
  tjenester, funn med ack, oversikten. JSON-API under `/api`. Kjører i samme
  prosess som scheduleren. Bundet til 127.0.0.1 som default, passord påkrevd
  for å binde videre. Trukket frem fra M6 til M2 etter ønske.
- **cli/**: `run` (daemon), `scan` (engangs), `inventory`, `devices`, `services`,
  `findings`, `ack <id>`, `name`, `overview`, `rules`, `web`, `config show`.

## 4. Funn-modellen

```
Finding
  id            stabil hash av (rule_id, device_id, nøkkel-evidence)
  rule_id
  severity      critical | high | medium | low | info     (settes av regelen)
  kind          security | problem | improvement
  device_id
  evidence      dict, maskinlesbart, det regelen faktisk så
  first_seen / last_seen
  status        open | acked | resolved   (auto-resolved når evidence forsvinner)
  explanation   LLM-tekst, fylles inn asynkront, cachet
```

Regler i M2 (se `lanwatch rules` for effektiv severity):
- inventar: ny enhet, IP-endring, nye åpne porter på kjent enhet
- tjenester: ukryptert fjerninnlogging, FTP uten TLS, SMBv1, VNC uten
  autentisering, database synlig for hele segmentet
- herding: SSH med legacy-algoritmer, utløpt eller snart utløpt TLS-sertifikat

Tjenesteregler leser gjeldende tilstand i store, ikke bare runden som nettopp
kjørte. Et funn lever nøyaktig så lenge tilstanden gjør, uansett hvilke
enheter en runde skannet. "Hendelsesfunn" (ny enhet, nye porter) lukkes med ack.

Regler i M5:
- infrastruktur: flere DHCP-servere (critical), UPnP IGD aktivt (medium), hver
  aktiv portmapping i routeren (high), IPv6-nåbare tjenester (medium)
- versjoner: `service.legacy-version` mot kuratert tabell i koden (ingen nett,
  ingen gjetting, backports gir falske positiver og sies rett ut),
  `service.known-cves` fra nmap `vulners` (opt-in, eneste feature som snakker
  med internett)
- forbedring: IoT-klasse og betrodde enheter på samme /24 (info), bygger på
  LLM-klassifiseringen men er selv deterministisk

Infra-probes beriker også inventaret: UPnP friendlyName/modell og mDNS-navn
lagres som enhetsattributter og går inn i LLM-ens klassifiseringsfakta, som
dermed får ny cache-nøkkel og reklassifiseres.

Lagt til etter M6:
- nettidentitet: IP-konflikt, endret MAC på gateway/DHCP/DNS-adresse, endrede
  DHCP-innstillinger (DNS, NTP, ruter, domene), ny IPv6-ruter
- angrepstegn uten speilport: lokkeporter, passiv ARP-lytter (spoofing, sveip),
  lokkespørsmål over LLMNR/mDNS/NetBIOS
- hygiene: firmware-sjekk for produkter som selv oppgir versjon (oppslag av siste
  versjon hos produsent er opt-in), DNS-filtrering (opt-in, sender testoppslag ut)

Utsatt: logger fra utstyr som ser all trafikk (DNS-logger, ruterens IDS), se issue #1.
Full trafikkinspeksjon på speilport er fortsatt et ikke-mål.

## 5. LLM-laget

Rolle: språk og klassifisering, ikke deteksjon.

| oppgave | input | output (JSON schema) |
|---|---|---|
| klassifiser enhet | OUI, hostname, mDNS-navn, åpne porter, banners | type, produsent, confidence |
| forklar funn | Finding + evidence + regelens tekst | forklaring, konsekvens, tiltak |
| daglig digest | åpne funn + endringer siste 24t | prioritert liste, 5 linjer sammendrag |
| foreslå forbedringer | hele inventaret oppsummert | liste med tiltak, begrunnelse |

- Default endepunkt: Ollama på `http://localhost:11434`. Modell pinnes i config.
- Maskinvare: Radeon RX 7900 XTX, 24 GB VRAM, via ROCm (gfx1100, støttet av
  Ollama). Kandidater (2026-11-04): `qwen3.8:27b` (default) og `gemma4:26b`.
  Begge er ~16–18 GB i Q4 og gir rom for 16k chat-kontekst. Velges med
  `lanwatch llm eval`, som har to suiter: klassifisering og tool-calling-chat.
  Hvis en modell ikke støtter tools i Ollama, faller chatten tilbake til å
  lime inn inventaret, og sier fra i loggen.
- Hvis agenten kjører på en annen boks enn GPU-maskinen, pek `llm.base_url`
  på GPU-maskinen. Fortsatt lokalt.
- Egen evalueringsharness: gullsett med fingerprints → forventet klasse, slik at
  modellbytte kan måles.
- Guardrails: temperatur lav, JSON-schema tvunget av Ollama, pydantic-validering
  med ett retry som siterer feilen, cache på hash av modell+prompt-versjon+input,
  budsjett per runde, digest-prioriteringer som peker på ukjente id-er kastes.
- Degradering: Ollama nede → skanning upåvirket, LLM-arbeid tas igjen neste
  runde. Varsel i logg maks én gang i timen.
- Språk: `llm.language`, default `nb`. Tekniske termer holdes på engelsk i prompt.

## 6. Scheduler, defaults

| jobb | default kadens | begrunnelse |
|---|---|---|
| discovery | 5 min | billig, gir "ny enhet" raskt |
| service inventory, nye enheter | umiddelbart, top 200 porter | vite hva det er før neste runde |
| service inventory, alle online | 1 t, top 200 porter | nok til diff |
| dyp inventar | ukentlig per enhet, alle porter + UDP top 50 | tungt, kan plage enheter |
| infra-probes (DHCP, UPnP, IPv6) | 15 min | billig, høy verdi |
| regler | etter hver jobb | |
| LLM-forklaringer | fortløpende, kø | |
| digest | daglig 07:00 | |

Autodeteksjon: subnett fra egne interfaces, ekskluder loopback, docker-,
veth-, tun-/wg-interfaces. Alt kan overstyres i `[network]`.

## 7. Konfig (utdrag av defaults)

```toml
[network]
subnets = "auto"            # eller liste
exclude_hosts = []          # IP eller MAC
exclude_interfaces = ["lo", "docker*", "veth*", "br-*", "tun*", "wg*"]

[scan]
profile = "gentle"          # gentle | normal | thorough
max_parallel_hosts = 4
rate_limit_pps = 100

[llm]
base_url = "http://localhost:11434"
model = "TBD-i-M3"
timeout_s = 120
enabled = true

[notify]
log = true
report_dir = "/var/lib/lanwatch/reports"
# ntfy, webhook, email, home_assistant: alle av som default

[rules]
# "rule.id" = { enabled = false } eller { severity = "low" }
```

## 8. Teknologivalg

| valg | hvorfor |
|---|---|
| Python 3.12, `uv` | raskest iterasjon, best økosystem for å wrappe nettverksverktøy |
| pydantic | typede observasjoner og JSON-schema til LLM gratis |
| typer | CLI |
| sqlite3 (stdlib) | ingen tjeneste, én fil, enkel backup |
| httpx2 | Ollama-klient |
| eksterne verktøy via subprocess | `arp-scan`, `nmap` (XML), `ssh-audit`, `miniupnpc`. Modne, ikke verdt å reimplementere |
| pytest + opptak av XML-output | tester uten nett |
| ruff + mypy strict | |

Deployment, tre støttede oppsett (`deploy/README.md`):
1. `systemd`-unit, egen bruker, `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN`.
2. Rootful podman via quadlet: `Network=host`, `DropCapability=ALL` +
   `AddCapability=NET_RAW NET_ADMIN`, read-only rootfs.
3. Rootless podman uten capabilities + `lanwatch-helper`: en liten root-daemon
   på verten som kun kjører allowlistede `nmap`/`arp-scan`/`ip`/`ping`-kall
   over en unix-socket. Argumentene valideres mot mønstre, targets må være
   IP/CIDR. Rootless + host-nett + raw sockets er en blindvei (capabilities
   gjelder bare i user namespace som eier nett-namespace), derfor helperen.
Ollama med ROCm har egen quadlet (`/dev/kfd`, `/dev/dri`).

Go ble vurdert (én statisk binær) og valgt bort: økosystemet rundt skann-
parsing og LLM-klienter er tynnere, og iterasjonshastighet veier tyngst nå.

## 9. Milepæler

| M | leveranse | verdi når ferdig |
|---|---|---|
| M0 | skjelett, config-lagdeling, logging, sqlite, CLI, CI | kjører, gjør ingenting |
| M1 | discovery + inventar + diff + "ny enhet"-funn + `overview.md` | allerede nyttig |
| M2 | service-inventar, regelmotor, 10 regler, web-UI | kjernen |
| M3 | LLM: klassifisering, forklaring, digest, forslag, eval-harness; podman + root-helper | det som gjør den lesbar |
| M4 | notify-adaptere (ntfy, webhook, e-post, Home Assistant med sensorer), varslingslogg | drift |
| M5 | infra-probes (DHCP, UPnP-mappinger, IPv6, mDNS), versjonstabell + opt-in vulners, flat-nett-regel | dybde |
| M6 | hendelseslogg + tidslinje, søk, LLM-chat mot inventaret, historikk-graf | bekvemmelighet |

Hver milepæl skal være kjørbar og nyttig alene.

Status 2026-11-04: M0–M6 levert. Se README for hva som er verifisert i ekte
nett og hva som bare er testet mot opptak og mocks.

Hendelsesloggen (M6) skrives av store selv der tilstand endres, ikke av
pipelinen, slik at CLI, web og scheduler alle produserer samme historikk.
Presence-hendelser (online/offline) lagres men skjules som default i UI,
siden telefoner som sover gir støy.

Chat (M6) bruker tool calling (bekreftet ok 2026-11-04). Lesende verktøy
mot store pluss tre handlinger: ack funn, navngi enhet, kjør skann.
Handlinger skal kun utføres når brukeren ber om det i samtalen, kan slås av
per forespørsel, og logges som `chat.action` i tidslinjen. Hvert svar bærer
med seg listen over verktøykall, så det er sporbart hva modellen slo opp.
System-prompten har bare et kort sammendrag; detaljer hentes via verktøy,
som skalerer bedre enn å lime inn hele inventaret.

## 10. Risiko og ærlige forbehold

- **Små LLM-er hallusinerer.** Derfor skjema-tvang, cache og ingen deteksjon
  i LLM. Forvent likevel at forklaringer må leses kritisk.
- **Skanning kan forstyrre.** Konservativ default. Første kjøring bør overvåkes.
- **Plassering.** Agenten må sitte på L2 på det nettet den skal se. En VM bak
  NAT ser ingenting. Pi/NUC/server på samme switch.
- **Ytelse for LLM.** Løst med 7900 XTX. Agenten og Ollama trenger ikke
  være på samme boks, remote Ollama på LAN er støttet oppsett.
- **ROCm.** Ollama på AMD er stabilt for gfx1100, men driverversjoner på
  verten kan bite. Dokumenteres i M3.
- **Juridisk.** Kun eget nett. Default-oppsettet ser bare subnett agenten er
  medlem av, alt annet er opt-in.

## 11. Beslutninger

Bekreftet 2026-11-04:

1. Python, ikke Go.
2. SQLite, ingen ekstern database.
3. Ollama som default LLM-backend, på RX 7900 XTX (24 GB).
4. LLM foreslår, utfører aldri. Ingen "auto-fix" i første versjon.
5. Home Assistant som første integrasjon etter ntfy/webhook.
6. ~~Web-UI er sist og valgfritt.~~ Endret 2026-11-04: web-UI er del av M2 og
   primær presentasjonsflate sammen med `overview.md`.
