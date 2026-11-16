# Menedżer sesji SSH i RDP - informacje startowe

Własna aplikacja desktopowa do sesji SSH i RDP z panelem bocznym w stylu mRemoteNG (katalogi, grupowanie hostów). Autor: Sebastian. Dokument zbiera ustalenia, żeby można było zacząć pisać kod bez wracania do rozmowy. Rzeczy oznaczone jako "propozycja" nie są jeszcze zatwierdzone.

## Ustalone

- Platformy: Linux (Gentoo) i Windows.
- Stos: Rust + Tauri, terminal xterm.js.
- RDP osadzony w karcie, uwierzytelnianie NLA wymagane. Klient: IronRDP (decyzja warunkowa, patrz niżej "Prototyp RDP").
- Hosty i hasła w pliku zaszyfrowanym hasłem głównym. Klucze SSH przez ssh-agent (nie przechowujemy kluczy prywatnych).
- Drzewo hostów z katalogami i dziedziczeniem ustawień z katalogu na host (host może nadpisać pole, katalog może przekazywać pole w dół).
- Tylko terminal SSH (bez SFTP i tuneli), bez podzielonych widoków, bez importu z mRemoteNG.
- Zatwierdzone dodatki: dziennik sesji, linki `ssh://` i `rdp://`, synchronizacja zaszyfrowanego pliku przez folder, ulubione i ostatnie, wiele monitorów w RDP, bastion (ProxyJump), szybkie łączenie (domyślnie Ctrl+Shift+K, bo Ctrl+K jest klawiszem sterującym powłoki), zaufane klucze i certyfikaty, kopie zapasowe pliku.
- Interfejs po polsku. Monochromatyczna paleta, natywna ramka okna.

## Prototyp RDP

Prototyp `tools/rdp/rdp-probe/` (workspace Cargo `tools/rdp`, osobny od głównego, ironrdp 0.17, ironrdp-blocking 0.10, sspi 0.21 z `network_client`): host, użytkownik, domena, hasło z `RDP_PASSWORD` albo z ukrytego pytania, opcje `--kerberos`, `--kdc`, `--width`, `--height`, zapis pierwszej ramki do PNG.

Wyniki (17.10.2026), serwer testowy `freerdp-shadow-cli` 3.32.1 na lokalnej maszynie, NLA z plikiem SAM, udostępniony tylko mały prostokąt ekranu:

- NLA przez CredSSP z NTLM przechodzi (ok. 125 ms). To rozstrzyga główne ryzyko na korzyść IronRDP.
- Odbiór grafiki kończy się błędem `received unexpected Share Control PDU`: serwer testowy wymusza sekwencję deaktywacji i reaktywacji, a `ActiveStageOutput::DeactivateAll` nie jest w sondzie obsłużone. Wymaga obsługi w Fazie 5 (ConnectionActivationSequence z ironrdp-connector).
- Niesprawdzone: serwer Windows, Kerberos (wariant `--kerberos` jest w sondzie, ale nie był uruchamiany), pełny odbiór ramki. Do sprawdzenia na prawdziwym hoście (`--host dc01 -u <user> -d FIRMA`).
- Kerberos jest hasłowy, bez logowania jednokrotnego z ccache.

Integracja (zrobiona): wybrano wyjście 2, czyli RDP w osobnym procesie `tools/rdp/rdp-worker` (własny workspace i `Cargo.lock`), z protokołem ramek przez stdio w `crates/rdp-proto`, klientem `crates/rdp` i komendami `connect_rdp`, `rdp_send`, `rdp_close` w aplikacji. Proces obsługuje reaktywację, wejście i decyzję o certyfikacie przed wysłaniem hasła. Testy `crates/rdp/tests/shadow.rs` przechodzą na lokalnym `freerdp-shadow-cli` (NLA NTLM, obraz, zły odcisk, złe hasło). Niesprawdzone: serwer Windows, Kerberos z prawdziwym KDC (pole w formularzu hosta RDP jest), pełny ekran. Niezrobione: wiele monitorów. Schowek i zmiana rozmiaru pulpitu doszły później, ich stan opisuje sekcja "Decyzje z planu pracy".

Konflikt zależności (przyczyna osobnego procesu): `ironrdp-connector` 0.10 wymaga `sspi ^0.21`, który przypina `curve25519-dalek =5.0.0-rc.1`, a `russh` 0.60-0.64 wymaga dalek 5 (pre-release albo stabilnego). Cargo nie scali ich w jednym `Cargo.lock`, dlatego `rdp-probe` jest poza workspace głównym, a RDP działa w aplikacji przez osobny proces (wybrane wyjście 2). Rozważane wyjścia: (1) `russh` 0.59 (dalek 4, starsze wydanie), (2) RDP jako osobny proces pomocniczy z własnym `Cargo.lock`, (3) poczekać na wydanie IronRDP zgodne z `sspi` 0.23, (4) libfreerdp przez FFI (plan awaryjny).

## Propozycja architektury

Workspace Cargo z osobnymi crate'ami, żeby moduł RDP dało się wymienić:

| Crate | Odpowiedzialność |
|---|---|
| `vault` | Format pliku, szyfrowanie, hasło główne, kopie zapasowe, wersjonowanie formatu |
| `model` | Drzewo (katalog, host), pola nadpisywalne, rozwiązywanie dziedziczenia |
| `ssh` | Sesje SSH, ProxyJump, agent, zaufane klucze |
| `rdp` | Sesje RDP za wspólnym interfejsem (trait), implementacja IronRDP |
| `sync` | Synchronizacja pliku przez folder, wykrywanie konfliktów |
| `app` | Tauri: komendy IPC, zdarzenia, okna, zasobnik, linki |

Frontend: framework do wyboru (propozycja: dowolny lekki, xterm.js nie wymusza żadnego). Obraz RDP do webview jako ramki na canvas przez zdarzenia lub własny schemat URI - do rozstrzygnięcia po prototypie, bo wpływa na wydajność przy wielu monitorach.

## Decyzje z planu pracy (17.10.2026)

Plan szczegółowy: `~/.claude/plans/zr-bmy-plan-pracy-technologia-agile-harbor.md`. Wersje sprawdzone `cargo info` i `npm view` w tym dniu.

- Licencja: MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
- Tauri 2.12.4 (gałąź 3.0 jest alfą, nie używamy). Frontend: Svelte 5 + Vite + TypeScript, pnpm, @xterm/xterm 6.
- Szyfrowanie: XChaCha20-Poly1305 (`chacha20poly1305` 0.11) + Argon2id (`argon2` 0.6) + `zeroize`.
- SSH: `russh` 0.64.1; ProxyJump przez własny kanał `direct-tcpip` (do potwierdzenia w spike'u).
- RDP: IronRDP 0.17 z `sspi` 0.21 (0.23 niezgodne z ironrdp-connector), plan B libfreerdp przez FFI. Patrz konflikt zależności w sekcji Prototyp RDP.
- `rdp-probe` powstał od zera w `tools/rdp-probe` (Faza 1), dziś leży w `tools/rdp/rdp-probe` obok procesu RDP.
- Zrobione: `vault`, `model` (w tym parser linków), `ssh` (testy na prawdziwym sshd), `sync` (konflikty po skrótach SHA-256), RDP w osobnym procesie, `app` (Tauri, zasobnik z trzema stanami ikony), frontend Svelte: drzewo, terminal SSH, widok RDP, edycja z dziedziczeniem, zaufanie do kluczy i certyfikatów, szybkie łączenie z linkami, ustawienia, edytowalne skróty, schematy terminala, synchronizacja z rozstrzyganiem konfliktów i automatyczną wysyłką, kopie zapasowe z przywracaniem, dziennik diagnostyczny bez sekretów, dziennik sesji SSH, hasło na jedną sesję, pełny ekran RDP. Dodatkowo zrobione: Kerberos w formularzu hosta RDP (parametry do procesu; niesprawdzone bez KDC), zmiana rozdzielczości pulpitu RDP razem z rozmiarem okna przez Display Control (obraz zawsze 1:1, bez skalowania; proces czeka na gotowość kanału i raz na sesję zgłasza, że serwer zmiany nie obsługuje; lokalny `freerdp-shadow-cli` jej nie ma, działanie z prawdziwym serwerem potwierdził użytkownik 14.11.2026), pełny schowek RDP: tekst, HTML, obrazy, pliki i katalogi w obu kierunkach z limitami i przełącznikiem (logika i bezpieczeństwo ścieżek pokryte testami jednostkowymi, które nie dotykają prawdziwego schowka; działanie z prawdziwym serwerem potwierdził użytkownik 14.11.2026), centrum powiadomień, pojedyncza instancja, pakiet deb ze sidecarem i rejestracją schematów. Niezrobione: lista ostatnio używanych hostów (z zatwierdzonego dodatku "ulubione i ostatnie" są tylko ulubione), wiele monitorów RDP (wymaga okien na osobnych monitorach), rejestracja schematów w systemie Windows, instalator dla Gentoo (ebuild), ekran aktualizacji (brak serwera aktualizacji).
- Poprawki po przeglądach (10-14.11.2026): odporność zapisu i zmiany hasła w `vault`, synchronizacja bez fałszywych kopii konfliktu, blokada pliku z jednego miejsca (`lock_all`, zdarzenie `vault-locked`), kolejka monitów o hasło, skróty w terminalu i pod oknami modalnymi, schowek RDP tylko z ogłoszonej migawki i tylko przy fokusie, lista dozwolonych poleceń `rdp_send`, limity czasu SSH, walidacja bastionów i ustawień, zapis pliku tylko przy faktycznej zmianie, uprawnienia dziennika sesji, kontrola przepływu obrazu RDP (potwierdzenia z interfejsu, ograniczona kolejka zdarzeń) i sprawdzanie lokalnego schowka z odstępem zależnym od kosztu odczytu. Niesprawdzone w działającej aplikacji: kontrola przepływu obrazu pod obciążeniem (np. wideo w sesji RDP), zachowania tylko dla Windows (okno konsoli procesu RDP, AltGr, nazwy zastrzeżone, tożsamość plików serwowanych przez schowek), Kerberos z KDC, Display Control i schowek z serwerem Windows.

## Do ustalenia przed kodem (propozycje)

1. Szyfrowanie pliku: XChaCha20-Poly1305 lub AES-GCM, KDF z hasła Argon2id (parametry do dobrania), nagłówek z numerem wersji formatu. Konkretne crate'y i ich aktualne wersje sprawdzić w dniu wyboru.
2. Biblioteka SSH: `russh` (czysty Rust, async) lub `ssh2` (libssh2). Sprawdzić wsparcie ProxyJump i agenta.
3. Przechowywanie zaufanych kluczy: osobny plik lub wewnątrz pliku z hostami.
4. Zasady dziedziczenia: pole puste = dziedzicz; kolejność rozwiązywania host -> katalog -> katalog nadrzędny -> ustawienia domyślne.
5. Frontend: wybór frameworka, system budowania, CI na obu platformach.
6. Zależności systemowe Tauri na Gentoo (webkit-gtk 4.1 i narzędzia GTK) - zweryfikować na maszynie.

## Pliki projektu wizualnego

W `design/`:

- `DESIGN.md` - tokeny (kolory ciemne i jasne), typografia, odstępy, promienie, wysokości, reguły stanów, mapa plansz.
- `icons/` - 47 ikon interfejsu, ikona programu w dwóch wariantach, trzy stany ikony zasobnika (SVG, siatka 24x24).
- `boards/` - 37 plansz `.dc.html` i `canvas.json` (układ). Plansze używają `./support.js` dostarczanego przez typ artefaktu, którego nie ma w repozytorium, więc samodzielnie otwarte w przeglądarce się nie wyrenderują. Źródłem do oglądania jest artefakt "Menedżer sesji SSH i RDP" w claude.ai. Pliki służą do odczytu wartości (style są wpisane inline) i jako archiwum.

## Mapa: ekran -> moduł

| Plansza | Moduł |
|---|---|
| Okno główne, Okno wąskie, Pasek kart i menu karty, Stany drzewa hostów, Menu kontekstowe | `app` (frontend), `model` |
| Widok sesji RDP, RDP pełny ekran, Stany sesji | `rdp`, `ssh`, `app` |
| Odblokowanie, Pierwsze uruchomienie, Zmiana hasła głównego, Błędy pliku z hostami, Kopie zapasowe | `vault` |
| Konflikt synchronizacji, Kreator synchronizacji | `sync` |
| Zaufanie do hosta, Zaufane klucze, Stany agenta SSH | `ssh`, `rdp` |
| Edycja hosta, Właściwości katalogu | `model` (dziedziczenie) |
| Ustawienia aplikacji, Skróty klawiszowe, Edycja skrótu, Schematy terminala | `app` (konfiguracja) |
| Szybkie łączenie, Połączenie z linku | `app` |
| Powiadomienia, Monit o hasło, Start i aktualizacja, O programie, Dziennik diagnostyczny | `app` |

## Kolejność prac (propozycja)

1. Wynik prototypu `rdp-probe` (NTLM, Kerberos) - rozstrzyga wybór klienta RDP.
2. `vault` + `model` z testami (dziedziczenie, szyfrowanie, kopie).
3. Szkielet Tauri z drzewem hostów i odblokowaniem.
4. SSH w karcie (xterm.js), agent, zaufane klucze, bastion.
5. RDP w karcie, potem pełny ekran i wiele monitorów.
6. Synchronizacja, kopie, ustawienia, skróty, linki.

## Uwagi

- Dane na planszach (nazwy hostów, odciski, wersje, ścieżki) są przykładowe. Nazwa "Menedżer sesji" i polecenie `multiremotemanager` są robocze.
- Plansze nie były oglądane w przeglądarce podczas tworzenia.
- Sekretów (hasła, klucze prywatne) nie wolno zapisywać w logach ani w dzienniku diagnostycznym; ekran dziennika zakłada tę regułę.
