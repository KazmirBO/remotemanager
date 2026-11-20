# Menedżer sesji SSH i RDP - informacje startowe

Własna aplikacja desktopowa do sesji SSH i RDP z panelem bocznym w stylu mRemoteNG (katalogi, grupowanie hostów). Autor: Sebastian. Dokument zbiera ustalenia, żeby można było zacząć pisać kod bez wracania do rozmowy. Rzeczy oznaczone jako "propozycja" nie są jeszcze zatwierdzone.

## Ustalone

- Platformy: Linux (Gentoo) i Windows.
- Stos: Rust + Tauri, terminal xterm.js.
- RDP osadzony w karcie, uwierzytelnianie NLA wymagane. Klient: IronRDP (decyzja warunkowa, patrz niżej "Prototyp RDP").
- Hosty i hasła w pliku zaszyfrowanym hasłem głównym. Klucze SSH przez ssh-agent albo własny klucz prywatny (patrz następny punkt).
- Klucze prywatne SSH (host albo katalog, oba pola dziedziczone niezależnie): `ssh_key` to klucz zapisany w pliku hostów (`model::StoredKey`: tekst OpenSSH bez hasła, algorytm i odcisk SHA256 liczone przy imporcie), `ssh_key_path` to ścieżka do pliku czytanego przy łączeniu (bezwzględna albo `~/`). Dekodowanie i formaty (OpenSSH, PKCS#8, PKCS#5/PKCS#1 PEM, PuTTY .ppk, także zaszyfrowane) są w `crates/ssh/src/keys.rs` (`parse_key`, `import_key`, `read_key_file`, limit 64 KiB). Zaszyfrowany klucz jest odszyfrowywany RAZ przy imporcie (`FieldsIo::prepare` w `dto.rs`, poza blokadą dokumentu): w pliku ląduje klucz bez hasła, chroniony hasłem głównym, a hasło klucza nie jest zapisywane. Błędy importu mają prefiksy `KEY_NEEDS_PASSPHRASE:`, `KEY_BAD_PASSPHRASE:`, `KEY_INVALID:`; widok dostaje tylko `has_ssh_key`, algorytm i odcisk, a usunięcie klucza (`clear_ssh_key`) wygrywa z wklejonym tekstem. Klucz ze ścieżki, jeśli jest zaszyfrowany, wymaga hasła przy każdym połączeniu (`NEEDS_KEY_PASSPHRASE:<powód>`, okno hasła na jedną sesję, tylko dla celu; na bastionie błąd z radą). Kolejność prób na przystanku (`sessions.rs`, `build_hop`): klucz z pliku hostów, plik klucza, agent, zapisane hasło, a na końcu pytanie o hasło; limit `MAX_AUTH_ATTEMPTS` = 5 prób na przystanek z rezerwą dla późniejszych metod (agent próbuje tylu kluczy, ile zostaje po odjęciu rezerwy). Dziennik mówi, która metoda zadziałała (algorytm i odcisk, bez materiału klucza). Ograniczenia: brak kluczy domyślnych z `~/.ssh`, generowania kluczy, certyfikatów OpenSSH, kluczy sprzętowych z pliku (`sk-*`) i przekazywania agenta; plik klucza, którego nie ma albo nie da się otworzyć, jest pomijany z wpisem `pominięto plik klucza ...` w dzienniku i w komunikacie niepowodzenia (ścieżka jest wspólna dla zsynchronizowanych maszyn, a plik bywa tylko na części z nich), natomiast plik za duży, bez obsługiwanego klucza albo zaszyfrowany przerywa łączenie przed próbą agenta i hasła; anulowanie okna hasła klucza kończy łączenie; `ssh_key` nie leży w `InheritableKey` (widok nie niesie klucza), dziedziczenie podpowiada `inheritsSshKey` w `tree.ts`; rozpoznanie zaszyfrowanego PPK i błędnego MAC opiera się na tekście błędu `ssh-key` (typ `PpkParseError` jest prywatny). Pliki PuTTY (.ppk) nie mają testu z prawdziwym kluczem, bo wymagałby klucza prywatnego w repozytorium: testy sprawdzają tylko rozpoznanie szyfrowania z nagłówka i opis błędu, a import PPK v2 (bez hasła, z dobrym i złym hasłem) był sprawdzony jednorazowo przy wdrożeniu; PPK v3 (Argon2) jest niesprawdzony.
- Stare serwery SSH (19.11.2026, zgłoszenie #12, poziom 1): dwa pola dziedziczone dla hosta i katalogu. `ssh_term` to typ terminala wysyłany w żądaniu PTY (`Session::open_shell`, domyślnie `ssh::DEFAULT_TERM` = `xterm-256color`; `ssh::valid_term` dopuszcza do 64 znaków ASCII z liter, cyfr i `-_.+`, a nazwa niepoprawna jest zastępowana domyślną). `ssh_legacy` włącza `Hop.legacy`: lista algorytmów biblioteki dostaje na końcu wymianę kluczy z SHA-1 (`diffie-hellman-group14-sha1`, `group-exchange-sha1`, `group1-sha1`), szyfry `aes*-cbc` i `hmac-sha1`, więc serwer znający nowe algorytmy nadal je wybiera; przy braku `server-sig-algs` klucz RSA podpisuje wtedy jako `ssh-rsa` (SHA-1), bo stary serwer nie zna `rsa-sha2-*`. Dziennik zapisuje, że starsze algorytmy były dozwolone. Sprawdzone testem na prawdziwym `sshd` ograniczonym do `group14-sha1`, `aes128-cbc` i `hmac-sha1`: bez przełącznika połączenie jest odrzucane, z nim działa. Ograniczenia: terminal aplikacji (xterm.js) emuluje xterm, więc typ `aixterm` zmienia tylko to, co wysyła serwer, a klawisze funkcyjne idą w kodowaniu xterm; brak `3des-cbc` i kluczy DSA (wymagałyby nowych cech biblioteki), brak przekodowania znaków dla serwerów bez UTF-8, brak Telnetu i emulacji blokowych (3270, 5250). Niesprawdzone z prawdziwym serwerem AIX.
- Przestawianie kart sesji (20.11.2026): karty na pasku przestawia się przeciąganiem (własny typ danych `application/x-mrm-tab`, więc drzewo hostów nie bierze karty za hosta; połowa karty pod wskaźnikiem wyznacza wstawienie przed albo za, wolne miejsce paska oznacza koniec, pasek przewija się przy krawędzi), pozycjami menu karty i akcjami `move_tab_left`, `move_tab_right` (bez domyślnych skrótów). Kolejność liczą czyste funkcje `moveItem` i `dropIndex` w `tabOrder.ts` (z testami), a stan zmieniają `moveTab` i `moveTabNextTo` w `store.svelte.ts`. Widoki sesji w `.stage` są układane według numeru otwarcia (`Tab.seq`), nie kolejności kart, żeby przestawienie nie przenosiło węzła terminala albo pulpitu w dokumencie (przeniesienie odbiera fokus). Kolejność kart nie jest zapisywana. Sprawdzone w atrapie interfejsu w Chromium; niesprawdzone w oknie Tauri (WebKitGTK, WebView2).
- Kategorie ustawień i zakładki hosta (19.11.2026): okno Ustawienia ma listę kategorii po lewej (Wygląd, Terminal, RDP, Sesje, Bezpieczeństwo, Synchronizacja, Skróty, Narzędzia) i jeden przycisk Zapisz; synchronizacja i kopie zapasowe działają od razu. Okna hosta i katalogu mają zakładki Ogólne, Logowanie, Połączenie, Terminal, Przekierowania (zakładka bez pól dla protokołu jest ukryta; błąd zapisu stoi w stopce, a zakładkę pola wskazuje `errorTab` w `hostTabs.ts`, po początku komunikatu backendu). Kod: `Tabs.svelte` i `tabNav.ts` (role ARIA, strzałki), `settings/` (panele kategorii), `hostTabs.ts`, `FieldsForm.svelte` z propsem `section`. Nowe ustawienia w `model::Settings` (wędrują z plikiem, każde z serde default, więc stare pliki czytają się bez zmian): kroj czcionki (wbudowana JetBrains Mono albo `monospace` systemu), kształt i miganie kursora, historia przewijania (domyślnie 5000), kopiowanie po zaznaczeniu, wklejanie prawym przyciskiem (tekst czyta backend przez wątek schowka, bo `navigator.clipboard.readText` w WebKitGTK bywa zablokowane), domyślny TERM (`ssh_term`), pytanie przed zamknięciem karty i programu (domyślnie wyłączone), podtrzymywanie SSH (`ssh_keepalive_secs`, domyślnie 30 s, 0 wyłącza; `ssh::Hop::keepalive`), automatyczna blokada po bezczynności (`auto_lock_minutes`, domyślnie wyłączona). Liczba kopii zapasowych leży w `config.json` (`backup_count`, 1-20, domyślnie 5), bo dotyczy tej maszyny i jest potrzebna przy zapisie; zmniejszenie usuwa kopie ponad limit. Pola dziedziczone: `terminal_font_size` (bez ustawienia obowiązuje rozmiar z ustawień) i `ssh_login_command` (wysyłane do powłoki po otwarciu, tylko dla celu, nie dla bastionów; limit 1024 znaków, bez znaków sterujących poza tabulatorem; zapisane jawnie w pliku z hostami, więc formularz ostrzega przed hasłami, a polecenie nie trafia do dziennika diagnostycznego). Zakresy sprawdza backend (`validate_settings`, `FieldsIo::prepare`). Pytanie o zamknięcie programu rozstrzyga backend (`request_quit`, `quit_pending`; druga prośba przy czekającym pytaniu kończy program, a blokada pliku zeruje flagę). Bezczynność liczy backend (`idle.rs`, dłuższy z czasów monotonicznego i ściennego; aktywność zgłasza interfejs najwyżej co 15 s i hak klawiatury Windows). Ograniczenia: zapis ustawień nie jest atomowy (hasło, plik, config.json), przywrócenie kopii zamyka okno ustawień, "systemowa" czcionka to tylko rodzina `monospace`, zmiany SSH (TERM, podtrzymywanie, polecenie) dotyczą nowych połączeń.
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
- Płynność i przechwytywanie klawiszy (16.11.2026): w RDP kursor lokalny (kształty wskaźnika z serwera jako kursor okna), lista prostokątów zmian zamiast jednego obejmującego, `TCP_NODELAY`, keepalive i krótszy obieg pętli procesu, profil łącza (szybkie albo wolne: wolne wyłącza efekty pulpitu; kompresja danych i 16 bitów koloru odpadły, bo IronRDP 0.17 nie dekompresuje ścieżki slow-path); w terminalu SSH renderer WebGL i kontrola przepływu wyjścia; przechwytywanie klawiszy w sesji RDP z ustawieniem (nigdy, pełny ekran, zawsze), przyciskiem na pasku sesji i skrótem zwalniającym, z klawiszami systemowymi przez GDK na Linuksie i przez hak klawiatury na Windows (crate `keygrab`, jedyny z `unsafe` w głównym workspace; hak potwierdzony na prawdziwej maszynie 17.11.2026, wersja 0.1.4). Sprawdzone testami jednostkowymi i na lokalnym `freerdp-shadow-cli` (połączenie, obraz, profil wolny). Niesprawdzone w działającej aplikacji: kursor lokalny i profil łącza z serwerem Windows (serwer testowy nie przysyła kształtów wskaźnika), przejęcie klawiszy na Waylandzie i X11, WebGL w WebKitGTK i WebView2, odczuwalna płynność.
- Klucze bezpieczeństwa w RDP (17.11.2026, zgłoszenie #3): przekierowanie FIDO2/WebAuthn kanałem dynamicznym `WebAuthN_Channel` ([MS-RDPEWA]). Protokół kanału (`ironrdp-rdpewa` 0.2) i wykonanie operacji przez systemowe API Windows (`ironrdp-rdpewa-native` 0.2) istnieją tylko dla nowszego stosu IronRDP, więc proces RDP trzyma je obok dotychczasowego stosu, a moduł `rdp-worker/src/webauthn.rs` przepisuje komunikaty między nimi; reszta procesu nie zmieniła wersji żadnej zależności. Kanał powstaje tylko dla hostów z włączonym polem dziedziczonym `rdp_webauthn` (domyślnie wyłączone) i tylko na Windows; poza Windows sesja zgłasza, że funkcja jest niedostępna. Protokół procesu ma wersję 3. Niesprawdzone z prawdziwym kluczem i serwerem; natywne zaplecze wymaga, żeby serwer przysłał `clientDataJSON`. Wariant z kartą inteligentną jest osobną funkcją (niżej).
- Czytniki kart w RDP (17.11.2026, zgłoszenie #3): przekierowanie czytników kart inteligentnych ([MS-RDPESC]) kanałem statycznym `rdpdr` z `ironrdp-rdpdr` 0.7 (cecha `rdpdr` stosu 0.17, bez zmiany wersji istniejących zależności); obok niego musi być ogłoszony kanał `rdpsnd`, bez żadnego formatu dźwięku. Biblioteka tylko dekoduje wywołania i koduje odpowiedzi, a operacje wykonuje moduł `rdp-worker/src/scard.rs`: wątki na kontekst (operacje i osobno czekanie na zmianę stanu) i na kartę, limity, pamięć podręczna danych karty, odpowiedź `ListReadersA` we własnym kodowaniu (biblioteka koduje listę tylko w UTF-16) i opakowania kanałów, które pomijają niedekodowalny komunikat zamiast kończyć sesję. Dostęp do czytników daje `scard_pcsc.rs` (biblioteka `pcsc` 2.9, WinSCard), tylko na Windows; poza Windows sesja zgłasza, że funkcja jest niedostępna. Pole dziedziczone `rdp_smartcard` ma trzy wartości: wyłączone (domyślnie), włączone i włączone z neutralnymi nazwami czytników ("Smart Card Reader N"). Neutralne nazwy są po to, że KeePassXC przy wyliczaniu kluczy pomija czytniki z "yubikey" w nazwie; czy klucz podłączony po USB odpowie przez interfejs kart na wyzwanie-odpowiedź, nie wiadomo (autorzy KeePassXC piszą, że bywa zablokowany). Biblioteka nie dekoduje m.in. `Reconnect`, `GetAttrib`, `Control` i `LocateCards`; takie wywołanie dostaje kod "funkcja nieobsługiwana" i wpis `karty: nieobsługiwane wywołanie ...` w dzienniku diagnostycznym. Protokół procesu ma wersję 4. Niesprawdzone z prawdziwym czytnikiem i serwerem: testy używają atrapy usługi kart, a część Windows sprawdza tylko kompilacja.

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
