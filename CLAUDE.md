# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Produkt

Desktopowa aplikacja do sesji SSH i RDP z panelem bocznym w stylu mRemoteNG (katalogi, dziedziczenie ustawień). Linux (Gentoo) i Windows. Rust + Tauri 2, frontend Svelte 5 + xterm.js, interfejs po polsku. Nazwa "Menedżer sesji" i polecenie `multiremotemanager` są robocze. Licencja MIT OR Apache-2.0. Zakres jest wąski: tylko terminal SSH (bez SFTP, tuneli, podzielonych widoków, importu z mRemoteNG).

Dokumenty źródłowe: `PROJECT.md` (ustalenia, wyniki prototypu RDP, stan prac, mapa ekran -> moduł) i `design/DESIGN.md` (tokeny wizualne). Plany robocze leżą poza repozytorium w `~/.claude/plans/`.

## Komendy

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --manifest-path tools/rdp/Cargo.toml     # proces RDP (osobny workspace); CI robi też clippy -D warnings i testy z tym manifestem
cargo test --manifest-path tools/rdp/Cargo.toml      # testy procesu RDP (schowek, pasy obrazu); nie wchodzą w `cargo test --workspace`
cargo test --workspace                       # w tym testy na prawdziwym sshd (ok. 20 s)
cargo test -p ssh --test sshd agent_auth     # pojedynczy test
cargo test -p rdp --test handshake           # powitanie procesu RDP; nie wymaga serwera

pnpm --dir app/ui install
pnpm --dir app/ui check                      # svelte-check
pnpm --dir app/ui test                       # vitest; pojedynczy plik: pnpm --dir app/ui exec vitest run src/lib/tree.test.ts
pnpm --dir app/ui build                      # wymagany przed budową aplikacji (frontendDist)
pnpm --dir app/ui icons                      # regeneruje src/lib/icons.generated.ts z design/icons/

scripts/build-release.sh --bundles deb          # pakiet instalacyjny: proces RDP jako sidecar Tauri (PROFILE=debug przyspiesza próbę; bez AppImage, bo pobiera narzędzia)
cargo build -p app --features custom-protocol   # binarka z wbudowanym frontendem (bez cechy ładuje devUrl :1420)
./target/debug/multiremotemanager               # uruchomienie; `env XDG_DATA_HOME=<katalog>` daje osobny plik hostów do prób
```

Po zmianie w `tools/rdp` albo `crates/rdp-proto` przebuduj proces RDP przed uruchomieniem aplikacji, a po zmianie frontendu zrób `pnpm --dir app/ui build` i przebuduj aplikację (frontend jest wbudowany w binarkę).

Testy `ssh` uruchamiają tymczasowy `sshd` i `ssh-agent` w katalogu tymczasowym (porty lokalne, bez dotykania `~/.ssh`) i pomijają się, gdy ich nie ma. Polecenia w powłoce muszą działać i w bash, i w fish. Sonda `rdp-probe` leży w workspace `tools/rdp` razem z procesem RDP.

## Architektura

Workspace Cargo (`crates/`): `vault`, `model`, `ssh`, `rdp`, `rdp-proto`, `sync`, `app`. Crate'y domenowe nie zależą od Tauri.

- `vault` - plik `MRMV` v1: nagłówek (magic, wersja, parametry Argon2id, sól, nonce) jest uwierzytelniany jako AAD przy XChaCha20-Poly1305. Klucz zostaje w pamięci (`Zeroizing`), więc `save` nie powtarza KDF. Zapis atomowy (plik tymczasowy + rename) z rotacją kopii `.bak1..N`. Ogólny względem typu dokumentu (serde).
- `model` - `Document { tree, trusted_keys, settings }` to cała zawartość pliku. Dziedziczenie: host -> katalog -> katalog nadrzędny -> ustawienia domyślne -> wartość wbudowana (port z protokołu). `resolve` zwraca też źródło każdego pola. Nowe pole dziedziczone dodaje się w makrze `fields!` (generuje też `mark_own`), w `FieldsIo` (`crates/app/src/dto.rs`) oraz w `InheritableKey` (`app/ui/src/lib/tree.ts`). Cykle katalogów i bastionów są wykrywane, bastion musi być hostem SSH. Bastion odziedziczony z poziomu, który wskazuje sam rozwiązywany host, jest pomijany tylko na tym poziomie (bastion leżący we własnym katalogu dziedziczy bramę z poziomu wyżej); tę samą regułę ma podpowiedź w `FieldsForm.svelte` (`inherited(..., skip)`).
- `ssh` - `Session::connect(&[Hop], HostKeyVerifier)`: ostatni `Hop` to cel, wcześniejsze to bastiony (kolejny przystanek idzie kanałem `direct-tcpip` przez poprzedni, russh nie ma ProxyJump). Klucze hosta weryfikuje wstrzyknięty callback. Uwierzytelnianie: agent (`Auth::Agent` z `SSH_AUTH_SOCK`, `Auth::AgentSocket` ze ścieżką) albo hasło. Limit 30 s na przystanek (`CONNECT_TIMEOUT`) nie liczy czasu czekania na użytkownika: pytania o klucz hosta i odpowiedzi agenta (`agent_reply`, np. potwierdzenie albo dotknięcie klucza sprzętowego, osobny limit 120 s).
- `app` - Tauri. Hasła nigdy nie trafiają do frontendu (`dto.rs`: widok ma tylko `has_password`; zmiana przez `password` / `clear_password`). Każda mutacja idzie przez `AppState::mutate`: działa na kopii dokumentu, zapisuje plik i dopiero potem podmienia stan; mutacja, która niczego nie zmieniła, nie zapisuje pliku (zapis rotuje kopie `.bakN`). Blokada pliku z każdego miejsca idzie przez `commands::lock_all`: najpierw usuwa klucz z pamięci, potem anuluje pytania o zaufanie i zamyka sesje, na końcu emituje `vault-locked`; `connect_ssh` i `connect_rdp` po wstawieniu sesji do mapy sprawdzają blokadę, więc tej kolejności nie wolno odwracać. Przeładowanie interfejsu (początek ładowania strony w głównym oknie, `commands::reset_after_reload`) zamyka sesje i pytania o zaufanie przez `close_all_sessions`, ale pliku nie blokuje; połączenie będące w toku zamyka się samo, bo po wstawieniu sesji do mapy porównuje licznik `AppState::reloads`. Dane terminala płyną surowymi bajtami przez `ipc::Channel` (backend -> UI) oraz `ssh_write` z nagłówkiem `x-session` (UI -> backend). `ssh_write` i `ssh_resize` są synchroniczne celowo (jak `rdp_send`): tylko wstawiają polecenie do kolejki w `ssh::ShellHandle`, z której jedno zadanie pisarza wysyła je po kolei; komenda `async` zamieniałaby porcje miejscami, bo Tauri uruchamia każde jej wywołanie jako osobne zadanie. Zaufanie do klucza hosta: backend emituje zdarzenie `trust-request`, czeka do 120 s na `answer_trust`, a po upływie czasu emituje `trust-expired`.
- Frontend `app/ui` - stan w `src/lib/store.svelte.ts` (runes), wywołania backendu w `src/lib/api.ts`, logika drzewa i dziedziczenia po stronie widoku w `src/lib/tree.ts` (z testami). Ikony z `design/icons/` trafiają do pakietu przez wygenerowany `icons.generated.ts` (pliki SVG mają duże bloki metadanych C2PA, nie importuj ich przez `?raw`).

## Funkcje poza rdzeniem

- `sync` - porównuje skróty SHA-256 pliku lokalnego, zdalnego i bazowego (z ostatniej synchronizacji): `classify` daje `InSync/LocalChanged/RemoteChanged/Conflict/RemoteMissing`. Przegrana wersja zostaje jako `*.konflikt-<czas>`. `AppState::mutate` wysyła plik automatycznie tylko wtedy, gdy przed zapisem był zsynchronizowany; bazą tej wysyłki jest skrót sprzed zapisu (`sync_pre`), a nie `sync_base` z konfiguracji, które bywa puste (ustawienie folderu je zeruje). Pobranie zdalnej wersji blokuje plik przez `lock_all` (mogło zmienić się hasło główne); klucz znika jeszcze pod blokadą dokumentu, żeby współbieżny `mutate` nie nadpisał pobranego pliku. Zdalny plik, który nie przechodzi `vault::validate_file` (struktura MRMV bez sprawdzania hasła) albo, przy tej samej soli i parametrach KDF, `Vault::verify_file` (uwierzytelnienie kluczem z pamięci), nie jest pobierany, a przed każdym pobraniem lokalna wersja zostaje w jednej, nadpisywanej kopii `<plik>.przed-pobraniem` (to nie kopia konfliktu).
- `crates/app/src/config.rs` - konfiguracja lokalna dla maszyny (`config.json`: folder i baza synchronizacji, dziennik sesji), osobno od zaszyfrowanego pliku, który się synchronizuje. `Settings` w `model` (motyw, skróty, schemat terminala) wędruje razem z hostami.
- `maintenance.rs` - komendy synchronizacji, kopii zapasowych (`restore_backup` wymaga hasła kopii), diagnostyki i linków. Dziennik diagnostyczny (`AppState::log`) to bufor w pamięci na 500 wpisów i nie wolno do niego pisać haseł ani kluczy. `session_log.rs` zapisuje tylko wyjście serwera (na Unix katalog `logs` 0700, pliki 0600).
- Hasło na jedną sesję: backend zwraca błąd `NEEDS_PASSWORD:<powód>` (RDP bez zapisanego hasła, SSH bez agenta albo kluczy), frontend pyta (`requestPassword`) i ponawia z parametrem `password`, którego nie zapisuje.
- Linki: `model::link::parse_link` (odrzuca hosty zaczynające się od `-`, znaki sterujące, ignoruje hasła). Link nigdy nie łączy sam, tylko otwiera istniejący host albo formularz nowego. Link z argumentu uruchomienia czeka w `pending_link` do odblokowania.
- Pojedyncza instancja (`tauri-plugin-single-instance`): kolejne uruchomienie z linkiem zapisuje go w `pending_link`, emituje `open-link` i kończy się. Szablon `packaging/desktop.hbs` rejestruje `ssh://` i `rdp://` w pakietach deb/rpm (Windows: brak rejestracji schematów).
- Pakowanie: sidecar `bundle.externalBin` wymaga pliku `crates/app/binaries/multiremotemanager-rdp-worker-<triple>` (robi go skrypt). Budowa aplikacji kopiuje ten plik obok binarki w `target/<profil>/` i nie odświeża go po zmianach procesu; odświeża go tylko `scripts/build-release.sh`. `beforeBuildCommand` jest pusty celowo, bo ścieżki względne CLI nie pasują do układu `crates/app`; frontend buduje skrypt.
- RDP w procesie: rozdzielczość pulpitu podąża za rozmiarem okna przez kanał Display Control, a obraz jest zawsze rysowany 1:1, bez skalowania (decyzja użytkownika; pulpit większy od okna przewija się). `RdpView` prosi o nowy rozmiar po 400 ms spokoju i nie wysyła tego samego rozmiaru dwa razy (serwer przycinający rozdzielczość odpowiadałby reaktywacją w kółko); proces czeka na gotowość kanału (`display_control_ready`) i raz na sesję zgłasza, że serwer zmiany nie obsługuje.
- Pełny schowek RDP (`cliprdr`):
  - Podział: proces (`rdp-worker/src/clip.rs`) mówi protokołem RDP i obsługuje pliki, aplikacja (`crates/app/src/clipboard.rs`, `arboard`) dotyka schowka systemowego. Konwersje DIB <-> RGBA, CF_HTML i `safe_relative_path` są w `rdp-proto/src/clipfmt.rs`.
  - Formaty: tekst, HTML (z tekstem zastępczym), obraz (DIB), pliki i katalogi w obu kierunkach. Priorytet pobierania zdalnego schowka: pliki, obraz, HTML, tekst (`RemoteAssembler`).
  - Inicjalizacja kanału: serwer po zalogowaniu wysyła Monitor Ready i czeka na listę formatów, więc proces musi na nią odpowiedzieć (`ClipEvent::InitRequested`), także pustą listą. Ogłoszenia z aplikacji przychodzą zwykle wcześniej i czekają w `ClipState` na gotowość serwera (`Phase`); lista plików idzie dopiero po `Ready`. Bez tego schowek stoi w obie strony.
  - Lokalne zmiany ogłaszamy tylko, gdy widok sesji ma fokus (`rdp_clipboard_focus`); dane ustawione ze zdalnej sesji zapamiętują odcisk (`ClipSync::apply`), żeby nie wracały jako echo. Serwer dostaje dane wyłącznie z migawki z chwili ogłoszenia, nigdy z bieżącego schowka.
  - Dostęp do schowka systemowego idzie przez jeden wątek (`serve` w `clipboard.rs`), który przeżywa panikę pojedynczego żądania. Brak odczytu (limit czasu) to nie pusty schowek (`Seen`). `Snapshot` celowo nie ma `Debug`, żeby treść schowka nie mogła trafić do logów.
  - Pliki z serwera są niezaufane: nazwy przez `safe_relative_path`, limit 512 MiB i 5000 elementów, limit czasu 30 s, pobieranie do `clip/<sesja>/<n>` w katalogu danych (czyszczone przy starcie). Lokalne pliki serwowane są tylko po indeksie z ogłoszonej listy, bez dowiązań symbolicznych i katalogów.
  - Przełącznik `rdp_clipboard` w `config.json` (Ustawienia) wyłącza cały schowek RDP.
  - Testy nie dotykają prawdziwego schowka. Lokalny `freerdp-shadow-cli` nie ma kanału schowka ani Display Control, więc obie funkcje sprawdza się tylko z prawdziwym serwerem (działają, potwierdzone przez użytkownika 2026-11-14). Do diagnozy służą wpisy `RDP <host>: schowek: ...` w dzienniku diagnostycznym (`FromWorker::Log`, etapy i rozmiary, bez treści).
- `tray.rs` - zasobnik, ikona zależy od blokady i liczby sesji (odświeżana co sekundę).
- Skróty: `app/ui/src/lib/shortcuts.ts` (domyślne w `ACTIONS`, nadpisania w `Settings.shortcuts`), ten sam `matchAction` chroni skróty aplikacji przed przechwyceniem przez `RdpView` i przez xterm (`attachCustomKeyEventHandler`). Skutek: klawisz przypisany do skrótu nie dociera do zdalnej powłoki ani pulpitu, więc skróty domyślne nie mogą być samym Ctrl+litera (szybkie łączenie to Ctrl+Shift+K, bo Ctrl+K wycina linię w bashu). Przy otwartym oknie modalnym działa tylko blokada pliku (`allowedWithModal`).

## RDP

IronRDP działa w osobnym procesie, bo jego stos (`sspi 0.21`, `curve25519-dalek =5.0.0-rc.1`) nie mieści się w jednym `Cargo.lock` z `russh`. `tools/rdp/` to osobny workspace (`rdp-worker`, `rdp-probe`), wyłączony z głównego (`exclude` w `Cargo.toml`). Nie dodawaj `ironrdp` ani `sspi` do głównego workspace.

- `crates/rdp-proto` - wspólny protokół: ramki `u32 długość | rodzaj | treść` (JSON `ToWorker`/`FromWorker` oraz obraz RGBA), używany przez oba workspace'y przez zależność ścieżkową (bez dziedziczenia z workspace).
- `crates/rdp` - `RdpClient::spawn` uruchamia proces i zamienia jego stdout na zdarzenia. Proces szuka `find_worker()`: `MRM_RDP_WORKER`, w debugu najpierw `tools/rdp/target/<profil>/rdp-worker`, potem plik `multiremotemanager-rdp-worker` obok aplikacji; w wydaniu tylko plik obok aplikacji. Kolejność w debugu jest celowa: kopia obok aplikacji bywa stara (patrz Pakowanie) i przez nią aplikacja po cichu działała bez schowka.
- Proces zaczyna od `FromWorker::Hello` z `rdp_proto::PROTOCOL`, a aplikacja odrzuca proces bez zgodnej wersji czytelnym błędem. Przy zmianie `ToWorker`, `FromWorker` albo ramek zwiększ tę stałą; przypomina o tym test migawkowy `wire_format_snapshot_requires_protocol_bump` w `rdp-proto`. Nowy wariant `FromWorker` trzeba też obsłużyć w pętli zdarzeń w `rdp_sessions.rs`: nieznany komunikat sterujący przekazany do `RdpView` kończy widok sesji.
- Hasło idzie do procesu przez stdin, a worker najpierw przesyła odcisk certyfikatu i czeka na `Trust`, dopiero potem robi CredSSP. Stdout procesu służy tylko protokołowi.
- Pamięć procesu jest ograniczona, bo IronRDP składa fragmenty kanałów bez górnej granicy: globalny alokator w `rdp-worker/src/memlimit.rs` liczy przydzielone bajty, powyżej 896 MiB pętla główna kończy sesję błędem (`check_soft`), powyżej 2 GiB alokacja się nie udaje. Próg miękki musi zostać poniżej połowy twardego (bufor składany z fragmentów rośnie przez podwajanie), czego pilnuje asercja w tym module. To jedyny moduł procesu z `unsafe`. Rozmiar pulpitu podany przez serwer przechodzi przez `validate_desktop_size` (także przy reaktywacji): bok najwyżej 16384, pole najwyżej 8192 x 8192.
- `rdp_send` przyjmuje od frontendu tylko wejście, Ctrl+Alt+Del i zmianę rozmiaru (`frontend_allowed`); polecenia schowka i `Trust` wysyła wyłącznie backend. Komenda jest synchroniczna celowo, żeby zdarzenia wejścia się nie wyprzedzały.
- Przepływ obrazu jest ograniczony na całej drodze: frontend potwierdza odebrane bajty (`rdp_ack`, co 1 MiB), pętla sesji wstrzymuje się po 64 MiB niepotwierdzonych (`Flow` w `rdp_sessions.rs`), kolejka zdarzeń z wątku czytającego ma `rdp::EVENT_QUEUE` miejsc, a zapełniony potok zatrzymuje proces i przez TCP sam serwer. Nowa ścieżka obrazu do frontendu musi liczyć bajty w `Flow`, inaczej sesja stanie albo pamięć urośnie.
- Budowa i testy: `cargo build --manifest-path tools/rdp/Cargo.toml`, potem `cargo test -p rdp` (testy `shadow` na lokalnym `freerdp-shadow-cli` udostępniającym prostokąt 200x200, pomijają się bez niego; `handshake` używa atrapy procesu i działa zawsze).
- Frontend: `RdpView.svelte` (canvas, scancody z `scancodes.ts`). Strona `app/ui/mock.html` (`pnpm --dir app/ui dev`, potem `/mock.html?seed=1`) uruchamia interfejs z atrapą backendu w pamięci, bez Tauri, do oglądania w przeglądarce.

## Projekt wizualny

Reguły z `design/DESIGN.md`, które łatwo złamać: paleta monochromatyczna (znaczenie niosą jasność, obramowanie, kształt i ikona, nigdy sam kolor, także błędy), odznaka SSH wypełniona akcentem a RDP tylko obrys, brak przycisków w kształcie pigułki (promień 6 px), natywna ramka okna, minimum 640 x 480, poniżej 900 px pasek boczny zwija się do ikon. Tokeny są w `app/ui/src/tokens.css`. Plansze `design/boards/*.dc.html` ładują brakujący `support.js`, więc nie renderują się samodzielnie; służą do odczytu wartości. W oknie Tauri musi być `dragDropEnabled: false`, inaczej na Windows nie działa przeciąganie HTML5 w drzewie hostów.

## Konwencje

Jedynym znakiem kreski w tekstach i kodzie jest łącznik `-`. Komunikaty dla użytkownika i komentarze są po polsku.
