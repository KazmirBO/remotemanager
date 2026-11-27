# Menedżer sesji SSH i RDP

Desktopowa aplikacja do sesji SSH i RDP z drzewem hostów w stylu mRemoteNG: katalogi, dziedziczenie ustawień z katalogu na host, hasła w pliku zaszyfrowanym hasłem głównym. Rust + Tauri 2, interfejs w Svelte 5 z terminalem xterm.js, po polsku.

Nazwa "Menedżer sesji" i polecenie `multiremotemanager` są robocze.

## Stan projektu

Wczesna wersja rozwojowa. Bieżące wydanie to 0.1.0, a wydania wstępne 0.1.1-rc1 i 0.1.1-rc2 dodają m.in. eksport i import hostów, podgląd różnic synchronizacji i kody jednorazowe przy otwieraniu pliku; pakiety są niepodpisane: instalator dla Windows i deb; opis zmian jest w [CHANGELOG.md](CHANGELOG.md). Wcześniejsze wydania wstępne mają numery 0.0.0-0.0.5 (do 20.11.2026 nosiły numery 0.1.0-0.1.5 i ich instalatory nadal je zgłaszają). Rozwijana i używana na Linuksie (Gentoo, KDE na Waylandzie). Kod jest pisany także pod Windows: instalator był uruchamiany na Windows, a sesje RDP i przechwytywanie klawiszy (hak klawiatury, od 0.0.3) potwierdzono tam w 0.0.4, ale większość funkcji nie ma na Windows pełnego sprawdzenia.

Sprawdzone w działaniu: sesje SSH (także przez bastion), sesje RDP z NLA, zmiana rozdzielczości pulpitu razem z oknem i schowek w obie strony. Niesprawdzone: Kerberos z prawdziwym KDC oraz dodane 16.11.2026 lokalny kursor RDP, profil łącza, przechwytywanie klawiszy na Linuksie (na Windows potwierdzone w 0.0.4) i renderer WebGL terminala. Szczegóły i lista rzeczy niezweryfikowanych są w [PROJECT.md](PROJECT.md). Lista kontrolna do przejścia ręcznie przed wydaniem jest w [TESTY-RECZNE.md](TESTY-RECZNE.md).

## Możliwości

- **Drzewo hostów** z katalogami, ulubionymi, wyszukiwaniem i przeciąganiem. Port, użytkownik, domena, hasło, bastion i schemat terminala dziedziczą się z katalogu, a host może każde pole nadpisać.
- **Zaszyfrowany plik hostów**: Argon2id i XChaCha20-Poly1305, zapis atomowy, rotowane kopie zapasowe (domyślnie pięć, do 20) z przywracaniem. Hasła nie trafiają do warstwy interfejsu. Opcjonalnie kod jednorazowy (TOTP) przy otwieraniu.
- **SSH**: terminal w karcie z rendererem WebGL, uwierzytelnianie kluczem prywatnym (zapisanym w pliku hostów albo wskazanym ścieżką, także zaszyfrowanym), agentem SSH albo hasłem, bastiony (odpowiednik ProxyJump, także łańcuchy), typ terminala i starsze algorytmy SSH dla starych serwerów (np. AIX), zapamiętywanie kluczy hostów z ostrzeżeniem o zmianie, polecenie po zalogowaniu, podtrzymywanie połączenia, opcjonalny dziennik sesji.
- **RDP**: pulpit w karcie z uwierzytelnianiem NLA (CredSSP), rozdzielczość podążająca za rozmiarem okna, pełny ekran, Ctrl+Alt+Del, lokalny kursor, profil łącza (szybkie albo wolne, także dla katalogu i hosta), przechwytywanie klawiszy z ustawieniem i przyciskiem (także klawiszy systemowych, np. Win i Alt+Tab), schowek w obie strony (tekst, HTML, obrazy, pliki i katalogi), zapamiętywanie certyfikatów. Na Windows także przekierowanie kluczy bezpieczeństwa FIDO2/WebAuthn (np. YubiKey) do zdalnego pulpitu, włączane dla hosta albo katalogu; niesprawdzone z prawdziwym kluczem. Tak samo włącza się przekierowanie czytników kart inteligentnych (PIV, klucz sprzętowy z interfejsem kart), też niesprawdzone z prawdziwym czytnikiem.
- **Szybkie łączenie** (domyślnie Ctrl+Shift+K) i linki `ssh://` oraz `rdp://`. Link nigdy nie łączy sam: otwiera zapisany host z pytaniem albo formularz nowego.
- **Powiadomienie o nowej wersji** po uruchomieniu, z linkiem do strony wydań (do wyłączenia w Ustawieniach).
- **Synchronizacja** zaszyfrowanego pliku przez wskazany folder (np. Syncthing, Nextcloud, dysk sieciowy) z wykrywaniem konfliktów i podglądem różnic między wersją lokalną a tą z folderu.
- **Eksport i import hostów**: osobny plik zaszyfrowany hasłem, z wyborem danych (np. bez haseł i kluczy) przy eksporcie i przy imporcie. Import scala po identyfikatorach: nowe hosty dodaje, a istniejące pomija albo aktualizuje, zostawiając niezaznaczone dane bez zmian. Importuje też zwykłą listę hostów w CSV, np. zrzuconą z Active Directory (opis niżej).
- Ikona w zasobniku, blokada pliku (także automatyczna po bezczynności), ustawienia podzielone na kategorie z wyborem czcionki, kursora i historii terminala, edytowalne skróty, motyw jasny i ciemny, dziennik diagnostyczny bez sekretów.

Poza zakresem: SFTP, tunele, podzielone widoki, import z mRemoteNG. Jeszcze niezrobione: lista ostatnio używanych hostów, wiele monitorów w RDP, rejestracja schematów linków w Windows, pakiet dla Gentoo, aktualizacje.

## Wymagania

- Rust 1.90 lub nowszy, Node.js 22 lub nowszy, pnpm.
- Linux: biblioteki Tauri, czyli WebKitGTK 4.1, GTK 3 i libsoup 3 (w Debianie i Ubuntu pakiety `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libsoup-3.0-dev`), oraz biblioteka appindicator dla ikony w zasobniku.
- Windows: narzędzia MSVC (Visual Studio Build Tools z obsługą C++). Asembler NASM nie jest potrzebny: `.cargo/config.toml` pozwala bibliotece kryptograficznej użyć gotowych obiektów, gdy polecenia `nasm` nie ma w `PATH`.
- Do testów opcjonalnie: OpenSSH (`sshd`, `ssh-agent`) i `freerdp-shadow-cli`. Testy, które ich potrzebują, pomijają się, gdy ich nie ma.

## Budowa i uruchomienie

Polecenia uruchamia się z katalogu repozytorium; działają w bash i w fish.

```
pnpm --dir app/ui install
pnpm --dir app/ui build
cargo build --manifest-path tools/rdp/Cargo.toml
mkdir -p crates/app/binaries
cp tools/rdp/target/debug/rdp-worker "crates/app/binaries/multiremotemanager-rdp-worker-$(rustc -vV | sed -n 's/^host: //p')"
cargo build -p app --features custom-protocol
./target/debug/multiremotemanager
```

Kilka rzeczy, które nie są oczywiste:

- Obsługa RDP jest osobnym procesem (`tools/rdp`, własny workspace Cargo), bo zależności IronRDP nie mieszczą się w jednym `Cargo.lock` z biblioteką SSH. Budowa aplikacji wymaga jego kopii w `crates/app/binaries`, stąd kroki `mkdir` i `cp`; bez niej nie przejdzie także `cargo clippy` ani `cargo test` dla całego workspace. Na Windows plik ma rozszerzenie `.exe`.
- Cecha `custom-protocol` wbudowuje interfejs w binarkę. Bez niej okno ładuje `http://localhost:1420` i wymaga działającego `pnpm --dir app/ui dev`.
- Po zmianie interfejsu trzeba ponowić `pnpm --dir app/ui build` i budowę aplikacji, a po zmianie procesu RDP jego budowę.

Pakiet instalacyjny (deb) z procesem RDP w środku buduje `scripts/build-release.sh --bundles deb`. Wydanie na GitHubie (tag, instalator NSIS i deb) robi workflow `wydanie` uruchamiany ręcznie z gałęzi `main`; wersję bierze z `crates/app/tauri.conf.json`, a opis z `CHANGELOG.md`.

## Import listy hostów z CSV

Oprócz własnych plików eksportu program importuje zwykłą listę hostów w CSV (Ustawienia, "Import i eksport", sekcja Import). Plik ma wiersz nagłówka i kolumny:

| Kolumna | Znaczenie |
|---|---|
| `nazwa` | nazwa hosta w drzewie |
| `adres` | adres albo nazwa DNS |
| `protokol` | `ssh` albo `rdp` |
| `katalog` | opcjonalnie: ścieżka katalogów rozdzielona ukośnikiem, np. `Serwery/Bazy` |

Separatorem może być przecinek, średnik albo tabulator, pola mogą być w cudzysłowach, a plik musi być zapisany w UTF-8. Lista niesie tylko nazwy, adresy, protokół i strukturę katalogów; loginy i hasła ustawiasz w programie (np. raz, we właściwościach katalogu).

Identyfikator hosta wynika z jego adresu, a katalogu ze ścieżki. Dzięki temu import odświeżonej listy z opcją "Zaktualizuj" zmienia te same hosty zamiast je dublować, a dane ustawione w programie zostają. Hostów, które z listy zniknęły, import nie usuwa.

Przykład dla Active Directory: lista komputerów z jednostki organizacyjnej, z jej podjednostkami jako podkatalogami (PowerShell z modułem ActiveDirectory; podstaw własną ścieżkę jednostki i sufiks DNS):

```powershell
$ou = "OU=Serwery,DC=firma,DC=example"
$sufiks = "firma.example"
Get-ADComputer -Filter * -SearchBase $ou | ForEach-Object {
  $czesci = @($_.DistinguishedName -split '(?<!\\),' | Where-Object { $_ -like 'OU=*' } | ForEach-Object { $_.Substring(3) })
  [array]::Reverse($czesci)
  [pscustomobject]@{ nazwa = $_.Name; adres = "$($_.Name).$sufiks"; protokol = "rdp"; katalog = $czesci -join "/" }
} | Export-Csv -Path serwery.csv -NoTypeInformation -Encoding UTF8
```

Żeby pominąć wybrane podjednostki, dodaj filtr zaraz po `Get-ADComputer`, np. `| Where-Object { $_.DistinguishedName -notmatch 'OU=(Wylaczone|Linux),' }`.

## Dane i bezpieczeństwo

- Plik hostów `hosts.mrm` leży w katalogu danych aplikacji, na Linuksie w `~/.local/share/dev.multiremotemanager.client/`. Do prób bez dotykania własnych danych: `env XDG_DATA_HOME=/tmp/proba ./target/debug/multiremotemanager`.
- Przy pierwszym uruchomieniu ustawiasz hasło główne (co najmniej 8 znaków). Nie da się go odzyskać: bez niego pliku nie można odszyfrować.
- Otwieranie pliku możesz dodatkowo zabezpieczyć kodem jednorazowym z aplikacji uwierzytelniającej (TOTP; Ustawienia, Bezpieczeństwo). Sekret leży w zaszyfrowanym pliku, więc to bramka w programie, a nie część szyfrowania: chroni przed otwarciem pliku w programie przez kogoś, kto zna samo hasło, ale nie przed odszyfrowaniem pliku innym narzędziem. Przy włączaniu dostajesz kody zapasowe; bez telefonu i bez nich pliku nie otworzysz w programie. Plik z włączonymi kodami ma nowszą wersję formatu i starsze wersje programu go nie otworzą.
- Klucz prywatny SSH możesz zapisać w pliku hostów (jest odszyfrowywany przy imporcie i chroniony hasłem głównym) albo wskazać ścieżką do pliku; program korzysta też z agenta SSH.
- Dziennik sesji, jeśli go włączysz, zapisuje wyjście terminala jawnym tekstem w katalogu `logs` (na Linuksie z dostępem tylko dla właściciela).
- Schowek RDP działa tylko wtedy, gdy widok sesji ma fokus, i da się go wyłączyć w Ustawieniach.
- Po uruchomieniu program pyta `api.github.com` o listę wydań i informuje, gdy jest nowsza wersja. To jedyne połączenie, którego nie zlecasz sam; nie wysyła żadnych danych z programu, niczego nie pobiera i da się je wyłączyć (Ustawienia, Narzędzia).

## Praca nad kodem

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                          # w tym testy na prawdziwym sshd (ok. 20 s)
cargo test --manifest-path tools/rdp/Cargo.toml # testy procesu RDP
pnpm --dir app/ui check                         # svelte-check
pnpm --dir app/ui test                          # vitest
```

Sam interfejs da się obejrzeć w przeglądarce bez Tauri i bez prawdziwych połączeń: `pnpm --dir app/ui dev`, potem `http://localhost:1420/mock.html?seed=1`.

Układ repozytorium:

| Katalog | Zawartość |
|---|---|
| `crates/vault` | format i szyfrowanie pliku, kopie zapasowe |
| `crates/model` | drzewo hostów, dziedziczenie ustawień, parser linków |
| `crates/ssh` | sesje SSH, bastiony, agent |
| `crates/sync` | synchronizacja pliku przez folder |
| `crates/rdp`, `crates/rdp-proto` | klient procesu RDP i wspólny protokół |
| `crates/app` | aplikacja Tauri: komendy, sesje, schowek, zasobnik |
| `app/ui` | interfejs (Svelte 5, xterm.js) |
| `tools/rdp` | proces RDP na IronRDP i sonda diagnostyczna |
| `design` | tokeny wizualne, ikony i plansze projektu |

Więcej: [PROJECT.md](PROJECT.md) (ustalenia i stan prac), [design/DESIGN.md](design/DESIGN.md) (reguły wizualne), [CLAUDE.md](CLAUDE.md) (architektura i pułapki, pisane dla asystenta kodu, ale przydatne także ludziom).

## Licencja

Do wyboru: [MIT](LICENSE-MIT) albo [Apache-2.0](LICENSE-APACHE).
