# Zmiany

Opis wydań. Sekcja danej wersji trafia do opisu wydania na GitHubie (workflow `wydanie`).

## 0.1.2 - 2026-11-17

Wydanie diagnostyczne, nadal wstępne: pakiety są niepodpisane. Poprawka haka z wersji 0.1.1 nie pomogła: na Windows w trybie przechwytywania Alt+Tab dalej działa lokalnie, a przyczyna nie jest jeszcze znana.

### Zmiany

- Dziennik diagnostyczny dostaje przy zdjęciu haka wpis `RDP: klawisze systemowe: liczniki haka: ...` (wywołań, zatrzymanych, przepuszczonych, bez scancodu, wstrzykniętych; bez treści klawiszy). Zero wywołań oznacza, że system nie woła funkcji haka.
- Windows: klawisz, który przychodzi bez scancodu (wstrzyknięty przez program samym kodem wirtualnym), dostaje scancode z układu klawiatury i trafia do sesji; wcześniej hak przepuszczał go do systemu.

### Pakiety

- `multiremotemanager_0.1.2_x64-setup.exe` - instalator dla Windows (NSIS, 64 bity).
- `multiremotemanager_0.1.2_amd64.deb` - pakiet dla Debiana i Ubuntu.

## 0.1.1 - 2026-11-17

Wydanie poprawkowe, nadal wstępne: pakiety są niepodpisane. Lista rzeczy niesprawdzonych w działaniu z wersji 0.1.0 pozostaje aktualna.

### Zmiany

- Panel z przyciskami w widoku RDP można przesunąć uchwytem po jego lewej stronie; wcześniej zasłaniał elementy zdalnego pulpitu. Położenie jest wspólne dla kart i zapamiętane na danej maszynie, a dwukrotne kliknięcie uchwytu przywraca miejsce domyślne.
- Windows: hak klawiatury trybu przechwytywania działa we własnym wątku. To poprawka do zgłoszenia, że w tym trybie Alt+Tab działał lokalnie, a klawisz Windows po obu stronach naraz. Nie została jeszcze potwierdzona na Windows.
- Dziennik diagnostyczny ma wpisy `RDP: klawisze systemowe: ...` (hak założony, zwolniony z powodem, zdjęty), bez treści klawiszy.

### Pakiety

- `multiremotemanager_0.1.1_x64-setup.exe` - instalator dla Windows (NSIS, 64 bity).
- `multiremotemanager_0.1.1_amd64.deb` - pakiet dla Debiana i Ubuntu.

## 0.1.0 - 2026-11-16

Pierwsze wydanie wstępne. Wczesna wersja rozwojowa: pakiety są niepodpisane i nie były dotąd uruchamiane poza środowiskiem budowania, a część funkcji czeka na sprawdzenie w działaniu (lista niżej).

### Pakiety

- `multiremotemanager_0.1.0_x64-setup.exe` - instalator dla Windows (NSIS, 64 bity). Windows SmartScreen pokaże ostrzeżenie, bo plik nie jest podpisany. Wymaga WebView2 (wbudowany w Windows 10 od wersji 1803 i w Windows 11).
- `multiremotemanager_0.1.0_amd64.deb` - pakiet dla Debiana i Ubuntu, zbudowany na Ubuntu 24.04.

Oba pakiety zawierają proces RDP jako osobny plik obok aplikacji.

### Możliwości

- Drzewo hostów z katalogami, ulubionymi, wyszukiwaniem i przeciąganiem; port, użytkownik, domena, hasło, bastion, schemat terminala i profil łącza RDP dziedziczą się z katalogu.
- Zaszyfrowany plik hostów (Argon2id i XChaCha20-Poly1305), zapis atomowy, rotowane kopie zapasowe z przywracaniem. Hasła nie trafiają do warstwy interfejsu.
- SSH: terminal w karcie z rendererem WebGL, agent SSH albo hasło, bastiony (także łańcuchy), zapamiętywanie kluczy hostów, opcjonalny dziennik sesji.
- RDP: pulpit w karcie z NLA (CredSSP), rozdzielczość podążająca za oknem, pełny ekran, Ctrl+Alt+Del, schowek w obie strony (tekst, HTML, obrazy, pliki i katalogi), kształty kursora z serwera, profil łącza (szybkie albo wolne), przechwytywanie klawiszy z ustawieniem i przyciskiem, także klawiszy systemowych (Windows oraz Linux na Waylandzie).
- Szybkie łączenie (Ctrl+Shift+K) i linki `ssh://` oraz `rdp://`.
- Synchronizacja zaszyfrowanego pliku przez folder z wykrywaniem konfliktów.
- Ikona w zasobniku, blokada pliku, edytowalne skróty, motyw jasny i ciemny, dziennik diagnostyczny bez sekretów.

### Niesprawdzone w działaniu

- Aplikacja na Windows: dotąd tylko kompilacja i testy w CI.
- Hak klawiatury na Windows i przejęcie klawiszy na Waylandzie.
- Kształty kursora i profil wolny z serwerem Windows.
- Renderer WebGL w WebKitGTK i WebView2.
- Kerberos z prawdziwym KDC.

### Znane ograniczenia

- Rejestracja linków `ssh://` i `rdp://` działa tylko w pakiecie deb; na Windows jej nie ma.
- Na X11 tryb przechwytywania obejmuje same skróty aplikacji, bez klawiszy systemowych.
- Brak wielu monitorów w RDP, listy ostatnio używanych hostów i aktualizacji.
