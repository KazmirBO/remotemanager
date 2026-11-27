# Zmiany

Opis wydań. Sekcja danej wersji trafia do opisu wydania na GitHubie (workflow `wydanie`).

## Niewydane

Zmiany na gałęzi roboczej, które wejdą do następnego wydania.

- Kody jednorazowe przy otwieraniu pliku z hostami (TOTP, zgłoszenie #17): po włączeniu w Ustawieniach (Bezpieczeństwo) program po haśle głównym pyta jeszcze o kod z aplikacji uwierzytelniającej. Włączenie wymaga potwierdzenia pierwszym kodem i daje 8 jednorazowych kodów zapasowych na wypadek braku telefonu; po 5 błędnych kodach trzeba ponownie podać hasło. To zabezpieczenie otwierania pliku w programie, a nie część szyfrowania: kto ma plik i hasło główne, odszyfruje go innym narzędziem. Składnikiem szyfrowania będzie dopiero klucz sprzętowy (w przygotowaniu).
- Nowa wersja formatu pliku z hostami (2) dla plików z włączonym dodatkowym składnikiem. Starsze wersje programu takiego pliku nie otworzą i pokażą błąd o nieobsługiwanej wersji, więc nie pominą wymogu kodu. Pliki bez dodatkowego składnika zostają w wersji 1 i nic się dla nich nie zmienia. Przy synchronizacji wszystkie komputery muszą mieć wersję programu z tą zmianą, zanim włączysz kody.
- Powiadomienie o nowej wersji: po uruchomieniu program pyta GitHuba o listę wydań i pokazuje powiadomienie, gdy jest nowsze wydanie; okno "O programie" podaje wtedy numer i ma przycisk otwierający stronę wydań. Program niczego sam nie pobiera ani nie instaluje. Wydania wstępne widzi tylko ten, kto sam używa wydania wstępnego. Sprawdzanie wyłącza się w Ustawieniach (Narzędzia); ustawienie dotyczy jednej maszyny.
- Import listy hostów z pliku CSV (Ustawienia, "Import i eksport"): kolumny `nazwa`, `adres`, `protokol` (`ssh` albo `rdp`) i opcjonalnie `katalog` (ścieżka rozdzielona ukośnikiem); separator to przecinek, średnik albo tabulator. Lista nie ma hasła i niesie tylko nazwy, adresy, protokół i strukturę katalogów. Identyfikatory wynikają z adresu hosta i ścieżki katalogu, więc import odświeżonej listy aktualizuje te same hosty zamiast je dublować. README ma przykład zrzutu komputerów z jednostki Active Directory.
- Synchronizacja: przycisk "Pokaż różnice" w Ustawieniach (kategoria Synchronizacja) przy zmianach lokalnych, zmianach zdalnych i konflikcie. Lista pokazuje hosty i katalogi, które są tylko u Ciebie, tylko w folderze albo różnią się po obu stronach, a dla różniących się wymienia, co się zmieniło: nazwę, adres, protokół i położenie z obiema wartościami, pozostałe dane jako nazwy (np. hasło, opcje połączenia, notatki), bez ich treści. Osobno podaje różnice w ustawieniach domyślnych drzewa, zaufanych kluczach i ustawieniach programu. Lista jest tylko do oglądania: synchronizacja nadal dotyczy całego pliku. Gdy plik w folderze ma inne hasło główne, porównanie nie jest możliwe i program to mówi.

## 0.1.1-rc1 - 2026-11-20

Wydanie wstępne, kandydat do wersji 0.1.1: pakiety są niepodpisane.

### Zmiany

- Eksport i import hostów (Ustawienia, kategoria "Import i eksport"; eksport jednego katalogu także z jego menu). Eksport zapisuje katalogi i hosty do osobnego pliku `.mrmx`, zaszyfrowanego hasłem podanym przy eksporcie (ten sam szyfr co plik z hostami). Przy eksporcie wybierasz, które dane trafiają do pliku, a przy imporcie, które z niego bierzesz: nazwy użytkowników i domeny, hasła, klucze prywatne SSH, ścieżki plików kluczy, opcje połączenia, polecenie po zalogowaniu, notatki, zaufane klucze hostów. Hasła, klucze i ścieżki kluczy są domyślnie odznaczone, a przy imporcie także polecenie po zalogowaniu i zaufane klucze. Import pokazuje najpierw podgląd (ile hostów i katalogów jest nowych, a ile już masz) i scala po identyfikatorach: nowe elementy dodaje w tej samej strukturze katalogów, istniejące pomija albo aktualizuje, zmieniając tylko zaznaczone dane, więc własne loginy i hasła zostają. Ponowny import tego samego pliku nie tworzy duplikatów. Ustawienia programu nie są przenoszone.

### Pakiety

- `multiremotemanager_0.1.1-rc1_x64-setup.exe` - instalator dla Windows (NSIS, 64 bity).
- `multiremotemanager_0.1.1-rc1_amd64.deb` - pakiet dla Debiana i Ubuntu.

## 0.1.0 - 2026-11-20

Pierwsze zwykłe wydanie. Pakiety nadal są niepodpisane. Wcześniejsze wydania wstępne zostały przenumerowane z 0.1.0-0.1.5 na 0.0.0-0.0.5 (tagi, tytuły, opisy i nazwy plików); same ich instalatory nadal zgłaszają dawne numery. Na systemie z zainstalowanym wydaniem wstępnym o dawnym numerze wyższym niż 0.1.0 (np. 0.1.5) menedżer pakietów potraktuje instalację jako cofnięcie wersji.

### Zmiany

- SSH: logowanie kluczem prywatnym. Klucz można wkleić albo wczytać z pliku do pliku hostów (wtedy jest odszyfrowywany przy imporcie, więc hasło klucza podajesz raz i nie jest zapisywane) albo wskazać ścieżką do pliku czytanego przy łączeniu (zaszyfrowany klucz wymaga wtedy hasła przy każdym połączeniu). Obie możliwości dziedziczą się z katalogu na host; obsługiwane formaty to OpenSSH, PKCS#8, PEM i PuTTY .ppk, limit 64 KiB. Kolejność prób: klucz z pliku hostów, plik klucza, agent SSH, zapisane hasło, na końcu pytanie o hasło; liczba prób na przystanek jest ograniczona do 5.
- Budowa ze źródeł na Windows nie wymaga już asemblera NASM (`.cargo/config.toml`).
- Zależności zaktualizowane do najnowszych zgodnych wersji.
- SSH dla starych serwerów (zgłoszenie #12): pole "Typ terminala (SSH)" ustawia nazwę wysyłaną serwerowi jako TERM (np. `vt100`, `vt220`, `aixterm` zamiast domyślnego `xterm-256color`), a pole "Starsze algorytmy SSH" dopuszcza wymianę kluczy i skróty oparte na SHA-1 oraz szyfry CBC dla serwerów, które nie znają nowych algorytmów. Oba pola są dla hosta albo katalogu, dziedziczone i domyślnie niczego nie zmieniają. Bez Telnetu i bez emulacji terminali innych niż zgodne z xterm.
- Bezpieczeństwo RDP: aplikacja sprawdza podpis w uzgadnianiu TLS. Wcześniej zapamiętany odcisk certyfikatu nie dowodził, że serwer ma klucz prywatny z tego certyfikatu, więc pośrednik w sieci mógł przedstawić cudzy certyfikat i zostać przyjęty bez pytania. Serwer, który nie przejdzie tej kontroli, jest odrzucany z komunikatem o możliwym podsłuchu.
- Konserwacja: plik z hostami, jego kopie i plik w folderze synchronizacji są zapisywane przez plik tymczasowy o unikalnej nazwie i z uprawnieniami tylko dla właściciela (Unix: 0600); wcześniej stała nazwa pliku tymczasowego pozwalała dowiązaniu w folderze synchronizacji przekierować zapis. Zdalny plik z niepoprawnymi parametrami KDF nie jest już pobierany.
- Konserwacja: linki `ssh://` i `rdp://` odrzucają znaki formatujące Unicode i zakodowane znaki struktury adresu; pytanie o klucz hosta nie przechodzi do interfejsu po jego przeładowaniu ani po zablokowaniu pliku; zamknięcie sesji RDP nie zawiesza się na procesie, który przestał czytać; drobne poprawki tekstów interfejsu.
- Nowy układ ustawień: okno Ustawienia ma listę kategorii (Wygląd, Terminal, RDP, Sesje, Bezpieczeństwo, Synchronizacja, Skróty, Narzędzia) i jeden przycisk Zapisz, a synchronizacja i skróty są kategoriami zamiast osobnych okien. Okna hosta i katalogu mają zakładki Ogólne, Logowanie, Połączenie, Terminal i Przekierowania, a błąd zapisu jest widoczny w każdej zakładce i wskazuje tę, w której leży pole. Zakładki i lista kategorii obsługują strzałki.
- Nowe opcje: krój czcionki, kształt i miganie kursora, historia przewijania, kopiowanie po zaznaczeniu, wklejanie prawym przyciskiem i domyślny TERM (terminal); pytanie przed zamknięciem karty i programu oraz odstęp podtrzymywania SSH (sesje); automatyczna blokada po bezczynności i liczba kopii zapasowych (bezpieczeństwo); dla hosta i katalogu rozmiar czcionki terminala i polecenie po zalogowaniu (SSH, tylko cel połączenia). Domyślnie program działa jak dotąd, a stare pliki z hostami czytają się bez zmian.
- Karty sesji można przestawiać: przeciąganiem na pasku kart (kreska przy krawędzi karty pokazuje miejsce wstawienia, upuszczenie na wolnym miejscu paska przenosi na koniec), pozycjami Przesuń w lewo i Przesuń w prawo w menu karty oraz dwiema nowymi akcjami skrótów (bez domyślnych kombinacji, do przypisania w Ustawieniach). Przestawienie nie przerywa sesji.

### Pakiety

- `multiremotemanager_0.1.0_x64-setup.exe` - instalator dla Windows (NSIS, 64 bity).
- `multiremotemanager_0.1.0_amd64.deb` - pakiet dla Debiana i Ubuntu.

## 0.0.5 - 2026-11-17

Wydanie nadal wstępne: pakiety są niepodpisane.

### Zmiany

- Windows: sesje RDP nie urywają się już czasami błędem "Pokrywająca się operacja We/Wy jest w toku (os error 997)".
- Drzewo hostów: podczas przeciągania hosta albo katalogu lista przewija się sama, gdy wskaźnik jest przy jej górnej albo dolnej krawędzi.
- RDP na Windows: przekierowanie czytników kart inteligentnych do zdalnego pulpitu (zgłoszenie #3), włączane dla hosta albo katalogu polem "Karty inteligentne (RDP)", domyślnie wyłączone. Zdalny system widzi czytniki tego komputera, także klucz sprzętowy z interfejsem kart (np. YubiKey z włączonym CCID): certyfikaty PIV, logowanie kartą. Wariant "pod neutralnymi nazwami" jest dla programów, które pomijają czytniki z "YubiKey" w nazwie (KeePassXC). Serwer z włączonym przekierowaniem może wysyłać do karty dowolne polecenia, więc funkcja jest dla zaufanych serwerów. Nie była jeszcze sprawdzona z prawdziwym czytnikiem i serwerem; nie wiadomo, czy klucz podłączony po USB odpowie tą drogą na wyzwanie KeePassXC.
- Skróty klawiszowe: nowe akcje do przypisania (połącz ponownie, duplikuj kartę, szukaj hosta, przejście do karty 1-9), edytowalny skrót kopiowania w terminalu SSH oraz możliwość wyłączenia skrótu. Nowe akcje nie mają skrótów domyślnych.

### Pakiety

- `multiremotemanager_0.0.5_x64-setup.exe` - instalator dla Windows (NSIS, 64 bity).
- `multiremotemanager_0.0.5_amd64.deb` - pakiet dla Debiana i Ubuntu.

## 0.0.4 - 2026-11-17

Wydanie poprawkowe, nadal wstępne: pakiety są niepodpisane.

### Zmiany

- Terminal SSH: po zakończeniu sesji (np. po `exit`) przyciski "Połącz ponownie" i "Zamknij kartę" znowu reagują na kliknięcia; wcześniej kliknięcie trafiało w terminal pod spodem.
- Windows: przechwytywanie klawiszy w sesji RDP (Alt+Tab, klawisz Windows) działa od wersji 0.0.3, co potwierdził test na prawdziwej maszynie.
- Windows: w trybie przechwytywania klawiszy prawy Shift działa w sesji RDP; wcześniej trafiał do sesji jako inny klawisz, więc np. prawy Shift+1 dawał 1.
- Prawy przycisk myszy nie pokazuje już menu przeglądarki (Wstecz, Odśwież, Drukuj); zostaje ono w polach tekstowych i w terminalu, gdzie daje kopiowanie i wklejanie.
- Karty sesji mają własne menu pod prawym przyciskiem myszy: połącz ponownie, duplikuj kartę, zamknij kartę, zamknij pozostałe, zamknij wszystkie.
- Pasek kart przy wielu sesjach nie dostaje suwaków: karty zwężają się, a gdy się nie mieszczą, pasek przewija się kółkiem myszy.
- Terminal SSH: Ctrl+Shift+C kopiuje zaznaczenie.
- RDP na Windows: przekierowanie kluczy bezpieczeństwa FIDO2/WebAuthn (np. YubiKey) do zdalnego pulpitu, włączane dla hosta albo katalogu polem "Klucze bezpieczeństwa FIDO2 (RDP)", domyślnie wyłączone. Każde użycie klucza potwierdza się w oknie systemu. Funkcja nie była jeszcze sprawdzona z prawdziwym kluczem i serwerem.

### Pakiety

- `multiremotemanager_0.0.4_x64-setup.exe` - instalator dla Windows (NSIS, 64 bity).
- `multiremotemanager_0.0.4_amd64.deb` - pakiet dla Debiana i Ubuntu.

## 0.0.3 - 2026-11-17

Wydanie poprawkowe, nadal wstępne: pakiety są niepodpisane.

### Zmiany

- Windows: aplikacja nie rejestruje już surowego wejścia klawiatury i myszy. Liczniki z wersji 0.0.2 pokazały, że system w ogóle nie wołał haka klawiatury w trybie przechwytywania; przyczyną jest ta rejestracja, którą biblioteka okna robi domyślnie i przy której system pomija hak własnego procesu, gdy jego okno jest aktywne.

### Pakiety

- `multiremotemanager_0.0.3_x64-setup.exe` - instalator dla Windows (NSIS, 64 bity).
- `multiremotemanager_0.0.3_amd64.deb` - pakiet dla Debiana i Ubuntu.

## 0.0.2 - 2026-11-17

Wydanie diagnostyczne, nadal wstępne: pakiety są niepodpisane. Poprawka haka z wersji 0.0.1 nie pomogła: na Windows w trybie przechwytywania Alt+Tab dalej działa lokalnie, a przyczyna nie jest jeszcze znana.

### Zmiany

- Dziennik diagnostyczny dostaje przy zdjęciu haka wpis `RDP: klawisze systemowe: liczniki haka: ...` (wywołań, zatrzymanych, przepuszczonych, bez scancodu, wstrzykniętych; bez treści klawiszy). Zero wywołań oznacza, że system nie woła funkcji haka.
- Windows: klawisz, który przychodzi bez scancodu (wstrzyknięty przez program samym kodem wirtualnym), dostaje scancode z układu klawiatury i trafia do sesji; wcześniej hak przepuszczał go do systemu.

### Pakiety

- `multiremotemanager_0.0.2_x64-setup.exe` - instalator dla Windows (NSIS, 64 bity).
- `multiremotemanager_0.0.2_amd64.deb` - pakiet dla Debiana i Ubuntu.

## 0.0.1 - 2026-11-17

Wydanie poprawkowe, nadal wstępne: pakiety są niepodpisane. Lista rzeczy niesprawdzonych w działaniu z wersji 0.0.0 pozostaje aktualna.

### Zmiany

- Panel z przyciskami w widoku RDP można przesunąć uchwytem po jego lewej stronie; wcześniej zasłaniał elementy zdalnego pulpitu. Położenie jest wspólne dla kart i zapamiętane na danej maszynie, a dwukrotne kliknięcie uchwytu przywraca miejsce domyślne.
- Windows: hak klawiatury trybu przechwytywania działa we własnym wątku. To poprawka do zgłoszenia, że w tym trybie Alt+Tab działał lokalnie, a klawisz Windows po obu stronach naraz. Nie została jeszcze potwierdzona na Windows.
- Dziennik diagnostyczny ma wpisy `RDP: klawisze systemowe: ...` (hak założony, zwolniony z powodem, zdjęty), bez treści klawiszy.

### Pakiety

- `multiremotemanager_0.0.1_x64-setup.exe` - instalator dla Windows (NSIS, 64 bity).
- `multiremotemanager_0.0.1_amd64.deb` - pakiet dla Debiana i Ubuntu.

## 0.0.0 - 2026-11-16

Pierwsze wydanie wstępne. Wczesna wersja rozwojowa: pakiety są niepodpisane i nie były dotąd uruchamiane poza środowiskiem budowania, a część funkcji czeka na sprawdzenie w działaniu (lista niżej).

### Pakiety

- `multiremotemanager_0.0.0_x64-setup.exe` - instalator dla Windows (NSIS, 64 bity). Windows SmartScreen pokaże ostrzeżenie, bo plik nie jest podpisany. Wymaga WebView2 (wbudowany w Windows 10 od wersji 1803 i w Windows 11).
- `multiremotemanager_0.0.0_amd64.deb` - pakiet dla Debiana i Ubuntu, zbudowany na Ubuntu 24.04.

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
