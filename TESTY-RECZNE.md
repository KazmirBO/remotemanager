# Lista kontrolna przed wydaniem

Rzeczy, których nie sprawdzają testy automatyczne: działanie w prawdziwym oknie programu, z prawdziwymi serwerami, na Linuksie i na Windows. Testy w repozytorium używają atrapy interfejsu i lokalnych serwerów testowych, więc każdy punkt tej listy ktoś musi przejść ręcznie.

## Jak korzystać

- Przejdź listę na zainstalowanym pakiecie wydania, nie na budowie ze źródeł: sprawdzasz też instalator.
- Przejdź ją na obu systemach. Punkt oznaczony tylko jednym systemem dotyczy tylko jego.
- Pracuj na osobnym pliku z hostami, żeby nie ryzykować własnego. Na Linuksie: `env XDG_DATA_HOME=<pusty katalog> multiremotemanager`. Na Windows zrób przed testem kopię pliku z hostami; gdyby coś poszło źle, poprzednią wersję przywrócisz też w Ustawieniach (Narzędzia, Kopie zapasowe).
- Przy każdym punkcie zapisz wynik: działa, nie działa (z opisem) albo pominięte (z powodem). Punkt, który nie działa, to zgłoszenie.
- Dopisek "Potwierdzone" mówi, kiedy punkt ostatnio przeszedł w prawdziwym programie. Punkt bez dopisku nie był jeszcze potwierdzony nigdy.
- Nowa funkcja dopisuje tu swoje punkty w tym samym PR, w którym powstaje.

## Instalacja i start

- [ ] Windows: instalator uruchamia się i instaluje program (SmartScreen ostrzega, bo pakiet jest niepodpisany). Potwierdzone: instalator 0.0.x.
- [ ] Linux: pakiet deb instaluje się, program jest w menu i uruchamia się poleceniem `multiremotemanager`.
- [ ] Instalacja na starszą wersję zachowuje plik z hostami i ustawienia.
- [ ] Pierwsze uruchomienie: utworzenie pliku z hasłem głównym (za krótkie hasło jest odrzucane).
- [ ] Drugie uruchomienie programu nie otwiera drugiego okna, tylko pokazuje pierwsze.
- [ ] Ikona w zasobniku zmienia się zależnie od blokady i liczby otwartych sesji.
- [ ] Okno 640 x 480: wszystko jest dostępne, poniżej 900 px pasek boczny zwija się do ikon.

## Plik z hostami i blokada

- [ ] Odblokowanie dobrym hasłem działa, złe hasło daje czytelny błąd.
- [ ] Blokada pliku (przycisk i skrót) zamyka sesje i chowa drzewo hostów.
- [ ] Zmiana hasła głównego: stare hasło przestaje działać, nowe działa po ponownym uruchomieniu.
- [ ] Automatyczna blokada po bezczynności blokuje po ustawionym czasie, także gdy fokus ma sesja.
- [ ] Kody jednorazowe (TOTP): włączenie z prawdziwą aplikacją uwierzytelniającą (sekret wpisany ręcznie i przez adres konfiguracji), potem odblokowanie wymaga hasła i kodu; zły kod nie odblokowuje, a po 5 błędach program wraca do hasła.
- [ ] Kod zapasowy odblokowuje plik raz; wyłączenie kodów wymaga kodu.
- [ ] Plik z włączonymi kodami: starsza wersja programu (np. 0.1.1-rc1) odmawia otwarcia z błędem o wersji formatu; po wyłączeniu kodów znowu go otwiera.
- [ ] Synchronizacja pliku z włączonymi kodami między dwoma komputerami z tą wersją programu działa; "Pokaż różnice" zgłasza różnicę w wymogu dodatkowego składnika.
- [ ] Kopie zapasowe: lista pokazuje kopie, przywrócenie kopii (z jej hasłem) przywraca poprzedni stan.
- [ ] Liczba kopii zapasowych: po zmniejszeniu starsze kopie znikają z dysku.

## Drzewo hostów

- [ ] Dodanie, edycja i usunięcie hosta oraz katalogu.
- [ ] Przeciąganie hosta i katalogu do innego katalogu, także z przewijaniem listy przy krawędzi. Windows: przeciąganie w ogóle działa.
- [ ] Dziedziczenie: pole ustawione w katalogu jest widoczne w hoście jako odziedziczone, a własna wartość hosta je nadpisuje.
- [ ] Ulubione, wyszukiwanie i kopiowanie adresu z menu hosta.
- [ ] Zakładki okna hosta i katalogu: przełączanie myszą i strzałkami, błąd zapisu wskazuje właściwą zakładkę.

## SSH

- [ ] Połączenie hasłem i przez agenta SSH. Potwierdzone: Linux.
- [ ] Pierwsze połączenie pyta o klucz hosta; zapamiętany klucz nie pyta drugi raz; zmieniony klucz ostrzega.
- [ ] Połączenie przez bastion i przez łańcuch bastionów. Potwierdzone: Linux.
- [ ] Klucz prywatny zapisany w pliku z hostami: import klucza bez hasła i z hasłem (OpenSSH, PEM, PuTTY .ppk), potem połączenie.
- [ ] Klucz ze ścieżki pliku: połączenie; klucz zaszyfrowany pyta o hasło klucza przy łączeniu.
- [ ] Kolejność prób: klucz z pliku z hostami, plik klucza, agent, zapisane hasło, pytanie o hasło.
- [ ] Typ terminala (np. `vt100`) dociera do serwera (`echo $TERM`).
- [ ] Starsze algorytmy SSH: połączenie ze starym serwerem (np. AIX) udaje się tylko z włączonym polem.
- [ ] Polecenie po zalogowaniu wykonuje się po otwarciu powłoki.
- [ ] Terminal: polskie znaki, kolory, zmiana rozmiaru okna, przewijanie historii, duże wyjście (np. `cat` dużego pliku) bez zawieszenia.
- [ ] Opcje terminala: krój i rozmiar czcionki (także ustawiony dla hosta), kształt i miganie kursora, kopiowanie po zaznaczeniu, wklejanie prawym przyciskiem.
- [ ] Renderer WebGL: terminal rysuje się poprawnie w oknie programu na obu systemach.
- [ ] Podtrzymywanie połączenia: bezczynna sesja nie zrywa się po kilkunastu minutach.
- [ ] Dziennik sesji: po włączeniu powstaje plik z wyjściem serwera.
- [ ] Zerwanie połączenia (np. wyłączenie sieci) daje czytelny stan karty, a "Połącz ponownie" działa.

## RDP

- [ ] Połączenie z serwerem Windows z NLA; pytanie o certyfikat przy pierwszym połączeniu. Potwierdzone: Linux i Windows (0.0.4).
- [ ] Hasło na jedną sesję, gdy host nie ma zapisanego hasła.
- [ ] Rozdzielczość pulpitu podąża za rozmiarem okna. Potwierdzone: 14.11.2026.
- [ ] Schowek w obie strony: tekst, obraz, plik i katalog. Potwierdzone: 14.11.2026.
- [ ] Pełny ekran i Ctrl+Alt+Del z paska sesji.
- [ ] Lokalny kursor: kształt zmienia się nad polem tekstowym i krawędzią okna zdalnego.
- [ ] Profil łącza wolny: pulpit bez tapety i animacji.
- [ ] Przechwytywanie klawiszy: Alt+Tab i klawisz Windows trafiają do zdalnego pulpitu, a Ctrl+Shift+F12 zwalnia klawisze. Potwierdzone: Windows (0.0.4). Linux: tylko Wayland.
- [ ] Serwer z cudzym albo zmienionym certyfikatem jest odrzucany albo pyta ponownie (kontrola podpisu TLS).
- [ ] Windows: przekierowanie czytników kart inteligentnych - zdalny system widzi czytnik. Potwierdzone częściowo: czytnik widoczny, KeePassXC z kluczem po USB odrzuca wyzwanie.
- [ ] Windows: przekierowanie kluczy bezpieczeństwa (WebAuthn) działa w przeglądarce na zdalnym pulpicie.
- [ ] Kerberos z prawdziwym KDC.
- [ ] Długa sesja (godzina pracy) bez zerwania i bez rosnącego zużycia pamięci.

## Karty i skróty

- [ ] Kilka sesji naraz, przełączanie kart myszą i skrótami, zamykanie karty, pozostałych i wszystkich.
- [ ] Przestawianie kart: przeciąganie na pasku (kreska pokazuje miejsce), pozycje menu "Przesuń w lewo" i "Przesuń w prawo". Sesja po przestawieniu działa dalej.
- [ ] Pytanie przed zamknięciem karty i przed zamknięciem programu z otwartymi sesjami (po włączeniu w Ustawieniach).
- [ ] Skróty: zmiana skrótu w Ustawieniach działa; klawisz przypisany do skrótu nie trafia do sesji, a nieprzypisany trafia.
- [ ] Szybkie łączenie (domyślnie Ctrl+Shift+K) otwiera sesję z wpisanego adresu.

## Ustawienia

- [ ] Każda kategoria otwiera się, a "Zapisz" zapisuje zmiany z wielu kategorii naraz.
- [ ] Motyw jasny, ciemny i systemowy.
- [ ] Błędna wartość (np. rozmiar czcionki 200) daje błąd i przenosi do właściwej kategorii.
- [ ] Dziennik diagnostyczny pokazuje wpisy i nie zawiera haseł.
- [ ] Nowa wersja: program starszy od najnowszego wydania pokazuje po uruchomieniu powiadomienie, a "O programie" podaje numer; przycisk "Strona wydań" otwiera przeglądarkę. Po wyłączeniu w Ustawieniach (Narzędzia) powiadomienia nie ma.

## Synchronizacja

- [ ] Ustawienie folderu i pierwsza synchronizacja wysyła plik.
- [ ] Zmiana na jednym komputerze pojawia się jako "zmiany zdalne" na drugim; pobranie blokuje plik i wymaga hasła głównego.
- [ ] Zmiana po obu stronach daje konflikt; wybór wersji zostawia drugą jako kopię konfliktu.
- [ ] "Pokaż różnice" przy zmianach lokalnych, zdalnych i w konflikcie pokazuje właściwe hosty i katalogi oraz to, co się w nich zmieniło.
- [ ] Zmiana hasła głównego na jednym komputerze: drugi po pobraniu wymaga nowego hasła, a "Pokaż różnice" mówi, że porównanie wymaga pobrania.

## Import i eksport

- [ ] Import pliku `.mrmx`: wybór pliku, hasło, podgląd, import; hosty pojawiają się w drzewie. Potwierdzone: 20.11.2026 (131 hostów).
- [ ] Ponowny import tego samego pliku niczego nie dubluje; "Zaktualizuj" zmienia tylko zaznaczone dane.
- [ ] Eksport całej listy i jednego katalogu (z menu katalogu) zapisuje plik pod wskazaną ścieżką; istniejący plik nie jest nadpisywany. Windows: ścieżka z literą dysku.
- [ ] Eksport bez haseł, import u innej osoby: hasła nie przechodzą, a z zaznaczonymi hasłami przechodzą.
- [ ] Złe hasło pliku, plik z hostami zamiast pliku eksportu i zwykły plik tekstowy dają czytelne błędy.
- [ ] Import listy CSV (kolumny `nazwa`, `adres`, `protokol`, `katalog`): bez pytania o hasło, hosty trafiają do katalogów z listy; ponowny import odświeżonej listy z "Zaktualizuj" nie dubluje hostów.
- [ ] Windows: komenda PowerShell z README zapisuje listę komputerów z jednostki Active Directory do CSV, który program importuje.

## Linki

- [ ] Linux: kliknięcie linku `ssh://` albo `rdp://` w innym programie otwiera host albo formularz nowego hosta; link nigdy nie łączy sam.
- [ ] Link przekazany przy zablokowanym pliku czeka na odblokowanie.
- [ ] Windows: linki nie są rejestrowane (znany brak).
