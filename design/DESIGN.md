# Menedżer sesji SSH i RDP - specyfikacja wizualna

Źródło: artefakt projektowy "Menedżer sesji SSH i RDP" (każda plansza to plik `.dc.html`). Ten dokument spisuje decyzje wizualne w jednym miejscu. Wartości są wyciągnięte z plansz, nie wymyślone osobno.

## Zasady

- Paleta jest monochromatyczna. Znaczenie niosą jasność, grubość obramowania, kształt i ikona, nigdy sam kolor.
- Protokoły rozróżnia kształt odznaki: SSH ma tło wypełnione kolorem akcentu, RDP ma tylko obrys.
- Brak przycisków w kształcie pigułki. Przyciski i pola mają promień 6 px.
- Cały interfejs po polsku. Jedyny znak kreski w tekstach to łącznik `-`.
- Natywna ramka okna na Linuksie i Windows, bez własnego paska tytułu.
- Minimalny rozmiar okna 640 x 480. Poniżej 900 px szerokości pasek boczny zwija się do ikon.

## Kolory

| Rola | Ciemny | Jasny |
|---|---|---|
| Tło okna | #0F0F0F | #F3F3F3 |
| Panel (pasek boczny, paski) | #161616 | #FAFAFA |
| Powierzchnia (przyciski, karty) | #1C1C1C | #EFEFEF |
| Zaznaczenie, najechanie | #262626 | #E4E4E4 |
| Obramowanie | #2C2C2C | #DCDCDC |
| Obramowanie wyraźne | #3A3A3A | #C2C2C2 |
| Tekst | #EDEDED | #1A1A1A |
| Tekst drugorzędny | #A0A0A0 | #5E5E5E |
| Terminal | #0A0A0A | #FFFFFF |
| Akcent (domyślny) | #EDEDED | #1A1A1A |
| Tekst na akcencie | #0F0F0F | #FFFFFF |

Akcent jest parametrem (w planszach `accent`). Wszystko, co jest "główne" (przycisk główny, aktywna karta, zaznaczone pola, pierścień fokusu), używa akcentu.

## Typografia

- Interfejs: IBM Plex Sans, 400 / 500 / 600. Domyślnie 14 px.
- Terminal, ścieżki, odciski kluczy, dziennik: JetBrains Mono, 11-12 px.
- Rozmiary: tytuł okna 16 px (600), tytuł dużego ekranu 18-20 px, etykieta pola 13 px (500), tekst pomocniczy 12-13 px (kolor drugorzędny), odznaki 10-11 px (600).

## Odstępy, promienie, wysokości

- Podstawa 4 px. Używane wielokrotności: 4, 8, 12, 16, 20, 24, 40.
- Okna dialogowe: nagłówek i stopka z paddingiem 14-16 px / 24 px, treść 20 px / 24 px.
- Promienie: odznaka 3 px, przełącznik i pole wyboru 3-4 px, przyciski i pola 6 px, menu 8 px, okna 10 px.
- Wysokości kontrolek: przycisk 36 px (kompaktowy 28-32 px), pole tekstowe 36-40 px, wiersz drzewa 32-34 px, wiersz listy 48 px, pasek kart 38 px, pasek stanu 26-28 px.
- Cień tylko dla menu i okien pływających: `0 8px 24px rgba(0,0,0,0.5)`.

## Stany

Pełna tabela jest na planszy "Stany komponentów". Reguły:

- Najechanie: jaśniejsze tło o jeden stopień (np. #1C1C1C -> #262626).
- Fokus z klawiatury: obrys 2 px w kolorze akcentu, odsunięty o 2 px (w wierszach listy odsunięcie do wewnątrz).
- Aktywny/wciśnięty: ciemniejsze tło o jeden stopień.
- Wyłączony: krycie 0,45 i brak kursora wskazującego.
- Błąd pola: obramowanie w kolorze tekstu, komunikat pod polem z ikoną, bez koloru czerwonego.
- Przycisk niebezpieczny: obrys w kolorze tekstu, po najechaniu wypełnienie.

## Ikony

47 ikon w paczce `design/icons/`. Siatka 24 x 24, obrys 1,75, zakończenia i łączenia zaokrąglone, `currentColor`. Każda ikona to jedna ścieżka. Rozmiary w użyciu: 14 px (paski i wiersze), 16 px (przyciski), 18-20 px (pasek boczny w trybie zwiniętym), 28 px (ekrany błędów).
Ikona programu: `app-icon.svg` (jasne tło) i `app-icon-light.svg`. Ikony zasobnika: `tray-idle.svg`, `tray-active.svg`, `tray-locked.svg`.

## Mapa plansz

| Plansza | Co pokazuje |
|---|---|
| Okno główne, Okno główne (jasny motyw), Okno wąskie | Układ główny, tryb ze zwiniętym paskiem |
| Widok sesji RDP, RDP pełny ekran | Sesja zdalnego pulpitu, pasek narzędzi |
| Pasek kart i menu karty | Przepełnienie, przeciąganie, menu |
| Stany drzewa hostów | Pusta lista, brak wyników, przeciąganie, zaznaczenie wielu |
| Menu kontekstowe | Menu hosta, katalogu, tła |
| Ustawienia aplikacji (i jasny motyw) | Wszystkie sekcje ustawień |
| Edycja hosta (i jasny motyw), Właściwości katalogu | Pola z dziedziczeniem |
| Odblokowanie, Pierwsze uruchomienie, Zmiana hasła głównego | Hasło główne |
| Błędy pliku z hostami, Kopie zapasowe | Uszkodzenie, wersje, przywracanie |
| Konflikt synchronizacji, Kreator synchronizacji | Synchronizacja przez folder |
| Zaufanie do hosta, Zaufane klucze | Odciski SSH i certyfikaty RDP |
| Stany sesji, Stany agenta SSH, Monit o hasło | Łączenie, błędy, brak agenta |
| Szybkie łączenie, Połączenie z linku | Ctrl+K i linki ssh:// rdp:// |
| Skróty klawiszowe, Edycja skrótu | Ściągawka i edycja |
| Schematy terminala | Trzy schematy w skali szarości |
| Powiadomienia, Start i aktualizacja, O programie, Dziennik diagnostyczny | Elementy pomocnicze |
| Ikona i elementy systemowe, Biblioteka ikon, Stany komponentów | Ikony, zasobnik, komponenty |

## Uwagi

- Dane na planszach (nazwy hostów, odciski, wersje, ścieżki) są przykładowe.
- Nazwa programu "Menedżer sesji" i polecenie `multiremotemanager` są robocze.
- Plansze nie były sprawdzane w przeglądarce w czasie tworzenia.
