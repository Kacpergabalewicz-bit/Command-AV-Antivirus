# Command AV

Command AV to rozbudowana desktopowa aplikacja bezpieczeństwa dla Windows.

## Główne funkcje

- szybki skan ważnych lokalizacji użytkownika,
- pełny skan wszystkich dostępnych dysków,
- skan pojedynczych plików i folderów,
- skan archiwów ZIP,
- heurystyka skryptów, LOLBins i podejrzanych rozszerzeń,
- skan uruchomionych procesów i ich linii poleceń,
- Live Guard oparty o monitoring zmian w czasie rzeczywistym,
- automatyczna lub ręczna kwarantanna,
- przywracanie i trwałe usuwanie z kwarantanny,
- raporty JSON i logi działania,
- system ustawień i wykluczeń.

## Uruchomienie w Pythonie

```bash
python main.py
```

Na Windows możesz też uruchamiać przez:

- [Command AV.pyw](Command%20AV.pyw)

## Build EXE

Po instalacji zależności można zbudować wersję `.exe` przez PyInstaller.

Efekt końcowy pojawi się w katalogu `dist`.

## Ważne

To nadal aplikacja użytkowa, nie sterownik jądra ani pełny enterprise EDR. Ma jednak działające funkcje desktopowe, monitoring live, kwarantannę, skan procesów i pełny skan systemu plików.
