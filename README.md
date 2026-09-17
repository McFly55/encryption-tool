# encryption-tool

Eine einfache, übersichtliche und moderne Benutzeroberfläche zum Ver- und Entschlüsseln von Text und Dateien. Gedacht für Personen ohne CLI-Kenntnisse — alles läuft im Browser, ohne Installation.

## Funktionen

- **Text & Dateien** in einer Oberfläche ver- und entschlüsseln
- **AES-256-GCM** mit passwortbasierter Schlüsselableitung (PBKDF2, SHA-256, 250 000 Iterationen)
- **Komplett lokal**: Alle Verarbeitung erfolgt im Browser (Web Crypto API), es werden keine Daten übertragen oder gespeichert
- **Modernes Design**: Übersichtliche Karten, Umschalter für Modus und Eingabeart, Drag-&-Drop für Dateien, Klartext-Statusmeldungen
- **Download / Kopieren**: Verschlüsselte Texte kopieren, Dateien als `.enc` herunterladen

## Nutzung

1. `index.html` in einem modernen Browser öffnen (Chrome, Firefox, Safari, Edge).
2. Modus wählen: **Verschlüsseln** oder **Entschlüsseln**.
3. Eingabeart wählen: **Text** oder **Datei**.
4. Passwort eingeben (mindestens 8 Zeichen).
5. Text einfügen bzw. Datei per Drag-&-Drop oder Auswahl hinzufügen.
6. Aktion auslösen — das Ergebnis erscheint direkt darunter.

> Hinweis: Da es kein Server-Backend gibt, gibt es keine Passwort-Wiederherstellung. Das Passwort ist zwingend zum Entschlüsseln erforderlich.

## Dateiformat

Verschlüsselte Daten werden als Base64-Text gespeichert:

```
ENC1.<salt>.<iv>.<ciphertext>
```

- `salt` (16 Byte) und `iv` (12 Byte) werden pro Verschlüsselung neu zufällig erzeugt.
- Der Schlüssel wird mit PBKDF2 (SHA-256, 250 000 Iterationen) aus dem Passwort abgeleitet.
- Bei Dateien wird derselbe Text in eine `.enc`-Datei geschrieben.

## Projektstruktur

- `index.html` — Aufbau der Oberfläche
- `styles.css` — Styling
- `app.js` — Verschlüsselungslogik und Interaktion

## Lizenz

GPL-3.0