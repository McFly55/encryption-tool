# encryption-tool

AES-256-Dateiverschlüsselung für die Kommandozeile. Das Tool verschlüsselt eine
Datei mit AES-256-GCM und legt das Ergebnis als neue Datei ab; die
verschlüsselte Datei lässt sich mit demselben Passwort wieder entschlüsseln.

## Funktionen

- **AES-256-GCM** (authentifizierte Verschlüsselung) über die Python-Bibliothek
  [`cryptography`](https://cryptography.io/).
- **Schlüsselableitung** aus einem Passwort mit PBKDF2-HMAC-SHA256
  (600 000 Iterationen, 128-Bit-Salt).
- **Neue Datei** beim Verschlüsseln (`<datei>.enc`); das Original bleibt
  unangetastet. Beim Entschlüsseln wird bei `.enc`-Dateien der Originalname
  wiederhergestellt, sonst `<datei>.dec`.
- **Fortschrittsanzeige** als Text-Balken, aktualisiert beim Einlesen in
  1-MiB-Blöcken – nützlich bei großen Dateien.
- **Fehlerbehandlung** für nicht existierende Quelldateien, schon vorhandene
  Zieldateien (kein Überschreiben), ungültiges Dateiformat sowie falsche
  Passwörter oder manipulierte Dateien (GCM erkennt das über den
  Authentifizierungs-Tag).

## Voraussetzungen

- Python 3.8+
- [`cryptography`](https://cryptography.io/) – installieren mit:

  ```bash
  pip install cryptography
  ```

## Verwendung

```bash
# Verschlüsseln (Passwort wird zweimal abgefragt)
python3 aes_file_crypto.py -e <datei>

# Entschlüsseln
python3 aes_file_crypto.py -d <datei>
```

- Verschlüsseln erzeugt `<datei>.enc`.
- Entschlüsseln erzeugt bei einer `.enc`-Datei den Originalnamen (ohne `.enc`),
  andernfalls `<datei>.dec`.

Beide Zieldateien werden **nicht** überschrieben, falls sie bereits existieren.

## Dateiformat

```
MAGIC (7 B) | Salt (16 B) | Nonce (12 B) | Ciphertext + GCM-Tag
```

Salt und Nonce werden pro Datei zufällig erzeugt, sodass gleiche Eingaben
unterschiedliche Ciphertexte liefern.

## Sicherheitshinweise

- AES-GCM prüft beim Entschlüsseln die Integrität der Daten. Bei einem falschen
  Passwort oder einer manipulierten Datei schlägt die Entschlüsselung
  kontrolliert fehl.
- Die gespeicherte verschlüsselte Datei enthält keinen Klartext; Salt und Nonce
  sind öffentliche Werte und dürfen zusammen mit dem Ciphertext gespeichert
  werden.
- Es liegt in der Verantwortung der Nutzenden, ein starkes Passwort zu wählen
  und die verschlüsselten Dateien sicher zu verwahren.

## Lizenz

Dieses Projekt steht unter der [GNU General Public License v3.0](LICENSE).
