# gaia-x
Status von https://www.data-infrastructure.eu/GAIAX/Navigation/EN/Home/home.html und tutorials für kiki


# was ist zu tun?

1. Wir werden drei verschiedene service-container erstellen, um die Funktionsweise von OpenID bzw. JWT anhand von folgendem Anwendungsbeispiel zu verstehen:
[Was ist JWT ?](https://www.youtube.com/watch?v=7Q17ubqLfaM&pp=ygUDand0)

Anwendungsbeispiel:
Da du bald deinen Führerschein hast möchte ich dir ein Beispiel zeigen, wie deine Zukunft als Autofahrer aussehen könnte, wenn gaia-x ein Erfolg werden sollte...
Als Student kannst du dir kein eigenes Auto leisten und musst einen oder mehrere Carsharing Services in Anspruch nehmen. Es ist nervig für jeden Car-Sharing-Anbieter neue Benutzerinformationen zu erstellen, wie war der Benutzername, welche Email-Addresse habe ich verwendet? Es ist auch nervig jedem Fahrzeug Nutzungsrechte zu erteilen z.B. mit meinem Handy zu koppeln und Rechte nur auf bestimmte Funktionen zu erteilen, habe ich doch gelernt wie wichtig es ist gewissenhaft mit seinen Daten umzugehen. Entweder man kümmert sich um seine Daten oder deine Daten kümmern sich um dich. 
JWT kann helfen um den Zugriff auf deine Daten zu verwalten.

Wie können sie genau helfen ist das sowas wie ein Passwort Manager?

Nein eigentlich nicht, aber es gibt Ähnlichkeiten. Der feine Unterschied ist das ein Passwortmanager authentifiiert und nicht autorisiert. 
Wichtig zu verstehen ist das JWT es ermöglicht zu autorisieren nicht zu authentifizieren. 

Was ist der Unterschied?

Der Dienst welcher weiß wer du bist (Authentifizierung), muss nicht unbedingt der gleiche Dienst sein welcher dir erlaubt etwas zu tun (Autorisierung).
Dein Personalausweiß sagt wer du bist, wohingegen dein Führerschein dir die Erlaubnis erteilt Auto zu fahren.
Um deinen Führerschein zu bekommen musst du deinen Personalausweis vorzeigen und eine Prüfung absolvieren, ähnlich ist es mit JWT.


2. Die heiligen drei Container

2.1 Keycloak -> wir nutzen einen bestehenden IAM service:
Keycloak ist eine Open-Source-Identitäts- und Zugriffsverwaltungsplattform (Identity and Access Management, IAM), die von Red Hat entwickelt wird. Es bietet eine umfassende Lösung zur Verwaltung von Benutzeridentitäten, Authentifizierung, Autorisierung und Single Sign-On (SSO) für Anwendungen und APIs.

Keycloak bietet eine Vielzahl von Funktionen, die in IAM-Szenarien häufig benötigt werden. Dazu gehören:

    Benutzerverwaltung: Keycloak ermöglicht die zentrale Verwaltung von Benutzern, einschließlich Registrierung, Profilverwaltung und Passwortrücksetzung.

    Authentifizierung: Keycloak unterstützt verschiedene Authentifizierungsmethoden wie Benutzername und Passwort, Social-Login über Plattformen wie Google und Facebook, OpenID Connect, SAML und mehr. Es bietet eine flexible Konfiguration für Multi-Faktor-Authentifizierung.

    Autorisierung und Zugriffssteuerung: Keycloak ermöglicht die Definition von Zugriffsrichtlinien und die Feinabstimmung des Zugriffs auf Ressourcen basierend auf Benutzerrollen, Gruppenzugehörigkeit und anderen Attributen.

    Single Sign-On (SSO): Keycloak ermöglicht die SSO-Integration für verschiedene Anwendungen und Dienste. Sobald sich ein Benutzer bei einer Anwendung authentifiziert hat, kann er auf andere Anwendungen zugreifen, ohne sich erneut anmelden zu müssen.

    Clientverwaltung: Keycloak stellt Clients bereit, die Anwendungen und Dienste repräsentieren, die sich bei Keycloak registrieren. Jeder Client hat seine eigenen Konfigurationsparameter und Zugriffsrichtlinien.

    Integration und Erweiterbarkeit: Keycloak bietet umfangreiche APIs und Erweiterungspunkte, um die Integration in bestehende Systeme zu erleichtern und die Funktionalität anzupassen.

Keycloak ist in Java geschrieben und kann als eigenständige Server-Instanz bereitgestellt oder in eine vorhandene Java-Anwendung integriert werden. Es bietet auch Docker-Images und Kubernetes-Integration für eine einfache Bereitstellung und Skalierung.

Durch die Verwendung von Keycloak können Entwickler Zeit sparen, indem sie komplexe IAM-Funktionen in ihren Anwendungen und APIs schnell implementieren und eine sichere und skalierbare Authentifizierungs- und Autorisierungslösung bereitstellen können.

2.2 Die Führerscheinstelle

2.3 Das Auto


3. Los geht's

3.1 Arbeite in einer geschlossen "Sandkasten"... ich will kein Sand auf meiner Terrasse ;)

![Nutze devcontainer wenn möglich](bilder/devcontainer.png)

3.2. Verknüpfe die Sandburgen mach den Sandkasten größer indem du sie mit einer Brücke verknüpfts 

Verwende [pods](https://kubernetes.io/docs/concepts/workloads/pods/) oder für die Sandkastenkinder [docker compose](https://docs.docker.com/compose/)

3.3 Jetzt geht es aber wirklick los...

3.3.1 Container 1 keycloak 

Um eine Keycloak-Instanz mit Docker Compose  zu erstellen benötigen wir eine docker-compose.yml Datei und fügen den folgenden Inhalt hinzu:
```
version: '3'
services:
  keycloak:
    image: jboss/keycloak
    environment:
      - KEYCLOAK_USER=admin
      - KEYCLOAK_PASSWORD=admin
    ports:
      - 8080:8080
```

Dieses Docker Compose-Setup startet eine Keycloak-Instanz mit Benutzername "admin" und Passwort "admin" auf dem Port 8080.

Um keycloak zu starten, öffne ein Terminalfenster, navigiere zum Verzeichnis mit der docker-compose.yml-Datei und führe den folgenden Befehl aus:

```
docker-compose up
```

Dies startet die Keycloak-Instanz und du solltest sehen, dass Keycloak auf dem Port 8080 läuft.


3.3.2 Container 2: Die Führerscheinstelle

Wir schreiben einen Dienst welcher einen Zugriffstoken in Form eines JWT token erstellt.

Erstelle eine Python-Datei, z.B. passierschein_A38_client.py, und füge den folgenden Code ein:

```
import subprocess
import json

# Keycloak-URL und Anmeldedaten
keycloak_url = 'http://localhost:8080/auth/realms/master/protocol/openid-connect/token'
client_id = 'your-client-id'
client_secret = 'your-client-secret'

# Tokenanforderung mit Curl ausführen
command = f"curl -d 'grant_type=client_credentials' -d 'client_id={client_id}' -d 'client_secret={client_secret}' {keycloak_url}"
output = subprocess.check_output(command, shell=True)

# JSON-Ausgabe analysieren
response = json.loads(output)

# JWT-Token extrahieren
access_token = response.get('access_token')
print('Access Token:', access_token)
```

Stelle sicher, dass <your-client-id> und <your-client-secret> durch die tatsächlichen Werte deines Keycloak-Clients ersetzt werden.

Öffne ein Terminalfenster, navigiere zum Verzeichnis mit der passierschein_A38_client.py-Datei und führe den folgenden Befehl aus:

```
python passierschein_A38_client.py
```

Der Python-Client führt [Curl-Befehle](https://curl.se/) aus, um ein JWT-Token von der Keycloak-Instanz abzurufen, und gibt das Access Token in der Konsole aus.

Das ist die grundlegende Vorgehensweise, um eine Keycloak-Instanz mit Docker Compose zu starten und einen Python-Client zu schreiben, um ein JWT-Token von Keycloak zu erhalten. Bitte beachte, dass weitere Schritte notwendig sind, um die Keycloak-Instanz zu konfigurieren, z. B. Clients, Realms, Benutzer usw., je nach spezifischen Anforderungen.

3.3.3 Container 3: Das Auto

Die Führerscheinstelle kann für jedes Fahrzeug einen Token mit Verfallsdatum erstellen, um das Fahrzeug benutzen zu dürfen.
Das Fahrzeug kann mit hilfe des folgenden codes prüfen ob jemand dazu befugt ist das Fahrzeug zu fahren.

```
import jwt
def verify_jwt(jwt_token, public_key):
    try:
        decoded_token = jwt.decode(jwt_token, public_key, algorithms=['RS256'])
        return decoded_token
    except jwt.ExpiredSignatureError:
        print("JWT has expired.")
    except jwt.InvalidTokenError:
        print("Invalid JWT.")
    except Exception as e:
        print(f"Error occurred while verifying JWT: {str(e)}")
    return None
```

Hier ist ein Beispiel zur Verwendung des obigen codes:

Diese Funktion nimmt das JWT und den öffentlichen Schlüssel als Eingabe entgegen und gibt das decodierte Token zurück, wenn es gültig ist. Andernfalls gibt sie None zurück und gibt eine entsprechende Fehlermeldung aus.

Rufe die verify_jwt-Funktion auf und übergebe das JWT und den öffentlichen Schlüssel. Hier ist ein Beispiel:

```

    jwt_token = "<Das zu überprüfende JWT>"
    public_key = "<Der öffentliche Schlüssel>"

    decoded_token = verify_jwt(jwt_token, public_key)
    if decoded_token:
        print("JWT is valid.")
        # Führen Sie hier die gewünschten Aktionen mit dem decodierten JWT aus
```

Ersetze <Das zu überprüfende JWT> durch das tatsächliche JWT, das du überprüfen möchtest, und <Der öffentliche Schlüssel> durch den entsprechenden öffentlichen Schlüssel, der zur Überprüfung verwendet werden soll.

Beachte, dass der öffentliche Schlüssel entsprechend der verwendeten Signaturalgorithmus und Schlüsselpaar-Generierung anpasst werden muss. In diesem Beispiel wurde RS256 (RSA mit SHA-256) als Signaturalgorithmus verwendet.

Mit diesem Ansatz kannst du die Gültigkeit des erstellten JWT in einem anderen Python-Programm überprüfen und entsprechend darauf reagieren. Stelle sicher, dass der öffentliche Schlüssel korrekt bereitgestellt und dass die erforderlichen Bibliotheken installiert sind, um die JWT-Verifikation durchzuführen.
