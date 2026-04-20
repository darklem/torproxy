# 🧅 TorProxy-Chain — Journal de session (20 avril 2026)

> Session de développement et debugging avec Cline (Claude Sonnet).

---

## 📋 Résumé des modifications

| Fichier | Action |
|---|---|
| `main.py` | Bug fix saisie pays + cache SQLite + détachement serveur + options CLI |
| `proxy_scraper.py` | Barre de progression géolocalisation |
| `proxy_chain.py` | Fix SOCKS5 + écoute 0.0.0.0 |
| `proxy_cache.py` | **Nouveau** — Cache SQLite + gestion PID |

---

## 1. Bug : saisie pays retournait toujours vide

### Symptôme
```
Entrez le code pays (ex: FR, US, DE): ❌ Code pays '' non disponible.
```

### Cause
`Prompt.ask()` de Rich ne captait pas l'entrée clavier dans certains terminaux, retournant une chaîne vide `''`.

### Correction (`main.py` — `select_country_interactive`)
```python
# AVANT (bugué)
choice = Prompt.ask("[bold cyan]Entrez le code pays[/bold cyan]...").strip().upper()

# APRÈS (corrigé)
console.print("[bold cyan]Entrez le code pays[/bold cyan] (...): ", end="")
choice = input().strip().upper()
```
Améliorations supplémentaires :
- Gestion `EOFError`/`KeyboardInterrupt` → `sys.exit(0)`
- Message explicite si saisie vide (au lieu de boucler silencieusement)

---

## 2. Cache SQLite des proxies géolocalisés

### Problème
À chaque lancement, `resolve_countries_batch` interrogeait ip-api.com pour **tous** les proxies, ce qui prenait plusieurs minutes.

### Solution : `proxy_cache.py` (nouveau fichier)
- **Base** : `~/.torproxy-chain/proxy_cache.db`
- **TTL** : 24 heures
- **Schema** :
  ```sql
  CREATE TABLE proxies (
      host         TEXT    NOT NULL,
      port         INTEGER NOT NULL,
      proto        TEXT    DEFAULT 'socks5',
      country      TEXT    DEFAULT '',
      country_name TEXT    DEFAULT '',
      cached_at    REAL    NOT NULL,
      PRIMARY KEY (host, port)
  )
  ```

### API
```python
load_cached_proxies(ttl=86400)    # Charge les proxies valides du cache
save_proxies_to_cache(proxies)    # Upsert dans SQLite
count_cached_proxies()            # Nombre de proxies en cache
cache_age_hours()                 # Âge du cache en heures (None si expiré)
clear_cache()                     # Vide tout le cache
```

### Flux dans `main.py` (étape 3)
```
1. Charger le cache SQLite
2. Appliquer les pays connus aux proxies scrapés (instantané)
3. Résoudre via ip-api.com UNIQUEMENT les proxies inconnus
4. Sauvegarder les nouvelles résolutions
```
→ Au 2ème lancement : géolocalisation quasi-instantanée.

### Options CLI ajoutées
```bash
python main.py --clear-cache    # Forcer une re-géolocalisation complète
```

---

## 3. Barre de progression géolocalisation

### Ajout dans `proxy_scraper.py` — `resolve_countries_batch`

Utilise `rich.progress` pour afficher :
```
🌍 Géolocalisation 3/12 batches...  ████████░░░░  25%  287 résolus
```

Composants :
- `SpinnerColumn()` — animation
- `TextColumn` avec description dynamique `batch X/Y`
- `BarColumn()` — barre de progression
- `TaskProgressColumn()` — pourcentage
- Champ custom `resolved` — compteur de proxies géolocalisés

La barre n'apparaît **que** si des proxies sont à résoudre (proxies déjà en cache = pas de barre).

---

## 4. Détachement du serveur (commande `[d]`)

### Fonctionnement
Dans la boucle interactive, `[d]` quitte le menu **sans arrêter** le serveur SOCKS5 :

```
╭─ ⛓️  Détaché ───────────────────────────────────╮
│  Le serveur tourne en arrière-plan.              │
│                                                   │
│  🔌 Proxy SOCKS5 actif : socks5://0.0.0.0:10800 │
│  🆔 PID : 12345                                   │
│                                                   │
│  Pour arrêter plus tard :                         │
│    python main.py --kill                          │
│    ou :  kill 12345                               │
╰───────────────────────────────────────────────────╯
```

Après détachement, le processus continue en boucle silencieuse (`time.sleep(60)`).

### Fichier PID
- Chemin : `~/.torproxy-chain/torproxy.pid`
- Contenu :
  ```
  12345        ← PID
  10800        ← port local
  FR           ← pays sélectionné
  ```

### API PID (`proxy_cache.py`)
```python
write_pid(pid, local_port, country)   # Écrit le PID au démarrage du serveur
read_pid()                            # Lit + vérifie que le processus existe encore
clear_pid()                           # Supprime le fichier
```

### Options CLI ajoutées
```bash
python main.py --kill    # Envoie SIGTERM au serveur détaché + nettoie le PID
```

---

## 5. Fix SOCKS5 — `proxy_chain.py`

### Erreur signalée
```
curl: (97) Can't complete SOCKS5 connection to ipconfig.io. (4)
```
Code SOCKS5 `4` = Host unreachable.

### Causes racines

**Bug 1 — `sock.recv(N)` non fiable**
TCP peut fragmenter les données → `recv(10)` peut retourner 3 octets.  
Le handshake SOCKS5 était corrompu de façon intermittente.

**Bug 2 — Parsing réponse CONNECT incorrect**
```python
# ANCIEN CODE (bugué)
resp = sock.recv(10)   # suppose toujours IPv4 + 10 octets
if resp[3] == 0x03:    # domain name
    sock.recv(domain_len + 2)   # ← lit trop d'octets (déjà consommés !)
```

La réponse CONNECT SOCKS5 a une longueur **variable** selon ATYP :
- `0x01` (IPv4) : 4 header + **4** addr + 2 port = 10 octets
- `0x03` (domain) : 4 header + **1+N** addr + 2 port = variable
- `0x04` (IPv6) : 4 header + **16** addr + 2 port = 22 octets

### Corrections

**Ajout de `_recvall(sock, n)`** :
```python
def _recvall(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"Socket closed after {len(data)}/{n} bytes")
        data += chunk
    return data
```

**`_socks5_handshake` (serveur local)** — utilise `_recvall` partout.

**`_socks5_connect` (client vers exit proxy)** — parsing correct :
```python
header = _recvall(sock, 4)                    # VER, REP, RSV, ATYP
if header[1] != 0x00: raise ConnectionError()
atyp = header[3]
if atyp == 0x01:   _recvall(sock, 4 + 2)     # IPv4
elif atyp == 0x03: _recvall(sock, _recvall(sock, 1)[0] + 2)  # domain
elif atyp == 0x04: _recvall(sock, 16 + 2)    # IPv6
```

**`_socks4_connect`** — `_recvall(sock, 8)` au lieu de `recv(8)`.

---

## 6. Vérification DNS & sécurité

### Question : les connexions et DNS passent-ils exclusivement par Tor ?

**Réponse : OUI, aucune fuite.**

| Nœud | DNS | TCP |
|---|---|---|
| Connexion locale → Tor | Aucun (127.0.0.1) | Local |
| Tor → Exit proxy | Aucun (IP numérique du scraper) | Via Tor ✅ |
| Exit proxy → Internet | **Par le proxy exit** (ATYP=0x03) | Via Tor ✅ |

Points clés :
- `rdns=True` sur PySocks → Tor gère le DNS si nécessaire
- `_socks5_connect` envoie toujours `ATYP=0x03` (domain name) → pas de résolution locale
- `socks5h://` dans `requests` → même garantie pour `resolve_countries_batch`

---

## 7. Écoute sur 0.0.0.0

### Modification
```python
# proxy_chain.py
LOCAL_BIND = "0.0.0.0"   # était "127.0.0.1"
```

Le serveur SOCKS5 est désormais accessible depuis le réseau local.

**Utilisation depuis un autre appareil :**
```
socks5://<IP-machine>:10800
```

`get_chained_ip()` utilise toujours `127.0.0.1` en interne (on ne peut pas connecter à `0.0.0.0`).

⚠️ **Sans authentification** — protéger par firewall si nécessaire.

---

## 🗂️ Structure finale des fichiers

```
torproxy-chain/
├── main.py              ← CLI + logique principale (cache + détachement)
├── proxy_scraper.py     ← Scraping + géolocalisation (avec barre de progression)
├── proxy_chain.py       ← Serveur SOCKS5 local (fix handshake, 0.0.0.0)
├── proxy_cache.py       ← NOUVEAU : cache SQLite + gestion PID
├── tor_manager.py       ← Gestion de Tor
├── README.md
├── requirements.txt
└── SESSION_LOG.md       ← Ce fichier
```

**Cache & PID :**
```
~/.torproxy-chain/
├── proxy_cache.db       ← SQLite (proxies géolocalisés, TTL 24h)
└── torproxy.pid         ← PID du serveur détaché (optionnel)
```

---

## 🚀 Commandes disponibles

```bash
# Lancer
python main.py                        # Mode interactif
python main.py --country FR           # Pays direct
python main.py --list-countries       # Lister les pays

# Options
python main.py --skip-verify          # Ne pas vérifier les proxies
python main.py --local-port 1080      # Changer le port local
python main.py --verbose              # Mode verbeux

# Gestion
python main.py --kill                 # Arrêter le serveur détaché
python main.py --clear-cache          # Vider le cache SQLite

# Tester le proxy
curl --proxy socks5h://127.0.0.1:10800 https://ipinfo.io
curl --proxy socks5h://<IP>:10800 https://ipinfo.io   # depuis un autre appareil
```

### Commandes dans la boucle interactive
| Touche | Action |
|---|---|
| `r` | Rotation du proxy de sortie |
| `n` | Nouveau circuit Tor |
| `i` | Vérifier l'IP actuelle |
| `d` | **Détacher** (quitter sans arrêter le serveur) |
| `q` | Quitter et arrêter tout |
