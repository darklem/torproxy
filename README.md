# 🧅 TorProxy-Chain

Un outil CLI qui établit une connexion Tor puis chaîne des proxies SOCKS publics pour masquer le trafic réseau avec sélection du pays de sortie.

## Architecture

```
Vous → Tor (circuit chiffré) → Proxy SOCKS5 public (pays choisi) → Internet
```

## Fonctionnalités

- 🧅 Connexion automatique au réseau Tor
- 🌍 Récupération de proxies SOCKS4/SOCKS5 publics depuis plusieurs sources
- 🗺️ Sélection interactive du pays de l'IP de sortie
- ⛓️ Chaînage : Tor → SOCKS proxy (double anonymisation)
- ✅ Vérification automatique des proxies
- 🔄 Rotation automatique si le proxy actif tombe
- 📊 Affichage de l'IP publique finale et de sa géolocalisation

## Prérequis

- Python 3.9+
- `tor` installé (`sudo apt install tor` sur Debian/Ubuntu)

## Installation

```bash
# Installer les dépendances Python
pip install -r requirements.txt

# Installer Tor (si pas déjà fait)
sudo apt install tor

# Lancer l'outil
python main.py
```

## Utilisation

```bash
# Mode interactif (recommandé)
python main.py

# Sélection directe du pays
python main.py --country FR

# Lister les pays disponibles
python main.py --list-countries

# Mode verbose
python main.py --country US --verbose

# Utiliser un port SOCKS local personnalisé
python main.py --country DE --local-port 1080
```

## Comment ça marche

1. **Connexion Tor** : Lance/contrôle un processus Tor local (port 9050 SOCKS, 9051 contrôle)
2. **Scraping proxies** : Récupère des listes de proxies SOCKS publics depuis proxyscrape, spys.one, etc.
3. **Filtrage par pays** : Filtre les proxies selon le code pays choisi
4. **Validation** : Teste chaque proxy via Tor pour s'assurer qu'il répond
5. **Chaînage** : Configure un proxy local qui route via Tor puis le SOCKS choisi
6. **Vérification IP** : Affiche l'IP finale et confirme le pays de sortie

## Avertissement

Cet outil est destiné à des fins éducatives et à la protection de la vie privée. Respectez les lois locales et les conditions d'utilisation des services.
