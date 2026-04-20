"""
Gestionnaire de connexion Tor.
Démarre, contrôle et surveille le processus Tor local.
"""

import subprocess
import time
import socket
import os
import signal
import sys
from typing import Optional

try:
    import stem
    import stem.process
    import stem.control
    from stem.control import Controller
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_CONTROL_PASSWORD = "torproxy_chain_secret"
TOR_DATA_DIR = "/tmp/torproxy_chain_data"


def is_tor_running() -> bool:
    """Vérifie si Tor est déjà en écoute sur le port SOCKS."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex(("127.0.0.1", TOR_SOCKS_PORT))
        s.close()
        return result == 0
    except Exception:
        return False


def is_tor_installed() -> bool:
    """Vérifie si tor est installé sur le système."""
    result = subprocess.run(
        ["which", "tor"],
        capture_output=True,
        text=True
    )
    return result.returncode == 0


def get_tor_config() -> str:
    """Génère la configuration Tor."""
    os.makedirs(TOR_DATA_DIR, exist_ok=True)

    # Hash du mot de passe pour le port de contrôle
    hash_result = subprocess.run(
        ["tor", "--hash-password", TOR_CONTROL_PASSWORD],
        capture_output=True,
        text=True
    )
    hashed_pw = ""
    if hash_result.returncode == 0:
        for line in hash_result.stdout.strip().split("\n"):
            if line.startswith("16:"):
                hashed_pw = line.strip()
                break

    config = f"""SocksPort {TOR_SOCKS_PORT}
ControlPort {TOR_CONTROL_PORT}
DataDirectory {TOR_DATA_DIR}
Log notice stdout
"""
    if hashed_pw:
        config += f"HashedControlPassword {hashed_pw}\n"

    return config


class TorManager:
    """Gestionnaire du processus Tor."""

    def __init__(self):
        self.tor_process: Optional[subprocess.Popen] = None
        self.controller: Optional["Controller"] = None
        self._using_existing = False

    def start(self) -> bool:
        """Démarre Tor ou se connecte à une instance existante."""
        if is_tor_running():
            console.print("[yellow]⚡ Tor déjà actif sur le port 9050, connexion à l'instance existante...[/yellow]")
            self._using_existing = True
            return self._connect_controller_no_auth()

        if not is_tor_installed():
            console.print("[red]❌ Tor n'est pas installé.[/red]")
            console.print("[cyan]   Installez-le avec : [bold]sudo apt install tor[/bold][/cyan]")
            return False

        return self._start_tor_process()

    def _start_tor_process(self) -> bool:
        """Lance le processus Tor avec stem."""
        console.print("[cyan]🧅 Démarrage de Tor...[/cyan]")

        if STEM_AVAILABLE:
            return self._start_with_stem()
        else:
            return self._start_with_subprocess()

    def _start_with_stem(self) -> bool:
        """Démarre Tor via stem."""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console,
            ) as progress:
                task = progress.add_task("Connexion au réseau Tor...", total=None)

                config_path = os.path.join(TOR_DATA_DIR, "torrc")
                os.makedirs(TOR_DATA_DIR, exist_ok=True)
                with open(config_path, "w") as f:
                    f.write(get_tor_config())

                self.tor_process = stem.process.launch_tor_with_config(
                    config={
                        "SocksPort": str(TOR_SOCKS_PORT),
                        "ControlPort": str(TOR_CONTROL_PORT),
                        "DataDirectory": TOR_DATA_DIR,
                        "HashedControlPassword": self._get_hashed_password(),
                    },
                    completion_percent=100,
                    init_msg_handler=lambda line: None,
                    take_ownership=True,
                )
                progress.update(task, description="[green]✓ Tor connecté !")

            self._connect_controller()
            return True

        except OSError as e:
            console.print(f"[red]❌ Erreur démarrage Tor (stem): {e}[/red]")
            return self._start_with_subprocess()

    def _start_with_subprocess(self) -> bool:
        """Démarre Tor via subprocess (fallback)."""
        try:
            config_path = os.path.join(TOR_DATA_DIR, "torrc")
            os.makedirs(TOR_DATA_DIR, exist_ok=True)
            with open(config_path, "w") as f:
                f.write(get_tor_config())

            self.tor_process = subprocess.Popen(
                ["tor", "-f", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Attendre que Tor soit prêt
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console,
            ) as progress:
                task = progress.add_task("Connexion au réseau Tor...", total=None)
                deadline = time.time() + 60
                bootstrapped = False

                while time.time() < deadline:
                    if self.tor_process.poll() is not None:
                        console.print("[red]❌ Tor s'est arrêté prématurément[/red]")
                        return False

                    if is_tor_running():
                        bootstrapped = True
                        break
                    time.sleep(1)

                if bootstrapped:
                    progress.update(task, description="[green]✓ Tor connecté !")
                else:
                    console.print("[red]❌ Timeout: Tor n'a pas démarré dans les 60 secondes[/red]")
                    self.stop()
                    return False

            self._connect_controller()
            return True

        except Exception as e:
            console.print(f"[red]❌ Erreur démarrage Tor: {e}[/red]")
            return False

    def _get_hashed_password(self) -> str:
        """Retourne le hash du mot de passe de contrôle."""
        try:
            result = subprocess.run(
                ["tor", "--hash-password", TOR_CONTROL_PASSWORD],
                capture_output=True, text=True
            )
            for line in result.stdout.strip().split("\n"):
                if line.startswith("16:"):
                    return line.strip()
        except Exception:
            pass
        return ""

    def _connect_controller(self) -> bool:
        """Connecte le contrôleur Tor avec authentification."""
        if not STEM_AVAILABLE:
            return True
        try:
            time.sleep(1)
            self.controller = Controller.from_port(port=TOR_CONTROL_PORT)
            self.controller.authenticate(password=TOR_CONTROL_PASSWORD)
            return True
        except Exception:
            return self._connect_controller_no_auth()

    def _connect_controller_no_auth(self) -> bool:
        """Connecte le contrôleur sans mot de passe (instance existante)."""
        if not STEM_AVAILABLE:
            return True
        try:
            self.controller = Controller.from_port(port=TOR_CONTROL_PORT)
            self.controller.authenticate()
            return True
        except Exception:
            # Pas de port de contrôle disponible, on continue sans
            return True

    def new_circuit(self) -> bool:
        """Force un nouveau circuit Tor (nouvelle identité)."""
        if self.controller:
            try:
                self.controller.signal(stem.Signal.NEWNYM)
                console.print("[cyan]🔄 Nouveau circuit Tor établi[/cyan]")
                time.sleep(3)  # Attendre que le circuit soit établi
                return True
            except Exception as e:
                console.print(f"[yellow]⚠ Impossible de changer le circuit: {e}[/yellow]")
        return False

    def get_exit_ip_via_tor(self) -> Optional[str]:
        """Récupère l'IP de sortie Tor actuelle."""
        import requests
        proxies = {
            "http": f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}",
            "https": f"socks5h://127.0.0.1:{TOR_SOCKS_PORT}",
        }
        try:
            resp = requests.get(
                "https://api.ipify.org",
                proxies=proxies,
                timeout=15
            )
            return resp.text.strip()
        except Exception:
            try:
                resp = requests.get(
                    "http://checkip.amazonaws.com",
                    proxies=proxies,
                    timeout=15
                )
                return resp.text.strip()
            except Exception:
                return None

    def stop(self):
        """Arrête le processus Tor si on l'a démarré nous-mêmes."""
        if self.controller:
            try:
                self.controller.close()
            except Exception:
                pass

        if self.tor_process and not self._using_existing:
            try:
                self.tor_process.terminate()
                self.tor_process.wait(timeout=5)
            except Exception:
                try:
                    self.tor_process.kill()
                except Exception:
                    pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stop()
