"""
Tor connection manager.
Starts, controls and monitors the local Tor process.
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


def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return True if a TCP listener is reachable on host:port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False


def is_tor_running(port: int = TOR_SOCKS_PORT) -> bool:
    """Check whether Tor is already listening on the given SOCKS port."""
    return _port_open("127.0.0.1", port)


def is_tor_installed() -> bool:
    """Check whether the tor binary is available on this system."""
    result = subprocess.run(["which", "tor"], capture_output=True, text=True)
    return result.returncode == 0


def _get_hashed_password() -> str:
    """Run `tor --hash-password` and return the hashed control password."""
    try:
        result = subprocess.run(
            ["tor", "--hash-password", TOR_CONTROL_PASSWORD],
            capture_output=True, text=True,
        )
        for line in result.stdout.strip().split("\n"):
            if line.startswith("16:"):
                return line.strip()
    except Exception:
        pass
    return ""


def _get_tor_config() -> str:
    """Generate a minimal torrc configuration."""
    os.makedirs(TOR_DATA_DIR, exist_ok=True)
    hashed_pw = _get_hashed_password()
    config = (
        f"SocksPort {TOR_SOCKS_PORT}\n"
        f"ControlPort {TOR_CONTROL_PORT}\n"
        f"DataDirectory {TOR_DATA_DIR}\n"
        "Log notice stdout\n"
    )
    if hashed_pw:
        config += f"HashedControlPassword {hashed_pw}\n"
    return config


class TorManager:
    """
    Manages the Tor process.

    Pass external_port to reuse an already-running Tor instance instead of
    starting a new one. The instance will not be stopped on close.
    """

    def __init__(self, external_port: Optional[int] = None):
        self.external_port = external_port
        self._socks_port: int = external_port if external_port else TOR_SOCKS_PORT
        self.tor_process: Optional[subprocess.Popen] = None
        self.controller: Optional["Controller"] = None
        self._using_existing = external_port is not None

    @property
    def socks_port(self) -> int:
        return self._socks_port

    def start(self) -> bool:
        """Start Tor or attach to an existing instance."""
        if self.external_port:
            if not _port_open("127.0.0.1", self.external_port):
                console.print(
                    f"[red]No SOCKS listener found on port {self.external_port}. "
                    "Make sure Tor is running.[/red]"
                )
                return False
            console.print(
                f"[yellow]Using existing Tor at "
                f"socks5://127.0.0.1:{self.external_port}[/yellow]"
            )
            self._connect_controller_no_auth()
            return True

        if is_tor_running():
            console.print(
                "[yellow]Tor already running on port 9050, attaching to existing instance...[/yellow]"
            )
            self._using_existing = True
            self._connect_controller_no_auth()
            return True

        if not is_tor_installed():
            console.print("[red]Tor is not installed.[/red]")
            console.print("[cyan]Install it with: [bold]sudo apt install tor[/bold][/cyan]")
            return False

        return self._start_tor_process()

    def _start_tor_process(self) -> bool:
        if STEM_AVAILABLE:
            return self._start_with_stem()
        return self._start_with_subprocess()

    def _start_with_stem(self) -> bool:
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console,
            ) as progress:
                task = progress.add_task("Connecting to the Tor network...", total=None)
                config_path = os.path.join(TOR_DATA_DIR, "torrc")
                os.makedirs(TOR_DATA_DIR, exist_ok=True)
                with open(config_path, "w") as f:
                    f.write(_get_tor_config())

                self.tor_process = stem.process.launch_tor_with_config(
                    config={
                        "SocksPort": str(TOR_SOCKS_PORT),
                        "ControlPort": str(TOR_CONTROL_PORT),
                        "DataDirectory": TOR_DATA_DIR,
                        "HashedControlPassword": _get_hashed_password(),
                    },
                    completion_percent=100,
                    init_msg_handler=lambda line: None,
                    take_ownership=True,
                )
                progress.update(task, description="[green]Tor connected!")

            self._connect_controller()
            return True

        except OSError as e:
            console.print(f"[red]Tor startup error (stem): {e}[/red]")
            return self._start_with_subprocess()

    def _start_with_subprocess(self) -> bool:
        try:
            config_path = os.path.join(TOR_DATA_DIR, "torrc")
            os.makedirs(TOR_DATA_DIR, exist_ok=True)
            with open(config_path, "w") as f:
                f.write(_get_tor_config())

            self.tor_process = subprocess.Popen(
                ["tor", "-f", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console,
            ) as progress:
                task = progress.add_task("Connecting to the Tor network...", total=None)
                deadline = time.time() + 60
                bootstrapped = False

                while time.time() < deadline:
                    if self.tor_process.poll() is not None:
                        console.print("[red]Tor exited prematurely.[/red]")
                        return False
                    if is_tor_running():
                        bootstrapped = True
                        break
                    time.sleep(1)

                if bootstrapped:
                    progress.update(task, description="[green]Tor connected!")
                else:
                    console.print("[red]Timeout: Tor did not start within 60 seconds.[/red]")
                    self.stop()
                    return False

            self._connect_controller()
            return True

        except Exception as e:
            console.print(f"[red]Tor startup error: {e}[/red]")
            return False

    def _connect_controller(self) -> bool:
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
        """Attach to control port without password (existing instance)."""
        if not STEM_AVAILABLE:
            return True
        try:
            self.controller = Controller.from_port(port=TOR_CONTROL_PORT)
            self.controller.authenticate()
            return True
        except Exception:
            # No control port available — continue without it
            return True

    def new_circuit(self) -> bool:
        """Request a new Tor circuit (new identity)."""
        if self.controller:
            try:
                self.controller.signal(stem.Signal.NEWNYM)
                console.print("[cyan]New Tor circuit established.[/cyan]")
                time.sleep(3)
                return True
            except Exception as e:
                console.print(f"[yellow]Could not rotate circuit: {e}[/yellow]")
        return False

    def stop(self):
        """Stop Tor if we started it ourselves."""
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

