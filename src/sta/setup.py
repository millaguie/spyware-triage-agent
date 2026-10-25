"""./start: set the agent up once, then run a phone check with it.

First run: install the phone tools, ask which model guides the check, and
test that the model can call the sta tools. Every run: open or continue a
case in the operator's terminal (consent is the operator's, never the
model's), start the agent with only the sta tools, and after it ends run
the steps that belong to the terminal (the owner's answers in guided mode,
cleanup) and print the result.

Standard library only: in the container mode this runs with the computer's
own python3, which has none of the project's packages. Settings and keys
stay in .sta/, inside the repo. pi keeps no conversation; Claude Code keeps
it in ~/.claude, and the operator is told so."""

import argparse
import datetime as dt
import getpass
import ipaddress
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import NoReturn

from sta.mcp_server import command, job_running, read_job

ROOT = Path(__file__).resolve().parents[2]
STA = ROOT / ".sta"
CONFIG = STA / "config.json"
SECRETS_ENV = STA / "secrets.env"
RUNTIME_FILE = STA / "runtime"
GUIDE = ROOT / "agent" / "GUIDE.md"
SHELL_PROMPT = ROOT / "agent" / "OPERATOR.md"
SERVER = ROOT / "src" / "sta" / "mcp_server.py"
GREETING = "Hello. I want to check a phone."
EXPLAIN = "The check is done. Explain the report to me."
# A case that does not exist: in the model test, next_step answers "no check is open".
TEST_CASE = "sta-model-test"
# A step answer waits up to WAIT_SECONDS; the runner gives a tool call a
# minute more before it gives up (pi's default is 60 s in all).
WAIT_SECONDS = 600
TOOL_TIMEOUT = WAIT_SECONDS + 60
TEST_TIMEOUT = 900  # a first answer on a CPU loads the model too
OLLAMA_PORT = 11435  # not Ollama's default, so an Ollama the operator runs is left alone
# The container image, when this computer has no ollama. Pinned by digest:
# a tag can be moved to another image.
OLLAMA_IMAGES = {
    "default": "ollama/ollama:0.40.7@sha256:2e6cc92ffa43b4b1a2e70e315407e00ac97ec125afc71277d73c7efe01c4f31b",
    "amd": "ollama/ollama:0.40.7-rocm@sha256:65e50ca00b1d05892cc50df3a9ce54e0e718a8915bed029d9a674f390cd26e3d",
}
OLLAMA_PID = STA / "ollama.pid"


def say(text: str = "") -> None:
    print(text, flush=True)


def ask(question: str, default: str = "", secret: bool = False) -> str:
    hint = f" [{default}]" if default else ""
    while True:
        answer = (getpass.getpass(f"{question}: ") if secret else input(f"{question}{hint}: ")).strip()
        if answer or default:
            return answer or default


def yes_no(question: str, default: bool | None = None) -> bool:
    hint = {True: "Y/n", False: "y/N", None: "yes/no"}[default]
    while True:
        answer = input(f"{question} [{hint}]: ").strip().lower()
        if not answer and default is not None:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def choose(question: str, options: list[tuple[str, str]], default: int = 1) -> str:
    say(f"\n{question}")
    for n, (_, label) in enumerate(options, 1):
        say(f"  {n}. {label}")
    while True:
        answer = input(f"Number [{default}]: ").strip() or str(default)
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1][0]


def stop(text: str, code: int = 1) -> NoReturn:
    say(f"\n{text}")
    sys.exit(code)


# ---------------------------------------------------------------- ./sta

def sta(*args: str, case: str | None = None, interactive: bool = False) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != "STA_CASE"}
    env["PYTHONUTF8"] = "1"
    if case:
        env["STA_CASE"] = case
    if interactive:
        return subprocess.run([*command(), *args], cwd=ROOT, env=env)
    return subprocess.run([*command(), *args], cwd=ROOT, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", stdin=subprocess.DEVNULL)


def next_info(case: str | None = None) -> dict:
    proc = sta("next", "--json", case=case)
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        stop(f"./sta next did not answer:\n{(proc.stderr or proc.stdout).strip()[-1500:]}")


# ---------------------------------------------------------------- tools

def install() -> None:
    if os.name == "nt":
        cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "install.ps1")]
    else:
        cmd = [str(ROOT / "install.sh")]
        if sys.platform.startswith("linux") and shutil.which("docker"):
            how = choose("How should the phone tools run?", [
                ("docker", "In a container (recommended): this computer needs only Docker"),
                ("local", "Installed on this computer: uses sudo and the package manager")])
            if how == "docker":
                cmd.append("--docker")
    say("\nInstalling the phone tools. This takes several minutes the first time.")
    if subprocess.run(cmd, cwd=ROOT).returncode != 0:
        stop("The installation failed: see the lines above. Fix the problem, then run ./start again.")


def ensure_tools() -> None:
    if not RUNTIME_FILE.exists():
        install()
    proc = sta("doctor")
    if proc.returncode != 0:
        say((proc.stdout + proc.stderr).strip())
        if not yes_no("\nSome tools are missing. Run the installer again?", True):
            stop("Run ./start again when the tools are installed.")
        install()
        proc = sta("doctor")
        if proc.returncode != 0:
            stop((proc.stdout + proc.stderr).strip())
    if not sys.platform.startswith("linux"):
        return
    if RUNTIME_FILE.read_text(encoding="utf-8").strip() == "docker":
        host_daemons()
    elif sta_container():
        # Its own usbmuxd and adb hold the phone: this computer's cannot reach it.
        say("\nThe sta container from the container mode is running, and it holds the phone's USB connection.")
        if not yes_no("Stop it?", True):
            stop("Stop it with: docker compose down, then run ./start again.")
        subprocess.run(["docker", "compose", "-f", str(ROOT / "compose.yaml"), "down"], capture_output=True,
                       env={**os.environ, "STA_DIR": str(ROOT)})
        say("Stopped. Unplug the phone and plug it in again.")
        input("Press Enter when it is plugged in again: ")


def sta_container() -> bool:
    if not shutil.which("docker"):
        return False
    return bool(subprocess.run(["docker", "compose", "-f", str(ROOT / "compose.yaml"), "ps", "-q", "--status",
                                "running", "sta"], capture_output=True, text=True,
                               env={**os.environ, "STA_DIR": str(ROOT)}).stdout.strip())


def host_daemons() -> None:
    """In the container mode, a usbmuxd or adb server on the computer holds
    the USB device, and the container cannot reach the phone."""
    fixes = {"usbmuxd": "sudo systemctl stop usbmuxd", "adb": "adb kill-server"}
    running = [name for name in fixes if subprocess.run(["pgrep", "-x", name], capture_output=True).returncode == 0]
    if not running or sta_container():
        return
    say("\nThese programs run on this computer and hold the phone's USB connection:")
    for name in running:
        say(f"  {name}: stop it with  {fixes[name]}")
    input("Stop them in another terminal, then press Enter: ")


# ---------------------------------------------------------------- hardware

def total_ram_gb() -> float:
    if sys.platform.startswith("linux"):
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) / 1024 ** 2
    if sys.platform == "darwin":
        out = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True).stdout
        return int(out.strip() or 0) / 1024 ** 3
    if os.name == "nt":
        import ctypes

        class Status(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        status = Status()
        status.dwLength = ctypes.sizeof(Status)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))  # pyright: ignore[reportAttributeAccessIssue]
        return status.ullTotalPhys / 1024 ** 3
    return 0.0


def nvidia_memory_gb() -> float:
    if not shutil.which("nvidia-smi"):
        return 0.0
    out = subprocess.run(["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                         capture_output=True, text=True).stdout
    sizes = [int(x) for x in re.findall(r"\d+", out)]
    return max(sizes, default=0) / 1024


def amd_memory(drm: Path = Path("/sys/class/drm")) -> tuple[float, float]:
    """(video memory, memory the GPU can borrow from RAM) of the largest AMD GPU, in GB."""
    best = (0.0, 0.0)
    for device in drm.glob("card[0-9]*/device"):
        try:
            if (device / "vendor").read_text().strip() != "0x1002":
                continue
            vram = int((device / "mem_info_vram_total").read_text()) / 1024 ** 3
            gtt = int((device / "mem_info_gtt_total").read_text()) / 1024 ** 3
        except (OSError, ValueError):
            continue
        best = max(best, (vram, gtt))
    return best


def hardware() -> dict:
    """What the local model can use. An integrated GPU (AMD APU, Apple)
    shares the RAM; Ollama uses an integrated AMD GPU only when told to."""
    hw = {"ram_gb": round(total_ram_gb(), 1), "gpu": "none", "memory_gb": 0.0, "integrated": False}
    nvidia = nvidia_memory_gb()
    if nvidia:
        hw.update(gpu="nvidia", memory_gb=nvidia)
    elif sys.platform == "darwin" and platform.machine() == "arm64":
        hw.update(gpu="apple", integrated=True, memory_gb=hw["ram_gb"] * 0.7)
    elif sys.platform.startswith("linux"):
        vram, gtt = amd_memory()
        if vram >= 4:
            hw.update(gpu="amd", memory_gb=vram)
        elif gtt:
            hw.update(gpu="amd", integrated=True, memory_gb=gtt)
    if hw["gpu"] == "none":
        hw["memory_gb"] = hw["ram_gb"] * 0.5
    hw["memory_gb"] = round(hw["memory_gb"], 1)
    return hw


def load_models() -> dict:
    return json.loads((ROOT / "kb" / "models.json").read_text(encoding="utf-8"))


def fitting(models: list[dict], memory_gb: float) -> list[dict]:
    return [m for m in models if m["memory_gb"] <= memory_gb]


# ---------------------------------------------------------------- ollama

def http_json(url: str, data: dict | None = None, key: str = "", timeout: float = 10):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def ollama_url() -> str:
    return f"http://127.0.0.1:{OLLAMA_PORT}"


def ollama_up() -> bool:
    try:
        http_json(f"{ollama_url()}/api/version", timeout=2)
        return True
    except (OSError, ValueError):
        return False


def ollama_env(cfg: dict) -> dict:
    env = {"OLLAMA_HOST": f"127.0.0.1:{OLLAMA_PORT}", "OLLAMA_NO_CLOUD": "1",
           "OLLAMA_CONTEXT_LENGTH": str(cfg["ollama"]["context"])}
    if cfg["ollama"].get("integrated") and cfg["ollama"].get("gpu") == "amd":
        env["OLLAMA_IGPU_ENABLE"] = "1"
    return env


def ollama_compose(cfg: dict) -> Path:
    """The container Ollama, when this computer has no ollama program.
    JSON is valid YAML, and compose reads it."""
    gpu = cfg["ollama"]["gpu"]
    service: dict = {
        "image": OLLAMA_IMAGES.get(gpu, OLLAMA_IMAGES["default"]),
        "ports": [f"127.0.0.1:{OLLAMA_PORT}:{OLLAMA_PORT}"],
        "environment": {**ollama_env(cfg), "OLLAMA_HOST": f"0.0.0.0:{OLLAMA_PORT}", "OLLAMA_MODELS": "/models"},
        "volumes": [f"{STA / 'ollama'}:/models"],
    }
    if gpu == "nvidia":
        service["deploy"] = {"resources": {"reservations": {"devices": [
            {"driver": "nvidia", "count": "all", "capabilities": ["gpu"]}]}}}
    elif gpu == "amd":
        service["devices"] = ["/dev/kfd", "/dev/dri"]
        service["group_add"] = ["video", "render"]
    path = STA / "compose.ollama.json"
    path.write_text(json.dumps({"name": "sta-ollama", "services": {"ollama": service}}, indent=2), encoding="utf-8")
    return path


def our_ollama(cfg: dict):
    """The Ollama a previous ./start left running (it was killed before it
    could stop it), as a stop_ollama handle. None when it is not ours."""
    if cfg["ollama"]["how"] != "binary":
        compose = ollama_compose(cfg)
        running = subprocess.run(["docker", "compose", "-f", str(compose), "ps", "-q", "--status", "running"],
                                 capture_output=True, text=True).stdout.strip()
        return compose if running else None
    try:
        pid = int(OLLAMA_PID.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    # The pid file can be old: after a restart the number may belong to another program.
    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                             capture_output=True, text=True).stdout
        return pid if out.lower().startswith('"ollama.exe"') else None
    args = subprocess.run(["ps", "-p", str(pid), "-o", "args="], capture_output=True, text=True).stdout
    return pid if re.match(r"\S*ollama serve\s*$", args.strip()) else None


def start_ollama(cfg: dict):
    """Start the repo's own Ollama, models in .sta/ollama. Returns what
    stop_ollama needs. Another program on our port would get the case data,
    so ./start stops instead of using it."""
    if ollama_up():
        handle = our_ollama(cfg)
        if handle is None:
            stop(f"Another program answers on port {OLLAMA_PORT}. Stop it, then run ./start again.")
        return handle
    (STA / "ollama").mkdir(parents=True, exist_ok=True)
    if cfg["ollama"]["how"] == "binary":
        log = open(STA / "ollama.log", "a", encoding="utf-8")
        env = {**os.environ, **ollama_env(cfg), "OLLAMA_MODELS": str(STA / "ollama")}
        if os.name == "nt":
            proc = subprocess.Popen(["ollama", "serve"], env=env, stdout=log, stderr=log,
                                    stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        else:
            proc = subprocess.Popen(["ollama", "serve"], env=env, stdout=log, stderr=log,
                                    stdin=subprocess.DEVNULL, start_new_session=True)
        OLLAMA_PID.write_text(str(proc.pid), encoding="utf-8")
        handle = proc.pid
    else:
        compose = ollama_compose(cfg)
        proc = subprocess.run(["docker", "compose", "-f", str(compose), "up", "-d"], capture_output=True, text=True)
        if proc.returncode != 0:
            stop(f"The Ollama container did not start:\n{proc.stderr.strip()[-1500:]}")
        handle = compose
    try:
        for _ in range(60):
            if ollama_up():
                return handle
            time.sleep(1)
    except KeyboardInterrupt:
        stop_ollama(handle)
        raise
    stop_ollama(handle)
    stop(f"Ollama did not start. See {STA / 'ollama.log'}.")


def stop_ollama(handle) -> None:
    """handle: the compose file, or the pid of `ollama serve` (the leader of
    its own process group, which holds the model runners too)."""
    if handle is None:
        return
    if isinstance(handle, Path):
        subprocess.run(["docker", "compose", "-f", str(handle), "down"], capture_output=True)
        return
    OLLAMA_PID.unlink(missing_ok=True)
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(handle), "/T", "/F"], capture_output=True)
        return
    try:
        os.killpg(handle, signal.SIGTERM)
        for _ in range(20):
            time.sleep(0.5)
            os.killpg(handle, 0)
        os.killpg(handle, signal.SIGKILL)
    except ProcessLookupError:
        pass


def pull(tag: str) -> None:
    have = [m["name"] for m in http_json(f"{ollama_url()}/api/tags").get("models", [])]
    if tag in have or f"{tag}:latest" in have:
        return
    say(f"\nDownloading {tag}. This can take a while.")
    req = urllib.request.Request(f"{ollama_url()}/api/pull", data=json.dumps({"model": tag}).encode(),
                                 headers={"Content-Type": "application/json"})
    last = ""
    with urllib.request.urlopen(req, timeout=3600) as resp:
        for raw in resp:
            msg = json.loads(raw)
            if msg.get("error"):
                stop(f"Ollama could not download {tag}: {msg['error']}")
            text = msg.get("status", "")
            if msg.get("total"):
                text += f" {100 * msg.get('completed', 0) // msg['total']}%"
            if text != last:
                print(f"\r  {text:60}", end="", flush=True)
                last = text
    say()


# ---------------------------------------------------------------- setup questions

def read_secrets() -> dict:
    out = {}
    if SECRETS_ENV.exists():
        for line in SECRETS_ENV.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                out[key.strip()] = value.strip()
    return out


def save_secret(name: str, value: str) -> None:
    secrets = {**read_secrets(), name: value}
    STA.mkdir(exist_ok=True)
    fd = os.open(SECRETS_ENV, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("# API keys for ./start. Keep this file private.\n")
        handle.writelines(f"{k}={v}\n" for k, v in secrets.items())


def setup_ollama() -> dict | None:
    hw = hardware()
    gpu = {"nvidia": "NVIDIA GPU", "amd": "AMD GPU", "apple": "Apple chip", "none": "no GPU found"}[hw["gpu"]]
    say(f"\nThis computer: {hw['ram_gb']} GB RAM, {gpu}{' (shares the RAM)' if hw['integrated'] else ''}.")
    say(f"The model can use about {hw['memory_gb']} GB.")
    table = load_models()
    fits = fitting(table["models"], hw["memory_gb"])
    if not fits:
        say(f"The smallest model needs {table['models'][-1]['memory_gb']} GB. Choose another option.")
        return None
    if hw["gpu"] == "none":
        say("Without a GPU the model runs on the processor: each answer can take a minute or more.")
    options = [(m["tag"], f"{m['tag']}: {m['download_gb']} GB download"
                + (" (recommended)" if n == 0 else "") + ("" if m.get("bench") else ", not tested with sta yet"))
               for n, m in enumerate(fits[:3])]
    tag = choose("Which model?", options)
    if shutil.which("ollama"):
        how = "binary"
    elif sys.platform.startswith("linux") and shutil.which("docker"):
        how = "docker"
        if hw["gpu"] == "nvidia" and "nvidia" not in subprocess.run(
                ["docker", "info", "--format", "{{json .Runtimes}}"], capture_output=True, text=True).stdout:
            say("Docker cannot use the NVIDIA GPU yet. Install the NVIDIA Container Toolkit:")
            say("  https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html")
            stop("Then run ./start --setup again.")
    else:
        stop("Ollama is not installed. Install it from https://ollama.com/download, then run ./start --setup.")
    return {"choice": "ollama", "runner": "pi", "provider": "sta", "model": tag, "where": "local",
            "base_url": f"{ollama_url()}/v1",
            "ollama": {"how": how, "gpu": hw["gpu"], "integrated": hw["integrated"], "context": table["context"]}}


def in_own_network(url: str) -> bool:
    """Whether every address of the server is a local one: this computer,
    a private network, or a VPN such as Tailscale (100.64.0.0/10)."""
    host = urllib.parse.urlsplit(url).hostname or ""
    try:
        addresses = {str(info[4][0]) for info in socket.getaddrinfo(host, None)}
    except (OSError, UnicodeError):
        return False
    return bool(addresses) and all(not ipaddress.ip_address(a.split("%")[0]).is_global for a in addresses)


def setup_lan() -> dict:
    say("\nThe server must speak the OpenAI chat API, for example vLLM, llama.cpp, LM Studio, LiteLLM or Ollama.")
    base = ask("Its address, ending in /v1 (for example http://192.168.1.20:8000/v1)").rstrip("/")
    where = "local"
    if not in_own_network(base):
        host = urllib.parse.urlsplit(base).hostname or base
        say(f"{host} is not in your own network (or its name does not resolve): the case data would leave it.")
        where = "cloud"
    key = ""
    if yes_no("Does it need an API key?", False):
        key = ask("API key (not shown)", secret=True)
        save_secret("STA_API_KEY", key)
        if base.startswith("http://"):
            say("Warning: with http:// the key and the case data cross the network unencrypted.")
    try:
        models = sorted(m["id"] for m in http_json(f"{base}/models", key=key).get("data", []))
    except (OSError, ValueError) as exc:
        say(f"Could not list its models ({exc}).")
        models = []
    if models:
        model = choose("Which model?", [(m, m) for m in models[:20]])
    else:
        model = ask("Model name")
    return {"choice": "lan", "runner": "pi", "provider": "sta", "model": model, "where": where,
            "base_url": base, "key": bool(key), "label": urllib.parse.urlsplit(base).hostname or base}


def setup_cloud() -> dict:
    providers = json.loads((ROOT / "kb" / "providers.json").read_text(encoding="utf-8"))["providers"]
    name = choose("Which provider?", [(p["name"], p["label"]) for p in providers])
    entry = next(p for p in providers if p["name"] == name)
    say(f"Get an API key at {entry['keys']}")
    save_secret(entry["key_env"], ask("API key (not shown)", secret=True))
    model = ask("Model", entry["suggest"])
    return {"choice": "cloud", "runner": "pi", "provider": name, "model": model, "where": "cloud",
            "label": entry["label"], "key_env": entry["key_env"]}


def setup_own() -> dict | None:
    runners = [(r, label) for r, label in (("pi", "pi, with your own providers"),
                                           ("claude", "Claude Code, with your own account")) if shutil.which(r)]
    if not runners:
        say("Neither pi nor Claude Code is installed. Choose another option.")
        return None
    runner = choose("Which agent?", runners)
    if runner == "claude":
        model = ask("Model (Enter for your account's default)", "default")
        return {"choice": "own", "runner": "claude", "provider": "anthropic", "model": model, "where": "cloud",
                "label": "Anthropic (Claude Code)"}
    provider = ask("pi provider name, as in your pi settings")
    model = ask("Model name")
    local = yes_no("Does this model run on this computer or on your own network?")
    return {"choice": "own", "runner": "pi", "provider": provider, "model": model,
            "where": "local" if local else "cloud", "label": f"{provider} (your pi settings)"}


def wizard() -> dict:
    say("\nSetup. The answers are saved in .sta/config.json; ./start --setup asks again.")
    cfg = None
    while cfg is None:
        choice = choose("Which model guides the check?", [
            ("ollama", "A model on this computer, with Ollama. The phone data stays here."),
            ("lan", "A server on your own network with an OpenAI-style API. The data stays in your network."),
            ("cloud", "A cloud provider: OpenRouter, OpenAI, Anthropic or Mistral. The case data leaves "
                      "this computer."),
            ("own", "An agent you already use, with your own settings: pi or Claude Code.")])
        cfg = {"ollama": setup_ollama, "lan": setup_lan, "cloud": setup_cloud, "own": setup_own}[choice]()
    cfg["review"] = choose("Who records the owner's answers to the questions?", [
        ("guided", "The operator types them in this terminal, after the agent ends. No model sees or "
                   "changes them (recommended)."),
        ("agent", "The agent asks the owner and records the answers.")])
    if cfg["where"] == "cloud":
        what = "the app names, the findings and the report" + (
            ", and the owner's answers" if cfg["review"] == "agent" else "")
        say(f"\nThe case data goes to {cfg['label']}: {what}.")
        if cfg["runner"] == "claude":
            say("Claude Code also keeps the conversation in ~/.claude on this computer: ./sta purge does "
                "not delete it.")
        say("Use a cloud model only if the phone owner agrees to that too.")
        if input("Type yes to accept: ").strip().lower() != "yes":
            stop("Nothing was saved. Run ./start again to choose a local model.")
    return cfg


def save_config(cfg: dict) -> None:
    STA.mkdir(exist_ok=True)
    CONFIG.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")


def load_config() -> dict | None:
    try:
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return None


# ---------------------------------------------------------------- runners

def own_pi_dir(cfg: dict) -> bool:
    """pi with the repo's own settings (.sta/pi), not the operator's."""
    return cfg["runner"] == "pi" and cfg["choice"] != "own"


def server_entry(cfg: dict, case: str, extra_env: dict) -> dict:
    env = {"STA_CASE": case, "STA_WAIT_SECONDS": str(WAIT_SECONDS), "STA_REVIEW": cfg["review"],
           "PYTHONUTF8": "1", **extra_env}
    return {"command": sys.executable, "args": [str(SERVER)], "env": env}


def write_runner_files(cfg: dict, case: str, extra_env: dict) -> None:
    """Written before each run: the server gets the case in its env, so
    `./sta use` in another terminal cannot switch the case under the agent."""
    entry = server_entry(cfg, case, extra_env)
    if own_pi_dir(cfg):
        pi_dir = STA / "pi"
        pi_dir.mkdir(parents=True, exist_ok=True)
        (pi_dir / "mcp.json").write_text(json.dumps({"mcpServers": {"sta": {
            **entry, "exposure": "direct", "timeout": TOOL_TIMEOUT}}}, indent=2), encoding="utf-8")
        if cfg["choice"] in ("ollama", "lan"):
            ctx = cfg.get("ollama", {}).get("context", 32768)
            (pi_dir / "models.json").write_text(json.dumps({"providers": {"sta": {
                "baseUrl": cfg["base_url"], "api": "openai-completions",
                "apiKey": "$STA_API_KEY" if cfg.get("key") else "none",
                "models": [{"id": cfg["model"], "name": cfg["model"], "reasoning": False, "input": ["text"],
                            "contextWindow": ctx, "maxTokens": 4096,
                            "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0}}]}}},
                indent=2), encoding="utf-8")
    if cfg["runner"] == "claude":
        (STA / "mcp.json").write_text(json.dumps({"mcpServers": {"sta": entry}}, indent=2), encoding="utf-8")


def node_trusts_system_ca() -> dict:
    """pi runs on Node, which ignores the system's certificate store: a LAN
    server with the owner's own certificate authority fails with a bare
    "Connection error". Node 24 and newer can use the store."""
    try:
        out = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {}
    match = re.match(r"v(\d+)", out.strip())
    if not match or int(match.group(1)) < 24 or "--use-system-ca" in os.environ.get("NODE_OPTIONS", ""):
        return {}
    return {"NODE_OPTIONS": f"{os.environ.get('NODE_OPTIONS', '')} --use-system-ca".strip()}


def runner_secrets(cfg: dict) -> dict:
    """Only the key this setup uses: the runner and its children see no other."""
    secrets = read_secrets()
    if cfg["choice"] == "lan":
        names = {"STA_API_KEY"}
    elif cfg["choice"] == "cloud":
        names = {cfg.get("key_env") or next(
            (p["key_env"] for p in json.loads((ROOT / "kb" / "providers.json").read_text(encoding="utf-8"))
             ["providers"] if p["name"] == cfg["provider"]), "")}
    else:
        names = set()
    return {k: v for k, v in secrets.items() if k in names}


def runner_command(cfg: dict, case: str, message: str, *, test: bool = False,
                   shell: bool = False, extra_env: dict | None = None) -> tuple[list[str], dict]:
    extra_env = extra_env or {}
    write_runner_files(cfg, case, extra_env)
    env = {**os.environ, **runner_secrets(cfg), **extra_env, "STA_CASE": case, "STA_WAIT_SECONDS": str(WAIT_SECONDS),
           "STA_REVIEW": cfg["review"], "PYTHONUTF8": "1"}
    if cfg["runner"] == "claude":
        env["MCP_TOOL_TIMEOUT"] = str(TOOL_TIMEOUT * 1000)
        cmd = ["claude", "--mcp-config", str(STA / "mcp.json"), "--strict-mcp-config", "--tools", "",
               "--allowedTools", "mcp__sta__*", "--append-system-prompt", GUIDE.read_text(encoding="utf-8")]
        if cfg["model"] != "default":
            cmd += ["--model", cfg["model"]]
        return cmd + (["-p"] if test else []) + [message], env
    env.update(node_trusts_system_ca())
    # --no-session: pi would keep the conversation about the phone, and
    # ./sta purge would not delete it.
    cmd = ["pi", "--provider", cfg["provider"], "--model", cfg["model"], "--no-session",
           "--no-extensions", "--no-skills", "--no-context-files", "--no-prompt-templates"]
    if own_pi_dir(cfg):
        env.update(PI_CODING_AGENT_DIR=str(STA / "pi"), PI_OFFLINE="1")
        cmd.append("--no-approve")
    else:
        cmd.append("--approve")  # trust the repo's .pi/mcp.json for this run only
    if shell:
        # The old mode: a shell, with the rule "only ./sta". Not a security boundary.
        cmd += ["--no-mcp", "--tools", "read,bash", "--system-prompt", SHELL_PROMPT.read_text(encoding="utf-8")]
    else:
        cmd += ["-e", "builtin:mcp", "--tools", "mcp__sta__*", "--system-prompt", GUIDE.read_text(encoding="utf-8")]
    if test:
        cmd.append("-p")
    return cmd + [message], env


def test_model(cfg: dict) -> bool:
    """One real turn: the runner, the model and the sta server. Passes when
    the model called next_step through the server."""
    say(f"\nTesting {cfg['model']} with the sta tools. The first answer can take a few minutes.")
    trace = STA / "model-test.trace"
    trace.unlink(missing_ok=True)
    cmd, env = runner_command(cfg, TEST_CASE, "Call the tool next_step once, then tell me in one sentence "
                              "what it says.", test=True, extra_env={"STA_MCP_TRACE": str(trace)})
    started = time.time()
    try:
        proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", stdin=subprocess.DEVNULL, timeout=TEST_TIMEOUT)
        output = (proc.stdout + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        output = f"No answer in {TEST_TIMEOUT // 60} minutes."
    seconds = round(time.time() - started)
    called = trace.exists() and "next_step" in trace.read_text(encoding="utf-8")
    cfg["tested"] = {"at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), "ok": called,
                     "seconds": seconds}
    if called:
        say(f"Test passed in {seconds} s: the model called the sta tool.")
        return True
    say(f"Test failed: the model did not call the sta tool. Its output:\n{output[-1500:]}")
    if "Connection error" in output:
        say("pi could not reach the server. With your own certificate authority, set NODE_EXTRA_CA_CERTS "
            "to a file that holds it, or use Node 24 or newer.")
    return False


# ---------------------------------------------------------------- the check

def choose_case() -> str:
    info = next_info()
    if info.get("case") and info.get("step"):
        # An old case is more likely another phone's: then Enter alone must not continue it.
        try:
            recent = (dt.date.today() - dt.date.fromisoformat(info["case"][:10])).days <= 1
        except ValueError:
            recent = False
        if yes_no(f"\nAn open check: {info['case']}, next step {info['step']}. Continue it?", recent):
            return info["case"]
    say("\nA new check. The next questions record the owner's consent.")
    alias = ask("A short name for this check, not the owner's real name")
    if sta("new-case", "--alias", alias, interactive=True).returncode != 0:
        stop("No case was opened.")
    case = next_info().get("case")
    if not case:
        stop("No case was opened.")
    return case


def offer_interview(case: str) -> None:
    info = next_info(case)
    if info.get("interview") or "triage" in info.get("done", []):
        return
    if yes_no("\nBefore the check, you can ask the owner a few optional questions (about two minutes). "
              "Ask them now?", False):
        sta("interview", case=case, interactive=True)


def run_agent(cmd: list[str], env: dict) -> None:
    """The agent owns the terminal until it ends. Ctrl+C belongs to it, not to us."""
    old = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        subprocess.run(cmd, cwd=ROOT, env=env)
    finally:
        signal.signal(signal.SIGINT, old)


def background_step(case: str) -> str | None:
    job = read_job(case)
    return job["step"] if job and job_running(job) else None


def finish(cfg: dict, case: str, shell: bool = False) -> None:
    """The steps that belong to the terminal, after the agent ends. When the
    check ends here, the agent comes back to explain the report: it has not
    seen the owner's answers or the result yet."""
    running = background_step(case)
    if running:
        stop(f"The step {running} still runs in the background. Run ./start again to follow it.", 0)
    info = next_info(case)
    ended_here = bool(info.get("step"))
    if info.get("step") == "review" and cfg["review"] == "guided":
        say("\nThe owner's questions. Type the owner's answers in their own words.")
        if sta("review", "--interactive", case=case, interactive=True).returncode != 0:
            stop("The review stopped. Run ./start again to finish it.")
        info = next_info(case)
    if info.get("step") == "cleanup":
        say(f"\nLast step: cleanup. {info['tell']}")
        if info.get("platform") == "ios":
            input("Press Enter when the iPhone is connected and unlocked: ")
        if sta("cleanup", case=case, interactive=True).returncode != 0:
            stop("Cleanup did not finish. Run ./start again to try it again.")
        info = next_info(case)
    if info.get("step"):
        stop(f"The check stopped before the step {info['step']}. Run ./start again to continue it.", 0)
    say(f"\nThe check is done. Result: {info.get('result')}")
    say(f"Report: {info.get('report')}")
    if ended_here and not shell and yes_no("Open the agent again, to explain the report?", True):
        say("Close it when you have no more questions (type /quit, or press Ctrl+D).")
        run_agent(*runner_command(cfg, case, EXPLAIN))
    say("The case folder holds personal data. When the case is closed, delete it with: ./sta purge --yes")
    if cfg["runner"] == "claude":
        say("Claude Code keeps its own copy of the conversation in ~/.claude: delete it there too.")


def stop_on_signal(signum, frame) -> NoReturn:
    raise KeyboardInterrupt


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="start", description="Set up the agent, then run a phone check with it.")
    parser.add_argument("--setup", action="store_true", help="ask the setup questions again")
    parser.add_argument("--test", action="store_true", help="only test the configured model with the sta tools")
    parser.add_argument("--explain", action="store_true",
                        help="open the agent only to explain the report of the last check")
    parser.add_argument("--shell", action="store_true",
                        help="old mode for pi: the agent gets a shell instead of the sta tools (not a security "
                             "boundary)")
    args = parser.parse_args(argv)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        stop("./start asks questions: run it in a terminal.", 2)
    STA.mkdir(exist_ok=True)
    # A closed terminal or a kill: still stop the Ollama we started.
    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), stop_on_signal)
    ensure_tools()
    cfg = None if args.setup else load_config()
    fresh = cfg is None
    if cfg is None:
        cfg = wizard()
    ollama = None
    try:
        if cfg["choice"] == "ollama":
            ollama = start_ollama(cfg)
            pull(cfg["model"])
        if fresh or args.test:
            ok = test_model(cfg)
            if not ok and not yes_no("Keep this setup anyway?", False):
                stop("Nothing was saved. Run ./start again.")
            save_config(cfg)
            if args.test:
                return
        if args.explain:
            info = next_info()
            if not info.get("case") or info.get("step"):
                stop("No finished check to explain. Run ./start to finish it first.", 2)
            run_agent(*runner_command(cfg, info["case"], EXPLAIN))
            return
        if args.shell and cfg["runner"] != "pi":
            stop("--shell works only with pi.", 2)
        case = choose_case()
        offer_interview(case)
        sta("agent-used", "--runner", cfg["runner"], "--model", cfg["model"], "--where", cfg["where"], case=case)
        say(f"\nStarting the agent ({cfg['runner']}, {cfg['model']}). It guides the check step by step.")
        if cfg["review"] == "guided":
            say("When it says so, close it (type /quit, or press Ctrl+D): the owner's questions come here.")
        cmd, env = runner_command(cfg, case, GREETING, shell=args.shell)
        run_agent(cmd, env)
        finish(cfg, case, args.shell)
    except (KeyboardInterrupt, EOFError):
        stop("Stopped.", 1)
    finally:
        stop_ollama(ollama)


if __name__ == "__main__":
    main()
