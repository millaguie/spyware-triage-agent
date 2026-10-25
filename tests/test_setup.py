"""./start: model choice, hardware reading, and the runner command lines.
The runners themselves are not started here."""

import json
import os
import re
import sys

import pytest

from sta import setup


@pytest.fixture
def sta_dir(tmp_path, monkeypatch):
    """Point ./start's .sta/ at tmp_path."""
    folder = tmp_path / ".sta"
    folder.mkdir()
    for name, value in (("STA", folder), ("CONFIG", folder / "config.json"),
                        ("SECRETS_ENV", folder / "secrets.env"), ("OLLAMA_PID", folder / "ollama.pid")):
        monkeypatch.setattr(setup, name, value)
    return folder


def config(choice, **extra):
    base = {"ollama": {"choice": "ollama", "runner": "pi", "provider": "sta", "model": "qwen3.5:9b",
                       "where": "local", "base_url": "http://127.0.0.1:11435/v1",
                       "ollama": {"how": "binary", "gpu": "amd", "integrated": True, "context": 16384}},
            "lan": {"choice": "lan", "runner": "pi", "provider": "sta", "model": "m", "where": "local",
                    "base_url": "https://llm.example/v1", "key": True},
            "cloud": {"choice": "cloud", "runner": "pi", "provider": "openrouter", "model": "x/y",
                      "where": "cloud", "label": "OpenRouter"},
            "own-pi": {"choice": "own", "runner": "pi", "provider": "mine", "model": "m", "where": "local"},
            "claude": {"choice": "own", "runner": "claude", "provider": "anthropic", "model": "default",
                       "where": "cloud"}}[choice]
    return {**base, "review": "guided", **extra}


def test_model_table_is_ordered_and_fits():
    table = setup.load_models()
    memory = [m["memory_gb"] for m in table["models"]]
    assert memory == sorted(memory, reverse=True), "best first: ./start offers the first that fits"
    assert all(re.fullmatch(r"[a-z0-9.\-]+:[a-z0-9.\-]+", m["tag"]) for m in table["models"])
    assert [m["tag"] for m in setup.fitting(table["models"], 9)] == ["qwen3:8b", "qwen3.5:4b", "granite4:micro"]
    assert setup.fitting(table["models"], 1) == []


def test_providers_name_their_key():
    providers = json.loads((setup.ROOT / "kb" / "providers.json").read_text())["providers"]
    assert all(p["key_env"].endswith("_API_KEY") and p["suggest"] for p in providers)


def test_amd_integrated_gpu_is_read_from_sysfs(tmp_path):
    device = tmp_path / "card1" / "device"
    device.mkdir(parents=True)
    (device / "vendor").write_text("0x1002\n")
    (device / "mem_info_vram_total").write_text(str(512 * 1024 ** 2))
    (device / "mem_info_gtt_total").write_text(str(62 * 1024 ** 3))
    other = tmp_path / "card0" / "device"
    other.mkdir(parents=True)
    (other / "vendor").write_text("0x8086\n")
    assert setup.amd_memory(tmp_path) == (0.5, 62.0)


def test_hardware_without_gpu_uses_half_the_ram(monkeypatch):
    monkeypatch.setattr(setup, "total_ram_gb", lambda: 16.0)
    monkeypatch.setattr(setup, "nvidia_memory_gb", lambda: 0.0)
    monkeypatch.setattr(setup, "amd_memory", lambda: (0.0, 0.0))
    monkeypatch.setattr(setup.sys, "platform", "linux")
    assert setup.hardware() == {"ram_gb": 16.0, "gpu": "none", "memory_gb": 8.0, "integrated": False}


def test_ollama_env_turns_on_the_integrated_gpu():
    env = setup.ollama_env(config("ollama"))
    assert env["OLLAMA_IGPU_ENABLE"] == "1" and env["OLLAMA_NO_CLOUD"] == "1"
    assert env["OLLAMA_HOST"] == "127.0.0.1:11435"


def test_ollama_container_binds_to_this_computer_only(sta_dir):
    cfg = config("ollama")
    cfg["ollama"]["how"] = "docker"
    service = json.loads(setup.ollama_compose(cfg).read_text())["services"]["ollama"]
    assert service["ports"] == ["127.0.0.1:11435:11435"]
    assert "-rocm@sha256:" in service["image"] and "/dev/kfd" in service["devices"]


def test_a_foreign_program_on_the_ollama_port_is_not_used(sta_dir, monkeypatch):
    """Whatever answers on the port gets the case data: only ours is used."""
    monkeypatch.setattr(setup, "ollama_up", lambda: True)
    setup.OLLAMA_PID.write_text(str(os.getpid()))
    if os.name != "nt":
        assert setup.our_ollama(config("ollama")) is None
        with pytest.raises(SystemExit):
            setup.start_ollama(config("ollama"))


@pytest.mark.parametrize("url, local", [("http://127.0.0.1:8000/v1", True), ("http://192.168.1.20:8000/v1", True),
                                        ("http://100.101.102.103/v1", True), ("http://8.8.8.8/v1", False),
                                        ("https://no-such-host.invalid/v1", False)])
def test_a_lan_server_must_be_in_the_own_network(url, local):
    assert setup.in_own_network(url) is local


@pytest.mark.parametrize("choice", ["ollama", "lan", "cloud", "own-pi"])
def test_pi_gets_only_the_sta_tools(sta_dir, choice):
    cmd, env = setup.runner_command(config(choice), "2026-01-01-x", "hi")
    assert cmd[0] == "pi" and cmd[-1] == "hi"
    assert "--no-session" in cmd, "pi must not keep the conversation about the phone"
    assert cmd[cmd.index("--tools") + 1] == "mcp__sta__*"
    assert "bash" not in " ".join(cmd) and "--no-context-files" in cmd and "--no-skills" in cmd
    assert env["STA_CASE"] == "2026-01-01-x" and env["STA_REVIEW"] == "guided"
    if choice == "own-pi":
        assert "--approve" in cmd and not (sta_dir / "pi").exists(), "the operator's own pi settings"
        return
    assert env["PI_CODING_AGENT_DIR"] == str(sta_dir / "pi") and "--no-approve" in cmd
    server = json.loads((sta_dir / "pi" / "mcp.json").read_text())["mcpServers"]["sta"]
    assert server["timeout"] > setup.WAIT_SECONDS and server["env"]["STA_CASE"] == "2026-01-01-x"
    assert server["command"] == sys.executable
    if choice in ("ollama", "lan"):
        provider = json.loads((sta_dir / "pi" / "models.json").read_text())["providers"]["sta"]
        assert provider["apiKey"] == ("$STA_API_KEY" if choice == "lan" else "none")


def test_shell_mode_is_the_old_operator_prompt(sta_dir):
    cmd, _ = setup.runner_command(config("lan"), "c", "hi", shell=True)
    assert cmd[cmd.index("--tools") + 1] == "read,bash" and "--no-mcp" in cmd


def test_claude_code_loads_no_other_server_and_waits_long_enough(sta_dir):
    cmd, env = setup.runner_command(config("claude"), "c", "hi", test=True)
    assert cmd[:2] == ["claude", "--mcp-config"] and "--strict-mcp-config" in cmd
    assert cmd[cmd.index("--tools") + 1] == "" and cmd[cmd.index("--allowedTools") + 1] == "mcp__sta__*"
    assert "-p" in cmd and "--model" not in cmd
    assert int(env["MCP_TOOL_TIMEOUT"]) > setup.WAIT_SECONDS * 1000
    assert json.loads((sta_dir / "mcp.json").read_text())["mcpServers"]["sta"]["env"]["STA_CASE"] == "c"


def test_secrets_stay_private_and_reach_the_runner(sta_dir):
    setup.save_secret("STA_API_KEY", "sk-test")
    setup.save_secret("OPENROUTER_API_KEY", "or-test")
    assert setup.read_secrets() == {"STA_API_KEY": "sk-test", "OPENROUTER_API_KEY": "or-test"}
    if os.name != "nt":
        assert (sta_dir / "secrets.env").stat().st_mode & 0o777 == 0o600
    _, env = setup.runner_command(config("cloud"), "c", "hi")
    assert env["OPENROUTER_API_KEY"] == "or-test" and "STA_API_KEY" not in env, "only the key in use"
    _, env = setup.runner_command(config("ollama"), "c", "hi")
    assert "OPENROUTER_API_KEY" not in env and "STA_API_KEY" not in env


def test_repo_pi_config_waits_longer_than_a_step():
    """The operator's own pi reads .pi/mcp.json: pi's default limit is 60 s."""
    server = json.loads((setup.ROOT / ".pi" / "mcp.json").read_text())["mcpServers"]["sta"]
    assert server["timeout"] >= setup.TOOL_TIMEOUT and server["exposure"] == "direct"
