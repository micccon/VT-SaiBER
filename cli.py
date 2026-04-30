#!/usr/bin/env python3
"""VT-SaiBER CLI - Interactive wizard for demos and testing.

Run with: python cli.py
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def is_running_on_linux_vm() -> bool:
    """Detect if we're running directly on a Linux VM with Docker."""
    if platform.system() != "Linux":
        return False
    try:
        result = subprocess.run(
            ["docker", "ps"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False

PROJECT_ROOT = Path(__file__).parent.resolve()
CONFIG_FILE = PROJECT_ROOT / ".vtsaiber_config.json"


@dataclass
class Config:
    vm_host: str = ""
    vm_user: str = ""
    vm_path: str = "/mnt/shared/VT-SaiBER"
    setup_complete: bool = False
    local_mode: bool = False  # True if running directly on VM

    def save(self):
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.__dict__, f, indent=2)

    @classmethod
    def load(cls) -> "Config":
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                return cls(**data)
            except Exception:
                pass
        return cls()

    @property
    def configured(self) -> bool:
        return self.local_mode or bool(self.vm_host and self.vm_user)

    @property
    def ssh_target(self) -> str:
        return f"{self.vm_user}@{self.vm_host}"


def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def print_header(title: str):
    clear_screen()
    print("\033[96m" + "=" * 60 + "\033[0m")
    print(f"\033[96m  {title}\033[0m")
    print("\033[96m" + "=" * 60 + "\033[0m")
    print()


def print_success(msg: str):
    print(f"\033[92m✓ {msg}\033[0m")


def print_error(msg: str):
    print(f"\033[91m✗ {msg}\033[0m")


def print_warning(msg: str):
    print(f"\033[93m! {msg}\033[0m")


def print_info(msg: str):
    print(f"\033[94m→ {msg}\033[0m")


def print_cmd(cmd: str):
    print(f"\033[96m  $ {cmd}\033[0m")


def prompt(msg: str, default: str = "") -> str:
    if default:
        result = input(f"{msg} [{default}]: ").strip()
        return result if result else default
    return input(f"{msg}: ").strip()


def confirm(msg: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    result = input(f"{msg} {suffix}: ").strip().lower()
    if not result:
        return default
    return result in ("y", "yes")


def menu(title: str, options: list[tuple[str, str]], back: bool = True) -> Optional[str]:
    """Display a menu and return the selected key."""
    print(f"\n\033[1m{title}\033[0m\n")
    for key, label in options:
        print(f"  [{key}] {label}")
    if back:
        print(f"  [b] Back")
    print(f"  [q] Quit")
    print()

    choice = input("Select: ").strip().lower()
    if choice == "q":
        print("\nGoodbye!")
        sys.exit(0)
    if choice == "b" and back:
        return None
    return choice


def ssh_run(config: Config, cmd: str, interactive: bool = True) -> subprocess.CompletedProcess:
    """Run a command on the VM via SSH, or locally if in local mode."""
    if config.local_mode:
        return subprocess.run(cmd, shell=True)
    ssh_cmd = ["ssh"]
    if interactive:
        ssh_cmd.append("-t")
    ssh_cmd.extend([config.ssh_target, cmd])
    return subprocess.run(ssh_cmd)


def ssh_check(config: Config, cmd: str) -> tuple[bool, str]:
    """Run a command on VM and return success status and output."""
    if config.local_mode:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    else:
        result = subprocess.run(
            ["ssh", config.ssh_target, cmd],
            capture_output=True,
            text=True,
        )
    return result.returncode == 0, result.stdout.strip()


# =============================================================================
# SETUP WIZARD
# =============================================================================

def run_setup_wizard(config: Config) -> bool:
    """Interactive setup wizard. Returns True if setup completed."""

    print_header("VT-SaiBER Setup Wizard")

    # Step 1: Where are you running from?
    print("\033[1mStep 1: Environment\033[0m\n")

    if config.configured:
        if config.local_mode:
            print("  Mode: Running directly on VM (local mode)")
        else:
            print(f"  Mode: SSH to {config.ssh_target}")
        if not confirm("  Use this configuration?"):
            config.vm_host = ""
            config.vm_user = ""
            config.local_mode = False

    if not config.configured:
        # Auto-detect Linux VM
        if is_running_on_linux_vm():
            print_success("Detected: Running on Linux VM with Docker")
            print()
            if confirm("  Use local mode (recommended)?"):
                config.local_mode = True
                config.vm_path = os.getcwd()
                config.save()
                print_success("Local mode enabled - no SSH needed.")
            else:
                config.local_mode = False
        else:
            print("  Where are you running this CLI from?\n")
            print("  [1] Mac/Windows (SSH into VM)")
            print("  [2] Directly on the Linux VM (local mode)\n")
            mode = prompt("  Select", "1")

            if mode == "2":
                config.local_mode = True
                config.vm_path = os.getcwd()
                config.save()
                print_success("Local mode enabled - no SSH needed.")
            else:
                config.local_mode = False

        if not config.local_mode:
            print("\n  To find these values, run these commands inside your VM:")
            print_cmd("hostname -I      # VM IP address")
            print_cmd("whoami           # VM username")
            print()
            print("  Typical IP ranges:")
            print("    UTM:       192.168.64.x")
            print("    Parallels: 10.211.55.x\n")
            config.vm_host = prompt("  VM IP address")
            config.vm_user = prompt("  VM username")
            config.save()

    # Step 2: Test SSH connection (skip in local mode)
    if config.local_mode:
        print(f"\n\033[1mStep 2: Skipping SSH (local mode)\033[0m\n")
        print_success("Running locally - no SSH needed.")
    else:
        print(f"\n\033[1mStep 2: Testing SSH Connection\033[0m\n")
        print_info(f"Connecting to {config.ssh_target}...")

        try:
            result = subprocess.run(
                [
                    "ssh",
                    "-o", "ConnectTimeout=5",
                    "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=accept-new",
                    "-o", "PubkeyAuthentication=yes",
                    config.ssh_target,
                    "echo connected",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                print_success("SSH connection successful!")
            else:
                print_error("SSH connection failed.")
                if result.stderr:
                    print(f"  Error: {result.stderr.strip()}")
                print("\n  Troubleshooting:")
                print("    1. Test SSH manually:")
                print_cmd(f"ssh {config.ssh_target}")
                print("    2. If prompted for password, set up SSH keys:")
                print_cmd(f"ssh-copy-id {config.ssh_target}")
                print("    3. If keys still don't work, fix permissions on VM:")
                print_cmd("chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys")
                return False
        except subprocess.TimeoutExpired:
            print_error("SSH connection timed out.")
            return False
        except Exception as e:
            print_error(f"SSH error: {e}")
            return False

    # Step 3: Check shared folder
    print(f"\n\033[1mStep 3: Shared Folder\033[0m\n")

    ok, _ = ssh_check(config, f"test -d {config.vm_path} && echo ok")
    if ok:
        print_success(f"Shared folder found: {config.vm_path}")
    else:
        print_warning(f"Shared folder not found: {config.vm_path}")
        print("\n  On your VM, run:")
        print_cmd("sudo mkdir -p /mnt/shared")
        print_cmd("sudo mount -t virtiofs share /mnt/shared")
        print()
        if not confirm("  Continue anyway?"):
            return False

    # Step 4: Docker setup
    print(f"\n\033[1mStep 4: Docker Environment\033[0m\n")

    ok, _ = ssh_check(config, "docker ps --format '{{.Names}}' | grep -q vt-saiber")
    if ok:
        print_success("VT-SaiBER containers are running!")
        if not confirm("  Skip Docker setup?", default=True):
            ok = False

    if not ok:
        print("  Run these commands on your VM:\n")
        print_cmd(f"cd {config.vm_path}")
        print_cmd("bash scripts/docker/full_reset_startup.sh")
        print()

        if confirm("  Run these commands now via SSH?"):
            print()
            ssh_run(config, f"cd {config.vm_path} && bash scripts/docker/full_reset_startup.sh")
            print()
        else:
            input("\n  Press Enter when done...")

    # Step 5: Testbed setup
    print(f"\n\033[1mStep 5: Automotive Testbed\033[0m\n")

    ok, _ = ssh_check(config, "docker ps --format '{{.Names}}' | grep -q automotive-testbed")
    if ok:
        print_success("Automotive testbed is running!")
    else:
        print("  Run these commands on your VM:\n")
        print_cmd(f"cd {config.vm_path}")
        print_cmd("bash scripts/testbed/setup_testbed.sh")
        print()

        if confirm("  Run these commands now via SSH?"):
            print()
            ssh_run(config, f"cd {config.vm_path} && bash scripts/testbed/setup_testbed.sh")
            print()
        else:
            input("\n  Press Enter when done...")

    # Done!
    config.setup_complete = True
    config.save()

    print("\n" + "=" * 60)
    print_success("Setup Complete!")
    print("=" * 60)
    input("\nPress Enter to continue...")
    return True


# =============================================================================
# STATUS CHECK
# =============================================================================

def show_status(config: Config):
    """Show current system status."""
    print_header("VT-SaiBER Status")

    if not config.configured:
        print_error("Not configured. Run setup first.")
        input("\nPress Enter to continue...")
        return

    if config.local_mode:
        print("Mode: Local (running on VM)\n")
    else:
        print(f"VM: {config.ssh_target}\n")

    containers = [
        ("vt-saiber-postgres", "PostgreSQL"),
        ("vt-saiber-attackbox", "Attackbox (Kali)"),
        ("vt-saiber-agents", "Agents"),
        ("automotive-testbed", "Automotive Testbed"),
    ]

    print("\033[1mContainers:\033[0m")
    for name, label in containers:
        ok, output = ssh_check(config, f"docker ps --filter name={name} --format '{{{{.Status}}}}'")
        if output:
            status = "healthy" if "healthy" in output.lower() else output
            color = "\033[92m" if "healthy" in output.lower() or "Up" in output else "\033[93m"
            print(f"  {color}✓\033[0m {label}: {status}")
        else:
            print(f"  \033[91m✗\033[0m {label}: not running")

    print()
    input("Press Enter to continue...")


# =============================================================================
# DEMO MENU
# =============================================================================

def run_demo_menu(config: Config):
    """Demo selection menu."""
    while True:
        print_header("VT-SaiBER Demos")

        choice = menu("Select a demo:", [
            ("1", "Quick Demo - Enumerate automotive testbed"),
            ("2", "Full Demo - Enumerate + exploit attempts"),
            ("3", "SSH Credential Test - Test default credentials"),
            ("4", "Custom Mission - Enter your own target/goal"),
        ])

        if choice is None:
            return

        if choice == "1":
            run_mission(
                config,
                target="automotive-testbed",
                goal="Perform quick reconnaissance on the automotive testbed. Enumerate open ports and identify running services.",
            )
        elif choice == "2":
            run_mission(
                config,
                target="automotive-testbed",
                goal="Enumerate all services on the automotive testbed, identify potential vulnerabilities, and attempt exploitation where safe.",
            )
        elif choice == "3":
            run_mission(
                config,
                target="automotive-testbed",
                goal="Test SSH on port 22 for default credentials. Try common username/password combinations including admin:password123.",
            )
        elif choice == "4":
            print()
            target = prompt("Target (IP/hostname)")
            goal = prompt("Mission goal")
            if target and goal:
                run_mission(config, target=target, goal=goal)


def run_mission(config: Config, target: str, goal: str):
    """Execute a mission on the VM."""
    print()
    print(f"\033[1mMission:\033[0m")
    print(f"  Target: {target}")
    print(f"  Goal: {goal}")
    print()

    if not confirm("Start mission?"):
        return

    cmd = (
        f"docker exec -it vt-saiber-agents python -m src.main "
        f"--target-scope '{target}' "
        f"--mission-goal '{goal}'"
    )

    print()
    ssh_run(config, cmd)
    print()
    input("Press Enter to continue...")


# =============================================================================
# TEST MENU
# =============================================================================

def run_test_menu(config: Config):
    """Test selection menu."""
    while True:
        print_header("VT-SaiBER Tests")

        choice = menu("Select a test:", [
            ("1", "Striker Integration Test (nmap + exploit)"),
            ("2", "Striker Automotive Test"),
            ("3", "Supervisor Routing Test"),
            ("4", "Fuzzer Test"),
            ("5", "Librarian Test"),
            ("6", "All Agent Tests (pytest)"),
            ("7", "Docker Health Tests"),
        ])

        if choice is None:
            return

        test_map = {
            "1": "tests/agent_tests/run_striker_minimal_live.sh",
            "2": "tests/agent_tests/run_striker_automotive_live.sh",
            "3": "docker exec vt-saiber-agents pytest /app/tests/agent_tests/test_supervisor_routing_demo.py -v",
            "4": "docker exec vt-saiber-agents pytest /app/tests/agent_tests/test_fuzzer.py -v",
            "5": "docker exec vt-saiber-agents pytest /app/tests/agent_tests/test_librarian.py -v",
            "6": "docker exec vt-saiber-agents pytest /app/tests/agent_tests/ -v",
            "7": "bash tests/docker_tests/agents_test.sh && bash tests/docker_tests/postgres_test.sh",
        }

        if choice in test_map:
            cmd = test_map[choice]
            if cmd.startswith("tests/"):
                cmd = f"cd {config.vm_path} && bash {cmd}"

            print()
            ssh_run(config, cmd)
            print()
            input("Press Enter to continue...")


# =============================================================================
# UTILITIES MENU
# =============================================================================

def run_utilities_menu(config: Config):
    """Utilities menu."""
    while True:
        print_header("VT-SaiBER Utilities")

        choice = menu("Select an option:", [
            ("1", "View container logs"),
            ("2", "Open shell in agents container"),
            ("3", "Open shell in attackbox"),
            ("4", "Open shell in testbed"),
            ("5", "SSH to VM"),
            ("6", "Restart all containers"),
            ("7", "Stop all containers"),
            ("8", "Force stop all (kill + remove volumes)"),
            ("9", "Reset everything (rebuild)"),
        ])

        if choice is None:
            return

        if choice == "1":
            print()
            container = prompt("Container name (agents/attackbox/testbed/postgres)", "agents")
            container_map = {
                "agents": "vt-saiber-agents",
                "attackbox": "vt-saiber-attackbox",
                "testbed": "automotive-testbed",
                "postgres": "vt-saiber-postgres",
            }
            name = container_map.get(container, container)
            ssh_run(config, f"docker logs -f --tail 100 {name}")

        elif choice == "2":
            ssh_run(config, "docker exec -it vt-saiber-agents /bin/bash")

        elif choice == "3":
            ssh_run(config, "docker exec -it vt-saiber-attackbox /bin/bash")

        elif choice == "4":
            ssh_run(config, "docker exec -it automotive-testbed /bin/bash")

        elif choice == "5":
            if config.local_mode:
                print_info("Already running on VM - use your terminal directly.")
                input("\nPress Enter to continue...")
            else:
                subprocess.run(["ssh", config.ssh_target])

        elif choice == "6":
            print()
            if confirm("Restart all containers?"):
                ssh_run(config, f"cd {config.vm_path}/third_party/automotive_testbed && docker compose restart")
                ssh_run(config, f"cd {config.vm_path} && docker compose restart")
                print_success("Containers restarted.")
                input("\nPress Enter to continue...")

        elif choice == "7":
            print()
            if confirm("Stop all containers?"):
                ssh_run(config, f"cd {config.vm_path}/third_party/automotive_testbed && docker compose down")
                ssh_run(config, f"cd {config.vm_path} && docker compose down")
                print_success("Containers stopped.")
                input("\nPress Enter to continue...")

        elif choice == "8":
            print()
            print_warning("This will KILL all containers and remove volumes (data loss)!")
            if confirm("Continue?", default=False):
                ssh_run(config, f"cd {config.vm_path}/third_party/automotive_testbed && docker compose down -v --remove-orphans")
                ssh_run(config, f"cd {config.vm_path} && docker compose down -v --remove-orphans")
                ssh_run(config, "docker system prune -f")
                print_success("All containers killed and volumes removed.")
                input("\nPress Enter to continue...")

        elif choice == "9":
            print()
            print_warning("This will stop and rebuild all containers!")
            if confirm("Continue?", default=False):
                ssh_run(config, f"cd {config.vm_path} && bash scripts/docker/full_reset_startup.sh")
                ssh_run(config, f"cd {config.vm_path} && bash scripts/testbed/setup_testbed.sh")
                input("\nPress Enter to continue...")


# =============================================================================
# MAIN
# =============================================================================

def main():
    config = Config.load()

    # First run - check if setup is needed
    if not config.setup_complete or not config.configured:
        print_header("Welcome to VT-SaiBER")
        print("  VT-SaiBER is an autonomous multi-agent")
        print("  cyber-physical security testing framework.\n")

        if config.setup_complete:
            print_success("Previous setup detected.\n")
        else:
            print("  It looks like this is your first time running the CLI.\n")

        if confirm("Run setup wizard?", default=not config.setup_complete):
            if not run_setup_wizard(config):
                print("\nSetup incomplete. Run the CLI again when ready.")
                sys.exit(1)

    # Main menu loop
    while True:
        print_header("VT-SaiBER Main Menu")

        if config.local_mode:
            print("  Mode: Local (running on VM)")
        else:
            print(f"  VM: {config.ssh_target}")
        print()

        choice = menu("What would you like to do?", [
            ("1", "Run a Demo"),
            ("2", "Run Tests"),
            ("3", "Check Status"),
            ("4", "Utilities"),
            ("5", "Re-run Setup"),
        ], back=False)

        if choice == "1":
            run_demo_menu(config)
        elif choice == "2":
            run_test_menu(config)
        elif choice == "3":
            show_status(config)
        elif choice == "4":
            run_utilities_menu(config)
        elif choice == "5":
            run_setup_wizard(config)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
        sys.exit(0)
