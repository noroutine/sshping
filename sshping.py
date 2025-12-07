#!/usr/bin/env python3

import socket
import random
import time
import os
import signal
import argparse
import logging
import getpass
from pathlib import Path
import paramiko
from rich.console import Console

console = Console(highlight=False)

# Suppress paramiko logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

PORT = 22
USERNAME = "git"
MIN_PORT = 10000
MAX_PORT = 65000
DELAY = 1  # 100ms between attempts
TIMEOUT = 3  # SSH timeout in seconds

def find_ssh_keys():
    """Find available SSH keys in ~/.ssh"""
    ssh_dir = Path.home() / ".ssh"
    if not ssh_dir.exists():
        return []

    key_files = []
    # Find all private key files (without .pub extension)
    for key_file in ssh_dir.iterdir():
        if key_file.is_file() and not key_file.name.endswith('.pub') and not key_file.name.startswith('.'):
            # Check if it looks like a private key and verify it's actually a key file
            if key_file.name.startswith('id_') or 'key' in key_file.name.lower():
                try:
                    # Check if file starts with SSH key headers
                    with open(key_file, 'r') as f:
                        first_line = f.readline().strip()
                        if ('BEGIN' in first_line and 'PRIVATE KEY' in first_line) or \
                           first_line.startswith('-----BEGIN'):
                            key_files.append(str(key_file))
                except:
                    pass  # Skip files we can't read

    return sorted(key_files)

def test_ssh_auth(target, port, username, source_port, key_files=None, timeout=5, command=None):
    """Attempt full SSH authentication"""
    start_time = time.time()
    tcp_time = 0  # Initialize to avoid unbound variable

    try:
        # Use only the first key for this attempt
        # (Don't try multiple keys with same source port)
        if not key_files:
            key_files = []

        if not key_files:
            return {
                'success': False,
                'error_type': 'AUTH_FAILED',
                'error': 'No valid SSH keys provided',
                'source_port': source_port,
                'total_time': 0
            }

        # Only try first key
        key_file = key_files[0]

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Create socket with specific source port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            # Bind to specific source port
            sock.bind(('', source_port))
            sock.settimeout(timeout)

            # TCP connect
            tcp_start = time.time()
            sock.connect((target, port))
            tcp_time = (time.time() - tcp_start) * 1000  # ms

            # Attempt SSH authentication with this key
            auth_start = time.time()
            client.connect(
                target,
                port=port,
                username=username,
                timeout=timeout,
                sock=sock,
                key_filename=key_file,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=timeout,
                auth_timeout=timeout
            )
            auth_time = (time.time() - auth_start) * 1000  # ms

            # If we get here, authentication succeeded
            successful_key = Path(key_file).name

            # Get SSH protocol banner
            ssh_banner = None
            try:
                transport = client.get_transport()
                if transport:
                    ssh_banner = transport.remote_version.strip()
            except:
                pass

            # Try to get the server message by executing a command
            server_msg = None
            if command:
                try:
                    _, stdout, stderr = client.exec_command(command, timeout=2)
                    stdout_lines = stdout.read().decode('utf-8', errors='ignore').strip()
                    stderr_lines = stderr.read().decode('utf-8', errors='ignore').strip()
                    # Combine stdout and stderr, prefer stdout if both present
                    if stdout_lines and stderr_lines:
                        server_msg = f"{stdout_lines} | {stderr_lines}"
                    elif stdout_lines:
                        server_msg = stdout_lines
                    elif stderr_lines:
                        server_msg = stderr_lines
                except:
                    pass

            client.close()
            sock.close()

            total_time = (time.time() - start_time) * 1000  # ms

            return {
                'success': True,
                'source_port': source_port,
                'ssh_banner': ssh_banner,
                'server_msg': server_msg,
                'key': successful_key,
                'tcp_time': tcp_time,
                'auth_time': auth_time,
                'total_time': total_time
            }

        except paramiko.AuthenticationException as e:
            try:
                client.close()
                sock.close()
            except:
                pass
            total_time = (time.time() - start_time) * 1000
            # For auth failures, we have tcp_time but auth failed
            return {
                'success': False,
                'error_type': 'AUTH_FAILED',
                'error': str(e),
                'source_port': source_port,
                'tcp_time': tcp_time if 'tcp_time' in locals() else 0,
                'auth_time': total_time - (tcp_time if 'tcp_time' in locals() else 0),
                'total_time': total_time
            }
        except (paramiko.SSHException, OSError, socket.error) as e:
            try:
                client.close()
                sock.close()
            except:
                pass
            # Re-raise to be caught by outer exception handlers
            raise

    except paramiko.AuthenticationException as e:
        total_time = (time.time() - start_time) * 1000
        return {
            'success': False,
            'error_type': 'AUTH_FAILED',
            'error': str(e),
            'source_port': source_port,
            'total_time': total_time
        }
    except paramiko.SSHException as e:
        total_time = (time.time() - start_time) * 1000
        return {
            'success': False,
            'error_type': 'SSH_ERROR',
            'error': str(e),
            'source_port': source_port,
            'total_time': total_time
        }
    except socket.timeout:
        total_time = (time.time() - start_time) * 1000
        return {
            'success': False,
            'error_type': 'TIMEOUT',
            'error': f'Connection timeout after {TIMEOUT}s',
            'source_port': source_port,
            'total_time': total_time
        }
    except ConnectionRefusedError:
        total_time = (time.time() - start_time) * 1000
        return {
            'success': False,
            'error_type': 'REFUSED',
            'error': 'Connection refused',
            'source_port': source_port,
            'total_time': total_time
        }
    except OSError as e:
        if "Address already in use" in str(e):
            return {'success': None, 'skipped': True}
        total_time = (time.time() - start_time) * 1000
        return {
            'success': False,
            'error_type': 'OS_ERROR',
            'error': str(e),
            'source_port': source_port,
            'total_time': total_time
        }
    except Exception as e:
        total_time = (time.time() - start_time) * 1000
        return {
            'success': False,
            'error_type': 'EXCEPTION',
            'error': str(e),
            'source_port': source_port,
            'total_time': total_time
        }

def print_result(result, seq):
    """Print compact ping-style result"""
    if result.get('skipped'):
        return

    sport = result['source_port']
    total_ms = result.get('total_time', 0)

    if result['success']:
        key_info = ""
        if result.get('key'):
            key_info = f" [white][dim]key[/dim]=[bold]{result['key']}[/bold][/white]"

        # Timing breakdown with highlighted values
        tcp_ms = result.get('tcp_time', 0)
        auth_ms = result.get('auth_time', 0)
        timing = f"[white][dim]time=[/dim][bold]{total_ms:.0f}ms[/bold][/white] [white][dim](tcp=[/dim][bold]{tcp_ms:.0f}ms[/bold], [dim]auth=[/dim][bold]{auth_ms:.0f}ms[/bold][dim])[/dim][/white]"

        banner_info = ""
        ssh_banner = result.get('ssh_banner')
        server_msg = result.get('server_msg')

        banner_parts = []
        if ssh_banner:
            # SSH protocol banner in dim
            banner_parts.append(f"[dim]{ssh_banner}[/dim]")

        if server_msg:
            # Server message in bright cyan
            msg = server_msg.replace('\n', ' | ')
            if len(msg) > 40:
                msg = msg[:37] + "..."
            banner_parts.append(f"[bright_cyan]{msg}[/bright_cyan]")

        if banner_parts:
            banner_info = " " + " | ".join(banner_parts)

        console.print(f"[bold green]OK[/bold green] [dim]seq=[/dim][bold white]{seq}[/bold white] [dim]sport=[/dim][bold white]{sport}[/bold white]{key_info} {timing}{banner_info}")
    else:
        error_type = result['error_type']
        error_msg = result['error']

        # Timing breakdown (if available) - matching success branch style
        tcp_ms = result.get('tcp_time', 0)
        auth_ms = result.get('auth_time', 0)
        if tcp_ms > 0 or auth_ms > 0:
            timing = f"[white][dim]time=[/dim][bold]{total_ms:.0f}ms[/bold][/white] [white][dim](tcp=[/dim][bold]{tcp_ms:.0f}ms[/bold], [dim]auth=[/dim][bold]{auth_ms:.0f}ms[/bold][dim])[/dim][/white]"
        else:
            timing = f"[white][dim]time=[/dim][bold]{total_ms:.0f}ms[/bold][/white]"

        # Shorten error messages
        if len(error_msg) > 50:
            error_msg = error_msg[:47] + "..."

        console.print(f"[bold red]{error_type}[/bold red] [dim]seq=[/dim][bold white]{seq}[/bold white] [dim]sport=[/dim][bold white]{sport}[/bold white] {timing} {error_msg}")

def main():
    parser = argparse.ArgumentParser(description='SSH Authentication Test Tool')
    parser.add_argument('target',
                        help='Target in format [user@]host[:port]')
    parser.add_argument('command', nargs='?',
                        help='Command to execute')
    parser.add_argument('-i', '--identity', type=str,
                        help='SSH private key file (like ssh -i)')
    parser.add_argument('-d', '--delay', type=float, default=DELAY,
                        help=f'Delay between attempts in seconds (default: {DELAY})')
    parser.add_argument('-t', '--timeout', type=int, default=TIMEOUT,
                        help=f'SSH timeout in seconds (default: {TIMEOUT})')

    args = parser.parse_args()

    # Parse target: [user@]host[:port]
    target = args.target
    USERNAME = None
    PORT = 22  # default

    # Extract user if present
    if '@' in target:
        USERNAME, target = target.split('@', 1)

    # Extract port if present
    if ':' in target:
        target, port_str = target.rsplit(':', 1)
        PORT = int(port_str)

    # Default to current user if not provided
    if not USERNAME:
        USERNAME = getpass.getuser()

    target_host = target
    delay = args.delay
    timeout = args.timeout

    cmd_part = f"cmd=[bold white]{args.command}[/bold white]" if args.command else ""
    # Use specified key or find available keys
    if args.identity:
        keys = [args.identity]
        console.print(f"SSH-PING target=[bold white]{target_host}:{PORT}[/bold white] user=[bold white]{USERNAME}[/bold white] key=[bold white]{Path(args.identity).name}[/bold white] delay=[bold white]{delay}s[/bold white] {cmd_part}")
    else:
        console.print(f"SSH-PING target=[bold white]{target_host}:{PORT}[/bold white] user=[bold white]{USERNAME}[/bold white] delay=[bold white]{delay}s[/bold white] {cmd_part}")
        keys = find_ssh_keys()
        if not keys:
            console.print("[yellow]⚠ No SSH keys in ~/.ssh[/yellow]")

    # Test all keys once to find which ones work
    working_keys = []
    if keys and not args.identity:
        try:
            console.print("Guessing keys... ", end="")
            first = True
            for key in keys:
                key_name = Path(key).name
                if not first:
                    console.print(", ", end="")
                first = False
                console.print(f"[bold white]{key_name}[/bold white] ", end="")
                try:
                    test_client = paramiko.SSHClient()
                    test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    test_client.connect(
                        target_host,
                        port=PORT,
                        username=USERNAME,
                        key_filename=key,
                        timeout=timeout,
                        look_for_keys=False,
                        allow_agent=False
                    )
                    test_client.close()
                    working_keys.append(key)
                    if len(working_keys) == 1:
                        console.print("[green]✓ using[/green]", end="")
                    else:
                        console.print("[green]✓[/green]", end="")
                except KeyboardInterrupt:
                    console.print()
                    raise
                except:
                    console.print("[red]✗[/red]", end="")

            console.print()

            if working_keys:
                keys = [working_keys[0]]  # Use first working key
            else:
                console.print("[yellow]⚠ No working keys found, will continue anyway[/yellow]\n")
        except KeyboardInterrupt:
            console.print("\n[dim]Interrupted during key testing[/dim]")
            os._exit(0)

    success_count = 0
    failure_count = 0
    seq = 0

    # Signal handler for immediate exit on Ctrl+C
    def signal_handler(_sig, _frame):
        console.print("\n[dim]---[/dim]")
        total = success_count + failure_count
        if total > 0:
            success_rate = (success_count / total) * 100
            console.print(f"[bold white]{total}[/bold white] attempts, [bold green]{success_count}[/bold green] success, [bold red]{failure_count}[/bold red] failed, [bold white]{success_rate:.1f}%[/bold white] success rate")
        else:
            console.print(f"[bold white]{total}[/bold white] attempts")
        os._exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    while True:
        sport = random.randint(MIN_PORT, MAX_PORT)
        result = test_ssh_auth(target_host, PORT, USERNAME, sport, key_files=keys, timeout=timeout, command=args.command)

        if result.get('success') is not None:
            seq += 1
            print_result(result, seq)

            if result['success']:
                success_count += 1
            else:
                failure_count += 1

        time.sleep(delay)

if __name__ == "__main__":
    main()
