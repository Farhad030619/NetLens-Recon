"""
NetLens-Recon Scanner Module
Fast async network pre-flight probing and Playwright headless browser capture pool.
Author: Farhad Jelve (CCNP Enterprise, CCNA, B.Sc. EE KTH)
"""

import asyncio
import ipaddress
import os
import re
import socket
import time
from typing import List, Optional, Tuple, Set, AsyncGenerator
from urllib.parse import urlparse

from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Error as PlaywrightError
from rich.console import Console

from src.models import Target, ProbeResult, ScanResult

console = Console()


def parse_targets(
    inputs: List[str],
    default_ports: List[int] = None,
    default_schemes: List[str] = None
) -> List[Target]:
    """
    Parse a list of target strings (domains, URLs, IPs, CIDR blocks) into structured Target objects.
    """
    if default_ports is None:
        default_ports = [80, 443]
    if default_schemes is None:
        default_schemes = ["http", "https"]

    targets: List[Target] = []
    seen_keys: Set[Tuple[str, int, str]] = set()

    for item in inputs:
        item = item.strip()
        if not item or item.startswith("#"):
            continue

        # Check if CIDR notation (e.g. 192.168.1.0/24)
        if "/" in item and not item.startswith("http://") and not item.startswith("https://"):
            try:
                network = ipaddress.ip_network(item, strict=False)
                # Cap CIDR expansion for safety (e.g. /24 max 256 hosts)
                hosts = list(network.hosts())
                if len(hosts) > 512:
                    console.print(f"[yellow]⚠️ Warning: Subnet {item} has {len(hosts)} hosts. Capping to first 512.[/yellow]")
                    hosts = hosts[:512]
                for host in hosts:
                    h_str = str(host)
                    for port in default_ports:
                        scheme = "https" if port in (443, 8443) else "http"
                        key = (h_str, port, scheme)
                        if key not in seen_keys:
                            seen_keys.add(key)
                            targets.append(Target(raw_input=item, host=h_str, port=port, scheme=scheme))
                continue
            except ValueError:
                pass

        # If item has explicit URL scheme
        if item.startswith("http://") or item.startswith("https://"):
            parsed = urlparse(item)
            scheme = parsed.scheme.lower()
            host = parsed.hostname or ""
            port = parsed.port or (443 if scheme == "https" else 80)
            path = parsed.path or ""
            if parsed.query:
                path += f"?{parsed.query}"
            key = (host, port, scheme, path)
            if key not in seen_keys and host:
                seen_keys.add(key)
                targets.append(Target(raw_input=item, host=host, port=port, scheme=scheme, path=path))
            continue

        # Check if host:port syntax
        if ":" in item and not item.count(":") > 1:  # Not IPv6
            parts = item.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
                scheme = "https" if port in (443, 8443) else "http"
                key = (host, port, scheme)
                if key not in seen_keys and host:
                    seen_keys.add(key)
                    targets.append(Target(raw_input=item, host=host, port=port, scheme=scheme))
                continue
            except ValueError:
                pass

        # Plain domain or IP: map to default ports
        host = item
        for port in default_ports:
            scheme = "https" if port in (443, 8443) else "http"
            key = (host, port, scheme)
            if key not in seen_keys and host:
                seen_keys.add(key)
                targets.append(Target(raw_input=item, host=host, port=port, scheme=scheme))

    return targets


async def probe_endpoint(
    target: Target,
    timeout: float = 2.5
) -> ProbeResult:
    """
    Fast asynchronous TCP pre-flight check to verify if the port is reachable.
    Avoids spinning up browser tabs for dead hosts or closed ports.
    """
    start_time = time.perf_counter()
    resolved_ip = None

    try:
        # Resolve host asynchronously in executor to avoid blocking event loop
        loop = asyncio.get_running_loop()
        try:
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(target.host, target.port, family=socket.AF_INET, type=socket.SOCK_STREAM),
                timeout=timeout
            )
            if addr_info:
                resolved_ip = addr_info[0][4][0]
        except (socket.gaierror, asyncio.TimeoutError):
            return ProbeResult(
                target=target,
                is_open=False,
                error="DNS resolution failed or timed out",
                latency_ms=(time.perf_counter() - start_time) * 1000
            )

        # Attempt quick TCP connect
        conn = asyncio.open_connection(target.host, target.port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()

        latency = (time.perf_counter() - start_time) * 1000
        return ProbeResult(
            target=target,
            is_open=True,
            resolved_ip=resolved_ip,
            latency_ms=latency
        )
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
        latency = (time.perf_counter() - start_time) * 1000
        return ProbeResult(
            target=target,
            is_open=False,
            resolved_ip=resolved_ip,
            error=str(e),
            latency_ms=latency
        )


def _safe_filename(url: str) -> str:
    """Generate a clean, filesystem-safe filename from URL."""
    sanitized = re.sub(r'https?://', '', url)
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', sanitized)
    sanitized = re.sub(r'_+', '_', sanitized).strip('_.')[:100]
    return f"{sanitized}.png"


class ReconScanner:
    """
    High-throughput asynchronous reconnaissance scanner with Playwright browser pool.
    """

    def __init__(
        self,
        concurrency: int = 8,
        page_timeout_sec: float = 15.0,
        output_dir: str = "./output",
        user_agent: Optional[str] = None,
        headless: bool = True
    ):
        self.concurrency = concurrency
        self.page_timeout_ms = int(page_timeout_sec * 1000)
        self.output_dir = output_dir
        self.screenshots_dir = os.path.join(output_dir, "screenshots")
        os.makedirs(self.screenshots_dir, exist_ok=True)
        self.headless = headless
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 NetLens/1.0"
        )
        self._semaphore = asyncio.Semaphore(concurrency)

    async def scan_single_target(
        self,
        browser: Browser,
        target: Target,
        resolved_ip: Optional[str] = None
    ) -> ScanResult:
        """
        Render target URL in headless Playwright, capture screenshot, inspect DOM & headers.
        """
        target_url = target.url
        start_time = time.perf_counter()
        headers_collected = {}
        redirect_chain = []
        status_code = None
        status_text = None

        context: Optional[BrowserContext] = None
        page: Optional[Page] = None

        async with self._semaphore:
            try:
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent=self.user_agent,
                    ignore_https_errors=True,
                    java_script_enabled=True,
                    bypass_csp=True
                )
                page = await context.new_page()

                def on_response(response):
                    nonlocal status_code, status_text
                    if response.url == target_url or response.url == page.url:
                        status_code = response.status
                        status_text = response.status_text
                        for k, v in response.headers.items():
                            headers_collected[k.lower()] = v

                page.on("response", on_response)

                # Navigate
                try:
                    response = await page.goto(
                        target_url,
                        timeout=self.page_timeout_ms,
                        wait_until="domcontentloaded"
                    )
                    if response:
                        status_code = response.status
                        status_text = response.status_text
                        for k, v in response.headers.items():
                            headers_collected[k.lower()] = v
                except PlaywrightError as pe:
                    # Retry with looser condition if network had delay
                    pass

                # Brief wait for client-side JS rendering / hydration
                await asyncio.sleep(0.6)

                final_url = page.url
                if final_url != target_url:
                    redirect_chain.append(final_url)

                # Extract page title and meta attributes
                title = await page.title()
                if not title:
                    title = await page.evaluate(
                        "() => document.querySelector('h1')?.innerText?.trim() || ''"
                    )

                meta_desc = await page.evaluate(
                    "() => document.querySelector('meta[name=\"description\"]')?.getAttribute('content') || ''"
                )
                meta_gen = await page.evaluate(
                    "() => document.querySelector('meta[name=\"generator\"]')?.getAttribute('content') || ''"
                )

                # Check for password inputs and login forms in the DOM
                has_pwd = await page.evaluate(
                    "() => Boolean(document.querySelector('input[type=\"password\"]'))"
                )
                has_login_form = await page.evaluate(
                    """() => {
                        const inputs = Array.from(document.querySelectorAll('input'));
                        const hasUserField = inputs.some(i => {
                            const name = (i.name || i.id || i.placeholder || '').toLowerCase();
                            return name.includes('user') || name.includes('login') || name.includes('email') || name.includes('auth');
                        });
                        const hasPassField = Boolean(document.querySelector('input[type="password"]'));
                        return hasUserField && hasPassField;
                    }"""
                )

                # Capture Viewport Screenshot
                screenshot_filename = _safe_filename(target_url)
                screenshot_full_path = os.path.join(self.screenshots_dir, screenshot_filename)
                
                await page.screenshot(
                    path=screenshot_full_path,
                    full_page=False,
                    type="png",
                    timeout=5000
                )

                rel_screenshot_path = os.path.join("screenshots", screenshot_filename)
                latency = (time.perf_counter() - start_time) * 1000

                return ScanResult(
                    url=target_url,
                    target_host=target.host,
                    target_port=target.port,
                    scheme=target.scheme,
                    resolved_ip=resolved_ip,
                    status_code=status_code or 200,
                    status_text=status_text or "OK",
                    final_url=final_url,
                    redirect_chain=redirect_chain,
                    page_title=title.strip() if title else None,
                    meta_description=meta_desc.strip() if meta_desc else None,
                    meta_generator=meta_gen.strip() if meta_gen else None,
                    screenshot_file=screenshot_filename,
                    screenshot_path=rel_screenshot_path,
                    response_headers=headers_collected,
                    has_password_input=bool(has_pwd),
                    has_login_form=bool(has_login_form),
                    response_time_ms=round(latency, 2)
                )

            except Exception as e:
                latency = (time.perf_counter() - start_time) * 1000
                return ScanResult(
                    url=target_url,
                    target_host=target.host,
                    target_port=target.port,
                    scheme=target.scheme,
                    resolved_ip=resolved_ip,
                    status_code=status_code,
                    error=str(e),
                    response_time_ms=round(latency, 2)
                )
            finally:
                if page:
                    try:
                        await page.close()
                    except Exception:
                        pass
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass

    async def run(
        self,
        targets: List[Target],
        skip_preflight: bool = False
    ) -> List[ScanResult]:
        """
        Run the complete pipeline:
        1. Async pre-flight port and DNS filtering
        2. Parallel Playwright headless browser capture
        """
        active_targets: List[Tuple[Target, Optional[str]]] = []

        if not skip_preflight:
            console.print(f"[cyan]⚡ Probing {len(targets)} candidate endpoints with async TCP pre-flight...[/cyan]")
            probe_tasks = [probe_endpoint(t) for t in targets]
            probe_results: List[ProbeResult] = await asyncio.gather(*probe_tasks)

            for pr in probe_results:
                if pr.is_open:
                    active_targets.append((pr.target, pr.resolved_ip))

            console.print(
                f"[green]✓ Pre-flight complete:[/green] [bold]{len(active_targets)}[/bold] / {len(targets)} endpoints reachable."
            )
        else:
            active_targets = [(t, None) for t in targets]

        if not active_targets:
            console.print("[yellow]⚠️ No active web endpoints discovered.[/yellow]")
            return []

        console.print(f"[cyan]📸 Launching Playwright pool (concurrency={self.concurrency}) for {len(active_targets)} endpoints...[/cyan]")

        results: List[ScanResult] = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=self.headless,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--ignore-certificate-errors",
                    "--disable-gpu"
                ]
            )

            tasks = [
                self.scan_single_target(browser, target, ip)
                for target, ip in active_targets
            ]
            results = await asyncio.gather(*tasks)

            await browser.close()

        return results
