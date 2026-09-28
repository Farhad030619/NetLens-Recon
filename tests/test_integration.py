"""
Integration test running a local HTTP server with simulated web assets:
- Login Portal (HVT)
- Swagger UI (HVT)
- Two identical visual clone pages (Cluster deduplication)
"""

import asyncio
import os
import tempfile
import pytest
from aiohttp import web

from src.models import Target
from src.scanner import parse_targets, ReconScanner
from src.analyzer import ReconAnalyzer
from src.reporter import ReconReporter


async def run_mock_server(host="127.0.0.1", port=8899):
    app = web.Application()

    async def handle_login(request):
        html = """<!DOCTYPE html>
        <html>
        <head><title>Secure Enterprise Admin Login</title></head>
        <body style="background:#111; color:#fff; font-family:sans-serif; padding:50px;">
          <h2>Corporate Management Console</h2>
          <form action="/auth" method="POST">
            <input type="text" name="username" placeholder="Username" /><br><br>
            <input type="password" name="password" placeholder="Password" /><br><br>
            <button type="submit">Sign In</button>
          </form>
        </body>
        </html>"""
        return web.Response(text=html, content_type="text/html", headers={"Server": "nginx/1.22.0"})

    async def handle_swagger(request):
        html = """<!DOCTYPE html>
        <html>
        <head><title>Swagger UI - Internal API Documentation</title></head>
        <body style="background:#fff; color:#333; font-family:sans-serif; padding:50px;">
          <h1>Swagger API Specification</h1>
          <p>Endpoints for microservices authentication and routing</p>
        </body>
        </html>"""
        return web.Response(text=html, content_type="text/html", headers={"Server": "Apache/2.4.52", "X-Powered-By": "PHP/8.1"})

    async def handle_clone(request):
        html = """<!DOCTYPE html>
        <html>
        <head><title>Default Server Landing Page</title></head>
        <body style="background:#f0f0f0; color:#333; text-align:center; padding:100px;">
          <h1>Under Construction</h1>
          <p>This web domain has been registered and is currently reserved.</p>
        </body>
        </html>"""
        return web.Response(text=html, content_type="text/html")

    app.router.add_get("/login", handle_login)
    app.router.add_get("/swagger", handle_swagger)
    app.router.add_get("/clone1", handle_clone)
    app.router.add_get("/clone2", handle_clone)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    return runner


@pytest.mark.asyncio
async def test_full_pipeline_mock_server():
    port = 8899
    runner = await run_mock_server(port=port)

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            targets = parse_targets([
                f"http://127.0.0.1:{port}/login",
                f"http://127.0.0.1:{port}/swagger",
                f"http://127.0.0.1:{port}/clone1",
                f"http://127.0.0.1:{port}/clone2",
            ])

            scanner = ReconScanner(
                concurrency=4,
                page_timeout_sec=5.0,
                output_dir=tmpdir,
                headless=True
            )

            results = await scanner.run(targets, skip_preflight=True)
            assert len(results) == 4

            # Run Intelligence Analysis
            analyzer = ReconAnalyzer(cluster_threshold=4, base_dir=tmpdir)
            clusters = analyzer.process(results)

            # Check HVT detection
            login_res = next(r for r in results if "login" in r.url)
            assert login_res.is_hvt is True
            assert "PASSWORD_INPUT" in login_res.hvt_flags or "LOGIN_PORTAL" in login_res.hvt_flags
            assert "Nginx" in login_res.technologies

            swagger_res = next(r for r in results if "swagger" in r.url)
            assert swagger_res.is_hvt is True
            assert "SWAGGER_API" in swagger_res.hvt_flags
            assert "Apache" in swagger_res.technologies
            assert "PHP" in swagger_res.technologies

            # Check Visual Deduplication: clone1 and clone2 should share the same cluster
            clone1_res = next(r for r in results if "clone1" in r.url)
            clone2_res = next(r for r in results if "clone2" in r.url)
            assert clone1_res.cluster_id == clone2_res.cluster_id
            assert clone1_res.cluster_size == 2

            # Check Reporter output
            reporter = ReconReporter(template_dir="./templates", output_dir=tmpdir)
            html_path = reporter.export(results, clusters, total_targets_supplied=4, duration_seconds=2.5)
            assert os.path.exists(html_path)
            assert os.path.exists(os.path.join(tmpdir, "results.json"))

        finally:
            await runner.cleanup()
