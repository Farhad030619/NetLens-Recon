"""
Tests for NetLens-Recon Analyzer: Tech Fingerprinting, HVT Detection, and dHash Visual Clustering.
"""

import os
import tempfile
import pytest
from PIL import Image, ImageDraw

from src.models import ScanResult
from src.analyzer import ReconAnalyzer


def test_tech_fingerprinting():
    analyzer = ReconAnalyzer()

    # Case 1: Nginx + React + Express
    res1 = ScanResult(
        url="https://app.example.com",
        target_host="app.example.com",
        target_port=443,
        scheme="https",
        response_headers={
            "server": "nginx/1.24.0",
            "x-powered-by": "Express"
        },
        page_title="React Admin Dashboard"
    )
    techs = analyzer.fingerprint_technologies(res1)
    assert "Nginx" in techs
    assert "Express.js" in techs
    assert "React" in techs


def test_hvt_detection():
    analyzer = ReconAnalyzer()

    # Case 1: Password input in DOM
    res1 = ScanResult(
        url="https://portal.example.com/login",
        target_host="portal.example.com",
        target_port=443,
        scheme="https",
        has_password_input=True,
        page_title="Corporate Authentication Portal"
    )
    is_hvt, flags = analyzer.evaluate_hvt(res1)
    assert is_hvt is True
    assert "PASSWORD_INPUT" in flags
    assert "ADMIN_PORTAL" in flags

    # Case 2: Cisco WebUI
    res2 = ScanResult(
        url="https://vpn.example.com",
        target_host="vpn.example.com",
        target_port=443,
        scheme="https",
        page_title="Cisco Adaptive Security Appliance (ASA) Clientless SSL VPN"
    )
    is_hvt, flags = analyzer.evaluate_hvt(res2)
    assert is_hvt is True
    assert "CISCO_WEBUI" in flags

    # Case 3: Swagger UI
    res3 = ScanResult(
        url="http://api.example.com/swagger-ui/",
        target_host="api.example.com",
        target_port=80,
        scheme="http",
        page_title="Swagger UI - Internal Microservices"
    )
    is_hvt, flags = analyzer.evaluate_hvt(res3)
    assert is_hvt is True
    assert "SWAGGER_API" in flags

    # Case 4: Benign blog
    res4 = ScanResult(
        url="https://blog.example.com",
        target_host="blog.example.com",
        target_port=443,
        scheme="https",
        page_title="Farhad's Tech Blog"
    )
    is_hvt, flags = analyzer.evaluate_hvt(res4)
    assert is_hvt is False
    assert len(flags) == 0


def test_visual_clustering():
    with tempfile.TemporaryDirectory() as tmpdir:
        screenshots_dir = os.path.join(tmpdir, "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)

        # Create two visually identical blue images
        img1_path = os.path.join(screenshots_dir, "page1.png")
        img2_path = os.path.join(screenshots_dir, "page2.png")
        # And one distinct red image with shapes
        img3_path = os.path.join(screenshots_dir, "page3.png")

        im_blue = Image.new("RGB", (200, 200), color=(10, 40, 90))
        im_blue.save(img1_path)
        im_blue.save(img2_path)

        im_red = Image.new("RGB", (200, 200), color=(220, 20, 20))
        draw = ImageDraw.Draw(im_red)
        draw.rectangle([10, 10, 100, 100], fill=(255, 255, 0))
        im_red.save(img3_path)

        res1 = ScanResult(
            url="http://node1.example.com",
            target_host="node1.example.com",
            target_port=80,
            scheme="http",
            screenshot_file="page1.png",
            screenshot_path="screenshots/page1.png"
        )
        res2 = ScanResult(
            url="http://node2.example.com",
            target_host="node2.example.com",
            target_port=80,
            scheme="http",
            screenshot_file="page2.png",
            screenshot_path="screenshots/page2.png"
        )
        res3 = ScanResult(
            url="http://node3.example.com",
            target_host="node3.example.com",
            target_port=80,
            scheme="http",
            screenshot_file="page3.png",
            screenshot_path="screenshots/page3.png"
        )

        analyzer = ReconAnalyzer(cluster_threshold=4, base_dir=tmpdir)
        clusters = analyzer.cluster_visuals([res1, res2, res3])

        # We should have 2 clusters: {res1, res2} and {res3}
        assert len(clusters) == 2
        # res1 and res2 must share cluster_id
        assert res1.cluster_id == res2.cluster_id
        assert res1.cluster_size == 2
        assert res2.cluster_size == 2
        assert res1.is_cluster_rep is True
        assert res2.is_cluster_rep is False

        # res3 should have a different cluster id
        assert res3.cluster_id != res1.cluster_id
        assert res3.cluster_size == 1
        assert res3.is_cluster_rep is True
