"""
Tests for NetLens-Recon Reporter: HTML dashboard rendering and JSON export.
"""

import json
import os
import tempfile

from src.models import ScanResult, ClusterGroup
from src.reporter import ReconReporter


def test_reporter_export():
    with tempfile.TemporaryDirectory() as tmpdir:
        res1 = ScanResult(
            url="https://admin.example.com",
            target_host="admin.example.com",
            target_port=443,
            scheme="https",
            status_code=200,
            page_title="Internal Admin Portal",
            technologies=["Nginx", "React"],
            hvt_flags=["PASSWORD_INPUT", "ADMIN_PORTAL"],
            is_hvt=True,
            cluster_id=1,
            is_cluster_rep=True,
            cluster_size=1,
            response_time_ms=45.2
        )

        cluster1 = ClusterGroup(
            cluster_id=1,
            representative_hash="1010101010101010",
            representative_url="https://admin.example.com",
            representative_title="Internal Admin Portal",
            members=[res1]
        )

        reporter = ReconReporter(
            template_dir="./templates",
            output_dir=tmpdir
        )

        html_path = reporter.export(
            results=[res1],
            clusters=[cluster1],
            total_targets_supplied=1,
            duration_seconds=1.25
        )

        assert os.path.exists(html_path)
        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "NetLens" in content
            assert "Farhad Jelve" in content
            assert "admin.example.com" in content

        json_path = os.path.join(tmpdir, "results.json")
        assert os.path.exists(json_path)
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert "summary" in data
            assert data["summary"]["high_value_targets_count"] == 1
            assert data["summary"]["unique_visual_clusters"] == 1
            assert len(data["results"]) == 1
            assert data["results"][0]["url"] == "https://admin.example.com"
