"""
NetLens-Recon Reporter Module
Generates self-contained interactive HTML dashboards and structured JSON reports.
Author: Farhad Jelve (CCNP Enterprise, CCNA, B.Sc. EE KTH)
"""

import json
import os
from datetime import datetime
from typing import List, Dict

from jinja2 import Environment, FileSystemLoader

from src.models import ScanResult, ClusterGroup, ScanSummary


class ReconReporter:
    """
    Renders reconnaissance metrics into interactive HTML5/Tailwind dashboard and exports JSON.
    """

    def __init__(self, template_dir: str = "./templates", output_dir: str = "./output"):
        self.template_dir = template_dir
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        self.jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=True
        )

    def generate_summary(
        self,
        results: List[ScanResult],
        clusters: List[ClusterGroup],
        total_targets_supplied: int,
        duration_seconds: float
    ) -> ScanSummary:
        """Compute aggregate statistics across all scanned endpoints."""
        status_dist: Dict[str, int] = {}
        tech_dist: Dict[str, int] = {}
        hvt_count = 0
        successful = 0
        failed = 0

        for r in results:
            if r.status_code:
                key = str(r.status_code)
                status_dist[key] = status_dist.get(key, 0) + 1
                successful += 1
            else:
                status_dist["ERROR"] = status_dist.get("ERROR", 0) + 1
                failed += 1

            if r.is_hvt:
                hvt_count += 1

            for tech in r.technologies:
                tech_dist[tech] = tech_dist.get(tech, 0) + 1

        return ScanSummary(
            total_targets_supplied=total_targets_supplied,
            endpoints_probed=total_targets_supplied,
            endpoints_open=len(results),
            endpoints_scanned=len(results),
            total_successful=successful,
            total_failed=failed,
            high_value_targets_count=hvt_count,
            unique_visual_clusters=len(clusters),
            status_distribution=status_dist,
            tech_distribution=tech_dist,
            duration_seconds=duration_seconds,
            scan_timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        )

    def export(
        self,
        results: List[ScanResult],
        clusters: List[ClusterGroup],
        total_targets_supplied: int,
        duration_seconds: float
    ) -> str:
        """
        Generate both the HTML dashboard and JSON export.
        Returns the absolute path to the generated HTML dashboard.
        """
        summary = self.generate_summary(
            results=results,
            clusters=clusters,
            total_targets_supplied=total_targets_supplied,
            duration_seconds=duration_seconds
        )

        results_data = [r.model_dump() for r in results]
        clusters_data = [c.model_dump() for c in clusters]
        summary_data = summary.model_dump()

        # 1. Export JSON results
        json_path = os.path.join(self.output_dir, "results.json")
        full_export = {
            "summary": summary_data,
            "clusters": clusters_data,
            "results": results_data
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(full_export, f, indent=2)

        # 2. Render HTML Dashboard
        template = self.jinja_env.get_template("report.html")
        rendered_html = template.render(
            summary=summary,
            results=results,
            clusters=clusters,
            results_json=json.dumps(results_data)
        )

        html_path = os.path.join(self.output_dir, "index.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(rendered_html)

        return os.path.abspath(html_path)
