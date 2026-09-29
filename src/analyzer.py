"""
NetLens-Recon Analyzer Module
Technology stack fingerprinting, High-Value Target (HVT) heuristic detection,
and Perceptual Image Hashing (dHash) visual clustering.
Author: Farhad Jelve (CCNP Enterprise, CCNA, B.Sc. EE KTH)
"""

import os
import re
from typing import List, Dict, Optional, Tuple
from PIL import Image
import imagehash

from src.models import ScanResult, ClusterGroup


TECH_PATTERNS = {
    # Web Servers
    "Nginx": [r"nginx"],
    "Apache": [r"apache", r"httpd"],
    "Microsoft IIS": [r"microsoft-iis"],
    "LiteSpeed": [r"litespeed"],
    "Caddy": [r"caddy"],
    "Cloudflare": [r"cloudflare"],
    "Envoy": [r"envoy"],
    "OpenResty": [r"openresty"],
    "Gunicorn": [r"gunicorn"],
    "Werkzeug": [r"werkzeug"],
    "Kestrel": [r"kestrel"],

    # Frameworks & Platforms
    "PHP": [r"php"],
    "ASP.NET": [r"asp\.net", r"aspnet"],
    "Express.js": [r"express"],
    "Node.js": [r"node\.js", r"nodejs"],
    "Next.js": [r"next\.js", r"nextjs"],
    "Nuxt": [r"nuxt"],
    "Django": [r"django", r"csrftoken"],
    "Flask": [r"flask", r"werkzeug"],
    "Laravel": [r"laravel", r"laravel_session"],
    "Ruby on Rails": [r"rails", r"rack"],
    "Spring Boot": [r"spring", r"whitelabel error page"],

    # CMS & Applications
    "WordPress": [r"wordpress", r"wp-content", r"wp-includes"],
    "Drupal": [r"drupal"],
    "Joomla": [r"joomla"],
    "Ghost": [r"ghost"],
    "Shopify": [r"shopify"],

    # Frontend Libraries
    "React": [r"react", r"_react"],
    "Vue.js": [r"vue", r"v-data"],
    "Angular": [r"angular", r"ng-"],
    "Bootstrap": [r"bootstrap"],
    "Tailwind CSS": [r"tailwind"],
    "jQuery": [r"jquery"],
}

HVT_SIGNATURES = [
    ("CISCO_WEBUI", [r"cisco", r"adaptive security appliance", r"cisco integrated", r"cisco systems", r"cisco switch", r"cisco router", r"meraki"]),
    ("GRAFANA", [r"grafana"]),
    ("JENKINS", [r"jenkins"]),
    ("PHPMYADMIN", [r"phpmyadmin"]),
    ("SWAGGER_API", [r"swagger", r"openapi", r"api documentation", r"api explorer"]),
    ("SPRING_ACTUATOR", [r"actuator", r"whitelabel error page"]),
    ("KUBERNETES_DOCKER", [r"kubernetes dashboard", r"portainer", r"rancher", r"docker registry"]),
    ("NETWORK_APPLIANCE", [r"pfsense", r"fortigate", r"mikrotik", r"ubiquiti", r"unifi", r"synology", r"\bidrac\b", r"\bilo\b", r"openwrt"]),
    ("IDENTITY_PROVIDER", [r"keycloak", r"\bokta\b", r"auth0", r"azure active directory", r"shibboleth"]),
    ("DATABASE_ADMIN", [r"adminer", r"pgadmin", r"mongo express", r"redis commander"]),
    ("MONITORING", [r"kibana", r"zabbix", r"prometheus", r"nagios", r"prtg", r"checkmk"]),
]


class ReconAnalyzer:
    """
    Analyzes scanned targets for tech stacks, security sensitivities, and visual clusters.
    """

    def __init__(self, cluster_threshold: int = 4, base_dir: str = "./output"):
        self.cluster_threshold = cluster_threshold
        self.base_dir = base_dir

    def fingerprint_technologies(self, result: ScanResult) -> List[str]:
        """Detect underlying tech stack from headers, title, generator, and URL."""
        detected = set()

        text_to_check = []
        if result.page_title:
            text_to_check.append(result.page_title)
        if result.meta_generator:
            text_to_check.append(result.meta_generator)
        if result.meta_description:
            text_to_check.append(result.meta_description)
        text_to_check.append(result.url)

        # Include all HTTP response header keys & values
        for k, v in result.response_headers.items():
            text_to_check.append(f"{k}: {v}")

        combined_text = " ".join(text_to_check).lower()

        for tech, patterns in TECH_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, combined_text, re.IGNORECASE):
                    detected.add(tech)
                    break

        return sorted(list(detected))

    def evaluate_hvt(self, result: ScanResult) -> Tuple[bool, List[str]]:
        """
        Evaluate if endpoint qualifies as a High-Value Target (HVT).
        Checks for login forms, admin interfaces, and sensitive infrastructure portals.
        """
        flags = set()

        # DOM-level login detection
        if result.has_password_input:
            flags.add("PASSWORD_INPUT")
        if result.has_login_form:
            flags.add("LOGIN_PORTAL")

        # Contextual text
        title_lower = (result.page_title or "").lower()
        url_lower = result.url.lower()
        headers_lower = " ".join([f"{k}:{v}" for k, v in result.response_headers.items()]).lower()
        search_blob = f"{title_lower} {url_lower} {headers_lower}"

        # Admin / Login keyword heuristic
        if any(kw in title_lower for kw in ["login", "sign in", "signin", "authenticate", "portal", "admin", "dashboard", "control panel", "management"]):
            if "LOGIN_PORTAL" not in flags and not any(f.endswith("_PANEL") for f in flags):
                flags.add("ADMIN_PORTAL")

        # Specific high-value technology signatures
        for hvt_tag, patterns in HVT_SIGNATURES:
            for pat in patterns:
                if re.search(pat, search_blob, re.IGNORECASE):
                    flags.add(hvt_tag)
                    break

        is_hvt = len(flags) > 0
        return is_hvt, sorted(list(flags))

    def compute_image_hashes(self, results: List[ScanResult]) -> None:
        """Calculate dHash for all results with valid screenshots."""
        for res in results:
            if not res.screenshot_file:
                continue

            full_path = os.path.join(self.base_dir, "screenshots", res.screenshot_file)
            if not os.path.exists(full_path):
                # Try relative if full path not found directly
                full_path = os.path.join(self.base_dir, res.screenshot_file)

            if os.path.exists(full_path):
                try:
                    with Image.open(full_path) as img:
                        # Difference Hash (dHash) is fast, robust to scaling and color shifts
                        dh = imagehash.dhash(img)
                        res.dhash = str(dh)
                except Exception:
                    pass

    def cluster_visuals(self, results: List[ScanResult]) -> List[ClusterGroup]:
        """
        Cluster screenshots using perceptual dHash Hamming distance.
        Groups visual clones (e.g., 50 Cloudflare 404s, generic default web server screens).
        """
        # Ensure hashes are computed
        self.compute_image_hashes(results)

        valid_results = [r for r in results if r.dhash]
        clusters: List[ClusterGroup] = []
        visited = set()
        cluster_counter = 1

        for i, item in enumerate(valid_results):
            if i in visited:
                continue

            visited.add(i)
            item_hash = imagehash.hex_to_hash(item.dhash)

            cluster_members = [item]
            item.cluster_id = cluster_counter
            item.is_cluster_rep = True

            for j in range(i + 1, len(valid_results)):
                if j in visited:
                    continue
                other_item = valid_results[j]
                other_hash = imagehash.hex_to_hash(other_item.dhash)

                # Hamming distance between perceptual hashes
                dist = item_hash - other_hash
                if dist <= self.cluster_threshold:
                    visited.add(j)
                    other_item.cluster_id = cluster_counter
                    other_item.is_cluster_rep = False
                    cluster_members.append(other_item)

            for member in cluster_members:
                member.cluster_size = len(cluster_members)

            group = ClusterGroup(
                cluster_id=cluster_counter,
                representative_hash=item.dhash,
                representative_url=item.url,
                representative_screenshot=item.screenshot_path,
                representative_title=item.page_title,
                members=cluster_members
            )
            clusters.append(group)
            cluster_counter += 1

        return clusters

    def process(self, results: List[ScanResult]) -> List[ClusterGroup]:
        """
        Run complete intelligence pipeline:
        1. Fingerprint technologies
        2. Evaluate High-Value Target (HVT) criteria
        3. Compute dHash & cluster visual duplicates
        """
        for res in results:
            res.technologies = self.fingerprint_technologies(res)
            is_hvt, flags = self.evaluate_hvt(res)
            res.is_hvt = is_hvt
            res.hvt_flags = flags

        clusters = self.cluster_visuals(results)
        return clusters
