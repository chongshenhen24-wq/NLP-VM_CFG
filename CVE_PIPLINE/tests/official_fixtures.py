"""Small, deterministic official-source bundles used by unit tests."""


def official_bundle(cve="CVE-2026-12345", description="No extra configuration is required.",
                    os_version="22.04", suite="jammy"):
    releases = {
        "20.04": {
            "fixed": "5.4.0-105.119", "meta_fixed": "5.4.0.105.109",
            "meta": "5.4.0.26.32", "release": "5.4.0-26-generic",
        },
        "22.04": {
            "fixed": "5.15.0-100.110", "meta_fixed": "5.15.0.100.110",
            "meta": "5.15.0.25.27", "release": "5.15.0-25-generic",
        },
        "24.04": {
            "fixed": "6.8.0-52.53", "meta_fixed": "6.8.0-52.53",
            "meta": "6.8.0-31.31", "release": "6.8.0-31-generic",
        },
    }
    kernel = releases[os_version]
    publication_url = f"https://launchpad.net/ubuntu/{suite}/amd64/linux-image-generic"
    return {
        "cve": cve,
        "mode": "enrich",
        "description": description,
        "errors": [],
        "sources": [
            {
                "name": "NVD",
                "url": f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds={cve}",
                "description": description,
                "cpe_matches": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                }],
            },
            {
                "name": "CVE.org / CNA record",
                "url": f"https://cveawg.mitre.org/api/cve/{cve}",
                "description": description,
                "affected": [{
                    "vendor": "Linux",
                    "product": "Linux",
                    "versions": [{"version": "4.0", "status": "affected"}],
                }],
            },
            {
                "name": "Ubuntu Security Tracker",
                "url": f"https://ubuntu.com/security/{cve}",
                "excerpt": description,
                "kernel_rows": [{
                    "version": os_version,
                    "suite": suite,
                    "status": "Fixed",
                    "fixed_version": kernel["fixed"],
                }],
                "selected_kernel": {
                    "version": os_version,
                    "suite": suite,
                    "status": "Fixed",
                    "fixed_version": kernel["fixed"],
                    "package": "linux-image-generic",
                    "meta_fixed_version": kernel["meta_fixed"],
                    "meta_url": publication_url,
                    "vulnerable_candidate": {
                        "meta_package": "linux-image-generic",
                        "meta_package_version": kernel["meta"],
                        "concrete_package": "linux-image-" + kernel["release"],
                        "running_kernel_release": kernel["release"],
                        "selection_policy": "explicit test Launchpad publication",
                        "publication_url": publication_url,
                    },
                },
            },
        ],
    }
