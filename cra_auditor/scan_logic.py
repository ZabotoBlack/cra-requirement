import nmap
import re
import requests
import socket
import logging
import os
import time
import threading
from datetime import datetime
import yaml
import urllib3
from vulnerability_data import NVDClient, VendorRules, build_cpe, match_cpe

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    _DNSPYTHON_AVAILABLE = True
except ImportError:
    _DNSPYTHON_AVAILABLE = False

try:
    from zeroconf import ServiceBrowser, Zeroconf
    _ZEROCONF_AVAILABLE = True
except Exception:
    ServiceBrowser = None
    Zeroconf = None
    _ZEROCONF_AVAILABLE = False

logger = logging.getLogger(__name__)

SCAN_INFO = 15
logging.addLevelName(SCAN_INFO, "SCAN_INFO")


class ScanAbortedError(RuntimeError):
    """Raised when a scan is canceled by user action or timeout."""


def _log_scan_info(message, *args, **kwargs):
    logger.log(SCAN_INFO, message, *args, **kwargs)

# Pre-compiled regex for NetBIOS hostname extraction (performance)
_NBSTAT_RE = re.compile(r"NetBIOS name:\s+([\w-]+)")

# Pre-compiled regex for generic firmware version extraction from HTTP content
_FW_VERSION_RE = re.compile(
    r'(?:firmware|fw|version|ver|software|sw)[:\s_=-]*v?(\d+\.\d+[\w./-]*)',
    re.IGNORECASE,
)

_GENERIC_HOSTNAME_RE = re.compile(
    r'^(?:ip|host|dhcp|unknown)[-_]?(?:\d+[-_]){2,}\d+$',
    re.IGNORECASE,
)

_MDNS_SERVICE_TYPES = (
    '_workstation._tcp.local.',
    '_http._tcp.local.',
    '_ipp._tcp.local.',
    '_printer._tcp.local.',
    '_airplay._tcp.local.',
    '_hap._tcp.local.',
    '_googlecast._tcp.local.',
)

_DEFAULT_SECURITY_LOG_PATHS = [
    '/api/logs',
    '/logs',
    '/admin/logs',
    '/syslog',
    '/journal',
    '/cgi-bin/log.cgi',
]

_SCAN_PROFILES = {
    "discovery": {
        "network_discovery": True,
        "port_scan": False,
        "os_detection": False,
        "service_version": False,
        "netbios_info": False,
        "compliance_checks": False,
        "auth_brute_force": False,
        "web_crawling": False,
        "port_range": "1-100",
    },
    "standard": {
        "network_discovery": True,
        "port_scan": True,
        "os_detection": False,
        "service_version": True,
        "netbios_info": True,
        "compliance_checks": True,
        "auth_brute_force": False,
        "web_crawling": True,
        "port_range": "1-100",
    },
    "deep": {
        "network_discovery": True,
        "port_scan": True,
        "os_detection": True,
        "service_version": True,
        "netbios_info": True,
        "compliance_checks": True,
        "auth_brute_force": True,
        "web_crawling": True,
        "port_range": "1-1024",
    },
}


class MDNSResolver:
    def __init__(self):
        self.enabled = _ZEROCONF_AVAILABLE

    def discover(self, timeout=5, service_types=None):
        if not self.enabled:
            return {}

        service_types = service_types or list(_MDNS_SERVICE_TYPES)
        discovered = {}
        lock = threading.Lock()

        class _Listener:
            def _process(self, zeroconf_client, service_type, service_name):
                try:
                    info = zeroconf_client.get_service_info(service_type, service_name, timeout=2000)
                except Exception:
                    return

                if not info:
                    return

                hostnames = []
                if getattr(info, 'server', None):
                    hostnames.append(str(info.server).strip().rstrip('.'))

                if isinstance(service_name, str):
                    label = service_name.split('.', 1)[0].strip()
                    if label:
                        hostnames.append(f"{label}.local")

                try:
                    addresses = info.parsed_addresses() or []
                except Exception:
                    addresses = []

                for address in addresses:
                    if not address:
                        continue
                    with lock:
                        host_bucket = discovered.setdefault(address, set())
                        for hostname in hostnames:
                            cleaned = str(hostname).strip().rstrip('.')
                            if cleaned:
                                host_bucket.add(cleaned)

            def add_service(self, zeroconf_client, service_type, service_name):
                self._process(zeroconf_client, service_type, service_name)

            def update_service(self, zeroconf_client, service_type, service_name):
                self._process(zeroconf_client, service_type, service_name)

            def remove_service(self, zeroconf_client, service_type, service_name):
                try:
                    try:
                        info = zeroconf_client.get_service_info(service_type, service_name, timeout=2000)
                    except Exception:
                        info = None

                    hostnames = []
                    if info and getattr(info, 'server', None):
                        hostnames.append(str(info.server).strip().rstrip('.'))

                    if isinstance(service_name, str):
                        label = service_name.split('.', 1)[0].strip()
                        if label:
                            hostnames.append(f"{label}.local")

                    addresses = []
                    if info:
                        try:
                            addresses = info.parsed_addresses() or []
                        except Exception:
                            addresses = []

                    for address in addresses:
                        if not address:
                            continue
                        with lock:
                            existing_hostnames = discovered.get(address)
                            if not existing_hostnames:
                                continue

                            for hostname in hostnames:
                                cleaned = str(hostname).strip().rstrip('.')
                                if cleaned:
                                    existing_hostnames.discard(cleaned)

                            if not existing_hostnames:
                                discovered.pop(address, None)
                except Exception:
                    return

        try:
            zeroconf_client = Zeroconf()
        except Exception:
            logger.debug("mDNS resolver initialization failed.", exc_info=True)
            return {}

        try:
            listener = _Listener()
            browsers = []
            for service_type in service_types:
                try:
                    browsers.append(ServiceBrowser(zeroconf_client, service_type, listener))
                except Exception:
                    logger.debug("mDNS service browse failed for %s", service_type, exc_info=True)

            if browsers:
                time.sleep(max(0.0, float(timeout)))
        finally:
            try:
                zeroconf_client.close()
            except Exception:
                pass

        return {
            ip: sorted(hostnames)
            for ip, hostnames in discovered.items()
            if hostnames
        }

class CRAScanner:
    def __init__(self):
        self.nm = None
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            logger.error("Nmap not found", exc_info=True)
        except Exception:
            logger.error("Unexpected error initializing nmap", exc_info=True)
            
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            logger.warning("Agent is NOT running as root. ARP scanning and MAC address detection will likely fail. Ensure NET_RAW/NET_ADMIN capabilities are configured in config.yaml.")
        else:
            logger.info("Agent is running as root/privileged. ARP scanning and MAC address detection enabled.")
            
        self.common_creds = [('admin', 'admin'), ('root', 'root'), ('user', '1234'), ('admin', '1234')]
        self.verify_ssl = self._resolve_verify_ssl()
        self.nvd_client = NVDClient(api_key=os.environ.get('NVD_API_KEY'))
        self.vendor_rules = VendorRules()
        self.security_log_paths = self._load_security_log_paths()
        self.mdns_resolver = MDNSResolver()

        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.info("SSL certificate verification disabled for HTTP probes (verify_ssl=False).")
        else:
            logger.info("SSL certificate verification enabled for HTTP probes (verify_ssl=True).")

        # Reuse a single requests.Session for connection pooling (performance)
        self.session = requests.Session()
        
        # Add retry logic for transient network failures (disabled for connect/read to prevent scan hangs on offline IPs)
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        retries = Retry(total=2, connect=False, read=False, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        self.session.verify = self.verify_ssl

    def _resolve_verify_ssl(self):
        """Resolve SSL verification behavior from env/config with safe fallback.

        Priority:
        1) CRA_VERIFY_SSL / VERIFY_SSL environment variable (set via add-on options)
        2) config.yaml option: options.verify_ssl
        3) default False (backward-compatible behavior)
        """
        env_value = os.environ.get('CRA_VERIFY_SSL')
        if env_value is None:
            env_value = os.environ.get('VERIFY_SSL')

        if env_value is not None:
            return str(env_value).strip().lower() in {'1', 'true', 'yes', 'on'}

        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        try:
            with open(config_path, 'r', encoding='utf-8') as handle:
                parsed = yaml.safe_load(handle) or {}
            options = parsed.get('options', {}) if isinstance(parsed, dict) else {}
            if isinstance(options, dict) and 'verify_ssl' in options:
                return bool(options.get('verify_ssl'))
        except Exception:
            logger.debug("Unable to read verify_ssl from config.yaml; using default False.", exc_info=True)

        return False

    def _load_security_log_paths(self):
        """Load HTTP logging probe paths from YAML config with safe defaults.

        Config format (YAML):
            log_paths:
              - /api/logs
              - /logs
        """
        config_path = os.environ.get(
            'CRA_SECURITY_LOG_PATHS_FILE',
            os.path.join(os.path.dirname(__file__), 'data', 'security_logging_paths.yaml')
        )

        try:
            if not os.path.exists(config_path):
                return list(_DEFAULT_SECURITY_LOG_PATHS)

            with open(config_path, 'r', encoding='utf-8') as handle:
                parsed = yaml.safe_load(handle) or {}

            raw_paths = parsed.get('log_paths', []) if isinstance(parsed, dict) else []
            if not isinstance(raw_paths, list):
                logger.warning("Security logging path config invalid format at %s; using defaults.", config_path)
                return list(_DEFAULT_SECURITY_LOG_PATHS)

            cleaned_paths = []
            for path in raw_paths:
                if not isinstance(path, str):
                    continue
                normalized = path.strip()
                if not normalized:
                    continue
                if not normalized.startswith('/'):
                    normalized = '/' + normalized
                cleaned_paths.append(normalized)

            if not cleaned_paths:
                logger.warning("Security logging path config empty at %s; using defaults.", config_path)
                return list(_DEFAULT_SECURITY_LOG_PATHS)

            return cleaned_paths
        except Exception:
            logger.error("Failed to load security logging path config from %s; using defaults.", config_path, exc_info=True)
            return list(_DEFAULT_SECURITY_LOG_PATHS)

    def _resolve_device_cpe(self, vendor: str, product: str | None = None, version: str | None = None):
        """Build and resolve a canonical CPE for a device/vendor tuple."""
        if not vendor or vendor == "Unknown":
            return None

        vendor_clean = vendor.split('(')[0].strip()
        product_name = (product or vendor_clean).strip() or vendor_clean
        cpe_candidate = build_cpe(vendor_clean, product_name, version or "*")
        return match_cpe(cpe_candidate, self.nvd_client)

    def _resolve_scan_features(self, options):
        """Resolve effective profile and feature flags from mixed legacy/new options."""
        options = options or {}

        requested_profile = (
            options.get('profile')
            or options.get('scan_type')
            or options.get('type')
            or 'deep'
        )
        profile_name = str(requested_profile).strip().lower()
        if profile_name not in _SCAN_PROFILES:
            profile_name = 'deep'

        features = dict(_SCAN_PROFILES[profile_name])

        raw_features = options.get('features')
        if not isinstance(raw_features, dict):
            raw_features = {}

        feature_flag_keys = {key for key in _SCAN_PROFILES['deep'].keys() if key != 'port_range'}
        for key in feature_flag_keys:
            if key in options and isinstance(options.get(key), bool):
                features[key] = options.get(key)
            if key in raw_features and isinstance(raw_features.get(key), bool):
                features[key] = raw_features.get(key)

        if 'port_range' in raw_features:
            features['port_range'] = raw_features.get('port_range')
        if 'port_range' in options:
            features['port_range'] = options.get('port_range')

        # Backward compatibility: old auth_checks maps to auth_brute_force feature
        if 'auth_checks' in options and isinstance(options.get('auth_checks'), bool):
            features['auth_brute_force'] = options.get('auth_checks')

        # Discovery profile is strict discovery-only by design.
        if profile_name == 'discovery':
            features['port_scan'] = False
            features['compliance_checks'] = False

        # Discovery stage is mandatory for this scanner architecture.
        if not features.get('network_discovery', True):
            logger.warning("[SCAN] network_discovery cannot be disabled; forcing enabled.")
            features['network_discovery'] = True

        return profile_name, features

    def _skipped_check_result(self, reason):
        """Build a standard check result payload for intentionally skipped checks."""
        return {"passed": True, "details": f"Skipped: {reason}."}

    def _build_vendor_ports(self, selected_vendors):
        """Return vendor-specific ports to append for targeted service discovery."""
        if selected_vendors is None:
            selected_vendors = []
        vendor_ports = []
        if selected_vendors == 'all' or 'tuya' in selected_vendors:
            vendor_ports.append('6668')
        if selected_vendors == 'all' or 'sonoff' in selected_vendors:
            vendor_ports.append('8081')
        if selected_vendors == 'all' or 'kasa' in selected_vendors:
            vendor_ports.append('9999')
        return vendor_ports

    def _normalize_port(self, port_value):
        """Normalize a port value to int, returning None when invalid."""
        try:
            return int(port_value)
        except (TypeError, ValueError):
            return None

    def _collect_http_ports(self, open_ports):
        """Collect unique HTTP/HTTPS management ports from open port metadata."""
        ports = set()
        for port_info in open_ports or []:
            if not isinstance(port_info, dict):
                continue

            port = self._normalize_port(port_info.get('port'))
            service = str(port_info.get('service', '')).lower()

            if port in (80, 443, 8080, 8443) or service in ('http', 'https'):
                if port is not None:
                    ports.add(port)

        return sorted(ports)

    def scan_subnet(self, subnet, options=None, progress_callback=None, should_abort=None):
        """
        Scans the given subnet using profile-driven modular stages.

        Supported option styles:
        - Legacy: {"scan_type": "discovery|standard|deep", "auth_checks": bool, "vendors": ...}
        - New: {
            "profile": "discovery|standard|deep",
            "features": {
                "network_discovery": bool,
                "port_scan": bool,
                "os_detection": bool,
                "service_version": bool,
                "netbios_info": bool,
                "compliance_checks": bool,
                "auth_brute_force": bool,
                "web_crawling": bool
            }
        }
        """
        options = options or {}
        scan_type, features = self._resolve_scan_features(options)
        selected_vendors = options.get('vendors', 'all')  # 'all' or list of strings

        completed_checks = 0
        total_checks = 1  # initialization

        def _emit_progress(stage: str, message: str, *, set_total: int | None = None, increment: bool = False):
            nonlocal completed_checks, total_checks
            if set_total is not None:
                total_checks = max(0, int(set_total))
            if increment:
                completed_checks += 1
            if not callable(progress_callback):
                return
            progress_callback({
                "completed": completed_checks,
                "total": total_checks,
                "stage": stage,
                "message": message,
            })

        def _abort_if_requested():
            if not callable(should_abort):
                return
            abort_reason = should_abort()
            if abort_reason:
                raise ScanAbortedError(str(abort_reason))

        scan_start = time.time()
        total_stages = 1  # discovery
        if features.get('port_scan'):
            total_stages += 1
        total_stages += 1  # merge
        if features.get('compliance_checks'):
            total_stages += 1

        _emit_progress('initializing', 'Initializing scan context', set_total=total_stages)
        _abort_if_requested()

        logger.info("[SCAN] " + "=" * 56)
        logger.info(
            "[SCAN] Starting scan on %s (profile=%s, features=%s, vendors=%s)",
            subnet,
            scan_type,
            features,
            selected_vendors,
        )
        logger.info("[SCAN] " + "-" * 56)

        ha_devices = self._get_ha_devices()

        # Scanned devices accumulator (IP -> Device Dict)
        scanned_devices = {}

        # Stage 1: Discovery Scan (Ping + ARP)
        current_stage = 1
        _emit_progress('discovery', f'Starting discovery stage ({current_stage}/{total_stages})')
        _abort_if_requested()
        if self.nm and features.get('network_discovery'):
            logger.info("[SCAN] Stage %s/%s: Discovery scan (-sn -PR)...", current_stage, total_stages)
            stage_start = time.time()
            try:
                self.nm.scan(hosts=subnet, arguments='-sn -PR')
                self._update_scanned_devices(scanned_devices, discovery_phase=True)
            except Exception as e:
                logger.error("[SCAN] Nmap discovery scan failed: %s", e)
                logger.debug("[SCAN] Discovery scan traceback", exc_info=True)
            stage_elapsed = time.time() - stage_start
            logger.info("[SCAN]   Found %s live hosts in %.1fs", len(scanned_devices), stage_elapsed)
            for ip, dev in scanned_devices.items():
                _log_scan_info(
                    "[SCAN]   -> %s (MAC: %s, vendor: %s)",
                    ip,
                    dev.get('mac', 'Unknown'),
                    dev.get('vendor', 'Unknown'),
                )
        elif not self.nm:
            logger.error("[SCAN] Nmap not initialized. Falling back to Home Assistant-only merge.")
            # Avoid expensive/low-value compliance probes when discovery cannot run.
            features['port_scan'] = False
            features['compliance_checks'] = False
        else:
            logger.info("[SCAN] Stage %s/%s: Discovery disabled by feature flags (skipped).", current_stage, total_stages)
        _emit_progress('discovery', f'Discovery stage complete ({len(scanned_devices)} hosts)', increment=True)
        _abort_if_requested()

        hosts_to_scan = list(scanned_devices.keys())
        mdns_hostnames = {}

        if hosts_to_scan:
            mdns_hostnames = self._discover_mdns_hostnames(timeout=5)

        nmap_devices = []

        # Optional Stage 2: Detailed Scan
        current_stage += 1
        _emit_progress('detailed_scan', f'Starting detailed scan stage ({current_stage}/{total_stages})')
        _abort_if_requested()
        if hosts_to_scan and features.get('port_scan') and self.nm:
            logger.info("[SCAN] Stage %s/%s: Detailed port scan on %s hosts...", current_stage, total_stages, len(hosts_to_scan))
            stage_start = time.time()

            target_spec = " ".join(hosts_to_scan)

            nmap_args = "-Pn -T4 --max-retries 1 --host-timeout 10m"
            if features.get('service_version'):
                nmap_args += " -sV --version-light"
            if features.get('os_detection'):
                nmap_args += " -O --osscan-limit --max-os-tries 1"
            if features.get('netbios_info'):
                nmap_args += " --script=nbstat"

            port_spec = str(features.get('port_range') or "1-100")
            vendor_ports = self._build_vendor_ports(selected_vendors)
            if vendor_ports:
                port_spec += "," + ",".join(vendor_ports)
            nmap_args += f" -p {port_spec}"
            
            try:
                _log_scan_info("[SCAN]   Nmap args: %s", nmap_args)
                self.nm.scan(hosts=target_spec, arguments=nmap_args)
                self._update_scanned_devices(scanned_devices, discovery_phase=False)
                stage_elapsed = time.time() - stage_start
                logger.info("[SCAN]   Completed in %.1fs -- updated %s devices", stage_elapsed, len(scanned_devices))
            except Exception as e:
                logger.error(
                    "[SCAN] Nmap detail scan failed: %s. Falling back to discovery results (%s devices).",
                    e,
                    len(scanned_devices),
                )
                logger.debug("[SCAN] Detailed scan traceback", exc_info=True)
        elif features.get('port_scan') and not hosts_to_scan:
            logger.info("[SCAN] Stage %s/%s: Detailed scan skipped (no discovered hosts).", current_stage, total_stages)
        elif not features.get('port_scan'):
            logger.info("[SCAN] Stage %s/%s: Detailed scan disabled by profile/features.", current_stage, total_stages)
        _emit_progress('detailed_scan', 'Detailed scan stage complete', increment=True)
        _abort_if_requested()

        if scanned_devices:
            self._enrich_hostnames(scanned_devices, mdns_hostnames)
        
        nmap_devices = list(scanned_devices.values())

        # Stage: HA Merge
        current_stage += 1
        _emit_progress('merge', f'Starting Home Assistant merge stage ({current_stage}/{total_stages})')
        _abort_if_requested()
        logger.info("[SCAN] Stage %s/%s: Merging with Home Assistant devices...", current_stage, total_stages)
        merged_devices = self._merge_devices(nmap_devices, ha_devices)
        scan_timestamp = datetime.now().isoformat()
        _emit_progress('merge', f'Merge stage complete ({len(merged_devices)} devices)', increment=True)
        _abort_if_requested()

        # Optional Stage: Compliance checks
        current_stage += 1
        total_devices = len(merged_devices)
        final_results = []

        if not features.get('compliance_checks'):
            logger.info("[SCAN] Stage %s/%s: Compliance checks disabled by profile/features.", current_stage, total_stages)
            _emit_progress('compliance', 'Compliance checks skipped by profile', increment=True)
            for dev in merged_devices:
                dev.update({
                    "status": "Discovered",
                    "checks": {},
                    "attackSurface": self.calculate_attack_surface_score(dev.get('openPorts', [])),
                    "lastScanned": scan_timestamp
                })
                final_results.append(dev)
        else:
            total_checks = max(total_checks, completed_checks + total_devices)
            _emit_progress('compliance', f'Starting compliance checks on {total_devices} devices', set_total=total_checks)
            logger.info("[SCAN] Stage %s/%s: Compliance checks on %s devices...", current_stage, total_stages, total_devices)
            stage_start = time.time()

            for idx, dev in enumerate(merged_devices, 1):
                _abort_if_requested()
                check_vendor = dev.get('model') if dev.get('model') and dev.get('model') != "Unknown" else dev.get('vendor', 'Unknown')
                if dev.get('manufacturer') and dev.get('manufacturer') != "Unknown":
                    check_vendor = f"{dev['manufacturer']} {check_vendor}"
                if check_vendor == "Unknown " or check_vendor.strip() == "Unknown":
                    check_vendor = dev.get('vendor', 'Unknown')

                dev_label = dev.get('hostname') or dev.get('ip', 'Unknown')
                _log_scan_info(
                    "[SCAN]   [%s/%s] %s (%s) - %s",
                    idx,
                    total_devices,
                    dev.get('ip', 'N/A'),
                    check_vendor,
                    dev_label,
                )

                # Set resolved vendor for SBOM/firmware checks to use enriched data
                dev['resolved_vendor'] = check_vendor

                sbd_result = self._skipped_check_result("auth brute-force checks disabled")
                if features.get('auth_brute_force'):
                    sbd_result = self.check_secure_by_default(dev)

                attack_surface = self.calculate_attack_surface_score(dev.get('openPorts', []))

                if features.get('web_crawling'):
                    https_result = self.check_https_redirect(dev)
                    sbom_result = self.check_sbom_compliance(dev)
                    fw_result = self.check_firmware_tracking(dev)
                    sec_txt_result = self.check_security_txt(dev)
                    sec_log_result = self.check_security_logging(dev)
                    conf_result = self.check_confidentiality(
                        dev.get('openPorts', []),
                        https_redirect_result=https_result,
                    )
                else:
                    https_result = self._skipped_check_result("web crawling disabled")
                    sbom_result = self._skipped_check_result("web crawling disabled")
                    fw_result = self._skipped_check_result("web crawling disabled")
                    sec_txt_result = self._skipped_check_result("web crawling disabled")
                    sec_log_result = self._skipped_check_result("web crawling disabled")
                    conf_result = self.check_confidentiality(dev.get('openPorts', []))

                vuln_result = self.check_vulnerabilities(check_vendor, dev.get('openPorts', []))

                # Vendor specific probes are considered part of active web/auth probing.
                vendor_warnings = []
                if features.get('web_crawling'):
                    vendor_warnings = self._check_vendor_specifics(dev, selected_vendors)

                if vendor_warnings:
                    if sbd_result['details'].startswith("Skipped"):
                        sbd_result['details'] = ""
                    sep = " " if sbd_result['details'] else ""
                    sbd_result['details'] += sep + "; ".join(vendor_warnings)
                    sbd_result['passed'] = False
                    
                mas_result = self.check_minimal_attack_surface(dev)

                status = "Compliant"
                if not sbd_result['passed'] or not https_result['passed'] or not vuln_result['passed'] or (not fw_result['passed'] and fw_result.get('version_cves')):
                    status = "Non-Compliant"
                elif not mas_result['passed']:
                    # Minimal Attack Surface failures are grounds for strict non-compliance under CRA requirements
                    status = "Non-Compliant"
                elif not conf_result['passed'] or not sbom_result['passed'] or not fw_result['passed'] or not sec_txt_result['passed'] or not sec_log_result['passed']:
                    status = "Warning"
                elif attack_surface['rating'] == "High":
                    status = "Warning"

                _p = lambda r: "pass" if r.get('passed') else "FAIL"
                _log_scan_info(
                    f"[SCAN]     Secure={_p(sbd_result)}  Confid={_p(conf_result)}  "
                    f"AttackSurface={attack_surface['rating']}({attack_surface['openPortsCount']})  "
                    f"MinSurface={_p(mas_result)}  "
                    f"HTTPS={_p(https_result)}  CVE={_p(vuln_result)}  SBOM={_p(sbom_result)}  "
                    f"FW={_p(fw_result)}  SecTxt={_p(sec_txt_result)}  SecLog={_p(sec_log_result)}  => {status}"
                )

                dev.update({
                    "status": status,
                    "attackSurface": attack_surface,
                    "checks": {
                        "secureByDefault": sbd_result,
                        "dataConfidentiality": conf_result,
                        "httpsOnlyManagement": https_result,
                        "vulnerabilities": vuln_result,
                        "sbomCompliance": sbom_result,
                        "firmwareTracking": fw_result,
                        "securityTxt": sec_txt_result,
                        "securityLogging": sec_log_result,
                        "minimalAttackSurface": mas_result
                    },
                    "lastScanned": scan_timestamp
                })
                final_results.append(dev)
                _emit_progress(
                    'compliance',
                    f'Completed checks for {dev.get("ip", "unknown")} ({idx}/{total_devices})',
                    increment=True,
                )

            stage_elapsed = time.time() - stage_start
            logger.info("[SCAN]   Compliance checks completed in %.1fs", stage_elapsed)

        total_elapsed = time.time() - scan_start

        # Final summary
        compliant = sum(1 for d in final_results if d.get('status') == 'Compliant')
        warning = sum(1 for d in final_results if d.get('status') == 'Warning')
        non_compliant = sum(1 for d in final_results if d.get('status') == 'Non-Compliant')
        discovered = sum(1 for d in final_results if d.get('status') == 'Discovered')
        logger.info("[SCAN] " + "=" * 56)
        logger.info(
            "[SCAN] Scan complete: %s devices (%s Compliant, %s Warning, %s Non-Compliant, %s Discovered) in %.1fs",
            len(final_results),
            compliant,
            warning,
            non_compliant,
            discovered,
            total_elapsed,
        )
        _emit_progress('complete', 'Scan complete', set_total=max(total_checks, completed_checks), increment=False)
        return final_results

    def _update_scanned_devices(self, scanned_devices, discovery_phase=False):
        """Helper to parse nmap results and update the devices dict."""
        for host in self.nm.all_hosts():
            # Filter out if no addresses found (rare but possible)
            if 'addresses' not in self.nm[host]:
                continue
                
            nmap_host = self.nm[host]
            # Use bracket access as existing tests mock __getitem__ but not .get()
            addresses = nmap_host['addresses']
            
            mac = addresses.get('mac', 'Unknown')
            ip = host
            if 'ipv4' in addresses:
                ip = addresses.get('ipv4')
            
            # If this is the second pass (detailed), we might already have this device.
            existing = scanned_devices.get(ip)
            
            # Hostname Resolution
            hostname = nmap_host.hostname()
            if not hostname and 'script' in nmap_host:
                # Try to extract from nbstat
                if 'nbstat' in nmap_host['script']:
                    match = _NBSTAT_RE.search(nmap_host['script']['nbstat'])
                    if match:
                        hostname = match.group(1)

            if not hostname and existing and existing.get('hostname'):
                # Keep existing hostname if new one is empty
                hostname = existing.get('hostname')
            # Vendor
            vendor = "Unknown"
            if 'vendor' in nmap_host and mac != 'Unknown' and mac in nmap_host['vendor']:
                    vendor = nmap_host['vendor'][mac]
            
            os_name = self._get_os_match(host)
            open_ports = self._get_open_ports(host)
            
            # MERGE LOGIC: preserve existing data if new scan is incomplete
            if existing:
                if mac == 'Unknown' and existing.get('mac') != 'Unknown':
                    mac = existing.get('mac')
                
                if vendor == "Unknown" and existing.get('vendor') != "Unknown":
                    vendor = existing.get('vendor')
                
                if not hostname and existing.get('hostname'):
                    hostname = existing.get('hostname')
                
                if os_name == "Unknown" and existing.get('osMatch', "Unknown") != "Unknown":
                    os_name = existing.get('osMatch')
                
                # Ports: Detailed scan is usually authoritative.
                # But if detailed scan returned nothing (e.g. failed/filtered) AND we had ports (unlikely for discovery but consistent logic), we could keep.
                # For now, we assume detailed scan overwrite for ports is acceptable as discovery has none.

            device_data = {
                "ip": ip,
                "mac": mac,
                "vendor": vendor, 
                "hostname": hostname,
                "openPorts": open_ports,
                "osMatch": os_name,
                "source": "nmap"
            }
            
            scanned_devices[ip] = device_data

    def _discover_mdns_hostnames(self, timeout=5):
        """Run mDNS discovery and return IP-to-hostname mappings."""
        if not self.mdns_resolver.enabled:
            return {}

        try:
            mdns_results = self.mdns_resolver.discover(timeout=timeout)
            if mdns_results:
                total_names = sum(len(names) for names in mdns_results.values())
                logger.info(
                    "[SCAN] mDNS discovery found %s hostname(s) across %s host(s)",
                    total_names,
                    len(mdns_results),
                )
            else:
                logger.info("[SCAN] mDNS discovery found no hostnames.")
            return mdns_results
        except Exception:
            logger.error("[SCAN] mDNS discovery failed.")
            logger.debug("[SCAN] mDNS discovery traceback", exc_info=True)
            return {}

    def _normalize_hostname(self, hostname):
        """Normalize hostnames by trimming whitespace and trailing dots."""
        if not isinstance(hostname, str):
            return None

        cleaned = hostname.strip().rstrip('.')
        return cleaned or None

    def _is_generic_hostname(self, hostname, ip=None):
        """Heuristically detect placeholder or low-quality hostnames."""
        normalized = self._normalize_hostname(hostname)
        if not normalized:
            return True

        lowered = normalized.lower()
        if lowered in {'unknown', 'n/a', 'na', 'localhost', 'localhost.localdomain'}:
            return True

        if ip:
            ip_lower = str(ip).strip().lower()
            if lowered == ip_lower:
                return True

        compact = lowered.replace('.', '-').replace('_', '-')
        if _GENERIC_HOSTNAME_RE.match(compact):
            return True

        return False

    def _hostname_score(self, hostname, ip=None):
        """Score hostname quality to pick the most useful display value."""
        normalized = self._normalize_hostname(hostname)
        if not normalized:
            return -1

        score = 0
        if not self._is_generic_hostname(normalized, ip):
            score += 10

        lowered = normalized.lower()
        if lowered.endswith('.local'):
            score += 4
        if '.' in lowered:
            score += 1

        score += min(len(normalized), 24) / 24.0
        return score

    def _pick_best_hostname(self, candidates, ip=None):
        """Choose best hostname candidate and optionally append meaningful aliases."""
        normalized_candidates = []
        for candidate in candidates:
            normalized = self._normalize_hostname(candidate)
            if normalized and normalized not in normalized_candidates:
                normalized_candidates.append(normalized)

        if not normalized_candidates:
            return None

        primary = max(
            normalized_candidates,
            key=lambda value: self._hostname_score(value, ip),
        )

        aliases = [
            value for value in normalized_candidates
            if value != primary and not self._is_generic_hostname(value, ip)
        ]

        if aliases:
            return f"{primary} ({', '.join(aliases[:2])})"
        return primary

    def _safe_reverse_dns(self, ip):
        """Perform reverse DNS lookup with exception-safe fallback."""
        if _DNSPYTHON_AVAILABLE:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                rev_name = dns.reversename.from_address(ip)
                answers = resolver.resolve(rev_name, "PTR")
                for rdata in answers:
                    name = str(rdata.target).rstrip('.')
                    if name:
                        return name
            except Exception as e:
                logger.debug("[SCAN] dnspython reverse DNS failed for %s: %s", ip, e)

        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def _enrich_hostnames(self, scanned_devices, mdns_hostnames=None):
        """Enrich device hostname fields using reverse DNS and mDNS candidates."""
        mdns_hostnames = mdns_hostnames or {}

        for ip, device in scanned_devices.items():
            if not ip or ip == "N/A":
                continue

            current_hostname = self._normalize_hostname(device.get('hostname'))
            candidates = []
            if current_hostname:
                candidates.append(current_hostname)

            if not current_hostname or self._is_generic_hostname(current_hostname, ip):
                reverse_dns_hostname = self._safe_reverse_dns(ip)
                if reverse_dns_hostname:
                    candidates.append(reverse_dns_hostname)

            for mdns_hostname in mdns_hostnames.get(ip, []):
                candidates.append(mdns_hostname)

            best_hostname = self._pick_best_hostname(candidates, ip)
            if best_hostname:
                device['hostname'] = best_hostname

    def _get_ha_devices(self):
        """Fetch devices from Home Assistant Supervisor API.
        
        Uses both the States API and the Device Registry API for richer data.
        The Device Registry provides sw_version, hw_version, manufacturer, and
        model which are often missing from entity states.
        """
        logger.info("[SCAN] Fetching Home Assistant devices...")
        supervisor_token = os.environ.get('SUPERVISOR_TOKEN')
        supervisor_url = "http://supervisor/core/api/states"
        
        if not supervisor_token:
            logger.warning("[SCAN]   SUPERVISOR_TOKEN not found. Using mock data for dev.")
            # MOCK DATA FOR LOCAL DEV / DEBUGGING
            mock_devices = [
                {"entity_id": "media_player.yamaha_yas_306", "attributes": {"friendly_name": "Living Room Soundbar", "ip_address": "192.168.1.55", "source": "ha", "manufacturer": "Yamaha", "model": "YAS-306", "sw_version": "2.51"}},
                {"entity_id": "light.zigbee_device_1", "attributes": {"friendly_name": "Kitchen Light", "source": "ha", "manufacturer": "Philips", "model": "LWB010", "sw_version": "1.50.2"}}, # Zigbee, no IP
                {"entity_id": "router.fritz_box_7590", "attributes": {"friendly_name": "FRITZ!Box 7590", "ip_address": "192.168.1.1", "source": "ha", "manufacturer": "AVM", "model": "FRITZ!Box 7590", "sw_version": "7.57"}}
            ]
            logger.info("[SCAN]   Loaded %s mock HA devices", len(mock_devices))
            return mock_devices
            
        headers = {
            "Authorization": f"Bearer {supervisor_token}",
            "Content-Type": "application/json",
        }
        
        # Fetch device registry for richer data (sw_version, manufacturer, model)
        device_registry = self._get_ha_device_registry(headers)
        logger.info("[SCAN]   Device Registry: %s entries", len(device_registry))
        
        devices = []
        try:
            response = self.session.get(supervisor_url, headers=headers, timeout=10)
            if response.status_code == 200:
                states = response.json()
                for state in states:
                    # Very simple heuristic to find "devices" with interesting attributes
                    attrs = state.get('attributes', {})
                    if 'ip_address' in attrs or 'manufacturer' in attrs or 'model' in attrs:
                        entity_id = state['entity_id']
                        # Enrich with device registry data
                        reg_info = device_registry.get(entity_id, {})
                        devices.append({
                            "entity_id": entity_id,
                            "attributes": attrs,
                            "ip": attrs.get('ip_address'),
                            "sw_version": reg_info.get('sw_version') or attrs.get('sw_version'),
                            "manufacturer": reg_info.get('manufacturer') or attrs.get('manufacturer'),
                            "model": reg_info.get('model') or attrs.get('model'),
                        })
            else:
                logger.error("[SCAN]   Failed to fetch HA states: %s %s", response.status_code, response.text)
        except Exception as e:
            logger.error("[SCAN]   Error communicating with Supervisor: %s", e)
            logger.debug("[SCAN] Supervisor communication traceback", exc_info=True)
        
        logger.info("[SCAN]   Found %s HA devices", len(devices))
        return devices

    def _get_ha_device_registry(self, headers):
        """Fetch the HA Device Registry for richer device metadata.
        
        Returns a dict mapping entity_id -> {sw_version, manufacturer, model, hw_version}.
        The Device Registry contains more reliable manufacturer/model data and
        software versions that the states API often lacks.
        """
        registry_url = "http://supervisor/core/api/config/device_registry"
        result = {}
        try:
            response = self.session.get(registry_url, headers=headers, timeout=10)
            if response.status_code == 200:
                devices = response.json()
                for device in devices:
                    # Map by identifiers — entities link to devices via device_id
                    # We store by device name as fallback key, and build entity mapping later
                    info = {
                        "sw_version": device.get('sw_version'),
                        "hw_version": device.get('hw_version'),
                        "manufacturer": device.get('manufacturer'),
                        "model": device.get('model'),
                        "name": device.get('name') or device.get('name_by_user'),
                    }
                    # Store by device ID for later entity matching
                    device_id = device.get('id')
                    if device_id:
                        result[device_id] = info
                
                # Also try to fetch entity registry to map entity_id -> device_id
                entity_map = self._map_entities_to_devices(headers, result)
                result.update(entity_map)
            else:
                logger.debug("Device Registry fetch returned %s (may not be available)", response.status_code)
        except Exception as e:
            logger.debug("Device Registry fetch failed: %s", e)
        
        return result

    def _map_entities_to_devices(self, headers, device_registry):
        """Map entity IDs to device registry entries via the Entity Registry API."""
        entity_url = "http://supervisor/core/api/config/entity_registry"
        entity_map = {}
        try:
            response = self.session.get(entity_url, headers=headers, timeout=10)
            if response.status_code == 200:
                entities = response.json()
                for entity in entities:
                    entity_id = entity.get('entity_id')
                    device_id = entity.get('device_id')
                    if entity_id and device_id and device_id in device_registry:
                        entity_map[entity_id] = device_registry[device_id]
        except Exception as e:
            logger.debug("Entity Registry fetch failed: %s", e)
        return entity_map

    def _merge_devices(self, nmap_devices, ha_devices):
        """
        Merge separate lists of devices. 
        Priority: 
        - Match by IP (Nmap IP == HA IP)
        - Else append as new
        """
        merged = {d['ip']: d for d in nmap_devices if d.get('ip')}
        # Keep track of non-IP devices separately
        non_ip_devices = [d for d in nmap_devices if not d.get('ip')]

        ip_matched = 0
        ha_only_added = 0

        for ha_dev in ha_devices:
            attrs = ha_dev.get('attributes', {})
            ip = attrs.get('ip_address')
            
            # Use enriched data from Device Registry if available
            manufacturer = ha_dev.get('manufacturer') or attrs.get('manufacturer', 'Unknown')
            model = ha_dev.get('model') or attrs.get('model', 'Unknown')
            sw_version = ha_dev.get('sw_version') or attrs.get('sw_version')
            
            # Prepare HA device info
            new_dev_entry = {
                "ip": ip if ip else "N/A",
                "mac": "Unknown", # HA states rarely show MAC
                "vendor": manufacturer,
                "manufacturer": manufacturer,
                "model": model,
                "hostname": attrs.get('friendly_name', ha_dev['entity_id']),
                "openPorts": [],
                "osMatch": "Unknown",
                "source": "Home Assistant",
                "sw_version": sw_version,
            }

            if ip and ip in merged:
                # MERGE: We found this IP in Nmap results. Enrich it.
                ip_matched += 1
                existing = merged[ip]
                existing['source'] = 'Merged (Nmap + HA)'
                if existing['vendor'] == "Unknown" and new_dev_entry['vendor'] != "Unknown":
                    existing['vendor'] = new_dev_entry['vendor']
                # Always carry manufacturer from HA (more reliable than Nmap OUI)
                if manufacturer != 'Unknown':
                    existing['manufacturer'] = manufacturer
                if model != "Unknown":
                    existing['model'] = model
                # Carry sw_version from HA
                if sw_version:
                    existing['sw_version'] = sw_version
                # Prefer user-friendly hostname from HA
                existing['hostname'] = f"{existing['hostname']} ({new_dev_entry['hostname']})"
            else:
                # NEW FOUND: Either no IP (Zigbee?) or Nmap missed it
                ha_only_added += 1
                merged[ip if ip else f"no_ip_{ha_dev['entity_id']}"] = new_dev_entry

        result = list(merged.values()) + non_ip_devices
        logger.info(
            f"[SCAN]   Merged: {ip_matched} matched by IP, "
            f"{ha_only_added} HA-only added, {len(result)} total devices"
        )
        return result

    def _get_open_ports(self, host):
        """Extract open port/service metadata from current nmap host entry."""
        ports = []
        for proto in self.nm[host].all_protocols():
            lport = self.nm[host][proto].keys()
            for port in lport:
                state = self.nm[host][proto][port]['state']
                if state == 'open':
                    port_info = self.nm[host][proto][port]
                    service = port_info['name']
                    entry = {"port": port, "protocol": proto, "service": service}
                    # Capture product/version from Nmap -sV (service version detection)
                    if port_info.get('product'):
                        entry['product'] = port_info['product']
                    if port_info.get('version'):
                        entry['version'] = port_info['version']
                    ports.append(entry)
        return ports

    def _get_os_match(self, host):
        """Return best nmap OS match name or Unknown when unavailable."""
        if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
            return self.nm[host]['osmatch'][0]['name']
        return "Unknown"

    def check_secure_by_default(self, device):
        """Check for weak credentials and insecure defaults."""
        details = []
        passed = True
        ip = device.get('ip')
        open_ports = device.get('openPorts', [])

        normalized_ports = []
        for port_info in open_ports:
            if not isinstance(port_info, dict):
                continue
            port = self._normalize_port(port_info.get('port'))
            if port is None:
                continue
            normalized_ports.append({
                'port': port,
                'service': str(port_info.get('service', '')).lower(),
            })
        
        # 1. Telnet Check (Port 23) - Active Credential Test
        if any(p['port'] == 23 for p in normalized_ports):
            details.append("Telnet (port 23) is open.")
            if ip and ip != "N/A":
                creds_found = self._check_telnet_auth(ip)
                if creds_found:
                    passed = False
                    details.append(f"CRITICAL: Found weak Telnet credentials: {creds_found}")
                else:
                    passed = False # Open telnet is bad regardless
                    details.append("Telnet login accessible (Brute-force failed but service is insecure).")

        # 2. HTTP Check (Port 80/8080) - Unauth Checks
        http_ports = [
            p['port'] for p in normalized_ports
            if p['service'] == 'http' or p['port'] in [80, 8080]
        ]
        for port in http_ports:
            if ip and ip != "N/A":
                unauth_info = self._check_http_auth(ip, port)
                if unauth_info:
                    passed = False
                    details.append(f"Insecure HTTP on port {port}: {unauth_info}")

        if not details:
            details.append("No obvious weak default access vectors found.")

        return {"passed": passed, "details": "; ".join(details)}

    def _check_telnet_auth(self, ip):
        """Try common credentials on Telnet."""
        # Simple socket-based brute force
        for user, password in self.common_creds:
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((ip, 23))
                # Very basic Telnet negotiation skip (will fail on complex telnet servers, efficient for IoT)
                # Receive banner
                data = s.recv(1024) 
                
                # Send User
                s.sendall(user.encode() + b"\r\n")
                time.sleep(0.5)
                data = s.recv(1024)
                
                # Send Pass
                s.sendall(password.encode() + b"\r\n")
                time.sleep(0.5)
                data = s.recv(1024)
                
                # Check for success (prompt like #, $, >)
                # This is heuristic.
                resp = data.decode('utf-8', errors='ignore')
                if "#" in resp or "$" in resp or ">" in resp or "Success" in resp:
                    return f"{user}/{password}"
            except Exception:
                pass
            finally:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
        return None

    def _check_http_auth(self, ip, port):
        """Check for unauthenticated access to standard endpoints."""
        endpoints = ['/', '/status', '/config', '/api', '/settings']
        import concurrent.futures

        def _check_ep(ep):
            try:
                url = f"http://{ip}:{port}{ep}"
                r = self.session.get(url, timeout=2)
                if r.status_code == 200:
                    # Filter out simple login pages
                    if "login" not in r.text.lower() and "password" not in r.text.lower():
                        return ep
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(endpoints))) as executor:
            for ep in executor.map(_check_ep, endpoints):
                if ep:
                    return f"Unauthenticated access to {ep}"
        return None

    def _check_vendor_specifics(self, device, selected_vendors='all'):
        """Identify and check specific vendor vulnerabilities."""
        warnings = []
        ip = device.get('ip')
        ports = []
        for port_info in device.get('openPorts', []):
            if not isinstance(port_info, dict):
                continue
            port = self._normalize_port(port_info.get('port'))
            if port is not None:
                ports.append(port)

        if selected_vendors is None:
            selected_vendors = []
        
        if not ip or ip == "N/A": return []
        
        # Tuya
        if (selected_vendors == 'all' or 'tuya' in selected_vendors) and 6668 in ports:
            warnings.append("Possible Tuya Device (Port 6668 open). Ensure default keys are replaced.")

        # TP-Link Kasa
        if (selected_vendors == 'all' or 'kasa' in selected_vendors) and 9999 in ports:
             warnings.append("TP-Link Kasa Device (Port 9999). Old protocols may be vulnerable to local control injection.")

        # Sonoff LAN Mode
        if (selected_vendors == 'all' or 'sonoff' in selected_vendors) and 8081 in ports:
             warnings.append("Sonoff Device in LAN Mode (Port 8081). Ensure local network is trusted.")

        # Shelly
        if (selected_vendors == 'all' or 'shelly' in selected_vendors) and 80 in ports:
            try:
                r = self.session.get(f"http://{ip}/status", timeout=1)
                if r.status_code == 200 and "mac" in r.text: # Shelly JSON signature
                    if "auth" not in r.json() or not r.json().get("auth"):
                         warnings.append("Shelly Device: Authentication is NOT enabled for local web interface.")
            except Exception: pass

        # Philips Hue
        if (selected_vendors == 'all' or 'hue' in selected_vendors) and 80 in ports:
             try:
                r = self.session.get(f"http://{ip}/description.xml", timeout=1)
                if r.status_code == 200 and "Philips hue" in r.text:
                    warnings.append("Philips Hue Bridge detected. Ensure 'Link Button' authentication is strictly required.")
             except Exception: pass
        
        # Ikea
        if (selected_vendors == 'all' or 'ikea' in selected_vendors) and 80 in ports:
             # Basic header check for Ikea gateway signature (heuristic)
             try:
                 r = self.session.get(f"http://{ip}", timeout=1)
                 if "IKEA" in r.text or "Tradfri" in r.text:
                      warnings.append("IKEA Gateway detected. Ensure latest firmware to avoid known zigbee crash exploits.")
             except Exception: pass

        return warnings

    def check_confidentiality(self, open_ports, https_redirect_result=None):
        """Check for unencrypted services.

        Port 80 is exempted when HTTPS redirect verification confirms it only redirects.
        """
        unencrypted_ports = [21, 23, 80] # FTP, Telnet, HTTP
        redirected_http_ports = set()

        if https_redirect_result and https_redirect_result.get('passed'):
            for port in https_redirect_result.get('redirected_ports', []) or []:
                try:
                    redirected_http_ports.add(int(port))
                except (TypeError, ValueError):
                    continue

        found_unencrypted = []
        
        for p in open_ports:
            try:
                port = int(p.get('port'))
            except (TypeError, ValueError):
                continue

            if port not in unencrypted_ports:
                continue

            if port == 80 and port in redirected_http_ports:
                continue

            found_unencrypted.append(f"{p.get('service', 'unknown')}/{port}")
        
        if found_unencrypted:
            return {"passed": False, "details": f"Unencrypted ports found: {', '.join(found_unencrypted)}"}

        if 80 in redirected_http_ports:
            return {"passed": True, "details": "No common unencrypted management ports found. Port 80 redirects to HTTPS."}
        
        return {"passed": True, "details": "No common unencrypted management ports found."}

    def calculate_attack_surface_score(self, open_ports):
        """Score device attack surface based on exposed open ports.

        CRA relevance: Annex I §1(3)(h) minimization of attack surface.
        """
        open_ports = open_ports or []

        if not isinstance(open_ports, list):
            open_ports = []

        normalized_ports = []
        for port_info in open_ports:
            if isinstance(port_info, dict):
                port_value = port_info.get('port')
            else:
                port_value = port_info

            try:
                normalized_ports.append(int(port_value))
            except (TypeError, ValueError):
                continue

        open_ports_count = len(normalized_ports)
        score = open_ports_count

        if score <= 1:
            rating = "Low"
            details = f"{open_ports_count} ports open. Attack surface is minimal."
        elif score <= 4:
            rating = "Medium"
            details = f"{open_ports_count} ports open. Consider disabling unused services."
        else:
            rating = "High"
            details = f"{open_ports_count} ports open. Potentially excessive exposure; minimize unnecessary services."

        return {
            "score": score,
            "rating": rating,
            "openPortsCount": open_ports_count,
            "details": details
        }

    def check_minimal_attack_surface(self, device):
        """Check if the device exposes a minimal attack surface per CRA Annex I §1(3)(e).

        Fails if the device exposes risky legacy services (UPnP, SMB) or discovery 
        services (mDNS) alongside an excessive number of other open ports.
        """
        open_ports = device.get('openPorts', []) or []
        normalized_ports = []
        for p in open_ports:
            if not isinstance(p, dict):
                continue
            port = self._normalize_port(p.get('port'))
            if port is not None:
                normalized_ports.append(port)

        unique_ports = set(normalized_ports)
        other_ports = unique_ports - {5353}

        risky_ports_found = []
        
        # Check for UPnP (5000, 1900)
        if 5000 in unique_ports or 1900 in unique_ports:
            risky_ports_found.append('UPnP (port 5000/1900)')
            
        # Check for SMB (139, 445)
        if 139 in unique_ports or 445 in unique_ports:
            risky_ports_found.append('SMB (port 139/445)')
            
        # Check for mDNS (5353) combined with excessive attack surface
        if 5353 in unique_ports and len(other_ports) >= 5:
            risky_ports_found.append('mDNS (port 5353) alongside >= 5 other ports')
            
        if risky_ports_found:
            return {
                'passed': False,
                'details': f"Excessive or risky interfaces exposed: {', '.join(risky_ports_found)}. Minimise attack surface."
            }
            
        return {
            'passed': True,
            'details': "No excessively risky interfaces (UPnP, SMB) or unnecessarily exposed metadata services detected."
        }

    def check_https_redirect(self, device):
        """Verify HTTP management interfaces redirect to HTTPS.

        CRA relevance: Annex I §1(3)(c), §1(3)(d).
        """
        ip = device.get('ip')
        open_ports = device.get('openPorts', [])

        if not ip or ip == "N/A":
            return {
                "passed": True,
                "details": "Skipped HTTPS redirect check (no routable IP address).",
                "checked_ports": [],
                "failed_ports": [],
                "inconclusive_ports": []
            }

        http_ports = set()
        for port_info in open_ports:
            if not isinstance(port_info, dict):
                continue

            port = self._normalize_port(port_info.get('port'))
            service = str(port_info.get('service', '')).lower()

            if port in (80, 8080):
                http_ports.add(port)
                continue

            if 'http' in service and 'https' not in service:
                if port is not None:
                    http_ports.add(port)

        if not http_ports:
            return {
                "passed": True,
                "details": "No HTTP management ports detected for HTTPS redirect verification.",
                "checked_ports": [],
                "failed_ports": [],
                "inconclusive_ports": []
            }

        checked_ports = sorted(http_ports)
        failed_ports = []
        inconclusive_ports = []
        redirected_ports = []

        valid_redirect_status_codes = {301, 302, 303, 307, 308}
        import concurrent.futures

        def _check_redirect(port):
            url = f"http://{ip}:{port}/"
            try:
                response = self.session.get(url, timeout=2, allow_redirects=False)
                status_code = response.status_code
                location = (response.headers.get('Location') or '').strip()

                if status_code in valid_redirect_status_codes and location.lower().startswith('https://'):
                    return port, 'redirected'
                elif status_code == 200:
                    return port, 'failed'
                elif 300 <= status_code < 400:
                    return port, 'failed'
                else:
                    return port, 'inconclusive'
            except requests.RequestException:
                return port, 'inconclusive'
            except Exception:
                return port, 'inconclusive'
                
        if checked_ports:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(checked_ports))) as executor:
                futures = {executor.submit(_check_redirect, port): port for port in checked_ports}
                for future in concurrent.futures.as_completed(futures):
                    port, status = future.result()
                    if status == 'redirected':
                        redirected_ports.append(port)
                    elif status == 'failed':
                        failed_ports.append(port)
                    else:
                        inconclusive_ports.append(port)


        if failed_ports:
            details = (
                f"HTTP management exposed without HTTPS redirect on ports: {', '.join(str(p) for p in failed_ports)}."
            )
            if inconclusive_ports:
                details += f" Inconclusive probes on ports: {', '.join(str(p) for p in inconclusive_ports)}."
            return {
                "passed": False,
                "details": details,
                "checked_ports": checked_ports,
                "failed_ports": failed_ports,
                "inconclusive_ports": inconclusive_ports
            }

        details = "All detected HTTP management ports redirect to HTTPS."
        if inconclusive_ports:
            details = (
                f"No insecure HTTP responses detected. Inconclusive probes on ports: "
                f"{', '.join(str(p) for p in inconclusive_ports)}."
            )
        elif redirected_ports:
            details = f"HTTP management redirects to HTTPS on ports: {', '.join(str(p) for p in redirected_ports)}."

        return {
            "passed": True,
            "details": details,
            "checked_ports": checked_ports,
            "redirected_ports": redirected_ports,
            "failed_ports": [],
            "inconclusive_ports": inconclusive_ports
        }

    def check_vulnerabilities(self, vendor, open_ports):
        """Query NVD using CPE matching and return critical vulnerabilities."""
        if not vendor or vendor == "Unknown":
             return {"passed": True, "details": "Vendor unknown, skipping CVE check.", "cves": []}

        search_term = vendor.split('(')[0].strip()
        product_hint = None
        version_hint = None
        for port in open_ports or []:
            if not isinstance(port, dict):
                continue
            product_hint = product_hint or port.get('product')
            version_hint = version_hint or port.get('version')

        canonical_cpe = self._resolve_device_cpe(search_term, product_hint, version_hint)
        if not canonical_cpe:
            canonical_cpe = self._resolve_device_cpe(search_term, search_term, "*")

        if not canonical_cpe:
            return {
                "passed": True,
                "details": f"No canonical CPE found for '{search_term}', skipping NVD CVE check.",
                "cves": [],
            }

        try:
            cves = self.nvd_client.get_cves_for_cpe(canonical_cpe, min_cvss=9.0, limit=5)
        except Exception as e:
            logger.error("NVD CVE lookup failed: %s", e)
            return {"passed": True, "details": "CVE lookup failed (network error).", "cves": []}

        if cves:
             return {
                 "passed": False,
                 "details": f"CPE identified: {canonical_cpe}. Found {len(cves)} critical CVEs associated with '{search_term}'.",
                 "cves": cves,
                 "cpe": canonical_cpe,
             }

        return {
            "passed": True,
            "details": f"CPE identified: {canonical_cpe}. No critical CVEs found for '{search_term}'.",
            "cves": [],
            "cpe": canonical_cpe,
        }

    def check_security_logging(self, device):
        """Check for security logging capability (CRA Annex I §1(3)(j)).

        Detection paths:
        1) Syslog listener availability on UDP/514 (best-effort probe)
        2) Common HTTP log endpoint exposure
        """
        ip = device.get('ip')
        open_ports = device.get('openPorts', []) or []

        details = []
        logging_endpoints = []

        # Signal 1: Syslog UDP/514 advertised by scan results
        syslog_by_scan = False
        for p in open_ports:
            if not isinstance(p, dict):
                continue
            port = self._normalize_port(p.get('port'))
            protocol = str(p.get('protocol', '')).lower()
            if port == 514 and protocol == 'udp':
                syslog_by_scan = True
                break

        syslog_reachable = syslog_by_scan
        syslog_probe_state = "not_probed"

        # Best-effort active UDP probe for devices with routable IPs
        if ip and ip != "N/A" and not syslog_reachable:
            syslog_reachable, syslog_probe_state = self._probe_udp_syslog(ip)

        if syslog_reachable:
            if syslog_by_scan:
                details.append("Syslog service detected on UDP/514.")
            else:
                details.append(f"UDP/514 appears reachable ({syslog_probe_state}).")
        else:
            if syslog_probe_state == "not_probed":
                details.append("No Syslog service detected on UDP/514.")
            else:
                details.append(f"No Syslog listener confirmed on UDP/514 ({syslog_probe_state}).")

        # Signal 2: HTTP log endpoints
        http_ports = self._collect_http_ports(open_ports)

        log_paths = self.security_log_paths

        urls_to_check = []
        if ip and ip != "N/A":
            for port in http_ports:
                scheme = 'https' if port in (443, 8443) else 'http'
                for path in log_paths:
                    urls_to_check.append(f"{scheme}://{ip}:{port}{path}")

        if urls_to_check:
            import concurrent.futures
            
            def _check_log_url(url):
                try:
                    response = self.session.get(url, timeout=2, allow_redirects=False)
                    if response.status_code in (200, 401, 403):
                        return url
                except Exception:
                    pass
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(urls_to_check))) as executor:
                for result_url in executor.map(_check_log_url, urls_to_check):
                    if result_url:
                        logging_endpoints.append(result_url)

        if logging_endpoints:
            details.append(
                f"Detected log-related HTTP endpoint(s): {', '.join(logging_endpoints[:3])}"
            )
            if len(logging_endpoints) > 3:
                details.append(f"(+{len(logging_endpoints) - 3} additional endpoint hits)")
        else:
            details.append("No common HTTP log endpoints detected.")

        passed = bool(syslog_reachable or logging_endpoints)
        if not passed:
            details.append(
                "Logging capability not externally verified; reporting Warning to avoid false non-compliance."
            )

        return {
            "passed": passed,
            "details": "; ".join(details),
            "syslog_udp_514": bool(syslog_reachable),
            "syslog_probe_state": syslog_probe_state,
            "logging_endpoints": logging_endpoints,
        }

    def _probe_udp_syslog(self, ip, timeout=0.5):
        """Best-effort UDP/514 probe.

        UDP is inherently inconclusive without reply. We classify:
        - timeout/no error after send as open|filtered
        - immediate connection-refused/reset as closed
        - routing/socket errors as unreachable/error
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.connect((ip, 514))
            sock.send(b"CRA-AUDITOR-SYSLOG-PROBE")
            try:
                sock.recv(1)
                return True, "response"
            except socket.timeout:
                return True, "open|filtered"
            except ConnectionRefusedError:
                return False, "closed"
            except OSError:
                return False, "closed"
        except OSError:
            return False, "unreachable"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def check_sbom_compliance(self, device):
        """Check for SBOM availability per CRA Annex I §2(1).
        
        Two-layer approach:
        1. Device-level: probe well-known HTTP endpoints for SBOM files
        2. Vendor-level: lookup known vendor SBOM publication status
        """
        details = []
        sbom_found = False
        sbom_format = None
        ip = device.get('ip')
        open_ports = device.get('openPorts', [])
        # Use resolved vendor (enriched from HA) if available, fallback to raw vendor
        vendor = device.get('resolved_vendor') or device.get('vendor', 'Unknown')
        
        # Layer 1: Device-level SBOM endpoint probing
        http_ports = self._collect_http_ports(open_ports)
        
        if ip and ip != "N/A" and http_ports:
            sbom_found, sbom_format = self._probe_sbom_endpoints(ip, http_ports)
            if sbom_found:
                details.append(f"SBOM endpoint found on device (format: {sbom_format}).")
        
        # Layer 2: Vendor-level SBOM status lookup
        vendor_status = self._lookup_vendor_sbom_status(vendor)
        
        # Layer 3: Vendor SBOM URL lookup (externalized rules + NVD CPE refs fallback)
        sbom_url = self.vendor_rules.get_sbom_url(vendor)
        cpe_name = self._resolve_device_cpe(vendor, device.get('model'), device.get('sw_version'))
        if not sbom_url and cpe_name:
            sbom_url = self.nvd_client.get_vendor_reference_url(cpe_name)
        
        if sbom_found:
            # Best case: device directly exposes SBOM
            return {
                "passed": True,
                "details": "; ".join(details),
                "sbom_found": True,
                "sbom_format": sbom_format,
                "sbom_url": sbom_url
            }
        elif vendor_status == "available":
            details.append(f"Vendor '{vendor}' is known to publish SBOMs for their products.")
            if sbom_url:
                details.append(f"SBOM portal: {sbom_url}")
            return {
                "passed": True,
                "details": "; ".join(details),
                "sbom_found": False,
                "sbom_format": None,
                "sbom_url": sbom_url
            }
        elif vendor_status == "unavailable":
            details.append(f"No SBOM endpoint found on device. Vendor '{vendor}' does not publish SBOMs.")
            return {
                "passed": False,
                "details": "; ".join(details) if details else f"No SBOM found. Vendor '{vendor}' has no known SBOM publication.",
                "sbom_found": False,
                "sbom_format": None,
                "sbom_url": None
            }
        else:
            # Unknown vendor or vendor status
            if vendor == "Unknown":
                details.append("Vendor unknown — cannot determine SBOM availability.")
            else:
                details.append(f"No SBOM endpoint found on device. Vendor '{vendor}' SBOM status is unknown.")
            return {
                "passed": False,
                "details": "; ".join(details),
                "sbom_found": False,
                "sbom_format": None,
                "sbom_url": None
            }

    def _probe_sbom_endpoints(self, ip, http_ports):
        """Probe well-known SBOM endpoints on a device.
        
        Returns (sbom_found: bool, sbom_format: str|None)
        """
        sbom_paths = [
            # IETF / CycloneDX well-known paths
            '/.well-known/sbom',
            '/sbom.json',
            '/sbom.xml',
            '/sbom',
            # Additional standard paths
            '/api/sbom',
            '/api/v1/sbom',
            '/device/sbom',
            '/bom.json',
            '/bom.xml',
            # CSAF (closely related to CRA)
            '/.well-known/csaf',
            # VEX (Vulnerability Exploitability eXchange)
            '/.well-known/vex',
        ]
        
        # CycloneDX and SPDX content-type indicators
        sbom_signatures = {
            'cyclonedx': 'CycloneDX',
            'spdx': 'SPDX',
            'bomFormat': 'CycloneDX',     # CycloneDX JSON key
            'specVersion': 'CycloneDX',   # CycloneDX JSON key (spec version field)
            'SPDXVersion': 'SPDX',        # SPDX JSON key
            'DocumentNamespace': 'SPDX',  # SPDX JSON key
            'spdxVersion': 'SPDX',        # SPDX JSON key (alt casing)
        }
        
        import concurrent.futures

        def _check_sbom(url):
            try:
                r = self.session.get(url, timeout=2)
                if r.status_code == 200 and len(r.text) > 50:
                    content = r.text[:2000]
                    for signature, fmt in sbom_signatures.items():
                        if signature in content:
                            return url, fmt
                    
                    ct = r.headers.get('Content-Type', '').lower()
                    if 'cyclonedx' in ct:
                        return url, 'CycloneDX'
                    elif 'spdx' in ct:
                        return url, 'SPDX'
                    
                    if r.headers.get('Content-Type', '').startswith(('application/json', 'application/xml', 'text/xml')):
                        return url, 'Unknown Format'
                return url, None
            except Exception as e:
                logger.debug("SBOM probe failed for %s: %s", url, e)
                return url, None
        
        urls_to_check = []
        for port in http_ports:
            scheme = 'https' if port in (443, 8443) else 'http'
            for path in sbom_paths:
                url = f"{scheme}://{ip}:{port}{path}"
                urls_to_check.append(url)

        if urls_to_check:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(urls_to_check))) as executor:
                futures = [executor.submit(_check_sbom, url) for url in urls_to_check]
                for future in concurrent.futures.as_completed(futures):
                    url, result_fmt = future.result()
                    if result_fmt:
                        return True, result_fmt
        
        return False, None

    def _lookup_vendor_sbom_status(self, vendor):
        """Check if vendor is known to publish SBOMs.
        
        Returns 'available', 'unavailable', or 'unknown'.
        """
        return self.vendor_rules.get_sbom_status(vendor)

    def check_security_txt(self, device):
        """Check for security.txt disclosure policy per CRA §2(5) and §2(6).

        Two-layer approach:
        1. Device-level: probe /.well-known/security.txt on HTTP/HTTPS ports
        2. Vendor-level: lookup known vendor disclosure policy status
        """
        details = []
        security_txt_found = False
        parsed_fields = None
        ip = device.get('ip')
        open_ports = device.get('openPorts', [])
        vendor = device.get('resolved_vendor') or device.get('vendor', 'Unknown')

        # Layer 1: Device-level security.txt probing
        http_ports = self._collect_http_ports(open_ports)

        if ip and ip != "N/A" and http_ports:
            security_txt_found, parsed_fields = self._probe_security_txt(ip, http_ports)
            if security_txt_found:
                details.append("security.txt found on device.")
                if parsed_fields.get('contact'):
                    details.append(f"Contact: {parsed_fields['contact']}")
                if parsed_fields.get('expires'):
                    details.append(f"Expires: {parsed_fields['expires']}")
                    # Check if expired
                    try:
                        from datetime import datetime, timezone
                        exp_str = parsed_fields['expires'].strip()
                        # Try ISO 8601 format
                        exp_date = datetime.fromisoformat(exp_str.replace('Z', '+00:00'))
                        if exp_date < datetime.now(timezone.utc):
                            details.append("WARNING: security.txt has expired!")
                    except Exception:
                        pass

        # Layer 2: Vendor-level disclosure status lookup
        vendor_status = self._lookup_vendor_security_txt_status(vendor)

        # Layer 3: Vendor disclosure URL lookup
        vendor_url = self.vendor_rules.get_security_txt_url(vendor)

        if security_txt_found:
            return {
                "passed": True,
                "details": "; ".join(details),
                "security_txt_found": True,
                "fields": parsed_fields,
                "vendor_url": vendor_url
            }
        elif vendor_status == "available":
            details.append(f"Vendor '{vendor}' is known to publish a security.txt disclosure policy.")
            if vendor_url:
                details.append(f"Disclosure policy: {vendor_url}")
            return {
                "passed": True,
                "details": "; ".join(details),
                "security_txt_found": False,
                "fields": None,
                "vendor_url": vendor_url
            }
        elif vendor_status == "unavailable":
            details.append(f"No security.txt found on device. Vendor '{vendor}' has no known disclosure policy.")
            return {
                "passed": False,
                "details": "; ".join(details) if details else f"No security.txt found. Vendor '{vendor}' has no known vulnerability disclosure policy.",
                "security_txt_found": False,
                "fields": None,
                "vendor_url": None
            }
        else:
            if vendor == "Unknown":
                details.append("Vendor unknown — cannot determine disclosure policy status.")
            else:
                details.append(f"No security.txt found on device. Vendor '{vendor}' disclosure status is unknown.")
            return {
                "passed": False,
                "details": "; ".join(details),
                "security_txt_found": False,
                "fields": None,
                "vendor_url": None
            }

    def _probe_security_txt(self, ip, http_ports):
        """Probe /.well-known/security.txt on a device.

        Returns (found: bool, fields: dict|None)
        Parses RFC 9116 fields: Contact, Expires, Encryption, Policy, Preferred-Languages, Canonical, Hiring
        """
        import concurrent.futures

        def _check_security_txt(port):
            scheme = 'https' if port in (443, 8443) else 'http'
            url = f"{scheme}://{ip}:{port}/.well-known/security.txt"
            try:
                r = self.session.get(url, timeout=2)
                if r.status_code == 200 and len(r.text) > 10:
                    content = r.text
                    if 'contact:' not in content.lower():
                        return url, None

                    fields = {
                        "contact": None,
                        "expires": None,
                        "encryption": None,
                        "policy": None,
                        "preferred_languages": None,
                    }

                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith('#') or not line:
                            continue
                        match = re.match(r'^([A-Za-z-]+):\s*(.*)', line)
                        if match:
                            key_lower = match.group(1).lower()
                            value = match.group(2).strip()
                            if key_lower == "contact" and not fields["contact"]:
                                fields["contact"] = value
                            elif key_lower == "expires":
                                fields["expires"] = value
                            elif key_lower == "encryption":
                                fields["encryption"] = value
                            elif key_lower == "policy" and not fields["policy"]:
                                fields["policy"] = value
                            elif key_lower == "preferred-languages":
                                fields["preferred_languages"] = value

                    if fields["contact"]:
                        return url, fields
            except Exception as e:
                logger.debug("security.txt probe failed for %s: %s", url, e)
            return url, None

        if http_ports:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(http_ports))) as executor:
                futures = [executor.submit(_check_security_txt, port) for port in http_ports]
                for future in concurrent.futures.as_completed(futures):
                    url, fields = future.result()
                    if fields:
                        return True, fields

        return False, None

    def _lookup_vendor_security_txt_status(self, vendor):
        """Check if vendor is known to publish a security.txt disclosure policy.

        Returns 'available', 'unavailable', or 'unknown'.
        """
        return self.vendor_rules.get_security_txt_status(vendor)

    def check_firmware_tracking(self, device):
        """Check firmware version tracking per CRA Annex I §2(2).
        
        Multi-source firmware version detection:
        1. Nmap -sV service version strings from open ports
        2. Vendor-specific firmware endpoints (Shelly, Hue, AVM, ESPHome, Tasmota, etc.)
        3. UPnP device description XML
        4. Generic HTTP content scraping (regex)
        5. Home Assistant sw_version attribute
        
        Then performs version-specific CVE lookup if version is found.
        """
        firmware_version = None
        firmware_source = None
        version_cves = []
        details = []
        ip = device.get('ip')
        # Use resolved vendor (enriched from HA) if available
        vendor = device.get('resolved_vendor') or device.get('vendor', 'Unknown')
        open_ports = device.get('openPorts', [])

        # Layer 1: Extract version from Nmap -sV service probe results
        for port_info in open_ports:
            if not isinstance(port_info, dict):
                continue
            product = port_info.get('product', '')
            version = port_info.get('version', '')
            if version:
                firmware_version = version
                firmware_source = f"Nmap service scan (port {port_info['port']}: {product} {version})".strip()
                details.append(f"Service version detected: {product} {version} on port {port_info['port']}.")
                break  # Use the first versioned service found

        # Layer 2: Vendor-specific firmware endpoint probing
        if not firmware_version and ip and ip != "N/A":
            http_ports = self._collect_http_ports(open_ports)
            if http_ports:
                fw_ver, fw_src = self._probe_firmware_endpoints(ip, http_ports, vendor)
                if fw_ver:
                    firmware_version = fw_ver
                    firmware_source = fw_src
                    details.append(f"Firmware version detected via {fw_src}: {fw_ver}.")

        # Layer 3: Home Assistant sw_version
        if not firmware_version and device.get('sw_version'):
            firmware_version = device['sw_version']
            firmware_source = "Home Assistant"
            details.append(f"Firmware version from Home Assistant: {firmware_version}.")

        # Version-specific CVE lookup via NVD (CPE-based)
        if firmware_version and vendor and vendor != "Unknown":
            canonical_cpe = self._resolve_device_cpe(vendor, device.get('model'), firmware_version)
            try:
                if canonical_cpe:
                    version_cves = self.nvd_client.get_cves_for_cpe(canonical_cpe, min_cvss=7.0, limit=5)
                    details.append(f"CPE identified for firmware tracking: {canonical_cpe}.")
                else:
                    details.append("No canonical CPE found for firmware version-specific CVE lookup.")
            except Exception as e:
                logger.error("Version-specific NVD CVE lookup failed: %s", e)
                details.append("Version-specific CVE lookup failed (network error).")

        if version_cves:
            details.append(f"Found {len(version_cves)} CVEs affecting firmware version '{firmware_version}'.")

        # Determine update URL from externalized rules
        update_url = self.vendor_rules.get_firmware_update_url(vendor)

        # Determine pass/fail
        if firmware_version:
            if version_cves:
                passed = False
                details.append("Firmware has known vulnerabilities — update recommended.")
            else:
                passed = True
                if not details:
                    details.append(f"Firmware version '{firmware_version}' detected, no known CVEs.")
        else:
            passed = False
            details.append("Could not determine firmware version. CRA §2(2) requires version tracking.")

        return {
            "passed": passed,
            "details": "; ".join(details),
            "firmware_version": firmware_version,
            "firmware_source": firmware_source,
            "update_available": True if version_cves else None,
            "update_url": update_url,
            "version_cves": version_cves
        }

    def _probe_firmware_endpoints(self, ip, http_ports, vendor):
        """Probe vendor-specific firmware version endpoints.
        
        Supports: Shelly, Hue, AVM/FRITZ!, ESPHome, Tasmota, Sonoff,
                  IKEA Tradfri, UPnP XML descriptors, and generic HTTP scraping.
        
        Returns (version: str|None, source: str|None)
        """
        vendor_lower = vendor.lower() if vendor else ""
        root_response_cache = {}

        def _get_root_response(base_url, cache_key):
            if cache_key in root_response_cache:
                return root_response_cache[cache_key]
            try:
                response = self.session.get(f"{base_url}/", timeout=2)
                root_response_cache[cache_key] = response
                return response
            except Exception:
                root_response_cache[cache_key] = None
                return None
        
        import concurrent.futures

        def _probe_firmware(port):
            scheme = 'https' if port in (443, 8443) else 'http'
            base_url = f"{scheme}://{ip}:{port}"
            cache_key = (scheme, int(port))
            
            try:
                # Shelly devices expose firmware version at /settings or /shelly
                if 'shelly' in vendor_lower or 'allterco' in vendor_lower:
                    for path in ['/settings', '/shelly']:
                        r = self.session.get(f"{base_url}{path}", timeout=2)
                        if r.status_code == 200:
                            data = r.json()
                            fw = data.get('fw') or data.get('fw_version')
                            if fw:
                                return fw, f"Shelly API ({path})"
                
                # Philips Hue bridges expose version at /api/config
                if 'philips' in vendor_lower or 'signify' in vendor_lower or 'hue' in vendor_lower:
                    r = self.session.get(f"{base_url}/api/config", timeout=2)
                    if r.status_code == 200:
                        data = r.json()
                        sw = data.get('swversion') or data.get('apiversion')
                        if sw:
                            return sw, "Hue Bridge API (/api/config)"
                
                # AVM/FRITZ!Box firmware version endpoints
                if 'avm' in vendor_lower or 'fritz' in vendor_lower:
                    for path in ['/jason_boxinfo.xml', '/cgi-bin/system_status']:
                        r = self.session.get(f"{base_url}{path}", timeout=2)
                        if r.status_code == 200:
                            text = r.text
                            # Parse FRITZ!Box version from XML or HTML
                            fw_match = re.search(r'<(?:Version|firmware_version|Labor)>([^<]+)</', text)
                            if fw_match:
                                return fw_match.group(1).strip(), f"AVM API ({path})"
                            # Try to find version pattern in text
                            fw_match = re.search(r'FRITZ!OS[:\s]*(\d+\.\d+[\w.]*)', text, re.IGNORECASE)
                            if fw_match:
                                return fw_match.group(1), f"AVM API ({path})"
                
                # ESPHome devices expose version at /api or via headers
                if 'esp' in vendor_lower or 'esphome' in vendor_lower:
                    r = _get_root_response(base_url, cache_key)
                    if r and r.status_code == 200:
                        # ESPHome sets X-Esphome-Version header
                        esphome_ver = r.headers.get('X-Esphome-Version')
                        if esphome_ver:
                            return esphome_ver, "ESPHome header (X-Esphome-Version)"
                        # Also check page content
                        ver_match = re.search(r'ESPHome[\s_-]*v?(\d+\.\d+[\w.]*)', r.text, re.IGNORECASE)
                        if ver_match:
                            return ver_match.group(1), "ESPHome web interface"
                
                # Tasmota devices: /cm?cmnd=Status%202 returns firmware info
                if 'tasmota' in vendor_lower:
                    r = self.session.get(f"{base_url}/cm?cmnd=Status%202", timeout=2)
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            fw = data.get('StatusFWR', {}).get('Version')
                            if fw:
                                return fw, "Tasmota API (Status 2)"
                        except (ValueError, AttributeError):
                            pass
                    # Fallback: root page often shows version
                    r = _get_root_response(base_url, cache_key)
                    if r and r.status_code == 200:
                        ver_match = re.search(r'Tasmota[\s_-]*v?(\d+\.\d+[\w.]*)', r.text, re.IGNORECASE)
                        if ver_match:
                            return ver_match.group(1), "Tasmota web interface"
                
                # Sonoff DIY Mode: /zeroconf/info
                if 'sonoff' in vendor_lower or 'itead' in vendor_lower:
                    try:
                        r = self.session.post(
                            f"{base_url}/zeroconf/info",
                            json={"deviceid": "", "data": {}},
                            timeout=2
                        )
                        if r.status_code == 200:
                            data = r.json()
                            fw = data.get('data', {}).get('fwVersion')
                            if fw:
                                return fw, "Sonoff DIY API (/zeroconf/info)"
                    except Exception:
                        pass
                
                # IKEA Tradfri Gateway
                if 'ikea' in vendor_lower or 'tradfri' in vendor_lower:
                    r = _get_root_response(base_url, cache_key)
                    if r and r.status_code == 200:
                        ver_match = re.search(r'(?:firmware|version)[:\s]*(\d+\.\d+[\w.]*)', r.text, re.IGNORECASE)
                        if ver_match:
                            return ver_match.group(1), "IKEA Gateway web interface"
                
                # UPnP device description XML (routers, NAS, media devices)
                for path in ['/description.xml', '/rootDesc.xml', '/gatedesc.xml',
                             '/DeviceDescription.xml', '/dmr/DeviceDescription.xml']:
                    try:
                        r = self.session.get(f"{base_url}{path}", timeout=2)
                        if r.status_code == 200 and '<root' in r.text[:500].lower():
                            text = r.text
                            # Extract firmware/software version from UPnP XML
                            for tag in ['firmwareVersion', 'softwareVersion', 'firmware_version']:
                                fw_match = re.search(rf'<{tag}>([^<]+)</', text, re.IGNORECASE)
                                if fw_match:
                                    return fw_match.group(1).strip(), f"UPnP XML ({path})"
                            # Try modelNumber as version indicator (some devices use this)
                            model_match = re.search(r'<modelNumber>([^<]+)</', text)
                            if model_match:
                                model_ver = model_match.group(1).strip()
                                # Only use if it looks like a version number
                                if re.match(r'\d+\.\d+', model_ver):
                                    return model_ver, f"UPnP XML modelNumber ({path})"
                    except Exception:
                        pass
                
                # Generic: try common firmware endpoints (JSON APIs)
                for path in ['/firmware', '/api/firmware', '/device/info',
                             '/system/info', '/api/system', '/api/device',
                             '/api/v1/device/info', '/status', '/api/status']:
                    r = self.session.get(f"{base_url}{path}", timeout=2)
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            for key in ['fw_version', 'firmware_version', 'version',
                                        'fw', 'softwareVersion', 'sw_version',
                                        'firmwareVersion', 'sys_version', 'os_version']:
                                if key in data:
                                    return str(data[key]), f"Device API ({path})"
                            # Check nested structures
                            for outer in ['system', 'device', 'firmware', 'info']:
                                if isinstance(data.get(outer), dict):
                                    for key in ['version', 'fw_version', 'firmware_version', 'sw_version']:
                                        if key in data[outer]:
                                            return str(data[outer][key]), f"Device API ({path} → {outer}.{key})"
                        except (ValueError, AttributeError):
                            pass
                
                # Last resort: regex scan HTTP root page for version patterns
                try:
                    r = _get_root_response(base_url, cache_key)
                    if r and r.status_code == 200 and len(r.text) > 20:
                        content = r.text[:5000]  # Only check first 5KB
                        match = _FW_VERSION_RE.search(content)
                        if match:
                            return match.group(1), "HTTP content scraping (regex)"
                except Exception:
                    pass
                
            except Exception as e:
                logger.debug("Firmware endpoint probe failed for %s: %s", base_url, e)
        
            return None, None
            
        if http_ports:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(http_ports))) as executor:
                futures = [executor.submit(_probe_firmware, port) for port in http_ports]
                for future in concurrent.futures.as_completed(futures):
                    fw, src = future.result()
                    if fw:
                        return fw, src
        return None, None

# For standalone testing
if __name__ == "__main__":
    scanner = CRAScanner()
    print(scanner.scan_subnet("192.168.1.0/24"))