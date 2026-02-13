import time

from zapv2 import ZAPv2


def scan(target_url, openapi_spec=None, progress_callback=None,auth_type=None,auth_value=None,mode=None,stop_check=None):
    zap = ZAPv2(
        apikey='v451tqjqiu00qaris7laarb2vv',
        proxies={'http': 'http://localhost:8080'},
    )

    if auth_type == 1 and auth_value:
        # Set cookie directly
        zap.httpsessions.add_session_token(target_url, 'sessionid')
        zap.httpsessions.set_active_session(target_url, auth_value)
        print("Set session cookie for authentication.")


    if openapi_spec:
        zap.openapi.import_file(openapi_spec, target_url)
    else:
        try:
            zap.spider.scan(target_url)
        except Exception as e:
            raise Exception(f"Spidering failed: {e}")


    if mode == "ATTACK mode":
        # Maximum aggression settings
        zap.ascan.set_option_default_policy('INSANE')
        zap.ascan.enable_all_scanners()
        zap.ascan.set_option_alert_threshold('Low')
        zap.ascan.set_option_thread_per_host(10)

        # Active scan with full power
        scan_id = zap.ascan.scan(target_url, recurse=True)
    else:
        zap.ascan.set_option_default_policy('LOW')
        scan_id = zap.ascan.scan(target_url)

    while int(zap.ascan.status(scan_id)) < 100:
        if stop_check and stop_check():
            zap.ascan.stop(scan_id)
            return [], {}
        progress = int(zap.ascan.status(scan_id))
        if progress_callback:
            progress_callback(progress, f"Active scanning… {progress}%")
        time.sleep(5)

    # Just add a small buffer instead
    time.sleep(3)

    if progress_callback:
        progress_callback(100, "Collecting alerts…")

    alerts = zap.core.alerts(baseurl=target_url)
    vulns = [format_alert(i, alert) for i, alert in enumerate(alerts, 1)]
    endpoints = extract_endpoints(openapi_spec,alerts)
    return vulns, endpoints


def extract_endpoints(openapi_spec, alerts):
    import yaml
    from urllib.parse import urlparse

    print(openapi_spec)
    with open(openapi_spec, "r") as f:
        spec = yaml.safe_load(f)

    # Extract alert paths
    alert_paths = [urlparse(a["url"]).path for a in alerts if "url" in a]

    endpoints = {}
    for path, methods in spec.get("paths", {}).items():
        # Count vulns for this path
        vulns = sum(1 for ap in alert_paths if ap.startswith(path.rstrip("/")))

        for method in methods:
            if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                endpoints.setdefault(path, []).append({
                    "method": method.upper(),
                    "path": path,  # Added this
                    "tested": vulns > 0,
                    "vulns": vulns
                })

    return endpoints



def format_alert(index, alert):
    """Map a raw ZAP alert dict to the format expected by the UI."""
    return {
        'id': index,
        'alert': alert.get('alert', alert.get('name', '')),
        'risk': alert.get('risk', 'Informational'),
        'confidence': alert.get('confidence', 'Low'),
        'url': alert.get('url', ''),
        'method': alert.get('method', ''),
        'param': alert.get('param', ''),
        'attack': alert.get('attack', ''),
        'description': alert.get('description', ''),
        'evidence': alert.get('evidence', ''),
        'solution': alert.get('solution', ''),
        'reference': alert.get('reference', ''),
        'cweid': alert.get('cweid', ''),
        'wascid': alert.get('wascid', ''),
    }
