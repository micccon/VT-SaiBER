from typing import List, Dict, Any
from src.state.cyber_state import CyberState


class TelemetryProcessor:
    """
    responsible for converting raw telemetry data 
    into a compact string format suitable for LLM input
    """

    @staticmethod
    def build_research_query(state: CyberState) -> str:
        """
        Convert target IP, ports, service versions, 
        and web findings into a compact Telemetry string
        """

        segments: List[str] = [f"mission={state.get('mission_goal', '')}"]
        discovered_targets = state.get("discovered_targets", {}) or {}
        web_findings = state.get("web_findings", []) or []

        # process up to 2 targets and 6 services per target for brevity
        for ip, target_data in list(discovered_targets.items())[:2]:
            services = target_data.get("services", {}) if isinstance(target_data, dict) else {}
            service_bits = []
            for port, service in list(services.items())[:6]:
                if isinstance(service, dict):
                    name = service.get("service_name", "unknown")
                    ver = service.get("version", "")
                    piece = f"{port}/{name}"
                    if ver:
                        piece += f" {ver}"
                    service_bits.append(piece)
                else:
                    service_bits.append(f"{port}/{service}")

            if service_bits:
                segments.append(f"target={ip} services={'; '.join(service_bits)}")

        interesting_paths: List[str] = []
        for f in web_findings[:8]:
            if not isinstance(f, dict):
                continue
            path = f.get("path") or f.get("url")
            status = f.get("status_code", f.get("status"))
            if path:
                if status is not None:
                    interesting_paths.append(f"{path} ({status})")
                else:
                    interesting_paths.append(path)

        if interesting_paths:
            segments.append(f"web_findings={', '.join(interesting_paths)}")

        return " | ".join(segments).replace("\n", " ").replace("`", "").strip()