from typing import List, Dict, Any
from src.state.cyber_state import CyberState


class TelemetryProcessor:
    """負責將複雜的 CyberState 轉換為簡潔的檢索查詢與上下文"""

    @staticmethod
    def build_research_query(state: CyberState) -> str:
        """將目標 IP、端口、服務版本及 Web 發現轉化為緊湊的 Telemetry 字串"""
        segments: List[str] = [f"mission={state.get('mission_goal', '')}"]
        discovered_targets = state.get("discovered_targets", {}) or {}
        web_findings = state.get("web_findings", []) or []

        # 處理前兩個目標的服務資訊 (避免 Prompt 過長)
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