from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from analysis.anomaly_detector import AnomalyDetector
    from analysis.chain_tracker import ChainTracker
    from analysis.toxic_flow import ToxicFlowAnalyzer
    from config import MCPSecConfig
    from discovery.discovery import ToolDiscovery
    from proxy.core import ProxyCore
    from proxy.router import Router
    from proxy.session import SessionManager


class AppState:
    proxy: "ProxyCore | None" = None
    router: "Router | None" = None
    sessions: "SessionManager | None" = None
    config: "MCPSecConfig | None" = None
    config_path: str | None = None
    discovery: "ToolDiscovery | None" = None
    toxic_flow: "ToxicFlowAnalyzer | None" = None
    chain_tracker: "ChainTracker | None" = None
    anomaly_detector: "AnomalyDetector | None" = None


state = AppState()
