from app.scanner.base import BaseModule
from app.scanner.tools.adapters import (
    run_nikto_scan,
    run_nuclei_scan,
    run_sqlmap_scan,
    run_tool_version,
)
from app.schemas.scan import Finding


class ExternalToolsModule(BaseModule):
    name = "external_tools"
    tools = ["nuclei", "nikto", "sqlmap"]

    async def run(
        self,
        target_url: str,
        in_scope_urls: list[str] | None = None,
        exclusions: list[str] | None = None,
        discovered_endpoints: list[str] | None = None,
    ) -> list[Finding]:
        _ = target_url
        _ = in_scope_urls
        _ = exclusions
        _ = discovered_endpoints
        versions = [run_tool_version(tool) for tool in self.tools]
        execution_results = [
            run_nuclei_scan(target_url),
            run_nikto_scan(target_url),
            run_sqlmap_scan(target_url),
        ]
        results = versions + execution_results
        available = [item["tool"] for item in results if item["status"] == "available"]
        return [
            Finding(
                module=self.name,
                title="External tool orchestration results",
                severity="info",
                description=(
                    "Executed external scanners (when installed) and captured lightweight outputs."
                ),
                evidence={"available_tools": available, "results": results},
                remediation=(
                    "Install required tools in worker environment and wire target-specific execution."
                ),
            )
        ]
