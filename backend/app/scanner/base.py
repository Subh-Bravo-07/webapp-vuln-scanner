from abc import ABC, abstractmethod

from app.schemas.scan import Finding


class BaseModule(ABC):
    name: str

    @abstractmethod
    async def run(
        self,
        target_url: str,
        in_scope_urls: list[str] | None = None,
        exclusions: list[str] | None = None,
        discovered_endpoints: list[str] | None = None,
    ) -> list[Finding]:
        raise NotImplementedError
