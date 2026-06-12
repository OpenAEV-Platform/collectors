"""Template Data Models."""

from typing import Optional

from pydantic import BaseModel, Field


class TemplateData(BaseModel):
    """Template data model."""

    key: Optional[str] = Field(None, description="Example key value")

    def __str__(self) -> str:
        """Detaield representation with key debugging information."""
        return f"TemplateData(key='{self.value}'"
