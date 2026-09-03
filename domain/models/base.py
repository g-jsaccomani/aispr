# -*- coding: utf-8 -*-
"""
Copyright © 2026 Joabson Saccomani (@jsaccomani).
Role: Cloud Security Consultant | LinkedIn: https://www.linkedin.com/in/jsaccomani
Licensed under the Apache License, Version 2.0.

AISPR Canonical Security Data Model - Base Model
"""

from datetime import datetime, timezone
from typing import Any, Dict
from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    """Returns current UTC timestamp with timezone awareness."""
    return datetime.now(timezone.utc)


class AISPRBaseModel(BaseModel):
    """
    Base Pydantic v2 model for all canonical AISPR entities.
    Provides strict validation, serialization helpers, and backward compatibility.
    """
    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True,
        arbitrary_types_allowed=True,
        use_enum_values=True,
        extra="allow",  # Allows forward compatibility with vendor-specific attributes
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convenience method returning a serializable Python dictionary."""
        return self.model_dump(mode="python")

    def to_json(self, indent: int = 2) -> str:
        """Convenience method returning a formatted JSON string."""
        return self.model_dump_json(indent=indent)
