"""MCPSec — Passthrough LLM Provider for MCP Server Mode.

When MCPSec runs as an MCP server, the calling client already has an LLM.
Instead of making its own LLM API calls, MCPSec returns classification
prompts and a classify_tools() tool that the client LLM can use to
submit its judgement back.

Flow:
    1. Client calls scan_tools(url) → gets findings + unclassified items
    2. Client LLM reasons over unclassified items using the provided prompt
    3. Client calls classify_tools(scan_id, classifications) → merged into findings
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from mcpsec.llm.classifier import (
    ClassificationBatch,
    ClassificationResult,
    ClassificationType,
    ClassificationVerdict,
    LLMProvider,
    _SYSTEM_PROMPT,
    _TOOL_POISONING_PROMPT,
    _DANGEROUS_NAME_PROMPT,
    _SCOPE_ANALYSIS_PROMPT,
)


# ---------------------------------------------------------------------------
# Passthrough models
# ---------------------------------------------------------------------------

class UnclassifiedItem(BaseModel):
    """A tool that was not flagged by rule-based checks and needs LLM review."""
    tool_name: str
    tool_description: str
    classification_type: ClassificationType
    prompt: str = Field(
        ...,
        description="Pre-built classification prompt for the client LLM"
    )


class PassthroughRequest(BaseModel):
    """Returned to the MCP client with items needing LLM classification."""
    scan_id: str
    system_prompt: str = Field(
        default=_SYSTEM_PROMPT,
        description="System prompt for the client LLM"
    )
    items: list[UnclassifiedItem] = Field(default_factory=list)
    instructions: str = Field(
        default=(
            "The following tools were not flagged by rule-based security checks. "
            "Please analyze each one using the provided prompt and respond with "
            "a JSON array of classifications. For each item, provide: "
            "verdict (flagged/clean/uncertain), reasoning, confidence (0.0-1.0), "
            "and flagged_patterns (list of concerning patterns found). "
            "Then call classify_tools() with the scan_id and your classifications."
        ),
    )


class ClientClassification(BaseModel):
    """A single classification submitted by the client LLM."""
    tool_name: str
    verdict: str = Field(..., description="flagged, clean, or uncertain")
    reasoning: str = Field(default="")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    flagged_patterns: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Passthrough Provider
# ---------------------------------------------------------------------------

class PassthroughProvider(LLMProvider):
    """Provider that collects prompts instead of calling an LLM.

    Used in MCP server mode. Accumulates unclassified items so they
    can be returned to the client for classification.
    """

    def __init__(self):
        self._pending: list[dict[str, Any]] = []

    def is_available(self) -> bool:
        return True

    def model_name(self) -> str:
        return "client-passthrough"

    async def classify(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> tuple[dict[str, Any], dict[str, int]]:
        """Capture the prompt instead of sending to an LLM."""
        self._pending.append({
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
        })
        return {
            "verdict": "uncertain",
            "reasoning": "Awaiting client LLM classification",
            "confidence": 0.0,
            "flagged_patterns": [],
        }, {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def clear_pending(self) -> None:
        self._pending.clear()


# ---------------------------------------------------------------------------
# Passthrough helpers
# ---------------------------------------------------------------------------

def build_passthrough_request(
    scan_id: str,
    tools: list[dict[str, Any]],
    rule_flagged_names: set[str],
    classification_type: ClassificationType,
    scopes: Optional[list[str]] = None,
) -> PassthroughRequest:
    """Build a PassthroughRequest for tools not flagged by rules.

    Args:
        scan_id: The scan these tools belong to.
        tools: Full tools list from MCP introspection.
        rule_flagged_names: Tools already flagged by rule-based checks.
        classification_type: What to check for.
        scopes: Server scopes (for scope analysis).

    Returns:
        PassthroughRequest ready to return to the MCP client.
    """
    items = []

    for tool in tools:
        name = tool.get("name", "<unnamed>")
        if name in rule_flagged_names:
            continue

        description = tool.get("description", "")

        if classification_type == ClassificationType.TOOL_POISONING:
            prompt = _TOOL_POISONING_PROMPT.format(name=name, description=description)
        elif classification_type == ClassificationType.DANGEROUS_NAME:
            prompt = _DANGEROUS_NAME_PROMPT.format(name=name, description=description)
        elif classification_type == ClassificationType.SCOPE_ANALYSIS:
            prompt = _SCOPE_ANALYSIS_PROMPT.format(
                name=name,
                description=description,
                scopes=", ".join(scopes or []),
            )
        else:
            continue

        items.append(UnclassifiedItem(
            tool_name=name,
            tool_description=description,
            classification_type=classification_type,
            prompt=prompt,
        ))

    return PassthroughRequest(scan_id=scan_id, items=items)


def parse_client_classifications(
    classifications: list[ClientClassification],
    classification_type: ClassificationType,
) -> list[ClassificationResult]:
    """Convert client-submitted classifications to ClassificationResults.

    Args:
        classifications: Raw classifications from the client LLM.
        classification_type: The type of classification performed.

    Returns:
        List of ClassificationResult ready for merging into findings.
    """
    results = []

    for c in classifications:
        try:
            verdict = ClassificationVerdict(c.verdict.lower())
        except ValueError:
            verdict = ClassificationVerdict.UNCERTAIN

        results.append(ClassificationResult(
            item_id=c.tool_name,
            classification_type=classification_type,
            verdict=verdict,
            reasoning=c.reasoning,
            confidence_score=max(0.0, min(1.0, c.confidence)),
            flagged_patterns=c.flagged_patterns,
        ))

    return results
