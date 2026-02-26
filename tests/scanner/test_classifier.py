"""MCPSec — LLM Classifier and Passthrough unit tests.

Tests the hybrid classification pipeline internals:
    - ClassificationCache
    - HybridClassifier._parse_response
    - MockProvider
    - LiteLLMProvider detection (no API keys)
    - PassthroughProvider
    - build_passthrough_request
    - parse_client_classifications
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from mcpsec.llm.classifier import (
    ClassificationBatch,
    ClassificationCache,
    ClassificationResult,
    ClassificationType,
    ClassificationVerdict,
    HybridClassifier,
    LiteLLMProvider,
    MockProvider,
)
from mcpsec.llm.passthrough import (
    ClientClassification,
    PassthroughProvider,
    build_passthrough_request,
    parse_client_classifications,
)


# ==================================================================
# ClassificationCache
# ==================================================================

class TestClassificationCache:

    @pytest.fixture
    def cache(self):
        return ClassificationCache()

    @pytest.fixture
    def sample_result(self):
        return ClassificationResult(
            item_id="test_tool",
            classification_type=ClassificationType.TOOL_POISONING,
            verdict=ClassificationVerdict.CLEAN,
            reasoning="Looks fine",
            confidence_score=0.9,
        )

    def test_put_and_get(self, cache, sample_result):
        cache.put("tool_poisoning", "test_tool:desc", sample_result)
        result = cache.get("tool_poisoning", "test_tool:desc")
        assert result is not None
        assert result.item_id == "test_tool"
        assert result.verdict == ClassificationVerdict.CLEAN

    def test_get_miss(self, cache):
        assert cache.get("tool_poisoning", "nonexistent") is None

    def test_different_type_different_key(self, cache, sample_result):
        cache.put("tool_poisoning", "content", sample_result)
        assert cache.get("dangerous_name", "content") is None

    def test_different_content_different_key(self, cache, sample_result):
        cache.put("tool_poisoning", "content_a", sample_result)
        assert cache.get("tool_poisoning", "content_b") is None

    def test_overwrite(self, cache, sample_result):
        cache.put("tool_poisoning", "content", sample_result)
        updated = sample_result.model_copy(update={"verdict": ClassificationVerdict.FLAGGED})
        cache.put("tool_poisoning", "content", updated)
        result = cache.get("tool_poisoning", "content")
        assert result.verdict == ClassificationVerdict.FLAGGED

    def test_clear(self, cache, sample_result):
        cache.put("tool_poisoning", "content", sample_result)
        assert cache.size == 1
        cache.clear()
        assert cache.size == 0
        assert cache.get("tool_poisoning", "content") is None

    def test_size(self, cache, sample_result):
        assert cache.size == 0
        cache.put("a", "1", sample_result)
        cache.put("b", "2", sample_result)
        assert cache.size == 2

    def test_deterministic_keys(self, cache, sample_result):
        """Same input always maps to same cache key."""
        cache.put("type", "content", sample_result)
        assert cache.get("type", "content") is not None
        assert cache.get("type", "content") is not None


# ==================================================================
# HybridClassifier._parse_response
# ==================================================================

class TestParseResponse:

    def test_clean_response(self):
        result = HybridClassifier._parse_response(
            "tool", ClassificationType.TOOL_POISONING,
            {"verdict": "clean", "reasoning": "Safe", "confidence": 0.95, "flagged_patterns": []},
        )
        assert result.verdict == ClassificationVerdict.CLEAN
        assert result.confidence_score == 0.95
        assert result.item_id == "tool"

    def test_flagged_response(self):
        result = HybridClassifier._parse_response(
            "evil", ClassificationType.TOOL_POISONING,
            {"verdict": "flagged", "reasoning": "Suspicious", "confidence": 0.8,
             "flagged_patterns": ["instruction override"]},
        )
        assert result.verdict == ClassificationVerdict.FLAGGED
        assert result.flagged_patterns == ["instruction override"]

    def test_uncertain_response(self):
        result = HybridClassifier._parse_response(
            "maybe", ClassificationType.DANGEROUS_NAME,
            {"verdict": "uncertain", "reasoning": "Hard to tell", "confidence": 0.4},
        )
        assert result.verdict == ClassificationVerdict.UNCERTAIN

    def test_invalid_verdict_defaults_uncertain(self):
        result = HybridClassifier._parse_response(
            "tool", ClassificationType.TOOL_POISONING,
            {"verdict": "banana", "reasoning": "Invalid", "confidence": 0.5},
        )
        assert result.verdict == ClassificationVerdict.UNCERTAIN

    def test_missing_verdict_defaults_uncertain(self):
        result = HybridClassifier._parse_response(
            "tool", ClassificationType.TOOL_POISONING,
            {"reasoning": "No verdict field"},
        )
        assert result.verdict == ClassificationVerdict.UNCERTAIN

    def test_confidence_clamped_high(self):
        result = HybridClassifier._parse_response(
            "tool", ClassificationType.TOOL_POISONING,
            {"verdict": "clean", "reasoning": "Ok", "confidence": 5.0},
        )
        assert result.confidence_score == 1.0

    def test_confidence_clamped_low(self):
        result = HybridClassifier._parse_response(
            "tool", ClassificationType.TOOL_POISONING,
            {"verdict": "clean", "reasoning": "Ok", "confidence": -1.0},
        )
        assert result.confidence_score == 0.0

    def test_string_confidence_parsed(self):
        result = HybridClassifier._parse_response(
            "tool", ClassificationType.TOOL_POISONING,
            {"verdict": "clean", "reasoning": "Ok", "confidence": "0.75"},
        )
        assert result.confidence_score == 0.75

    def test_invalid_string_confidence(self):
        result = HybridClassifier._parse_response(
            "tool", ClassificationType.TOOL_POISONING,
            {"verdict": "clean", "reasoning": "Ok", "confidence": "high"},
        )
        assert result.confidence_score == 0.5

    def test_missing_confidence_defaults(self):
        result = HybridClassifier._parse_response(
            "tool", ClassificationType.TOOL_POISONING,
            {"verdict": "clean", "reasoning": "Ok"},
        )
        assert result.confidence_score == 0.5

    def test_missing_reasoning(self):
        result = HybridClassifier._parse_response(
            "tool", ClassificationType.TOOL_POISONING,
            {"verdict": "clean"},
        )
        assert result.reasoning == "No reasoning provided"

    def test_missing_flagged_patterns(self):
        result = HybridClassifier._parse_response(
            "tool", ClassificationType.TOOL_POISONING,
            {"verdict": "flagged", "reasoning": "Bad", "confidence": 0.9},
        )
        assert result.flagged_patterns == []

    def test_classification_type_preserved(self):
        result = HybridClassifier._parse_response(
            "tool", ClassificationType.SCOPE_ANALYSIS,
            {"verdict": "clean", "reasoning": "Ok", "confidence": 0.9},
        )
        assert result.classification_type == ClassificationType.SCOPE_ANALYSIS


# ==================================================================
# MockProvider
# ==================================================================

class TestMockProvider:

    @pytest.mark.asyncio
    async def test_clean_verdict(self):
        provider = MockProvider("clean")
        response, usage = await provider.classify("system", "user")
        assert response["verdict"] == "clean"
        assert usage["total_tokens"] == 0

    @pytest.mark.asyncio
    async def test_flagged_verdict(self):
        provider = MockProvider("flagged")
        response, usage = await provider.classify("system", "user")
        assert response["verdict"] == "flagged"

    def test_is_available(self):
        assert MockProvider().is_available() is True

    def test_model_name(self):
        assert MockProvider().model_name() == "mock"

    @pytest.mark.asyncio
    async def test_confidence_always_one(self):
        provider = MockProvider("clean")
        response, _ = await provider.classify("s", "u")
        assert response["confidence"] == 1.0

    @pytest.mark.asyncio
    async def test_empty_flagged_patterns(self):
        provider = MockProvider("flagged")
        response, _ = await provider.classify("s", "u")
        assert response["flagged_patterns"] == []


# ==================================================================
# LiteLLMProvider detection (no API keys)
# ==================================================================

class TestLiteLLMProviderDetection:

    def test_no_keys_not_available(self):
        with patch.dict(os.environ, {}, clear=True):
            provider = LiteLLMProvider()
            assert provider.is_available() is False

    def test_no_keys_model_none(self):
        with patch.dict(os.environ, {}, clear=True):
            provider = LiteLLMProvider()
            assert provider.model_name() == "none"

    def test_anthropic_key_detected(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=True):
            provider = LiteLLMProvider()
            assert provider.is_available() is True
            assert "claude" in provider.model_name()

    def test_openai_key_detected(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}, clear=True):
            provider = LiteLLMProvider()
            assert provider.is_available() is True
            assert "gpt" in provider.model_name()

    def test_gemini_key_detected(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}, clear=True):
            provider = LiteLLMProvider()
            assert provider.is_available() is True
            assert "gemini" in provider.model_name()

    def test_explicit_model_overrides(self):
        provider = LiteLLMProvider(model="custom-model")
        assert provider.is_available() is True
        assert provider.model_name() == "custom-model"

    def test_env_var_override(self):
        with patch.dict(os.environ, {"MCPSEC_LLM_MODEL": "my-model"}, clear=True):
            provider = LiteLLMProvider()
            assert provider.is_available() is True
            assert provider.model_name() == "my-model"

    def test_anthropic_priority_over_openai(self):
        with patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "a-key",
            "OPENAI_API_KEY": "o-key",
        }, clear=True):
            provider = LiteLLMProvider()
            assert "claude" in provider.model_name()


# ==================================================================
# HybridClassifier — classify_tools
# ==================================================================

class TestHybridClassifierIntegration:

    @pytest.fixture
    def tools(self):
        return [
            {"name": "read_data", "description": "Read data from the database"},
            {"name": "write_data", "description": "Write data to the database"},
        ]

    @pytest.mark.asyncio
    async def test_clean_mock_all_clean(self, tools):
        classifier = HybridClassifier(provider=MockProvider("clean"))
        batch = await classifier.classify_tools(
            tools=tools,
            rule_flagged_names=set(),
            classification_type=ClassificationType.TOOL_POISONING,
        )
        assert all(r.verdict == ClassificationVerdict.CLEAN for r in batch.results)
        assert len(batch.results) == 2

    @pytest.mark.asyncio
    async def test_flagged_mock_all_flagged(self, tools):
        classifier = HybridClassifier(provider=MockProvider("flagged"))
        batch = await classifier.classify_tools(
            tools=tools,
            rule_flagged_names=set(),
            classification_type=ClassificationType.TOOL_POISONING,
        )
        assert all(r.verdict == ClassificationVerdict.FLAGGED for r in batch.results)

    @pytest.mark.asyncio
    async def test_rule_flagged_skipped(self, tools):
        classifier = HybridClassifier(provider=MockProvider("flagged"))
        batch = await classifier.classify_tools(
            tools=tools,
            rule_flagged_names={"read_data"},
            classification_type=ClassificationType.TOOL_POISONING,
        )
        assert len(batch.results) == 1
        assert batch.results[0].item_id == "write_data"

    @pytest.mark.asyncio
    async def test_all_flagged_empty_batch(self, tools):
        classifier = HybridClassifier(provider=MockProvider("flagged"))
        batch = await classifier.classify_tools(
            tools=tools,
            rule_flagged_names={"read_data", "write_data"},
            classification_type=ClassificationType.TOOL_POISONING,
        )
        assert len(batch.results) == 0

    @pytest.mark.asyncio
    async def test_cache_reuse(self, tools):
        classifier = HybridClassifier(provider=MockProvider("clean"))
        await classifier.classify_tools(
            tools=tools,
            rule_flagged_names=set(),
            classification_type=ClassificationType.TOOL_POISONING,
        )
        batch2 = await classifier.classify_tools(
            tools=tools,
            rule_flagged_names=set(),
            classification_type=ClassificationType.TOOL_POISONING,
        )
        assert batch2.from_cache == 2

    @pytest.mark.asyncio
    async def test_model_name_in_batch(self, tools):
        classifier = HybridClassifier(provider=MockProvider("clean"))
        batch = await classifier.classify_tools(
            tools=tools,
            rule_flagged_names=set(),
            classification_type=ClassificationType.TOOL_POISONING,
        )
        assert batch.model_used == "mock"

    @pytest.mark.asyncio
    async def test_unavailable_provider_skips(self, tools):
        with patch.dict(os.environ, {}, clear=True):
            classifier = HybridClassifier(provider=LiteLLMProvider())
            batch = await classifier.classify_tools(
                tools=tools,
                rule_flagged_names=set(),
                classification_type=ClassificationType.TOOL_POISONING,
            )
            assert batch.skipped is True
            assert len(batch.results) == 0

    @pytest.mark.asyncio
    async def test_is_available_mock(self):
        classifier = HybridClassifier(provider=MockProvider())
        assert classifier.is_available is True

    @pytest.mark.asyncio
    async def test_is_available_no_key(self):
        with patch.dict(os.environ, {}, clear=True):
            classifier = HybridClassifier(provider=LiteLLMProvider())
            assert classifier.is_available is False


# ==================================================================
# Prompt building
# ==================================================================

class TestPromptBuilding:

    @pytest.fixture
    def classifier(self):
        return HybridClassifier(provider=MockProvider())

    def test_poisoning_prompt(self, classifier):
        prompt = classifier._build_prompt(
            ClassificationType.TOOL_POISONING,
            {"name": "my_tool", "description": "Does things"},
        )
        assert "my_tool" in prompt
        assert "Does things" in prompt
        assert "poisoning" in prompt.lower() or "injection" in prompt.lower()

    def test_dangerous_name_prompt(self, classifier):
        prompt = classifier._build_prompt(
            ClassificationType.DANGEROUS_NAME,
            {"name": "evil_tool", "description": "Bad stuff"},
        )
        assert "evil_tool" in prompt
        assert "misleading" in prompt.lower() or "dangerous" in prompt.lower()

    def test_scope_analysis_prompt(self, classifier):
        prompt = classifier._build_prompt(
            ClassificationType.SCOPE_ANALYSIS,
            {"name": "write_data", "description": "Write to DB"},
            scopes=["read", "write", "admin"],
        )
        assert "write_data" in prompt
        assert "read" in prompt
        assert "admin" in prompt

    def test_invalid_type_raises(self, classifier):
        with pytest.raises(ValueError):
            classifier._build_prompt(
                "invalid_type",
                {"name": "tool", "description": "desc"},
            )


# ==================================================================
# PassthroughProvider
# ==================================================================

class TestPassthroughProvider:

    @pytest.mark.asyncio
    async def test_returns_uncertain(self):
        provider = PassthroughProvider()
        response, usage = await provider.classify("system", "user")
        assert response["verdict"] == "uncertain"
        assert response["confidence"] == 0.0

    @pytest.mark.asyncio
    async def test_captures_prompts(self):
        provider = PassthroughProvider()
        await provider.classify("sys1", "user1")
        await provider.classify("sys2", "user2")
        assert len(provider._pending) == 2
        assert provider._pending[0]["system_prompt"] == "sys1"
        assert provider._pending[1]["user_prompt"] == "user2"

    @pytest.mark.asyncio
    async def test_clear_pending(self):
        provider = PassthroughProvider()
        await provider.classify("sys", "user")
        provider.clear_pending()
        assert len(provider._pending) == 0

    def test_is_available(self):
        assert PassthroughProvider().is_available() is True

    def test_model_name(self):
        assert PassthroughProvider().model_name() == "client-passthrough"

    @pytest.mark.asyncio
    async def test_zero_tokens(self):
        provider = PassthroughProvider()
        _, usage = await provider.classify("sys", "user")
        assert usage["total_tokens"] == 0


# ==================================================================
# build_passthrough_request
# ==================================================================

class TestBuildPassthroughRequest:

    @pytest.fixture
    def tools(self):
        return [
            {"name": "read_data", "description": "Read from DB"},
            {"name": "write_data", "description": "Write to DB"},
            {"name": "admin_delete", "description": "Delete records"},
        ]

    def test_all_tools_included(self, tools):
        request = build_passthrough_request(
            scan_id="scan_123",
            tools=tools,
            rule_flagged_names=set(),
            classification_type=ClassificationType.TOOL_POISONING,
        )
        assert len(request.items) == 3
        assert request.scan_id == "scan_123"

    def test_rule_flagged_excluded(self, tools):
        request = build_passthrough_request(
            scan_id="scan_123",
            tools=tools,
            rule_flagged_names={"admin_delete"},
            classification_type=ClassificationType.TOOL_POISONING,
        )
        names = {item.tool_name for item in request.items}
        assert "admin_delete" not in names
        assert len(request.items) == 2

    def test_all_flagged_empty(self, tools):
        request = build_passthrough_request(
            scan_id="scan_123",
            tools=tools,
            rule_flagged_names={"read_data", "write_data", "admin_delete"},
            classification_type=ClassificationType.TOOL_POISONING,
        )
        assert len(request.items) == 0

    def test_system_prompt_present(self, tools):
        request = build_passthrough_request(
            scan_id="scan_123",
            tools=tools,
            rule_flagged_names=set(),
            classification_type=ClassificationType.TOOL_POISONING,
        )
        assert len(request.system_prompt) > 0

    def test_item_has_prompt(self, tools):
        request = build_passthrough_request(
            scan_id="scan_123",
            tools=tools,
            rule_flagged_names=set(),
            classification_type=ClassificationType.TOOL_POISONING,
        )
        for item in request.items:
            assert len(item.prompt) > 0
            assert item.tool_name in item.prompt

    def test_scope_analysis_includes_scopes(self, tools):
        request = build_passthrough_request(
            scan_id="scan_123",
            tools=tools,
            rule_flagged_names=set(),
            classification_type=ClassificationType.SCOPE_ANALYSIS,
            scopes=["read", "write"],
        )
        for item in request.items:
            assert "read" in item.prompt
            assert "write" in item.prompt

    def test_classification_type_set(self, tools):
        request = build_passthrough_request(
            scan_id="scan_123",
            tools=tools,
            rule_flagged_names=set(),
            classification_type=ClassificationType.DANGEROUS_NAME,
        )
        for item in request.items:
            assert item.classification_type == ClassificationType.DANGEROUS_NAME


# ==================================================================
# parse_client_classifications
# ==================================================================

class TestParseClientClassifications:

    def test_basic_parsing(self):
        classifications = [
            ClientClassification(
                tool_name="read_data",
                verdict="clean",
                reasoning="Safe tool",
                confidence=0.9,
                flagged_patterns=[],
            ),
        ]
        results = parse_client_classifications(
            classifications, ClassificationType.TOOL_POISONING
        )
        assert len(results) == 1
        assert results[0].item_id == "read_data"
        assert results[0].verdict == ClassificationVerdict.CLEAN
        assert results[0].confidence_score == 0.9

    def test_flagged_parsing(self):
        classifications = [
            ClientClassification(
                tool_name="evil_tool",
                verdict="flagged",
                reasoning="Contains hidden instructions",
                confidence=0.85,
                flagged_patterns=["instruction override"],
            ),
        ]
        results = parse_client_classifications(
            classifications, ClassificationType.TOOL_POISONING
        )
        assert results[0].verdict == ClassificationVerdict.FLAGGED
        assert results[0].flagged_patterns == ["instruction override"]

    def test_invalid_verdict_becomes_uncertain(self):
        classifications = [
            ClientClassification(
                tool_name="tool",
                verdict="maybe",
                reasoning="Not sure",
                confidence=0.5,
            ),
        ]
        results = parse_client_classifications(
            classifications, ClassificationType.TOOL_POISONING
        )
        assert results[0].verdict == ClassificationVerdict.UNCERTAIN

    def test_confidence_clamped(self):
        with pytest.raises(Exception):
            ClientClassification(
            tool_name="tool",
            verdict="clean",
            confidence=1.5,
        )

        #assert results[0].confidence_score == 1.0

    def test_classification_type_preserved(self):
        classifications = [
            ClientClassification(tool_name="tool", verdict="clean"),
        ]
        results = parse_client_classifications(
            classifications, ClassificationType.DANGEROUS_NAME
        )
        assert results[0].classification_type == ClassificationType.DANGEROUS_NAME

    def test_empty_list(self):
        results = parse_client_classifications([], ClassificationType.TOOL_POISONING)
        assert results == []

    def test_multiple_classifications(self):
        classifications = [
            ClientClassification(tool_name="a", verdict="clean", confidence=0.9),
            ClientClassification(tool_name="b", verdict="flagged", confidence=0.8),
            ClientClassification(tool_name="c", verdict="uncertain", confidence=0.3),
        ]
        results = parse_client_classifications(
            classifications, ClassificationType.TOOL_POISONING
        )
        assert len(results) == 3
        assert results[0].verdict == ClassificationVerdict.CLEAN
        assert results[1].verdict == ClassificationVerdict.FLAGGED
        assert results[2].verdict == ClassificationVerdict.UNCERTAIN


# ==================================================================
# Classification models validation
# ==================================================================

class TestClassificationModels:

    def test_result_confidence_bounds(self):
        with pytest.raises(Exception):
            ClassificationResult(
                item_id="tool",
                classification_type=ClassificationType.TOOL_POISONING,
                verdict=ClassificationVerdict.CLEAN,
                reasoning="Ok",
                confidence_score=1.5,
            )

    def test_result_valid(self):
        result = ClassificationResult(
            item_id="tool",
            classification_type=ClassificationType.TOOL_POISONING,
            verdict=ClassificationVerdict.CLEAN,
            reasoning="All good",
            confidence_score=0.95,
            flagged_patterns=[],
        )
        assert result.item_id == "tool"
        assert result.confidence_score == 0.95

    def test_batch_defaults(self):
        batch = ClassificationBatch()
        assert batch.results == []
        assert batch.model_used == "none"
        assert batch.total_tokens == 0
        assert batch.from_cache == 0
        assert batch.skipped is False

    def test_batch_with_results(self):
        result = ClassificationResult(
            item_id="tool",
            classification_type=ClassificationType.TOOL_POISONING,
            verdict=ClassificationVerdict.CLEAN,
            reasoning="Fine",
            confidence_score=0.9,
        )
        batch = ClassificationBatch(
            results=[result],
            model_used="mock",
            total_tokens=100,
        )
        assert len(batch.results) == 1
        assert batch.total_tokens == 100
