import os

import pytest
from openai import OpenAI

from deconvolute import guard
from deconvolute.detectors.content.language.engine import LanguageDetector
from deconvolute.detectors.integrity.canary.engine import CanaryDetector
from deconvolute.errors import ThreatDetectedError

run_live = os.getenv("DCV_LIVE_TEST") == "true"
reason = "Skipping live OpenAI tests. Run with DCV_LIVE_TEST=true to enable."


@pytest.mark.skipif(not run_live, reason=reason)
class TestLiveOpenAI:
    @pytest.fixture
    def api_key(self):
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            pytest.fail("OPENAI_API_KEY not found in environment.")
        return key

    def test_end_to_end_passthrough(self, api_key):
        """
        Scenario: Standard usage.
        Verifies: Injection -> API Call -> Output Cleaning -> Result.
        """
        raw_client = OpenAI(api_key=api_key)
        # Use Canary to ensure we test the full inject/check/clean lifecycle
        client = guard(raw_client, detectors=[CanaryDetector()])

        print("\nSending request to OpenAI (Real API)...")
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Return the number 42."},
            ],
            temperature=0,  # Deterministic
        )

        content = response.choices[0].message.content
        print(f"Received: {content}")

        # Ensure we got a valid response
        assert content is not None, "Response content was None"
        assert "42" in content
        # Ensure no Canary artifacts leaked (e.g. )
        assert "dcv_token" not in content

    def test_end_to_end_blocking(self, api_key):
        """
        Scenario: Security Block.
        Verifies: The proxy correctly raises ThreatDetectedError on real data.
        """
        raw_client = OpenAI(api_key=api_key)

        # Configure to allow French, but we will force the model to speak English.
        # This guarantees a violation.
        client = guard(
            raw_client, detectors=[LanguageDetector(allowed_languages=["fr"])]
        )

        print("\nAttempting to trigger a Language Violation...")

        # Assert that the error is raised
        with pytest.raises(ThreatDetectedError) as exc:
            client.chat.completions.create(
                model="gpt-3.5-turbo",
                # We force the model to output English, which is NOT allowed.
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "Say 'Hello' in English."},
                ],
                temperature=0,
            )

        print(f"Successfully blocked threat: {exc.value}")
        assert exc.value.result.component == "LanguageDetector"
