
import base64
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types

from contracts.models import Action
from .prompts import SYSTEM_PROMPT


ROOT = Path(__file__).resolve().parents[2]


def build_request(view, task, history, secret_names):
    """Build an AI request using only the sanitized webpage view."""

    elements = []

    for element in view.elements:
        if hasattr(element, "model_dump"):
            elements.append(element.model_dump())
        else:
            elements.append(element.dict())

    screenshot_b64 = base64.b64encode(
        view.screenshot
    ).decode("utf-8")

    return {
        "task": task,
        "url": view.url,
        "elements": elements,
        "screenshot_b64": screenshot_b64,
        "history": history,
        "secret_names": secret_names,
    }


def call_llm(request):
    """Use Gemini to generate one structured PrivacyLens action."""

    load_dotenv(ROOT / ".env")

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is missing. Check your root .env file."
        )

    model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")
    client = genai.Client(api_key=api_key)

    # Send only the sanitized page information and task.
    safe_request = {
        key: value
        for key, value in request.items()
        if key != "screenshot_b64"
    }

    contents = [
        json.dumps(safe_request, ensure_ascii=False)
    ]

    screenshot_b64 = request.get("screenshot_b64")
    if screenshot_b64:
        contents.append(
            types.Part.from_bytes(
                data=base64.b64decode(screenshot_b64),
                mime_type="image/png",
            )
        )

    response = client.models.generate_content(
        model=model,
        contents=contents,
        config=types.GenerateContentConfig(
    system_instruction=SYSTEM_PROMPT,
    response_mime_type="application/json",
    response_schema=Action,
),
    )

    if not response.text:
        raise RuntimeError("Gemini returned an empty response.")

    try:
        parsed = json.loads(response.text)
        return Action.model_validate(parsed)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(
            "Gemini returned an invalid action."
        ) from exc
