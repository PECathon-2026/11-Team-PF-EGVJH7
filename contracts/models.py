from typing import Literal, Optional, Any
from pydantic import BaseModel, Field


DetType = Literal[
    "CARD", "AADHAAR", "PAN", "EMAIL", "PHONE", "PASSWORD", "OTP",
    "API_KEY", "IP", "FACE", "PERSON", "ADDRESS", "OTHER"
]


class BBox(BaseModel):
    x: float
    y: float
    w: float
    h: float  # Pixel coordinates relative to the screenshot


class Element(BaseModel):
    id: str
    tag: str
    role: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    label: Optional[str] = None
    text: str = ""
    value: str = ""
    bbox: Optional[BBox] = None
    attrs: dict[str, str] = Field(default_factory=dict)


class PageSnapshot(BaseModel):
    url: str
    title: str = ""
    screenshot: bytes
    elements: list[Element] = Field(default_factory=list)


class Detection(BaseModel):
    type: DetType
    source: Literal["regex", "dom", "ocr", "ner", "face", "detector"] = "regex"
    element_id: Optional[str] = None
    field: Literal["text", "value", "label"] = "value"
    span: Optional[tuple[int, int]] = None
    bbox: Optional[BBox] = None
    confidence: float = 1.0


class RedactionRecord(BaseModel):
    element_id: Optional[str] = None
    type: str
    source: str
    placeholder: str
    reason: str


class SanitizedView(BaseModel):
    url: str
    title: str = ""
    screenshot: bytes
    screenshot_sha256: str
    elements: list[Element] = Field(default_factory=list)
    report: list[RedactionRecord] = Field(default_factory=list)


class Action(BaseModel):
    type: Literal["click", "type", "select", "scroll", "navigate", "done"]
    element_id: Optional[str] = None
    text: Optional[str] = None
    secret_ref: Optional[str] = None
    url: Optional[str] = None
    reason: str = ""


class GuardResult(BaseModel):
    ok: bool
    reasons: list[str] = Field(default_factory=list)


class ValidationResult(BaseModel):
    ok: bool
    needs_approval: bool = False
    reasons: list[str] = Field(default_factory=list)