
from typing import Literal, Optional, Any
from pydantic import BaseModel, Field, ConfigDict

DetType = Literal[
    "CARD", "AADHAAR", "PAN", "EMAIL", "PHONE", "PASSWORD", "OTP",
    "API_KEY", "IP", "FACE", "PERSON", "ADDRESS", "OTHER", "SECRET"
]


class BBox(BaseModel):
    x: float
    y: float
    w: float
    h: float


class Element(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    tag: str
    role: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    label: Optional[str] = None
    placeholder: str = ""
    text: str = ""
    value: str = ""
    placeholder: str = ""
    title: str = ""
    bbox: Optional[BBox] = None
    attrs: dict[str, Any] = Field(default_factory=dict)
    attributes: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if self.attributes and not self.attrs:
            self.attrs = dict(self.attributes)
        elif self.attrs and not self.attributes:
            self.attributes = dict(self.attrs)


PageElement = Element


class PageSnapshot(BaseModel):
    url: str
    title: str = ""
    screenshot: bytes
    elements: list[Element] = Field(default_factory=list)
    # take_snapshot captures a viewport screenshot at Playwright's CSS scale.
    viewport_size: Optional[tuple[int, int]] = None
    device_pixel_ratio: Optional[float] = None
    snapshot_id: Optional[str] = None


class Detection(BaseModel):
    type: DetType
    source: Literal[
        "regex", "dom", "ocr", "ner", "face", "detector",
        "custom_privacy_rule"
    ] = "regex"
    element_id: Optional[str] = None
    field: Literal["text", "value", "label", "placeholder", "title"] = "value"
    span: Optional[tuple[int, int]] = None
    bbox: Optional[dict[str, Any] | BBox] = None
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
    report: list[dict[str, Any]] = Field(default_factory=list)


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
