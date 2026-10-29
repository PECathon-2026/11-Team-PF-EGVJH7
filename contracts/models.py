from typing import Literal, Optional
from pydantic import BaseModel

DetType = Literal["CARD","AADHAAR","PAN","EMAIL","PHONE","PASSWORD","OTP", "API_KEY","IP","FACE","PERSON","ADDRESS","OTHER"]

class BBox(BaseModel):
    x: float
    y: float
    w: float
    h: float # pixels, == screenshot pixels

class Element(BaseModel):
    id: str # stable, e.g. "e12"
    tag: str
    role: Optional[str] = None
    type: Optional[str] = None # input type
    name: Optional[str] = None
    label: Optional[str] = None
    text: str = ""
    value: str = ""
    bbox: BBox
    attrs: dict[str, str] = {} # autocomplete, placeholder, etc.

class PageSnapshot(BaseModel):
    url: str
    title: str = ""
    screenshot: bytes # PNG
    elements: list[Element]

class Detection(BaseModel):
    type: DetType
    source: Literal["regex","dom","ocr","ner","face"]
    element_id: Optional[str] = None
    field: Literal["text","value","label"] = "value"
    span: Optional[tuple[int,int]] = None # char range inside that field
    bbox: Optional[BBox] = None # for OCR/face (no element)
    confidence: float = 1.0

class RedactionRecord(BaseModel):
    element_id: Optional[str] = None
    type: str
    source: str
    placeholder: str
    reason: str # for explainable redaction

class SanitizedView(BaseModel):
    url: str
    title: str = ""
    screenshot: bytes
    screenshot_sha256: str
    elements: list[Element] # same ids, values replaced
    report: list[RedactionRecord]

class Action(BaseModel):
    type: Literal["click","type","select","scroll","navigate","done"]
    element_id: Optional[str] = None
    text: Optional[str] = None
    secret_ref: Optional[str] = None
    url: Optional[str] = None
    reason: str = ""

class GuardResult(BaseModel):
    ok: bool
    reasons: list[str] = []

class ValidationResult(BaseModel):
    ok: bool
    needs_approval: bool = False
    reasons: list[str] = []
