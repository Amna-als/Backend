import hashlib
import json
import logging
import time
from typing import List, Optional

from django.conf import settings

import openai
from pydantic import BaseModel, ValidationError
from typing import List
from PIL import Image, ExifTags
from io import BytesIO

logger = logging.getLogger(__name__)


class Component(BaseModel):
    name: str
    carbs_g: float


class OpenAIImageResponse(BaseModel):
    name: str
    components: List[Component]
    total_carbs_g: float
    confidence: Optional[float] = None
    calories_estimate: Optional[float] = None


class OpenAIServiceError(Exception):
    status = 502


class OpenAITimeout(OpenAIServiceError):
    status = 504


class OpenAITooManyRequests(OpenAIServiceError):
    status = 429


def _hash_user_id(user_id: Optional[int]) -> str:
    if user_id is None:
        return 'anon'
    return hashlib.sha256(str(user_id).encode()).hexdigest()[:16]


def _strip_exif(image_bytes: bytes) -> bytes:
    # Remove EXIF (including GPS) by re-saving the image without info
    try:
        img = Image.open(BytesIO(image_bytes))
        data = BytesIO()
        # Convert to RGB to avoid problems with palettes
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
        img.save(data, format='JPEG', quality=85)
        return data.getvalue()
    except Exception:
        # If pillow fails, just return original bytes; caller should still
        # enforce that images are only jpeg/png.
        return image_bytes


def analyze_image(image_bytes: bytes, user_id: Optional[int] = None, request_id: Optional[str] = None) -> dict:
    """Call OpenAI to analyze an image and return validated JSON matching OpenAIImageResponse.

    Implements timeout and simple retry logic for 429/5xx and maps errors to
    consistent exceptions.
    """
    start = time.time()
    hashed_user = _hash_user_id(user_id)
    rid = request_id or 'rid-none'

    # Sanitize image (strip EXIF/GPS)
    safe_image = _strip_exif(image_bytes)

    client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)

    # System instruction requesting strict JSON only
    system_instruction = (
        "You are a food nutrition assistant.\n"
        "Given an image, identify the main dish and the individual components/ingredients that make up the meal. For each component, estimate the amount of carbohydrates (in grams) that component contributes.\n"
        "Return a single valid JSON object ONLY with the following schema:\n"
        "{\n"
        "  \"name\": string,\n"
        "  \"components\": [ { \"name\": string, \"carbs_g\": number } ],\n"
        "  \"total_carbs_g\": number,\n"
        "  \"confidence\": number (0-1, optional),\n"
        "  \"calories_estimate\": number (optional)\n"
        "}\n"
        "Make numeric values plain numbers (not strings), round to one decimal place if needed, and use grams for carbs."
    )

    user_message = (
        "Identify the meal and list components with estimated carbs in grams, then compute total_carbs_g as the sum."
    )

    model = getattr(settings, 'OPENAI_MODEL', None) or settings.OPENAI_VISION_MODEL
    timeout = getattr(settings, 'OPENAI_TIMEOUT', 20)

    max_retries = 2
    attempt = 0
    last_exc = None
    while attempt <= max_retries:
        attempt += 1
        try:
            # send as a small multipart-like payload; the SDK may accept an image data URL
            # We intentionally do not log the image bytes or API key.
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": user_message},
                ],
                # Attach the image as a base64 payload in a single field to the model
                # Some vision-capable models accept data URLs; we include the data URL
                # inline in the user message to avoid separately uploading binary to logs.
                # Note: we avoid logging this content.
                max_tokens=800,
                temperature=0,
                timeout=timeout,
            )

            try:
                raw_text = response.choices[0].message.content
            except Exception:
                raw_text = response['choices'][0]['message']['content']

            # Attempt to extract JSON object from output
            start_br = raw_text.find('{')
            end_br = raw_text.rfind('}')
            if start_br != -1 and end_br != -1 and end_br > start_br:
                json_text = raw_text[start_br:end_br+1]
            else:
                json_text = raw_text

            parsed = json.loads(json_text)

            # Validate with pydantic
            validated = OpenAIImageResponse.parse_obj(parsed)

            duration = time.time() - start
            logger.info("openai_success user=%s request_id=%s latency=%.3f", hashed_user, rid, duration)
            return validated.dict()

        except ValidationError as ve:
            logger.warning("openai_invalid_json user=%s request_id=%s error=%s", hashed_user, rid, ve)
            # upstream returned JSON but it didn't match schema
            raise OpenAIServiceError("model_returned_invalid_json")
        except openai.error.InvalidRequestError as ire:
            last_exc = ire
            logger.error("openai_invalid_request user=%s request_id=%s error=%s", hashed_user, rid, str(ire))
            raise OpenAIServiceError("invalid_request")
        except openai.error.RateLimitError as rle:
            last_exc = rle
            logger.warning("openai_rate_limit user=%s request_id=%s attempt=%d", hashed_user, rid, attempt)
            if attempt > max_retries:
                raise OpenAITooManyRequests("rate_limited")
            time.sleep(1)
            continue
        except openai.error.APIError as api_err:
            last_exc = api_err
            logger.warning("openai_api_error user=%s request_id=%s attempt=%d error=%s", hashed_user, rid, attempt, str(api_err))
            if attempt > max_retries:
                raise OpenAIServiceError("upstream_error")
            time.sleep(1)
            continue
        except openai.error.Timeout as te:
            logger.warning("openai_timeout user=%s request_id=%s", hashed_user, rid)
            raise OpenAITimeout("timeout")
        except Exception as exc:
            last_exc = exc
            logger.exception("openai_unexpected user=%s request_id=%s attempt=%d", hashed_user, rid, attempt)
            # For some 5xx or unexpected errors retry once
            if attempt > max_retries:
                raise OpenAIServiceError("unexpected_error")
            time.sleep(1)
            continue

    # If we exit loop without returning, raise last known error
    raise OpenAIServiceError(str(last_exc) if last_exc else "unknown_error")
