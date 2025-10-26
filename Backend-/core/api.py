from rest_framework import viewsets, permissions
from .models import FoodEntry, GlucoseRecord
from .serializers import FoodEntrySerializer, GlucoseRecordSerializer

# Additional DRF imports used by the sync endpoints below
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.conf import settings
from .models import LibreConnection, NutritionalInfo
from .utils import estimate_components_carbs
from .insulin import calculate_insulin
from .libre import build_authorize_url, exchange_code_for_token
import requests
from .libre import login_with_password
from rest_framework.throttling import UserRateThrottle
from .openai_service import analyze_image, OpenAIServiceError, OpenAITimeout, OpenAITooManyRequests
import uuid
import logging
import time
import hashlib
from typing import List, Optional

try:
    # lightweight validation; pydantic may already be in requirements
    from pydantic import BaseModel, ValidationError
except Exception:
    BaseModel = None
    ValidationError = Exception

logger = logging.getLogger(__name__)


class FoodEntryViewSet(viewsets.ModelViewSet):
    # Scope FoodEntry queries to the requesting user and require
    # authentication for all operations.
    # Provide a default queryset so DRF routers can auto-determine the basename
    queryset = FoodEntry.objects.none()
    serializer_class = FoodEntrySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user and user.is_authenticated:
            return FoodEntry.objects.filter(user=user)
        return FoodEntry.objects.none()

    def perform_create(self, serializer):
        # Ensure the created FoodEntry is owned by the requesting user.
        instance = serializer.save(user=self.request.user)

        # Try to determine total carbs from the saved nutritional_info or
        # from the incoming request payload (clients may include
        # `total_carbs_g` when creating a food entry). If we can compute
        # carbs and the user has a carb ratio, compute and persist the
        # insulin recommendation for display/audit.
        total_carbs = None
        if instance.nutritional_info and instance.nutritional_info.carbs:
            try:
                total_carbs = float(instance.nutritional_info.carbs)
            except Exception:
                total_carbs = None
        if total_carbs is None:
            # Accept a few possible keys from clients
            total_carbs = self.request.data.get('total_carbs_g') or self.request.data.get('total_carbs')
            try:
                total_carbs = float(total_carbs) if total_carbs is not None else None
            except Exception:
                total_carbs = None

        if total_carbs is not None:
            # Pull user-specific ratios; fall back to zero which yields 0 carb insulin
            carb_ratio = getattr(self.request.user, 'insulin_to_carb_ratio', None) or 0
            correction_factor = getattr(self.request.user, 'correction_factor', None)

            # Try to find the latest glucose record for a correction calculation
            current_glucose = None
            try:
                latest = self.request.user.glucose_records.order_by('-timestamp').first()
                if latest:
                    current_glucose = latest.glucose_level
            except Exception:
                current_glucose = None

            res = calculate_insulin(
                total_carbs_g=total_carbs,
                carb_ratio=carb_ratio,
                current_glucose=current_glucose,
                correction_factor=correction_factor,
            )
            instance.insulin_recommended = res.get('recommended_dose')
            instance.insulin_rounded = res.get('rounded_dose')
            instance.save()


class GlucoseRecordViewSet(viewsets.ModelViewSet):
    # Provide a default queryset so DRF routers can auto-determine the basename
    queryset = GlucoseRecord.objects.none()
    serializer_class = GlucoseRecordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user and user.is_authenticated:
            return GlucoseRecord.objects.filter(user=user)
        return GlucoseRecord.objects.none()

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


# HealthSyncView
#
# This view accepts a single POST with batch payloads coming from mobile
# apps (HealthKit on iOS or Google Fit on Android). The endpoint is
# authenticated (JWT) and creates GlucoseRecord and FoodEntry rows for the
# authenticated user. The payload format is intentionally simple — a list
# of glucose_entries and food_entries — and the view uses a small fallback
# estimator to compute carbs when the client omits them.
class HealthSyncView(APIView):
    """Endpoint for mobile apps to POST batch health data (HealthKit/Google Fit).

    Expected payload example:
    {
      "glucose_records": [{"timestamp":"2025-10-25T00:00:00Z","glucose_level":120,"source":"healthkit"}],
      "food_entries": [{"food_name":"Burger","timestamp":"2025-10-25T00:00:00Z","components":[{"name":"bun","carbs_g":30}]}]
    }
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        payload = request.data
        created = {"glucose_records": 0, "food_entries": 0}

        # Ingest glucose records (best-effort). We swallow malformed items
        # to make the endpoint resilient to partially-correct clients.
        for gr in payload.get('glucose_records', []):
            try:
                GlucoseRecord.objects.create(
                    user=user,
                    timestamp=gr.get('timestamp'),
                    glucose_level=gr.get('glucose_level'),
                    trend_arrow=gr.get('trend_arrow'),
                    source=gr.get('source', 'mobile')
                )
                created['glucose_records'] += 1
            except Exception:
                continue

        # Ingest food entries. If component-level carbs are provided we'll
        # create a NutritionalInfo row using the local estimator as a fallback.
        for fe in payload.get('food_entries', []):
            try:
                components = fe.get('components')
                nutritional = None
                if components:
                    normalized, total = estimate_components_carbs(components)
                    ni = NutritionalInfo.objects.create(carbs=total)
                    nutritional = ni

                FoodEntry.objects.create(
                    user=user,
                    food_name=fe.get('food_name'),
                    description=fe.get('description'),
                    meal_type=fe.get('meal_type'),
                    nutritional_info=nutritional
                )
                created['food_entries'] += 1
            except Exception:
                continue

        return Response({'created': created}, status=status.HTTP_201_CREATED)


class LibreConnectView(APIView):
    """Endpoint for a user to register LibreView credentials (recommended to use token instead).

    The POST body should include `email` and either a `password` or `account_id`.
    We store the password using the small signing helper (dev-safe) to avoid
    leaving plaintext in the DB; for production, replace this with strong
    encryption or a token-based flow.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        body = request.data
        # In static mode, ignore posted email/password/account_id and use
        # the server-wide static Libre credentials instead.
        if getattr(settings, 'LIBRE_STATIC_ENABLED', False):
            email = getattr(settings, 'LIBRE_STATIC_EMAIL', None)
            password = getattr(settings, 'LIBRE_STATIC_PASSWORD', None)
            account_id = None
        else:
            email = body.get('email')
            password = body.get('password')
            account_id = body.get('account_id')
        # Support server-side OAuth exchange: clients can POST {"code": "...", "redirect_uri": "..."}
        code = body.get('code')
        redirect_uri = body.get('redirect_uri')

        if not email or not (password or account_id):
            return Response({'error': 'email and password or account_id required'}, status=status.HTTP_400_BAD_REQUEST)

        lc, _ = LibreConnection.objects.get_or_create(user=user)
        lc.email = email or lc.email
        if password:
            lc.set_password_encrypted(password)
        if account_id:
            lc.account_id = account_id

        # If an OAuth authorization code is provided, exchange it for tokens
        if code and redirect_uri:
            try:
                token_data = exchange_code_for_token(code, redirect_uri)
                lc.set_token_data(token_data)
            except Exception as e:
                return Response({'error': f'token_exchange_failed: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        lc.save()

        return Response({'status': 'ok'})


class LibrePasswordLoginView(APIView):
    """Authenticate to LibreView using email/password and save tokens on LibreConnection.

    POST payload: { email: string, password: string }
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # In static mode the server uses the configured static Libre account.
        # Otherwise accept email/password from the requesting client.
        if getattr(settings, 'LIBRE_STATIC_ENABLED', False):
            email = getattr(settings, 'LIBRE_STATIC_EMAIL', None)
            password = getattr(settings, 'LIBRE_STATIC_PASSWORD', None)
        else:
            body = request.data
            email = body.get('email')
            password = body.get('password')

        if not email or not password:
            return Response({'error': 'email and password required (or enable static account)'}, status=status.HTTP_400_BAD_REQUEST)

        base_url, token_response, headers = login_with_password(email, password)
        if not base_url or not token_response:
            return Response({'error': 'libre_login_failed'}, status=status.HTTP_400_BAD_REQUEST)

        # Save connection data
        user = request.user
        lc, _ = LibreConnection.objects.get_or_create(user=user)
        # store raw account id (not hashed) for lookup
        account_id = token_response.get('account_id')
        if account_id:
            lc.account_id = account_id
        # save the password encrypted for dev (use vault in production)
        try:
            if password:
                lc.set_password_encrypted(password)
        except Exception:
            pass

        # store token info (we only have access token from this flow)
        try:
            lc.token = token_response.get('access_token')
            lc.connected = True if lc.token else False
            lc.api_endpoint = base_url
            lc.save()
        except Exception:
            pass

        # Optionally fetch connections list for immediate verification
        try:
            resp = requests.get(f"{base_url}/llu/connections", headers=headers, timeout=10)
            connections = resp.json()
        except Exception:
            connections = None

        return Response({'status': 'ok', 'connections': connections})


class LibreWebhookView(APIView):
    """Webhook endpoint to receive CGM pushes from LibreView or a relay.

    This view is publicly reachable (AllowAny) but checks a shared secret header
    (`X-Libre-Secret`) against the `LIBRE_WEBHOOK_SECRET` setting to provide a
    minimal authentication layer for webhook payloads. The webhook expects an
    `account_id` or `email` in the payload so we can find the matching
    `LibreConnection` and therefore the owning user.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        secret = getattr(settings, 'LIBRE_WEBHOOK_SECRET', None)
        header = request.headers.get('X-Libre-Secret')
        if secret and header != secret:
            return Response({'error': 'unauthorized'}, status=status.HTTP_403_FORBIDDEN)
        payload = request.data

        # Minimal schema validation using pydantic if available. Keep it small
        # to avoid over-engineering: validate top-level keys and each record
        if BaseModel is not None:
            class WebhookRecordModel(BaseModel):
                timestamp: str
                glucose_level: float
                trend_arrow: Optional[str] = None

            class WebhookPayloadModel(BaseModel):
                account_id: Optional[str] = None
                email: Optional[str] = None
                glucose_records: List[WebhookRecordModel] = []

            try:
                validated = WebhookPayloadModel.parse_obj(payload)
            except ValidationError as ve:
                # Return 400 but keep message minimal to avoid leaking schema
                return Response({'error': 'invalid_payload'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            # pydantic not present: best-effort extraction
            validated = None
        # Identify user by account_id/email in the webhook payload
        if validated is not None:
            account_id = validated.account_id or validated.email
            records = [r.dict() for r in validated.glucose_records]
        else:
            account_id = payload.get('account_id') or payload.get('email')
            records = payload.get('glucose_records', [])
        created = 0
        if account_id:
            try:
                lc = LibreConnection.objects.filter(account_id=account_id).first()
                user = lc.user if lc else None
            except Exception:
                user = None
        else:
            user = None

        # Create GlucoseRecord rows for any records in the payload for the
        # resolved user. To keep the webhook idempotent for demos we do a
        # simple dedupe check: if a record with the same timestamp, value
        # and source already exists we skip it. This avoids creating duplicates
        # when clients retry deliveries. Keep it minimal and DB-backed
        # (no extra models/migrations required).
        for r in records:
            if not user:
                continue

            timestamp = r.get('timestamp')
            glucose_level = r.get('glucose_level')
            trend = r.get('trend_arrow') if isinstance(r.get('trend_arrow'), str) else None

            if not timestamp or glucose_level is None:
                # skip malformed items but don't fail the whole webhook
                continue

            try:
                exists = GlucoseRecord.objects.filter(
                    user=user,
                    timestamp=timestamp,
                    glucose_level=glucose_level,
                    source='libre_webhook'
                ).exists()
                if exists:
                    # already seen, skip
                    continue

                GlucoseRecord.objects.create(
                    user=user,
                    timestamp=timestamp,
                    glucose_level=glucose_level,
                    trend_arrow=trend,
                    source='libre_webhook'
                )
                created += 1
            except Exception:
                # swallow individual failures to keep webhook resilient
                continue

        # Respond 201 if we created new records, 200 otherwise (idempotent)
        status_code = status.HTTP_201_CREATED if created > 0 else status.HTTP_200_OK
        return Response({'created': created}, status=status_code)


class InsulinCalculateView(APIView):
    """Calculate insulin dose deterministically.

    POST JSON payload (example):
    {
      "total_carbs_g": 60,
      "carb_ratio": 10,               # grams per 1 unit
      "current_glucose": 185,         # mg/dL (optional)
      "target_range": [90, 110],      # optional
      "correction_factor": 50,        # mg/dL per 1 unit
      "iob": 0.5,                     # insulin on board (units)
      "min_dose": 0,                  # optional
      "max_dose": 20,                 # optional
      "round_to": 0.5                 # rounding increment
    }

    Returns JSON with breakdown and recommended dose.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        body = request.data
        total_carbs_g = body.get('total_carbs_g', 0)
        carb_ratio = body.get('carb_ratio', 0)
        current_glucose = body.get('current_glucose')
        target_range = body.get('target_range')
        target_bg = body.get('target_bg')
        correction_factor = body.get('correction_factor')
        iob = body.get('iob', 0.0)
        min_dose = body.get('min_dose', 0.0)
        max_dose = body.get('max_dose', 25.0)
        round_to = body.get('round_to', 0.5)

        try:
            result = calculate_insulin(
                total_carbs_g=total_carbs_g,
                carb_ratio=carb_ratio,
                current_glucose=current_glucose,
                target_bg=target_bg,
                target_range=tuple(target_range) if target_range else None,
                correction_factor=correction_factor,
                iob=iob,
                min_dose=min_dose,
                max_dose=max_dose,
                round_to=round_to,
            )
            return Response(result)
        except Exception as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)


class LibreOAuthStartView(APIView):
    """Return an authorization URL that the frontend can redirect the user to.

    Expects GET params:
    - redirect_uri (required): where Libre will redirect after user authorizes
    - state (optional): opaque state value
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        redirect_uri = request.query_params.get('redirect_uri')
        state = request.query_params.get('state')
        if not redirect_uri:
            return Response({'error': 'redirect_uri required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            url = build_authorize_url(redirect_uri=redirect_uri, state=state)
            return Response({'authorize_url': url})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LibreOAuthCallbackView(APIView):
    """Accept an authorization code (POST) and exchange it for tokens server-side.

    POST payload: { code: string, redirect_uri: string }
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        body = request.data
        code = body.get('code')
        redirect_uri = body.get('redirect_uri')
        if not code or not redirect_uri:
            return Response({'error': 'code and redirect_uri required'}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        lc, _ = LibreConnection.objects.get_or_create(user=user)
        try:
            token_data = exchange_code_for_token(code, redirect_uri)
            lc.set_token_data(token_data)
            return Response({'status': 'ok'})
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class OpenAIAnalyzeImageView(APIView):
    """Production-ready image->nutrition endpoint.

    Requirements implemented:
    - JWT (SimpleJWT) required via global REST_FRAMEWORK setting
    - Per-user rate limit (throttle_scope='ai_image')
    - Accept only image/jpeg or image/png, max 4 MB
    - Timeout and simple retries handled in service
    - Strict JSON validated via Pydantic in `openai_service`
    - EXIF stripping performed server-side
    """
    throttle_classes = [UserRateThrottle]
    throttle_scope = 'ai_image'

    def post(self, request):
        user = request.user
        request_id = request.headers.get('X-Request-Id') or str(uuid.uuid4())

        # Validate file input
        f = request.FILES.get('image')
        if not f:
            return Response({'error': 'image file required'}, status=status.HTTP_400_BAD_REQUEST)

        # Content type check
        content_type = f.content_type
        if content_type not in ('image/jpeg', 'image/png'):
            return Response({'error': 'unsupported_media_type'}, status=status.HTTP_400_BAD_REQUEST)

        # Size check (max 4MB)
        max_bytes = 4 * 1024 * 1024
        if f.size > max_bytes:
            return Response({'error': 'file_too_large'}, status=status.HTTP_400_BAD_REQUEST)

        # Read bytes (do not log)
        image_bytes = f.read()

        # Call service
        try:
            start = time.time()
            result = analyze_image(image_bytes=image_bytes, user_id=getattr(user, 'id', None), request_id=request_id)
            latency = time.time() - start
            user_hash = hashlib.sha256(str(getattr(user, 'id', None)).encode('utf-8')).hexdigest()[:16]
            logger.info('ai_request success user=%s request_id=%s latency=%.3f', user_hash, request_id, latency)
            return Response(result)
        except OpenAITimeout:
            user_hash = hashlib.sha256(str(getattr(user, 'id', None)).encode('utf-8')).hexdigest()[:16]
            logger.warning('ai_request timeout user=%s request_id=%s', user_hash, request_id)
            return Response({'error': 'upstream_timeout'}, status=status.HTTP_504_GATEWAY_TIMEOUT)
        except OpenAITooManyRequests:
            user_hash = hashlib.sha256(str(getattr(user, 'id', None)).encode('utf-8')).hexdigest()[:16]
            logger.warning('ai_request rate_limited user=%s request_id=%s', user_hash, request_id)
            return Response({'error': 'rate_limited'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
        except OpenAIServiceError as se:
            user_hash = hashlib.sha256(str(getattr(user, 'id', None)).encode('utf-8')).hexdigest()[:16]
            logger.error('ai_request upstream_fail user=%s request_id=%s error=%s', user_hash, request_id, str(se))
            return Response({'error': 'upstream_model_error'}, status=status.HTTP_502_BAD_GATEWAY)
        except Exception as exc:
            user_hash = hashlib.sha256(str(getattr(user, 'id', None)).encode('utf-8')).hexdigest()[:16]
            logger.exception('ai_request unexpected user=%s request_id=%s', user_hash, request_id)
            return Response({'error': 'internal_error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
