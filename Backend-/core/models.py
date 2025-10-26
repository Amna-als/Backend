from django.db import models
from django.conf import settings
import uuid


# Core domain models following the provided class diagram
#
# Each model below maps to a box on the UML diagram 
# Classes are intentionally lightweight: fields model data and helper methods are
# small placeholders that can later be implemented to call external services
# (e.g., image analysis, Libre auth) or to perform domain logic.


class NutritionalInfo(models.Model):
    calories = models.FloatField(blank=True, null=True)
    carbs = models.FloatField(blank=True, null=True)
    sugar = models.FloatField(blank=True, null=True)
    protein = models.FloatField(blank=True, null=True)
    salt = models.FloatField(blank=True, null=True)
    fat = models.FloatField(blank=True, null=True)
    fiber = models.FloatField(blank=True, null=True)
    portion_size = models.CharField(max_length=100, blank=True, null=True)

    # Convenience accessor for calories. In future this can compute calories
    # from component breakdowns or portion sizing logic.
    def get_calories(self):
        return self.calories

    def get_carbs(self):
        return self.carbs

    def __str__(self):
        return f"NutritionalInfo(cal={self.calories}, carbs={self.carbs})"


class FoodEntry(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='food_entries')
    image = models.ImageField(upload_to='food_images/', blank=True, null=True)
    food_name = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    meal_type = models.CharField(max_length=50, blank=True, null=True)
    nutritional_info = models.OneToOneField(NutritionalInfo, on_delete=models.SET_NULL, null=True, blank=True)
    # Recommended insulin values (calculated deterministically). These are
    # stored for UI/display and audit; they do NOT trigger any insulin
    # delivery. Values are optional and set when the backend computes a
    # recommendation for a FoodEntry.
    insulin_recommended = models.FloatField(blank=True, null=True)
    insulin_rounded = models.FloatField(blank=True, null=True)

    # analyze_food: placeholder hook where you can call the vision + nutrition
    # pipeline (OpenAI or other) to produce a NutritionalInfo object or dict.
    # It intentionally does not implement the call here to keep the model layer
    # free of network dependencies; implement in a service layer or view.
    def analyze_food(self, image_file=None):
        """Placeholder for analysis (e.g., call vision API); returns NutritionalInfo-like dict or object."""
        return None

    def __str__(self):
        return f"FoodEntry({self.food_name or self.id})"


class GlucoseRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='glucose_records')
    timestamp = models.DateTimeField()
    glucose_level = models.FloatField()
    trend_arrow = models.CharField(max_length=50, blank=True, null=True)
    source = models.CharField(max_length=50, blank=True, null=True)  # e.g., 'cgm' or 'manual'

    # Domain-level helper: quick abnormality check using thresholds.
    # In real use you may use user-specific targets stored in the User model
    # or Preferences and more sophisticated rolling-window checks.
    def is_abnormal(self, low_threshold=70, high_threshold=180):
        return not (low_threshold <= self.glucose_level <= high_threshold)

    def __str__(self):
        return f"GlucoseRecord(user={self.user_id}, level={self.glucose_level} at {self.timestamp})"


class LibreConnection(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='libre_connection')
    email = models.CharField(max_length=200)
    # Store encrypted password/token to avoid plaintext storage; use users.utils for encrypt/decrypt
    password = models.CharField(max_length=200, blank=True, null=True)
    password_encrypted = models.TextField(blank=True, null=True)
    token = models.CharField(max_length=500, blank=True, null=True)
    refresh_token = models.CharField(max_length=500, blank=True, null=True)
    token_type = models.CharField(max_length=50, blank=True, null=True)
    token_expires_at = models.DateTimeField(blank=True, null=True)
    scope = models.CharField(max_length=200, blank=True, null=True)
    account_id = models.CharField(max_length=200, blank=True, null=True)
    api_endpoint = models.CharField(max_length=500, blank=True, null=True)
    connected = models.BooleanField(default=False)
    region = models.CharField(max_length=100, blank=True, null=True)
    last_synced = models.DateTimeField(blank=True, null=True)

    # authenticate: placeholder where code would reach out to LibreView/LibreLink
    # API to exchange email/password for tokens. Implementations should store
    # tokens (not raw passwords) and handle retry/refresh flows.
    def authenticate(self):
        # placeholder for Libre authentication
        return False

    # helpers to set/get encrypted password using users.utils
    def set_password_encrypted(self, raw_password: str):
        try:
            from users.utils import encrypt_password
            self.password_encrypted = encrypt_password(raw_password)
            self.password = None
            self.save()
        except Exception:
            pass

    def get_password_decrypted(self):
        try:
            from users.utils import decrypt_password
            return decrypt_password(self.password_encrypted)
        except Exception:
            return None

    def set_token_data(self, token_response: dict):
        """Store token response from an OAuth token endpoint.

        Expected keys: access_token, refresh_token, token_type, expires_in, scope
        """
        try:
            from django.utils import timezone
            self.token = token_response.get('access_token')
            self.refresh_token = token_response.get('refresh_token')
            self.token_type = token_response.get('token_type')
            scope = token_response.get('scope')
            if isinstance(scope, list):
                scope = ' '.join(scope)
            self.scope = scope
            expires_in = token_response.get('expires_in')
            if expires_in:
                try:
                    self.token_expires_at = timezone.now() + timezone.timedelta(seconds=int(expires_in))
                except Exception:
                    self.token_expires_at = None
            self.connected = True if self.token else False
            self.save()
        except Exception:
            pass

    # Disconnect helper - clears connection metadata locally. The real
    # implementation should also call the remote API if required.
    def disconnect(self):
        self.connected = False
        self.token = None
        self.save()

    def __str__(self):
        return f"LibreConnection({self.user_id}, connected={self.connected})"


class GlucoseMonitor(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='glucose_monitor')
    connection = models.OneToOneField(LibreConnection, on_delete=models.SET_NULL, null=True, blank=True)
    # store recent glucose values or metadata as JSON; glucose data itself is stored in GlucoseRecord
    meta = models.JSONField(blank=True, null=True)

    # Monitoring helpers. These are placeholders to express the intent that a
    # GlucoseMonitor can orchestrate polling/streaming of CGM data via a
    # `LibreConnection` or other provider.
    def start_live_monitoring(self):
        # placeholder to start monitoring using connection
        pass

    def fetch_latest_glucose(self):
        # placeholder to fetch latest readings
        return []

    def __str__(self):
        return f"GlucoseMonitor(user={self.user_id})"


class Preferences(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='preferences')
    notification_enabled = models.BooleanField(default=True)
    preferred_glucose_unit = models.CharField(max_length=10, default='mg/dL')
    color_scheme = models.CharField(max_length=50, blank=True, null=True)
    language = models.CharField(max_length=20, blank=True, null=True)

    # Simple setter helper for preferred unit. In a complete product this
    # might trigger a conversion of stored values or a user-visible message.
    def set_preferred_unit(self, unit: str):
        self.preferred_glucose_unit = unit
        self.save()

    def __str__(self):
        return f"Preferences(user={self.user_id})"


class Alert(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='alerts')
    alert_type = models.CharField(max_length=100)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    # send: placeholder where notification logic (push, SMS, email) would be
    # implemented. Keep the model simple and implement delivery in a service
    # layer so you can retry and log delivery attempts.
    def send(self):
        # placeholder for sending notifications
        pass

    def __str__(self):
        return f"Alert({self.alert_type}) for {self.user_id} at {self.timestamp}"


class InsightReport(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='insight_reports')
    avg_glucose = models.FloatField(blank=True, null=True)
    most_frequent_meal_type = models.CharField(max_length=100, blank=True, null=True)
    time_of_day_with_spikes = models.CharField(max_length=100, blank=True, null=True)
    general_insights = models.TextField(blank=True, null=True)

    # generate_insights: intended to compute aggregated statistics over a
    # user's GlucoseRecord/FoodEntry history. Implementation belongs in a
    # separate service or management command; the model holds the result.
    def generate_insights(self):
        # placeholder for generating report
        pass

    def __str__(self):
        return f"InsightReport(user={self.user_id})"


class Recommendation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='recommendations')
    admin_id = models.CharField(max_length=200, blank=True, null=True)
    content = models.TextField()
    category = models.CharField(max_length=100, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Recommendation({self.id}) for {self.user_id}"


# Keep small convenience Images model (used earlier in project)
class Images(models.Model):
    title = models.CharField(max_length=200)

    def __str__(self):
        return self.title

