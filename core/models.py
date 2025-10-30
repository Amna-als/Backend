from django.db import models
from django.conf import settings
import uuid
from datetime import timedelta
from django.utils import timezone


# Core domain models following the provided class diagram
#
# Each model below maps to a box on the UML diagram 
#


class NutritionalInfo(models.Model):
    calories = models.FloatField(blank=True, null=True)
    carbs = models.FloatField(blank=True, null=True)
    sugar = models.FloatField(blank=True, null=True)
    protein = models.FloatField(blank=True, null=True)
    salt = models.FloatField(blank=True, null=True)
    fat = models.FloatField(blank=True, null=True)
    fiber = models.FloatField(blank=True, null=True)
    portion_size = models.CharField(max_length=100, blank=True, null=True)



    def get_carbs(self):
        return self.carbs

    def __str__(self):
        return f"NutritionalInfo(cal={self.calories}, carbs={self.carbs})"


class FoodEntry(models.Model):
    MEAL_TYPES = [
        ('breakfast', 'Breakfast'),
        ('lunch', 'Lunch'),
        ('dinner', 'Dinner'),
        ('snack', 'Snack'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='food_entries')
    image = models.ImageField(upload_to='food_images/', blank=True, null=True)
    food_name = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    meal_type = models.CharField(max_length=16, choices=MEAL_TYPES, default="lunch")
    nutritional_info = models.OneToOneField(NutritionalInfo, on_delete=models.SET_NULL, null=True, blank=True)
  
    insulin_recommended = models.FloatField(blank=True, null=True)
    insulin_rounded = models.FloatField(blank=True, null=True)

   
    def analyze_food(self, image_file=None):
        """Placeholder for analysis, returns NutritionalInfo-like dict or object."""
        return None

    def __str__(self):
        return f"FoodEntry({self.food_name or self.id})"


class GlucoseRecord(models.Model):
    SOURCE_CHOICES = [
        ("manual", "Manual"),
        ("libre", "Libre"),
        ("other", "Other")
        
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='glucose_records')
    timestamp = models.DateTimeField()
    glucose_level = models.FloatField()
    trend_arrow = models.CharField(max_length=50, blank=True, null=True)
    source = models.CharField(max_length=50, choices=SOURCE_CHOICES, default="manual")  # e.g., 'cgm' or 'manual'

  
    def is_abnormal(self, low_threshold=70, high_threshold=180):
        return not (low_threshold <= self.glucose_level <= high_threshold)

    def __str__(self):
        return f"GlucoseRecord(user={self.user_id}, level={self.glucose_level} at {self.timestamp})"
    class Meta:
        indexes = [
            models.Index(fields=['user', 'timestamp']),
        ]
        constraints = [
            models.UniqueConstraint(fields=['user', 'timestamp','glucose_level', 'source',], name='uniq_glucose_row'),
        ]
class LibreConnection(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='libre_connection')
    email = models.CharField(max_length=200)
    # Store encrypted password/token to avoid plaintext storage; 
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
    # API to exchange email/password for tokens.
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
    def is_token_expired(self):
        """Check if the stored token is expired."""
        if not self.token_expires_at:
            return True
        return timezone.now() >= self.token_expires_at      

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
                    self.token_expires_at = timezone.now() + timedelta(seconds=int(expires_in))
                except Exception:
                    self.token_expires_at = None
                try:
                    self.token_expires_at = timezone.now() + timedelta(seconds=int(expires_in))
                except Exception:
                    self.token_expires_at = None    
            self.connected = True if self.token else False
            self.save()
        except Exception:
            pass


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

    # Simple setter helper for preferred unit.
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

    # send: placeholder where notification logic (push, SMS, email) 
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
    # user's GlucoseRecord/FoodEntry history. 
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



class Images(models.Model):
    title = models.CharField(max_length=200)

    def __str__(self):
        return self.title


