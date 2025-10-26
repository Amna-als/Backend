
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers

from core import views
from core.api import FoodEntryViewSet, GlucoseRecordViewSet
from core.api import (
    HealthSyncView, LibreConnectView, LibreWebhookView, InsulinCalculateView,
    LibreOAuthStartView, LibreOAuthCallbackView, LibrePasswordLoginView,
    OpenAIAnalyzeImageView,
)

router = routers.DefaultRouter()
router.register(r'food-entries', FoodEntryViewSet)
router.register(r'glucose-records', GlucoseRecordViewSet)

urlpatterns = [
    path('', views.aiopen, name="openai"),
    path('api/sample-ai/', views.sample_ai_view, name='sample_ai'),
    path('api/', include(router.urls)),
    path('api/sync/health/', HealthSyncView.as_view(), name='health_sync'),
    path('api/libre/connect/', LibreConnectView.as_view(), name='libre_connect'),
    path('api/libre/webhook/', LibreWebhookView.as_view(), name='libre_webhook'),
    path('api/insulin/calculate/', InsulinCalculateView.as_view(), name='insulin_calculate'),
    path('api/libre/oauth/start/', LibreOAuthStartView.as_view(), name='libre_oauth_start'),
    path('api/libre/oauth/callback/', LibreOAuthCallbackView.as_view(), name='libre_oauth_callback'),
    path('api/libre/login/', LibrePasswordLoginView.as_view(), name='libre_password_login'),
    path('api/ai/analyze-image/', OpenAIAnalyzeImageView.as_view(), name='ai_analyze_image'),
]
