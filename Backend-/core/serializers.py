from rest_framework import serializers
from .models import FoodEntry, GlucoseRecord, NutritionalInfo


# Serializers convert model instances to JSON and validate incoming JSON for
# API endpoints. These are intentionally minimal; customize fields, nesting,
# and validation logic as your API evolves.
class NutritionalInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = NutritionalInfo
        fields = '__all__'


class FoodEntrySerializer(serializers.ModelSerializer):
    # Include a read-only nested representation of the nutritional info if
    # present. When creating FoodEntry via the API you may prefer to accept a
    # nested payload and write custom create() logic to build NutritionalInfo.
    nutritional_info = NutritionalInfoSerializer(read_only=True)

    class Meta:
        model = FoodEntry
        fields = (
            'id', 'user', 'food_name', 'description', 'timestamp', 'meal_type',
            'image', 'nutritional_info', 'insulin_recommended', 'insulin_rounded'
        )
        read_only_fields = ('insulin_recommended', 'insulin_rounded', 'user')


class GlucoseRecordSerializer(serializers.ModelSerializer):
    # Simple serializer exposing the primary glucose fields. In future add
    # validation to ensure timestamps are timezone-aware and glucose_level is
    # within reasonable bounds.
    class Meta:
        model = GlucoseRecord
        fields = ('id', 'user', 'timestamp', 'glucose_level', 'trend_arrow', 'source')
