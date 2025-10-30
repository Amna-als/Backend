from rest_framework import serializers
from .models import FoodEntry, GlucoseRecord, NutritionalInfo



class NutritionalInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = NutritionalInfo
        fields = '__all__'
    def create(self, validated_data):
        return NutritionalInfo.objects.create(**validated_data)


class FoodEntrySerializer(serializers.ModelSerializer):
    nutritional_info = NutritionalInfoSerializer(read_only=True)

    class Meta:
        model = FoodEntry
        fields = (
            'id', 'user', 'food_name', 'description', 'timestamp', 'meal_type',
            'image', 'nutritional_info', 'insulin_recommended', 'insulin_rounded'
        )
        read_only_fields = ('insulin_recommended', 'insulin_rounded', 'user')
    def create(self, validated_data):
        nutrional_info_data = validated_data.pop('nutritional_info', None)
        user = self.context['request'].user
        food_entry = FoodEntry.objects.create(user=user, **validated_data)
        if nutrional_info_data:
            nutrational_info_data = NutritionalInfo.objects.create(**nutrional_info_data)
            food_entry.nutritional_info = nutrational_info_data
            food_entry.save()
        return food_entry


class GlucoseRecordSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = GlucoseRecord
        fields = ('id', 'user', 'timestamp', 'glucose_level', 'trend_arrow', 'source')
        read_only_fields = ('user',)

    def create(self, validated_data):
        user = self.context['request'].user
        return GlucoseRecord.objects.create(user=user, **validated_data)

