from rest_framework import serializers
from .models import FoodEntry, GlucoseRecord, NutritionalInfo
from .insulin import calculate_insulin



class NutritionalInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = NutritionalInfo
        fields = '__all__'
    

class FoodEntrySerializer(serializers.ModelSerializer):
    
    nutritional_info = NutritionalInfoSerializer(read_only=True)
    total_carbs_g = serializers.FloatField(write_only = True, required= False)


    class Meta:
        model = FoodEntry
        fields = (
            'id', 'user', 'food_name', 'description', 'timestamp', 'meal_type',
            'image', 'nutritional_info', 'insulin_recommended', 'insulin_rounded', 'total_carbs_g'
        )
        read_only_fields = ('user', 'timestamp', 'insulin_recommended', 'insulin_rounded')
    def create(self, validated_data):
        total_carbs_g = validated_data.pop('total_carbs_g', None)
        validated_data.pop('user', None)

        #build foodentry for user
        user = self.context['request'].user
        instance = FoodEntry.objects.create(user=user, **validated_data)


        ni_payload = self.initial_data.get('nutritional_info')
        if isinstance(ni_payload, dict):
            ni_serializer = NutritionalInfoSerializer(data= ni_payload)
            ni_serializer.is_valid(raise_exception=True)
            ni = ni_serializer.save()
            instance.nutritional_info=ni
            instance.save(update_fields=['nutritional_info'])
            if total_carbs_g is None and ni.carbs is not None:
                total_carbs_g=ni.carbs
        
        if total_carbs_g is not None:
            carb_ratio = getattr(user, 'insulin_to_carb_ratio', 0) or 0
            correction_factor= getattr(user, 'correction_factor', None)
            current_glucose = None
            try:
                latest = user.glucose_records.order_by('-timestamp').first()
                if latest:
                    current_glucose = latest.glucose_level
            except Exception:
                pass
            
            res = calculate_insulin(
                total_carbs_g=float(total_carbs_g),
                carb_ratio=float(carb_ratio),
                current_glucose=current_glucose,
                correction_factor=correction_factor,
            )
            instance.insulin_recommended = res.get('recommended_dose')
            instance.insulin_rounded= res.get('rounded_dose')
            instance.save(update_fields=['insulin_recommended','insulin_rounded'])
        return instance
     


class GlucoseRecordSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = GlucoseRecord
        fields = ('id', 'user', 'timestamp', 'glucose_level', 'trend_arrow', 'source')
        read_only_fields = ('user',)

    def create(self, validated_data):
        user = self.context['request'].user
        return GlucoseRecord.objects.create(user=user, **validated_data)

