from django.contrib import admin
from .models import Framework, FrameworkControl


@admin.register(Framework)
class FrameworkAdmin(admin.ModelAdmin):
    list_display = ['name', 'version', 'is_active', 'created_at']
    list_filter = ['is_active']
    search_fields = ['name']


@admin.register(FrameworkControl)
class FrameworkControlAdmin(admin.ModelAdmin):
    list_display = ['control_id', 'title', 'category', 'framework']
    list_filter = ['framework', 'category']
    search_fields = ['control_id', 'title', 'description']
