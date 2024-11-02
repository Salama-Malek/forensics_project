from django.contrib import admin
from .models import Evidence, MalwareAnalysis, LogFile

admin.site.register(Evidence)
admin.site.register(MalwareAnalysis)
admin.site.register(LogFile)
