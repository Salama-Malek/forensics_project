from django.db import models
from django.contrib.auth.models import User

# **************************
# Evidence Management Models
# **************************

class Evidence(models.Model):
    """Model for storing uploaded evidence files."""
    file = models.FileField(upload_to='evidence_files/')
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=1)
    is_deleted = models.BooleanField(default=False)  # Soft delete flag for evidence

    def __str__(self):
        return f"Evidence {self.id} - {self.file.name}"


class MalwareAnalysis(models.Model):
    """Model for storing analysis results for malware in evidence files."""
    evidence = models.ForeignKey(Evidence, on_delete=models.CASCADE)
    analysis_result = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"MalwareAnalysis {self.id} - Evidence {self.evidence.id}"


class LogFile(models.Model):
    """Model for managing log files uploaded by the user."""
    file = models.FileField(upload_to='logs/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.file.name


# **************************
# Directory Scan Models
# **************************

class ScanHistory(models.Model):
    """Model for tracking each scan event performed by the user."""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scan_date = models.DateTimeField(auto_now_add=True)
    directory_scanned = models.CharField(max_length=255)
    files_found = models.IntegerField()
    files_restored = models.IntegerField()

    def __str__(self):
        return f"Scan on {self.scan_date} by {self.user.username}"



from django.db import models
from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField  # Use only if PostgreSQL is available
import json

class ScanResult(models.Model):
    """Model to store results of each directory scan with deleted files."""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    directory_path = models.CharField(max_length=255)
    scan_date = models.DateTimeField(auto_now_add=True)
    files_found = models.IntegerField()
    files_restored = models.IntegerField()
    # Using TextField with JSON for SQLite compatibility; alternatively, ArrayField with PostgreSQL
    deleted_files = models.TextField(blank=True, default='[]')  # JSON serialized list of deleted files

    def set_deleted_files(self, files):
        self.deleted_files = json.dumps(files)

    def get_deleted_files(self):
        return json.loads(self.deleted_files)

    def __str__(self):
        return f"Scan Result - {self.user.username} on {self.scan_date}"
