from django.db import models

# Create your models here.

class VulnerabilitySignature(models.Model):
    name = models.CharField(max_length=255, unique=True, help_text="Name of the vulnerability signature")
    description = models.TextField(help_text="Detailed description of the vulnerability")
    severity = models.CharField(
        max_length=10,
        choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High'), ('Critical', 'Critical')],
        help_text="Severity level of the vulnerability"
    )
    affected_component = models.CharField(max_length=255, help_text="Component or system affected by the vulnerability")
    pattern = models.TextField(help_text="Regex or string pattern for detecting the vulnerability")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.severity})"