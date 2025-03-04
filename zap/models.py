from django.db import models
from django.contrib.postgres.fields import JSONField

# Create your models here.


class CVE(models.Model):
    cve_id = models.CharField(max_length=20, unique=True)
    published_date = models.DateTimeField()
    last_modified_date = models.DateTimeField()
    descriptions = JSONField()  # Stores multiple language descriptions
    metrics = JSONField()  # CVSS scores and other metrics
    weaknesses = JSONField()  # CWE identifiers
    references = JSONField()  # List of reference URLs
    configurations = JSONField()  # Affected products/configurations

    def __str__(self):
        return self.cve_id
