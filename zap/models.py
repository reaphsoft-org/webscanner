from django.db import models
from django.contrib.postgres.fields import JSONField

# Create your models here.


class CVE(models.Model):
    cve_id = models.CharField(max_length=20, unique=True)
    source_identifier = models.CharField(max_length=100)
    vuln_status = models.CharField(max_length=50)
    published_date = models.DateTimeField()
    last_modified_date = models.DateTimeField()
    evaluator_comment = models.TextField(blank=True, null=True)
    evaluator_solution = models.TextField(blank=True, null=True)
    evaluator_impact = models.TextField(blank=True, null=True)
    descriptions = JSONField()  # List of descriptions in various languages
    metrics = JSONField(blank=True, null=True)  # CVSS scores and other metrics
    weaknesses = JSONField(blank=True, null=True)  # CWE identifiers
    configurations = JSONField(blank=True, null=True)  # Affected products/configurations
    references = JSONField(blank=True, null=True)  # List of reference URLs
    cisa_exploit_add = models.DateField(blank=True, null=True)
    cisa_action_due = models.DateField(blank=True, null=True)
    cisa_required_action = models.TextField(blank=True, null=True)
    cisa_vulnerability_name = models.CharField(max_length=255, blank=True, null=True)
    tags = JSONField(blank=True, null=True)  # Additional tags
    vendor_comments = JSONField(blank=True, null=True)  # Additional tags

    def __str__(self):
        return self.cve_id
