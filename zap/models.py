from django.db import models

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
    descriptions = models.JSONField()  # List of descriptions in various languages
    metrics = models.JSONField(blank=True, null=True)  # CVSS scores and other metrics
    weaknesses = models.JSONField(blank=True, null=True)  # CWE identifiers
    configurations = models.JSONField(blank=True, null=True)  # Affected products/configurations
    references = models.JSONField(blank=True, null=True)  # List of reference URLs
    cisa_exploit_add = models.DateField(blank=True, null=True)
    cisa_action_due = models.DateField(blank=True, null=True)
    cisa_required_action = models.TextField(blank=True, null=True)
    cisa_vulnerability_name = models.CharField(max_length=255, blank=True, null=True)
    tags = models.JSONField(blank=True, null=True)  # Additional tags
    vendor_comments = models.JSONField(blank=True, null=True)  # Additional tags

    def __str__(self):
        return self.cve_id
