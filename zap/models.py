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

    cisa_exploit_add = models.DateField(blank=True, null=True)
    cisa_action_due = models.DateField(blank=True, null=True)
    cisa_required_action = models.TextField(blank=True, null=True)
    cisa_vulnerability_name = models.CharField(max_length=255, blank=True, null=True)

    cve_tags = models.JSONField(blank=True, null=True)  # Only cve_tags is included
    descriptions = models.JSONField()  # List of descriptions in various languages
    references = models.JSONField(blank=True, null=True)  # List of reference URLs
    metrics = models.JSONField(blank=True, null=True)  # CVSS scores and other metrics
    weaknesses = models.JSONField(blank=True, null=True)  # CWE identifiers
    configurations = models.JSONField(blank=True, null=True)  # Affected products/configurations
    vendor_comments = models.JSONField(blank=True, null=True)  # Vendor comments

    def __str__(self):
        return self.cve_id

    def to_dict(self):
        return {
            "cve_id": self.cve_id,
            "source_identifier": self.source_identifier,
            "vuln_status": self.vuln_status,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "last_modified_date": self.last_modified_date.isoformat() if self.last_modified_date else None,

            "evaluator_comment": self.evaluator_comment,
            "evaluator_solution": self.evaluator_solution,
            "evaluator_impact": self.evaluator_impact,

            "cisa_exploit_add": self.cisa_exploit_add.isoformat() if self.cisa_exploit_add else None,
            "cisa_action_due": self.cisa_action_due.isoformat() if self.cisa_action_due else None,
            "cisa_required_action": self.cisa_required_action,
            "cisa_vulnerability_name": self.cisa_vulnerability_name,

            "cve_tags": self.cve_tags,
            "descriptions": self.descriptions,
            "references": self.references,
            "metrics": self.metrics,
            "weaknesses": self.weaknesses,
            "configurations": self.configurations,
            "vendor_comments": self.vendor_comments,
        }

