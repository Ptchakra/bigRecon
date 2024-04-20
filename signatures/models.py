from django.db import models

# Create your models here.
class Signatures(models.Model):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    SEVERITY = (
        (INFO, 'Info'),
        (LOW, 'Low'),
        (MEDIUM, 'Medium'),
        (HIGH, 'High'),
        (CRITICAL, 'Critical')
    )
    LIST = 0
    FUZZ = 1
    ROUTINE = 2
    TYPE = (
        (0, 'List'),
        (1, 'Fuzz'),
        (2, 'Routine')
    )
    sign_id = models.CharField(max_length=200, primary_key=True)
    sign_name = models.CharField(max_length=500)
    severity = models.IntegerField(default=0)
    os = models.CharField(max_length=500, null=True)
    target_for = models.CharField(max_length=1000, null=True)
    type_sign = models.IntegerField(default=0)
    description = models.CharField(max_length=2000, null=True)
    last_modified = models.DateTimeField()
    sign_path = models.CharField(max_length=100, null=True, default=None)

    def __str__(self):
        return self.sign_id
