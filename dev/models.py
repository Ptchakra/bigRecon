from django.db import models

class Dev(models.Model):
    File_name = models.CharField(max_length=1000)
    Status = models.CharField(max_length=100)
    Path = models.CharField(max_length=100)
    Date = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return str(self.File_name)
