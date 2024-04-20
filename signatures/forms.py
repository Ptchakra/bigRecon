from django import forms
from bigRecon.validators import validate_url
from django_ace import AceWidget


class DoScanForm(forms.Form):
    url = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "url",
                "placeholder": "https://example.com",
            }
        ),
    )

    signature_file = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "id": "signature-file",
                "placeholder": "test",
            }
        ),
    )


class EditSignatureForm(forms.Form):
    content = forms.CharField(
        widget=AceWidget(
            mode="text",
            theme="monokai",
            width="100%",
            height="450px",
            tabsize=4,
            fontsize=13,
            toolbar=True,
        )
    )
