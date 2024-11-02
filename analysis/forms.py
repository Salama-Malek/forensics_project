from django import forms
from .models import Evidence
from .models import MalwareAnalysis


class EvidenceForm(forms.ModelForm):
    class Meta:
        model = Evidence
        fields = ['file']

# *******************************


class MalwareAnalysisForm(forms.ModelForm):
    class Meta:
        model = MalwareAnalysis
        fields = ['evidence', 'analysis_result']
        widgets = {
            'analysis_result': forms.Textarea(attrs={'rows': 5}),
        }


    

class DirectoryScanForm(forms.Form):
    directory_path = forms.CharField(
        widget=forms.HiddenInput(),  # Hidden field for directory paths populated by JavaScript
        required=False,
        label="Directory Path"
    )
