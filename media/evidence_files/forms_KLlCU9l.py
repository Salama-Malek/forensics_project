from django import forms
from .models import Evidence

class EvidenceForm(forms.ModelForm):
    class Meta:
        model = Evidence
        fields = ['file']

# *******************************

from .models import MalwareAnalysis

class MalwareAnalysisForm(forms.ModelForm):
    class Meta:
        model = MalwareAnalysis
        fields = ['evidence', 'analysis_result']
        widgets = {
            'analysis_result': forms.Textarea(attrs={'rows': 5}),
        }
