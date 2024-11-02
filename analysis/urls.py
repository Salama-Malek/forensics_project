from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    # Landing page
    path('', views.landing, name='landing'),  
    
    # Dashboard
    path('dashboard/', views.dashboard, name='dashboard'), 
    
    # Evidence-related paths
    path('upload-evidence/', views.upload_evidence, name='upload_evidence'),
    path('evidence-list/', views.evidence_list, name='evidence_list'),
    path('download-report/<int:evidence_id>/', views.download_report, name='download_report'),
    path('delete-evidence/<int:evidence_id>/', views.delete_evidence, name='delete_evidence'),

    # Analysis-related paths
    path('add-analysis/', views.add_analysis, name='add_analysis'),
    path('analyze-pcap/<int:evidence_id>/', views.analyze_pcap, name='analyze_pcap'),

    # User authentication paths
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='landing'), name='logout'),
    path('register/', views.register, name='register'),

    # Directory scan and history
    path('directory-scan/', views.DirectoryScanForm, name='directory_scan_view'),
    path('scan-history/', views.ScanHistory, name='scan_history'),

    # User profile paths
    path('profile/', views.user_profile, name='user_profile'),
    path('profile/edit/', views.edit_profile, name='edit_profile'),

]
