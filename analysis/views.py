import asyncio
import json
from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse
from django.utils import timezone
from .forms import EvidenceForm, MalwareAnalysisForm, DirectoryScanForm
from .models import Evidence, LogFile, ScanResult, ScanHistory
import pyshark

# **********************************
# User Authentication Views
# **********************************

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            auth_login(request, user)
            return redirect('dashboard')  # Redirect to dashboard after successful login
    else:
        form = AuthenticationForm()

    return render(request, 'registration/login.html', {'form': form})

# New landing page view
def landing(request):
    if request.user.is_authenticated:
        return redirect('dashboard')  # Redirect authenticated users to their dashboard
    return render(request, 'base.html')  # Serve main homepage for unauthenticated users

# Dashboard view
@login_required
def dashboard(request):
    return render(request, 'analysis/dashboard.html')

# **********************************
# User Registration
# **********************************

def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            auth_login(request, user)  # Automatically log the user in after registration
            return redirect('dashboard')
    else:
        form = UserCreationForm()
    return render(request, 'registration/register.html', {'form': form})

# **********************************
# User Logout
# **********************************

@login_required
def logout_view(request):
    auth_logout(request)
    return redirect('landing')

# **********************************
# Upload Evidence
# **********************************

@login_required
def upload_evidence(request):
    if request.method == 'POST':
        form = EvidenceForm(request.POST, request.FILES)
        if form.is_valid():
            evidence = form.save(commit=False)
            evidence.user = request.user  # Associate evidence with the logged-in user
            
            # Adjust the created_at timestamp based on timezone offset
            timezone_offset = int(request.POST.get('timezone_offset', 0))
            adjusted_time = timezone.now() - timedelta(minutes=timezone_offset)
            evidence.created_at = adjusted_time
            
            evidence.save()
            messages.success(request, 'Evidence uploaded successfully!')
            return render(request, 'analysis/upload_evidence.html', {'form': form, 'redirect': True})
    else:
        form = EvidenceForm()
    return render(request, 'analysis/upload_evidence.html', {'form': form})

@login_required
def evidence_list(request):
    user_evidence = Evidence.objects.filter(user=request.user, is_deleted=False)
    return render(request, 'analysis/evidence_list.html', {'evidence': user_evidence})

# **********************************
# Analyze PCAP
# **********************************

@login_required
def analyze_pcap(request, evidence_id):
    evidence = get_object_or_404(Evidence, id=evidence_id, user=request.user)
    pcap_file_path = evidence.file.path
    tshark_path = '/usr/bin/tshark'  # Path to TShark

    # Ensure there's a running event loop for pyshark
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    # Load the PCAP file using pyshark
    try:
        capture = pyshark.FileCapture(pcap_file_path, tshark_path=tshark_path)
    except Exception as e:
        return HttpResponse(f'Error processing PCAP file: {str(e)}', status=500)

    # Extract packet information (first 10 packets)
    packet_data = []
    for packet in capture:
        packet_info = {
            'number': packet.number,
            'protocol': packet.highest_layer,
            'src_ip': getattr(packet, 'ip', None).src if hasattr(packet, 'ip') else 'N/A',
            'dst_ip': getattr(packet, 'ip', None).dst if hasattr(packet, 'ip') else 'N/A',
            'length': packet.length,
            'info': getattr(packet, 'info', None) if hasattr(packet, 'info') else 'N/A'
        }
        packet_data.append(packet_info)
        if len(packet_data) >= 10:  # Limit to first 10 packets
            break

    context = {
        'evidence': evidence,
        'packet_data': packet_data
    }

    return render(request, 'analysis/analyze_pcap.html', context)

# **********************************
# Upload Log File
# **********************************

@login_required
def upload_log(request):
    if request.method == 'POST':
        log_file = request.FILES['log_file']
        log_instance = LogFile.objects.create(file=log_file, user=request.user)  # Associate log with user
        return redirect('analyze_log', log_id=log_instance.id)
    return render(request, 'analysis/upload_log.html')

# **********************************
# Analyze Log File (Placeholder for Splunk integration)
# **********************************

@login_required
def analyze_log(request, log_id):
    log = get_object_or_404(LogFile, id=log_id, user=request.user)
    return HttpResponse(f'Analysis of log file {log.file.name} is under construction.', status=200)

# **********************************
# Add Malware Analysis
# **********************************

@login_required
def add_analysis(request):
    if request.method == 'POST':
        form = MalwareAnalysisForm(request.POST)
        # Filtering queryset after POST to avoid including deleted files on validation errors
        form.fields['evidence'].queryset = Evidence.objects.filter(user=request.user, is_deleted=False)
        
        if form.is_valid():
            malware_analysis = form.save(commit=False)
            # Ensure the evidence is owned by the user
            if malware_analysis.evidence.user == request.user:
                malware_analysis.save()
                messages.success(request, 'Malware analysis submitted successfully!')
                return redirect('dashboard')
            else:
                messages.error(request, 'You do not have permission to analyze this evidence.')
    else:
        form = MalwareAnalysisForm()
        # Initial queryset setup for new GET requests
        form.fields['evidence'].queryset = Evidence.objects.filter(user=request.user, is_deleted=False)

    return render(request, 'analysis/add_analysis.html', {'form': form})


# **********************************
# Download Report
# **********************************

@login_required
def download_report(request, evidence_id):
    evidence = get_object_or_404(Evidence, id=evidence_id, user=request.user)

    response = HttpResponse(content_type='text/plain')
    response['Content-Disposition'] = f'attachment; filename="evidence_{evidence_id}_report.txt"'

    response.write(f"Evidence ID: {evidence.id}\n")
    response.write(f"File Name: {evidence.file.name}\n")
    response.write(f"Uploaded on: {evidence.created_at}\n\n")

    analysis = evidence.malwareanalysis_set.all()
    if analysis.exists():
        for a in analysis:
            response.write(f"Analysis Result: {a.analysis_result}\n")
            response.write(f"Analyzed on: {a.created_at}\n\n")
    else:
        response.write("No analysis available for this evidence.\n")

    return response

# **********************************
# Delete Evidence
# **********************************

@login_required
def delete_evidence(request, evidence_id):
    evidence = get_object_or_404(Evidence, id=evidence_id, user=request.user, is_deleted=False)
    evidence.is_deleted = True  # Mark as soft deleted
    evidence.save()
    messages.success(request, 'Evidence marked as deleted successfully!')
    return redirect('evidence_list')

# **********************************
# Initiate Directory Scan
# **********************************

@login_required
def initiate_scan(request):
    if request.method == 'POST':
        form = DirectoryScanForm(request.POST)
        if form.is_valid():
            directory_json = form.cleaned_data.get('directory_path')
            try:
                directories = json.loads(directory_json) if directory_json else []
            except json.JSONDecodeError:
                messages.error(request, "Invalid directory data format.")
                return redirect('directory_scan_view')

            # Example scan simulation logic
            deleted_files = ["file1.txt", "file2.txt"]  # Example deleted files
            
            # Save results to ScanResult model
            scan_result = ScanResult.objects.create(
                user=request.user,
                directory_path=str(directories),
                scan_date=timezone.now(),
                files_found=len(deleted_files),
                files_restored=0
            )
            scan_result.set_deleted_files(deleted_files)
            scan_result.save()
            
            # Log scan in ScanHistory
            ScanHistory.objects.create(
                user=request.user,
                scan_date=timezone.now(),
                directory_scanned=directory_json,
                files_found=len(deleted_files),
                files_restored=0
            )

            messages.success(request, f'Scan completed! Files found: {len(deleted_files)}')
            return redirect('scan_history')
    else:
        form = DirectoryScanForm()

    return render(request, 'analysis/directory_scan.html', {'form': form})

# **********************************
# User Profile Views
# **********************************

@login_required
def user_profile(request):
    return render(request, 'profile.html')

from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import render, redirect
from django.contrib import messages

@login_required
def edit_profile(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')
        
        # Update username if it has changed
        if username and request.user.username != username:
            request.user.username = username
            request.user.save()
            messages.success(request, 'Username updated successfully!')

        # Optional Password Change
        if new_password1 or new_password2:
            if new_password1 == new_password2:
                # Set the new password and save the user object
                request.user.set_password(new_password1)
                request.user.save()
                # Update the session to keep the user logged in
                update_session_auth_hash(request, request.user)
                messages.success(request, 'Password updated successfully!')
            else:
                messages.error(request, 'New passwords do not match.')

        return redirect('user_profile')

    return render(request, 'edit_profile.html')
