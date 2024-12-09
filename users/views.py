from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import UserRegistrationForm, UserTopUp
from .models import Transcation, Profile
import requests
from django.conf import settings


def register(request):
    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your account has been created! You can now log in.")
            return redirect('users:login')
    else:
        form = UserRegistrationForm()
    return render(request, 'users/register.html', {'form': form})


@login_required(login_url='users:login')
def user(request):
    # Check if the user has a profile, create one if missing
    if not hasattr(request.user, 'profile'):
        Profile.objects.create(user=request.user)

    profile = request.user.profile  # Safe to access now
    transactions = Transcation.objects.filter(user=request.user).order_by('-created_at')
    return render(request, "users/user.html", {
        'user': request.user,
        'balance': profile.balance,
        'transactions': transactions,
    })


def login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', reverse("users:user"))
            return HttpResponseRedirect(next_url)
        else:
            messages.error(request, "Invalid Credentials.")
    return render(request, "users/login.html")


def logout_view(request):
    logout(request)
    messages.success(request, "Successfully logged out.")
    return redirect('users:login')


def login_view(request):
    if request.method == "POST":
        # Retrieve user input
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "").strip()
        recaptcha_response = request.POST.get("recaptcha-token", "")

        # Verify reCAPTCHA
        recaptcha_data = {
            'secret': settings.RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response,
            'remoteip': request.META.get('REMOTE_ADDR', ''),
        }
        
        try:
            recaptcha_verification = requests.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data=recaptcha_data
            )
            recaptcha_verification.raise_for_status()  # Ensure the request was successful
            recaptcha_result = recaptcha_verification.json()
        except requests.RequestException as e:
            messages.error(request, "Unable to verify reCAPTCHA. Please try again later.")
            return redirect("users:login")

        # Check reCAPTCHA response
        if not recaptcha_result.get("success", False):
            messages.error(request, "reCAPTCHA validation failed. Please try again.")
            return redirect("users:login")  # Redirect back to the login page

        # Authenticate user if reCAPTCHA is valid
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Redirect to the next URL if provided, else default to user profile
            next_url = request.GET.get('next', reverse("users:user"))
            return redirect(next_url)
        else:
            messages.error(request, "Invalid username or password.")
            return redirect("users:login")  # Redirect back to the login page

    # Render the login page for GET requests
    return render(request, "users/login.html")


@login_required(login_url='users:login')
def user_view(request):
    # Check if the user has a profile, create one if missing
    if not hasattr(request.user, 'profile'):
        Profile.objects.create(user=request.user)

    profile = request.user.profile  # Safe to access now
    return render(request, 'users/user.html', {'balance': profile.balance})


@login_required(login_url='users:login')
def top_up(request):
    # Check if the user has a profile, create one if missing
    if not hasattr(request.user, 'profile'):
        Profile.objects.create(user=request.user)

    profile = request.user.profile  # Safe to access now
    if request.method == 'POST':
        form = UserTopUp(request.POST)
        if form.is_valid():
            amount = form.cleaned_data['amount']
            profile.balance += amount
            profile.save()
            Transcation.objects.create(user=request.user, amount=amount)
            messages.success(request, f"${amount} has been successfully added to your balance")
            return redirect('users:user')
    else:
        form = UserTopUp()
    return render(request, 'users/topup.html', {'form': form, 'balance': profile.balance})
