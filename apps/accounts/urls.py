# ---
# LOCATION : apps/accounts/urls.py
# PURPOSE  : URL patterns for everything authentication-related — logging in,
#            viewing and editing the user profile, and logging out.
#            Included by omnigov/urls.py under the '/accounts/' prefix.
#
# CONNECTS TO:
#   - omnigov/urls.py              → includes this file under the 'accounts' namespace
#   - apps/accounts/views.py       → LoginView, ProfileView, logout_view defined here
#   - omnigov/settings/base.py     → LOGIN_URL and LOGIN_REDIRECT_URL reference
#                                    'accounts:login' and 'dashboard:home'
# ---
from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    # The main login page — LoginView handles both GET (render form) and POST (submit).
    path('login/', views.LoginView.as_view(), name='login'),
    # Lets the logged-in user update their first name, last name, and email.
    path('profile/', views.ProfileView.as_view(), name='profile'),
    # POST-only endpoint that ends the session and redirects to the login page.
    path('logout/', views.logout_view, name='logout'),
]
