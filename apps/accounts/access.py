# ---
# LOCATION : apps/accounts/access.py
# PURPOSE  : Central permission-checking helpers used by every view in the project
#            to enforce role-based access control.
#            Centralising these rules here means changing who can do what requires
#            editing only this one file — not hunting across a dozen view files.
#
# CONNECTS TO:
#   - apps/scanner/views.py    → ScanListView, ScanCreateView, ScanDetailView call
#                                user_can_manage_scans and user_can_view_all_data
#   - apps/reports/views.py    → ReportListView and ReportDownloadView call
#                                user_can_view_all_data to scope the queryset
#   - apps/dashboard/views.py  → DashboardView calls both helpers to decide whether
#                                to show all users' data or only the current user's
# ---


def user_can_manage_scans(user):
    # Only staff or superusers may create and manage scans.
    # A plain authenticated account (e.g. a future read-only user) should never
    # be able to launch a vulnerability scan against a network target.
    return user.is_authenticated and (user.is_staff or user.is_superuser)


def user_can_view_all_data(user):
    # Only superusers can see every user's scans and reports.
    # Staff can manage their own scans but cannot see data belonging to other accounts.
    return user.is_authenticated and user.is_superuser
