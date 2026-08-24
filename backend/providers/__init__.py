"""
Provider registry.

To add a new provider (Outlook, Yahoo/IMAP, ...) later:
  1. Write a new provider class implementing EmailProvider (see base.py)
  2. Add its accounts table name + class here
That's it — the shared poller in poller.py iterates this registry and
needs no changes to support the new provider.
"""

from .gmail_provider import GmailProvider
from .outlook_provider import OutlookProvider
from .imap_provider import IMAPProvider

# provider_name -> (accounts_table_name, provider_class)
REGISTRY = {
    "gmail": ("gmail_accounts", GmailProvider),
    "outlook": ("outlook_accounts", OutlookProvider),
    "imap": ("imap_accounts", IMAPProvider),
}
