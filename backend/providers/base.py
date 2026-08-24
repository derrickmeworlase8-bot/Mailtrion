"""
PhishGuard AI — Email Provider Interface

Every mail provider (Gmail, Outlook, Yahoo/IMAP, ...) implements this same
interface. The polling loop and the detection engine (app.perform_scan)
never need to know which provider they're talking to — they only ever
call these four methods. This is what lets a new provider be added later
by writing one new class here, without touching the poller, the scan
pipeline, or any other provider's code.

Folder names are logical, not provider-specific: "inbox" and "spam" are
the two folders PhishGuard polls. Each provider maps these to whatever
its own system actually calls them (e.g. Gmail's "SPAM" label vs. an
IMAP "Junk" folder — that mapping detail lives inside each provider).
"""

from abc import ABC, abstractmethod

POLLED_FOLDERS = ["inbox", "spam"]


class EmailProvider(ABC):
    """One polling cycle's worth of operations for a single connected account."""

    #: Short machine-readable name, e.g. "gmail", "outlook", "imap".
    #: Used as a prefix for the `source` field stored on each scan
    #: (e.g. "gmail-inbox", "outlook-spam") so results stay traceable
    #: to their origin across providers.
    provider_name = "base"

    def __init__(self, account_row, get_db):
        self.account = account_row  # a row from the accounts table for this provider
        self.get_db = get_db

    @abstractmethod
    def ensure_fresh_credentials(self):
        """
        Refresh/renew authentication if needed (e.g. an expired OAuth
        access token). Called once per account per poll cycle, before
        any folder is checked. Should persist any renewed credentials
        back to the database itself.
        """
        raise NotImplementedError

    @abstractmethod
    def list_new_message_ids(self, folder, is_first_poll):
        """
        Return a list of provider-native message IDs for the given
        logical folder ("inbox" or "spam"). `is_first_poll` lets a
        provider bound the very first check (e.g. "only look at the
        last 24 hours") without needing that logic duplicated in the
        shared poller.
        """
        raise NotImplementedError

    @abstractmethod
    def fetch_normalized_message(self, msg_id):
        """
        Return a plain dict with the fields the detection engine
        needs, regardless of provider:
            {"sender": str, "subject": str, "body": str, "raw_headers": str}
        `raw_headers` must be a newline-joined "Name: Value" string
        suitable for app.parse_auth_results() — this is what lets
        SPF/DKIM/DMARC checking work identically across all providers.
        """
        raise NotImplementedError

    @abstractmethod
    def quarantine_message(self, msg_id, folder):
        """
        Move/label the given message as quarantined in the provider's
        own system (e.g. Gmail label swap, IMAP move-to-folder). Called
        only when perform_scan() has already scored the message as
        phishing.
        """
        raise NotImplementedError

    @abstractmethod
    def delete_message(self, msg_id):
        """
        Permanently remove an already-quarantined message from the
        mailbox — called when the user deletes a quarantined item from
        PhishGuard's UI, so the message actually leaves the account
        rather than just disappearing from PhishGuard's own records.

        Implementations move the message to the provider's own Trash/
        Deleted Items rather than an unrecoverable instant purge — this
        keeps behavior consistent across providers, avoids requiring
        broader OAuth scopes than what's already granted, and matches
        how every major mail client's own "delete" button behaves.

        Note this acts on the message where it currently lives (the
        Quarantine folder/label it was already moved into), not the
        original inbox/spam location — no folder parameter is needed.
        """
        raise NotImplementedError
