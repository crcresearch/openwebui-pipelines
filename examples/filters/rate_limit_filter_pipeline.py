import os
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel
from schemas import OpenAIChatMessage
import time


class Pipeline:
    class Valves(BaseModel):
        # List target pipeline ids (models) that this filter will be connected to.
        # If you want to connect this filter to all pipelines, you can set pipelines to ["*"]
        pipelines: List[str] = []

        # Assign a priority level to the filter pipeline.
        # The priority level determines the order in which the filter pipelines are executed.
        # The lower the number, the higher the priority.
        priority: int = 0

        # Valves for rate limiting
        requests_per_minute: Optional[int] = None
        requests_per_hour: Optional[int] = None
        sliding_window_limit: Optional[int] = None
        sliding_window_minutes: Optional[int] = None

        # Usernames that are exempt from rate limiting (e.g. admins, service accounts)
        exempt_usernames: List[str] = []

        # Emails that are exempt (use if you log in with OAuth and don't have a username)
        exempt_emails: List[str] = []

        # User IDs that are exempt (optional; same as user["id"] from Open WebUI, often OAuth id)
        exempt_user_ids: List[str] = []

        # When True, rate limiting applies only on weekdays (Mon–Fri); when False, every day
        weekdays_only: bool = True

    def __init__(self):
        # Pipeline filters are only compatible with Open WebUI
        # You can think of filter pipeline as a middleware that can be used to edit the form data before it is sent to the OpenAI API.
        self.type = "filter"

        # Optionally, you can set the id and name of the pipeline.
        # Best practice is to not specify the id so that it can be automatically inferred from the filename, so that users can install multiple versions of the same pipeline.
        # The identifier must be unique across all pipelines.
        # The identifier must be an alphanumeric string that can include underscores or hyphens. It cannot contain spaces, special characters, slashes, or backslashes.
        # self.id = "rate_limit_filter_pipeline"
        self.name = "Rate Limit Filter"

        # Initialize rate limits
        self.valves = self.Valves(
            **{
                "pipelines": os.getenv("RATE_LIMIT_PIPELINES", "*").split(","),
                "requests_per_minute": int(
                    os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", 10)
                ),
                "requests_per_hour": int(
                    os.getenv("RATE_LIMIT_REQUESTS_PER_HOUR", 1000)
                ),
                "sliding_window_limit": int(
                    os.getenv("RATE_LIMIT_SLIDING_WINDOW_LIMIT", 100)
                ),
                "sliding_window_minutes": int(
                    os.getenv("RATE_LIMIT_SLIDING_WINDOW_MINUTES", 15)
                ),
                "exempt_usernames": [
                    name.strip().lower()
                    for name in os.getenv("RATE_LIMIT_EXEMPT_USERNAMES", "").split(",")
                    if name.strip()
                ],
                "exempt_emails": [
                    e.strip().lower()
                    for e in os.getenv("RATE_LIMIT_EXEMPT_EMAILS", "").split(",")
                    if e.strip()
                ],
                "exempt_user_ids": [
                    uid.strip() for uid in os.getenv("RATE_LIMIT_EXEMPT_USER_IDS", "").split(",") if uid.strip()
                ],
                "weekdays_only": os.getenv("RATE_LIMIT_WEEKDAYS_ONLY", "true").lower()
                in ("true", "1", "yes"),
            }
        )

        # Tracking data - user_id -> (timestamps of requests)
        self.user_requests = {}

    async def on_startup(self):
        # This function is called when the server is started.
        print(f"on_startup:{__name__}")
        pass

    async def on_shutdown(self):
        # This function is called when the server is stopped.
        print(f"on_shutdown:{__name__}")
        pass

    def prune_requests(self, user_id: str):
        """Prune old requests that are outside of the sliding window period."""
        now = time.time()
        if user_id in self.user_requests:
            self.user_requests[user_id] = [
                req
                for req in self.user_requests[user_id]
                if (
                    (self.valves.requests_per_minute is not None and now - req < 60)
                    or (self.valves.requests_per_hour is not None and now - req < 3600)
                    or (
                        self.valves.sliding_window_limit is not None
                        and now - req < self.valves.sliding_window_minutes * 60
                    )
                )
            ]

    def log_request(self, user_id: str):
        """Log a new request for a user."""
        now = time.time()
        if user_id not in self.user_requests:
            self.user_requests[user_id] = []
        self.user_requests[user_id].append(now)

    def rate_limited(self, user_id: str) -> bool:
        """Check if a user is rate limited."""
        self.prune_requests(user_id)

        user_reqs = self.user_requests.get(user_id, [])

        if self.valves.requests_per_minute is not None:
            requests_last_minute = sum(1 for req in user_reqs if time.time() - req < 60)
            if requests_last_minute >= self.valves.requests_per_minute:
                return True

        if self.valves.requests_per_hour is not None:
            requests_last_hour = sum(1 for req in user_reqs if time.time() - req < 3600)
            if requests_last_hour >= self.valves.requests_per_hour:
                return True

        if self.valves.sliding_window_limit is not None:
            requests_in_window = len(user_reqs)
            if requests_in_window >= self.valves.sliding_window_limit:
                return True

        return False

    def is_weekday(self) -> bool:
        """Return True if today is a weekday (Monday=0 through Friday=4)."""
        return datetime.now().weekday() < 5

    def is_exempt(self, user: Optional[dict]) -> bool:
        """Return True if the user is exempt (matched by username, email, or user id)."""
        if not user:
            return False
        if self.valves.exempt_usernames:
            username = (user.get("username") or "").strip().lower()
            if username in self.valves.exempt_usernames:
                return True
        if self.valves.exempt_emails:
            email = (user.get("email") or "").strip().lower()
            if email in self.valves.exempt_emails:
                return True
        if self.valves.exempt_user_ids:
            uid = user.get("id")
            if uid is not None:
                uid_str = str(uid).strip()
                if uid_str in self.valves.exempt_user_ids:
                    return True
        return False

    async def inlet(self, body: dict, user: Optional[dict] = None) -> dict:
        print(f"pipe:{__name__}")
        print(body)
        print(user)

        if user.get("role", "admin") == "user":
            user_id = user["id"] if user and "id" in user else "default_user"
            # Skip rate limiting for exempt usernames; apply only on weekdays when weekdays_only is True
            if not self.is_exempt(user):
                if not self.valves.weekdays_only or self.is_weekday():
                    if self.rate_limited(user_id):
                        raise Exception("Rate limit exceeded. Please try again later.")
                    self.log_request(user_id)
        return body
