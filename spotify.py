import json
import logging
import time
import random
from typing import Dict, Optional

import requests
from spotipy import Spotify
from spotipy.cache_handler import CacheFileHandler, MemoryCacheHandler
from spotipy.oauth2 import SpotifyClientCredentials, SpotifyOAuth

from spotdl.utils.config import get_cache_path, get_spotify_cache_path

__all__ = [
    "SpotifyError",
    "SpotifyClient",
    "save_spotify_cache",
]

logger = logging.getLogger(__name__)

class SpotifyError(Exception):
    """
    Base class for all exceptions related to SpotifyClient.
    """

class Singleton(type):
    _instance = None

    def __call__(self):  # pylint: disable=bad-mcs-method-argument
        if self._instance is None:
            raise SpotifyError(
                "Spotify client not created. Call SpotifyClient.init"
                "(client_id, client_secret, user_auth, cache_path, no_cache, open_browser) first."
            )
        return self._instance

    def init(  # pylint: disable=bad-mcs-method-argument
        self,
        client_id: str,
        client_secret: str,
        user_auth: bool = False,
        no_cache: bool = False,
        headless: bool = False,
        max_retries: int = 5,  # Increased retries
        use_cache_file: bool = False,
        auth_token: Optional[str] = None,
        cache_path: Optional[str] = None,
    ) -> "Singleton":
        if isinstance(self._instance, self):
            raise SpotifyError("A spotify client has already been initialized")

        credential_manager = None

        cache_handler = (
            CacheFileHandler(cache_path or get_cache_path())
            if not no_cache
            else MemoryCacheHandler()
        )
        if user_auth:
            credential_manager = SpotifyOAuth(
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri="http://127.0.0.1:9900/",
                scope="user-library-read,user-follow-read,playlist-read-private",
                cache_handler=cache_handler,
                open_browser=not headless,
            )
        else:
            credential_manager = SpotifyClientCredentials(
                client_id=client_id,
                client_secret=client_secret,
                cache_handler=cache_handler,
            )
        if auth_token is not None:
            credential_manager = None

        self.user_auth = user_auth
        self.no_cache = no_cache
        self.max_retries = max_retries
        self.use_cache_file = use_cache_file

        self._instance = super().__call__(
            auth=auth_token,
            auth_manager=credential_manager,
            status_forcelist=(429, 500, 502, 503, 504, 404),
        )

        return self._instance

class SpotifyClient(Spotify, metaclass=Singleton):
    _initialized = False
    cache: Dict[str, Optional[Dict]] = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialized = True

        use_cache_file: bool = self.use_cache_file  # type: ignore # pylint: disable=E1101
        cache_file_loc = get_spotify_cache_path()

        if use_cache_file and cache_file_loc.exists():
            with open(cache_file_loc, "r", encoding="utf-8") as cache_file:
                self.cache = json.load(cache_file)
        elif use_cache_file:
            with open(cache_file_loc, "w", encoding="utf-8") as cache_file:
                json.dump(self.cache, cache_file)

    def exponential_backoff(self, retry_count):
        base = 2
        jitter = random.uniform(0, 1)
        wait_time = base ** retry_count + jitter
        return wait_time

    def _get(self, url, args=None, payload=None, **kwargs):
        use_cache = not self.no_cache  # type: ignore # pylint: disable=E1101

        if args:
            kwargs.update(args)

        cache_key = None
        if use_cache:
            key_obj = dict(kwargs)
            key_obj["url"] = url
            key_obj["data"] = json.dumps(payload)
            cache_key = json.dumps(key_obj)
            if cache_key is None:
                cache_key = url
            if self.cache.get(cache_key) is not None:
                return self.cache[cache_key]

        response = None
        retries = self.max_retries  # type: ignore # pylint: disable=E1101
        retry_count = 0
        while response is None and retries > 0:
            try:
                response = self._internal_call("GET", url, payload, kwargs)
                if isinstance(response, requests.Response) and response.status_code == 429:
                    raise requests.exceptions.RequestException("Rate limit exceeded")
            except (requests.exceptions.Timeout, requests.ConnectionError, requests.exceptions.RequestException) as exc:
                if response and isinstance(response, requests.Response) and response.status_code == 429:
                    retry_count += 1
                    wait_time = self.exponential_backoff(retry_count)
                    logger.warning(f"Rate limit exceeded. Waiting for {wait_time} seconds before retrying... Retry count: {retry_count}")
                    time.sleep(wait_time)
                else:
                    retries -= 1
                    if retries <= 0:
                        logger.error(f"Max retries reached for URL: {url}.")
                        raise exc
                    time.sleep(self.exponential_backoff(retry_count))

        if use_cache and cache_key is not None:
            self.cache[cache_key] = response

        return response

def save_spotify_cache(cache: Dict[str, Optional[Dict]]):
    cache_file_loc = get_spotify_cache_path()

    logger.debug("Saving Spotify cache to %s", cache_file_loc)

    cache = {
        key: value
        for key, value in cache.items()
        if value is not None and "tracks/" in key
    }

    with open(cache_file_loc, "w", encoding="utf-8") as cache_file:
        json.dump(cache, cache_file)
