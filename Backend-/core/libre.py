"""Helpers to interact with LibreView OAuth endpoints.

This module provides two small helpers:
- build_authorize_url(redirect_uri, state): constructs the authorization URL
- exchange_code_for_token(code, redirect_uri): exchanges an authorization
  code for tokens using the configured token endpoint.

Configure the following settings in `config/settings.py` or your environment:
- LIBRE_OAUTH_AUTHORIZE_URL
- LIBRE_OAUTH_TOKEN_URL
- LIBRE_OAUTH_CLIENT_ID
- LIBRE_OAUTH_CLIENT_SECRET
- LIBRE_OAUTH_SCOPE (optional)
"""

from urllib.parse import urlencode
import requests
from django.conf import settings
import hashlib
from typing import Tuple, Optional, Dict


def build_authorize_url(redirect_uri: str, state: str = None) -> str:
    base = getattr(settings, 'LIBRE_OAUTH_AUTHORIZE_URL', None)
    client_id = getattr(settings, 'LIBRE_OAUTH_CLIENT_ID', None)
    scope = getattr(settings, 'LIBRE_OAUTH_SCOPE', None)
    if not base or not client_id:
        raise RuntimeError('Libre OAuth not configured (LIBRE_OAUTH_AUTHORIZE_URL or LIBRE_OAUTH_CLIENT_ID missing)')

    params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': redirect_uri,
    }
    if scope:
        params['scope'] = scope
    if state:
        params['state'] = state
    return base + '?' + urlencode(params)


def exchange_code_for_token(code: str, redirect_uri: str) -> dict:
    token_url = getattr(settings, 'LIBRE_OAUTH_TOKEN_URL', None)
    client_id = getattr(settings, 'LIBRE_OAUTH_CLIENT_ID', None)
    client_secret = getattr(settings, 'LIBRE_OAUTH_CLIENT_SECRET', None)
    if not token_url or not client_id or not client_secret:
        raise RuntimeError('Libre OAuth token endpoint not configured')

    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'client_secret': client_secret,
    }

    headers = {'Accept': 'application/json'}
    resp = requests.post(token_url, data=payload, headers=headers, timeout=10)
    resp.raise_for_status()
    return resp.json()


def uuid_to_sha256(uuid_str: str) -> str:
    """Return SHA-256 hex digest for a UUID string."""
    return hashlib.sha256(uuid_str.encode('utf-8')).hexdigest()


def login_with_password(email: str, password: str, timeout: int = 10) -> Tuple[Optional[str], Optional[Dict], Optional[Dict]]:
    """Perform LibreView password login flow (non-OAuth).

    Returns a tuple: (base_url, token_response_dict, headers) on success,
    or (None, None, None) on failure.
    """
    base_url = getattr(settings, 'LIBRE_PASSWORD_BASE_URL', 'https://api.libreview.io')
    login_url = f"{base_url}/llu/auth/login"

    headers = {
        'accept-encoding': 'gzip, deflate, br',
        'cache-control': 'no-cache',
        'connection': 'Keep-Alive',
        'content-type': 'application/json',
        'product': 'llu.android',
        'version': '4.8.0',
    }

    payload = {'email': email, 'password': password}
    try:
        r = requests.post(url=login_url, headers=headers, json=payload, timeout=timeout)
        r.raise_for_status()
        response_json = r.json()
    except Exception as e:
        return None, None, None

    # Handle region redirect
    if response_json.get('data', {}).get('redirect') is True:
        region = response_json['data'].get('region')
        if region:
            base_url = f"https://api-{region}.libreview.io"
            login_url = f"{base_url}/llu/auth/login"
            try:
                r = requests.post(url=login_url, headers=headers, json=payload, timeout=timeout)
                r.raise_for_status()
                response_json = r.json()
            except Exception:
                return None, None, None

    # Extract token and user id
    try:
        JWT_token = response_json['data']['authTicket']['token']
        libre_id = response_json['data']['user']['id']
    except Exception:
        return None, None, None

    hashed_libre_id = uuid_to_sha256(libre_id)
    extra_headers = {
        'authorization': f'Bearer {JWT_token}',
        'account-id': hashed_libre_id,
    }
    headers.update(extra_headers)

    token_response = {
        'access_token': JWT_token,
        'account_id': libre_id,
    }

    return base_url, token_response, headers
