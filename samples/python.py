#!/usr/bin/env python3
"""Python client for the Veritas authentication API."""

import base64
import hashlib
import json
import urllib.parse
from typing import Any, Dict, Optional, Union

import requests
from Crypto.Cipher import AES


class VeritasClient:
    """Client for interacting with the Veritas authentication API."""

    def __init__(self, api_url: str, api_key: str, hash_key: str):
        """
        Initialize the Veritas client.

        Args:
            api_url: Base URL for the Veritas API
            api_key: Your service API key
            hash_key: Your service hash key for encrypting data
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.hash_key = hash_key

    def authenticate(self, email: str, password: str) -> Dict[str, Any]:
        """
        Authenticate a user with email and password.

        Args:
            email: User's email
            password: User's password

        Returns:
            Authentication result
        """
        credentials = {"email": email, "password": password}
        hashed_data = self.hash_data(credentials)

        response = self.post("/auth/authenticate", {"credentials": hashed_data})
        
        if response.get("authenticated"):
            print(f"User authenticated successfully! User ID: {response.get('pd_id')}")
        else:
            print("Authentication failed")

        return response

    def get_user(self, pd_id: str) -> Dict[str, Any]:
        """
        Get user information by PD_ID.

        Args:
            pd_id: User's PD_ID

        Returns:
            User information
        """
        return self.get(f"/users/{pd_id}")

    def get_user_by_email(self, email: str) -> Dict[str, Any]:
        """
        Get user information by email.

        Args:
            email: User's email

        Returns:
            User information
        """
        encoded_email = urllib.parse.quote(email)
        return self.get(f"/users/by_email?email={encoded_email}")

    def create_user(self, user_data: Dict[str, str]) -> Dict[str, Any]:
        """
        Create a new user.

        Args:
            user_data: User data including first_name, last_name, email, password, password_confirmation

        Returns:
            New user information
        """
        hashed_data = self.hash_data(user_data)
        return self.post("/users", {"hashed_data": hashed_data})

    def get(self, path: str) -> Dict[str, Any]:
        """
        Make a GET request to the API.

        Args:
            path: API endpoint path

        Returns:
            Response data
        """
        url = f"{self.api_url}/api/v1{path}"
        headers = {
            "X-Api-Key": self.api_key,
            "Accept": "application/json",
        }

        response = requests.get(url, headers=headers)
        return self._handle_response(response)

    def post(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make a POST request to the API.

        Args:
            path: API endpoint path
            data: Request data

        Returns:
            Response data
        """
        url = f"{self.api_url}/api/v1{path}"
        headers = {
            "Content-Type": "application/json",
            "X-Api-Key": self.api_key,
            "Accept": "application/json",
        }

        response = requests.post(url, headers=headers, json=data)
        return self._handle_response(response)

    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """
        Handle API response.

        Args:
            response: Response object

        Returns:
            Response data
        """
        try:
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP error: {e}"
            try:
                error_data = response.json()
                if "error" in error_data:
                    error_msg = f"API error: {error_data['error']}"
            except ValueError:
                pass
            return {"error": error_msg}
        except ValueError:
            return {"error": "Invalid response from server"}

    def hash_data(self, data: Dict[str, Any]) -> str:
        """
        Hash data using the service's hash_key.

        Args:
            data: Data to encrypt

        Returns:
            Base64 encoded encrypted data
        """
        # Convert data to JSON string
        json_data = json.dumps(data).encode('utf-8')

        # Create key and iv from the hash_key
        key = hashlib.sha256(self.hash_key.encode('utf-8')).digest()[:32]
        iv = self.hash_key[:16].ljust(16, '0').encode('utf-8')

        # Encrypt the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = self._pad(json_data)
        encrypted = cipher.encrypt(padded_data)

        # Encode to base64
        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def _pad(data: bytes) -> bytes:
        """
        Pad data to a multiple of 16 bytes (AES block size).

        Args:
            data: Data to pad

        Returns:
            Padded data
        """
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length]) * padding_length
        return data + padding


if __name__ == "__main__":
    # Development URL (change to production URL in production environment)
    # Development: http://localhost:3000/api/v1/
    # Production: https://veritas.phish.directory/api/v1/
    # Note: Contact a core team member if you need production keys for authenticating with Veritas
    import os
    
    is_production = os.environ.get("ENVIRONMENT") == "production"
    API_URL = "https://veritas.phish.directory" if is_production else "http://localhost:3000"
    API_KEY = "your_api_key_here"  # Obtain from core team member for production
    HASH_KEY = "your_hash_key_here"  # Obtain from core team member for production

    client = VeritasClient(API_URL, API_KEY, HASH_KEY)

    # Example usage - uncomment to test

    # Authenticate a user
    # result = client.authenticate("user@example.com", "password123")
    # print(result)

    # Get user by PD_ID
    # user = client.get_user("PDU1A2B3C4")
    # print(user)

    # Get user by email
    # user = client.get_user_by_email("user@example.com")
    # print(user)

    # Create a new user
    # new_user = client.create_user({
    #     "first_name": "John",
    #     "last_name": "Doe",
    #     "email": "john.doe@example.com",
    #     "password": "SecureP@ssw0rd",
    #     "password_confirmation": "SecureP@ssw0rd"
    # })
    # print(new_user)
