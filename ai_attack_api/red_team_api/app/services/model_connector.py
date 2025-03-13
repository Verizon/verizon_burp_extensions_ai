import os
import requests
import json
import logging
from requests.exceptions import HTTPError
from pydantic import BaseModel
from typing import Optional, Union

# GCP
import google.auth
from google.oauth2.credentials import Credentials
import vertexai
from vertexai.generative_models import GenerativeModel, GenerationConfig

# OpenAI / Azure imports
from openai import OpenAI, AzureOpenAI
from azure.identity import DefaultAzureCredential, get_bearer_token_provider


###############################################################################
# OIDC for GCP
###############################################################################
def exchange_and_save_oidc_token_for_jwt(client_id: str, client_secret: str) -> None:
    """
    Retrieves an OIDC token from OIDC_URL in .env, writes it to 'oidc_token.json'.
    """
    print('Retrieving JWT from OIDC provider...')

    # Must exist in .env => OIDC_URL
    oidc_url = os.getenv("OIDC_URL", "")
    if not oidc_url:
        raise ValueError("OIDC_URL not defined in environment variables.")

    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'read'
    }
    try:
        response = requests.post(url=oidc_url, params=payload)
        response.raise_for_status()
        token = response.json()
        with open('oidc_token.json', 'w') as f:
            json.dump(token, f)
        print("OIDC token saved to oidc_token.json")
    except HTTPError as e:
        raise e


###############################################################################
# Base interface for chat models
###############################################################################
class ChatModel:
    async def get_response(self, prompt: str) -> str:
        """
        Base class for all chat connectors.
        Subclasses must implement get_response().
        """
        raise NotImplementedError("Subclasses must implement get_response.")


###############################################################################
# 1) Standard OpenAI Chat
###############################################################################
class OpenAIChatConnector(ChatModel):
    """
    Connector for public OpenAI.
    """
    def __init__(
        self,
        model_id: str,
        system_prompt: str = "",
        response_schema: Optional[dict] = None
    ):
        self.model_id = model_id
        self.system_prompt = system_prompt
        self.response_schema = response_schema
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY", ""))

    async def get_response(self, prompt: str) -> str:
        try:
            messages = []
            if self.system_prompt:
                messages.append({"role": "system", "content": self.system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = self.client.chat.completions.create(
                model=self.model_id,
                messages=messages,
                temperature=0.0
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            raise RuntimeError(f"OpenAI generation failed: {e}")


###############################################################################
# 2) Ollama Chat
###############################################################################
class OllamaChatConnector(ChatModel):
    """
    Connector for Ollama. We fetch OLLAMA_URL from .env if no URL is passed in.
    """
    def __init__(
        self,
        url: str = None,
        model_name: str = "llama2.7b",
        response_schema: Optional[dict] = None
    ):
        default_ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
        self.url = url if url else default_ollama_url
        self.model_name = model_name
        self.response_schema = response_schema

    async def get_response(self, prompt: str) -> str:
        try:
            request_headers = {"Content-Type": "application/json"}
            data = {
                "model": self.model_name,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "stream": False
            }
            if self.response_schema:
                data["format"] = self.response_schema

            resp = requests.post(self.url, headers=request_headers, json=data, timeout=600)
            resp.raise_for_status()

            ollama_json = resp.json()
            message_obj = ollama_json.get("message", {})
            content_str = message_obj.get("content", "").strip()
            if not content_str:
                raise ValueError("No content found in Ollama response message.")
            return content_str
        except Exception as e:
            raise RuntimeError(f"Ollama request failed: {e}")


###############################################################################
# 3) Azure OpenAI Chat
###############################################################################
class AzureOpenAIChatConnector(ChatModel):
    """
    Connector for Azure OpenAI.
    """
    def __init__(
        self,
        deployment_name: str = "",
        endpoint: Optional[str] = None,
        auth_type: Optional[str] = None,
        api_version: Optional[str] = None,
        system_prompt: str = "",
        response_schema: Optional[dict] = None
    ):
        self.system_prompt = system_prompt
        self.response_schema = response_schema

        self.azure_endpoint = endpoint or os.getenv("AZURE_OPENAI_ENDPOINT", "")
        self.deployment_name = deployment_name or os.getenv("AZURE_OPENAI_DEPLOYMENT", "")
        self.api_version = api_version or os.getenv("AZURE_OPENAI_API_VERSION", "2024-05-01-preview")
        self.auth_type = auth_type or os.getenv("AZURE_AUTH_TYPE", "api_key")

        from openai import AzureOpenAI
        if self.auth_type == "entra_id":
            token_provider = get_bearer_token_provider(
                DefaultAzureCredential(),
                "https://cognitiveservices.azure.com/.default"
            )
            self.client = AzureOpenAI(
                azure_endpoint=self.azure_endpoint,
                azure_ad_token_provider=token_provider,
                api_version=self.api_version
            )
        else:
            sub_key = os.getenv("AZURE_OPENAI_API_KEY", "")
            self.client = AzureOpenAI(
                azure_endpoint=self.azure_endpoint,
                api_key=sub_key,
                api_version=self.api_version
            )

    async def get_response(self, prompt: str) -> str:
        try:
            messages = []
            if self.system_prompt:
                messages.append({"role": "system", "content": self.system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=messages,
                temperature=0.0
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            raise RuntimeError(f"AzureOpenAI generation failed: {e}")


###############################################################################
# 4) GCP Chat Connector (Now purely from .env)
###############################################################################
class GCPChatConnector(ChatModel):
    """
    """
    def __init__(
        self,
        model_id: str,
        location: str,
        system_prompt: str = "",
        response_schema: Optional[dict] = None
    ):
        self.model_id = model_id
        self.location = location
        self.system_prompt = system_prompt
        self.response_schema = response_schema

        # Gather from .env
        client_id = os.getenv("GCP_CLIENT_ID", "")
        client_secret = os.getenv("GCP_CLIENT_SECRET", "")
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "")
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")

        # Exchange OIDC -> store in oidc_token.json
        exchange_and_save_oidc_token_for_jwt(client_id, client_secret)

        # Set environment variables for GCP
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = cred_path
        os.environ['GOOGLE_CLOUD_PROJECT'] = project_id

        # Auth with google.auth
        self.credentials, self.project_id = google.auth.default()

        # Initialize Vertex AI
        vertexai.init(
            project=self.project_id,
            location=self.location,
            credentials=self.credentials
        )

    async def get_response(self, prompt: str) -> str:
        try:
            # Re-init in case environment changed or tokens updated
            vertexai.init(
                project=self.project_id,
                location=self.location,
                credentials=self.credentials
            )

            model = GenerativeModel(
                model_name=self.model_id,
                system_instruction=self.system_prompt
            )

            gen_config = GenerationConfig(
                max_output_tokens=1024,
                temperature=0.0
            )
            if self.response_schema:
                gen_config.response_mime_type = "application/json"
                gen_config.response_schema = self.response_schema

            response = model.generate_content(
                prompt,
                generation_config=gen_config,
            )
            return response.text.strip()

        except Exception as e:
            raise RuntimeError(f"GCP Vertex AI generation failed: {e}")


###############################################################################
# 5) create_model_connector (Factory)
###############################################################################
def create_model_connector(
    model_type: str,       # "OpenAI", "Ollama", "AzureOpenAI", or "GCP"
    model_id: str,
    url: Optional[str] = None,
    system_prompt: str = "",
    response_schema: Optional[dict] = None
) -> ChatModel:
    """
    """
    if model_type == "OpenAI":
        return OpenAIChatConnector(
            model_id=model_id,
            system_prompt=system_prompt,
            response_schema=response_schema
        )
    elif model_type == "Ollama":
        default_ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
        return OllamaChatConnector(
            url=url if url else default_ollama_url,
            model_name=model_id if model_id else "llama2.7b",
            response_schema=response_schema
        )
    elif model_type == "AzureOpenAI":
        return AzureOpenAIChatConnector(
            deployment_name=model_id,
            endpoint=url,
            system_prompt=system_prompt,
            response_schema=response_schema
        )
    elif model_type == "GCP":
        # GCP_CLIENT_ID, GCP_CLIENT_SECRET, GOOGLE_CLOUD_PROJECT, GOOGLE_APPLICATION_CREDENTIALS
        gcp_model_locations = {
            "gemini-2.0-flash-exp": "us-central1",
            "gemini-1.5-flash-002": "us-east4",
            "gemini-1.5-pro-002": "us-east4",
            "projects/614392940578/locations/us-east4/endpoints/347010267772616704": "us-east4"
        }
        location = gcp_model_locations.get(model_id, "us-east4")

        return GCPChatConnector(
            model_id=model_id,
            location=location,
            system_prompt=system_prompt,
            response_schema=response_schema
        )
    else:
        raise ValueError("Unsupported model_type. Must be 'OpenAI', 'Ollama', 'AzureOpenAI', or 'GCP'.")


