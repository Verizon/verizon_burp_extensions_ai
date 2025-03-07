"""
app/endpoints/prompt_augmentor_payload_processor
"""

import os
import json
import pandas as pd
from datetime import datetime
from typing import List, Dict, Optional, Union
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.services.model_connector import create_model_connector
from app.prompts.prompt_definitions import BURP_AUGMENTATION_PLUGIN_PROMPT

router = APIRouter()

# -------------------------------------------------
# 1) GET /available_models => from .env (ADD GCP)
# -------------------------------------------------
@router.get("/available_models/", response_class=JSONResponse)
async def get_available_models():
    """
    Returns { "providers": { "Azure": [...], "OpenAI": [...], "Ollama": [...], "GCP": [...] } }
    from environment variables or fallback defaults.
    """
    azure_str = os.getenv("AZURE_MODELS", "azure-gpt-3.5,azure-gpt-4")
    openai_str = os.getenv("OPENAI_MODELS", "gpt-3.5-turbo,gpt-4")
    ollama_str = os.getenv("OLLAMA_MODELS", "ollama-7b,ollama-phi4")
    # Add GCP variable
    gcp_str = os.getenv("GCP_MODELS", "gemini-2.0-flash-exp,gemini-1.5-flash-002")

    azure_list = [x.strip() for x in azure_str.split(",") if x.strip()]
    openai_list = [x.strip() for x in openai_str.split(",") if x.strip()]
    ollama_list = [x.strip() for x in ollama_str.split(",") if x.strip()]
    gcp_list = [x.strip() for x in gcp_str.split(",") if x.strip()]

    return {
        "providers": {
            "Azure": azure_list,
            "OpenAI": openai_list,
            "Ollama": ollama_list,
            "GCP": gcp_list
        }
    }

# -------------------------------------------------
# 2) SingleShotRequest model
# -------------------------------------------------
class SingleShotRequest(BaseModel):
    column_name: str = "prompt"
    number_of_augments: int = 1
    prompt_list: List[Dict[str, str]] = []
    augmentor_model_type: str = "OpenAI"  # "AzureOpenAI", "Ollama", "GCP"
    model_type: str = "OpenAI"            # not always used, but included
    augmentor_model_id: str = "gpt-3.5-turbo"
    augmentor_url: Optional[str] = None
    augmentor_api_key_env: Optional[str] = None
    augment_types: List[str] = ["Prompt Injection"]
    augment_type_csv_path: Optional[str] = None
    download_csv: bool = False
    download_csv_path: Optional[str] = None
    suppress_terminal_output: bool = False
    input_prompt_dataset_file_path: Optional[str] = None
    objective: Optional[str] = None
    llm_information: Optional[str] = None
    special_notes: Optional[str] = None

# -------------------------------------------------
# 3) POST => produce "augmented_prompt_list"
# -------------------------------------------------
@router.post("/", response_class=JSONResponse, tags=["Prompt Augmentation"])
async def single_shot_attack_json(input_data: SingleShotRequest):
    """
    Accept prompt(s), objective, special notes, etc. 
    Return {"augmented_prompt_list": [...]}.
    Allows model_type=GCP if the create_model_connector supports it.
    """
    try:
        # 1) Load base prompts
        base_prompts = load_prompts(
            data_source=(input_data.input_prompt_dataset_file_path or input_data.prompt_list),
            column_name=input_data.column_name
        )

        # 2) Validate
        if not input_data.augmentor_model_type:
            raise ValueError("No 'augmentor_model_type' provided. Must be 'OpenAI','AzureOpenAI','Ollama','GCP'.")
        if not input_data.augmentor_model_id:
            raise ValueError("No 'augmentor_model_id' provided.")

        # 3) Create model connector (including GCP if "GCP" is passed)
        response_schema = {
            "type": "object",
            "properties": {
                "augmented_prompts": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "required": ["augmented_prompts"]
        }
        augmentor = create_model_connector(
            model_type=input_data.augmentor_model_type,
            model_id=input_data.augmentor_model_id,
            url=input_data.augmentor_url,
            system_prompt="",
            response_schema=response_schema
        )

        # 4) Load augment types
        augment_types = load_augment_types(
            data_source=(input_data.augment_type_csv_path or input_data.augment_types),
            column_name="augment_type"
        )

        # 5) Generate
        augmented_prompts = await generate_augmentations(
            prompt_list=base_prompts,
            augment_types=augment_types,
            llm=augmentor,
            objective=input_data.objective,
            special_notes=input_data.special_notes,
            llm_information=input_data.llm_information,
            number_of_augments=input_data.number_of_augments
        )

        # 6) Possibly write to CSV
        if input_data.download_csv:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_path = input_data.download_csv_path or f"output_{ts}.csv"
            df = pd.DataFrame({"augmented_prompt": augmented_prompts})
            df.to_csv(out_path, index=False)

        return JSONResponse(content={"augmented_prompt_list": augmented_prompts})

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------------------------
# SERVICE LOGIC
# -------------------------------------------------
def load_prompts(
    data_source: Union[str, List[Dict[str,str]]],
    column_name: str="prompt"
) -> List[Dict[str,str]]:
    """
    If data_source is a CSV path => read the column.
    If data_source is a list => assume it's already [{"prompt":...}, ...]
    """
    if isinstance(data_source, str):
        df = pd.read_csv(data_source)
        if column_name not in df.columns:
            raise ValueError(f"Column '{column_name}' not found in the dataset.")
        return [{"prompt": p} for p in df[column_name]]
    return data_source

def load_augment_types(
    data_source: Union[str, List[str]],
    column_name: str="augment_type"
) -> List[str]:
    """
    If data_source is a CSV => load column.
    If it's a List[str], return as is.
    """
    if isinstance(data_source, str):
        df = pd.read_csv(data_source)
        if column_name not in df.columns:
            raise ValueError(f"Column '{column_name}' not found in CSV.")
        return df[column_name].tolist()
    return data_source

async def generate_augmentations(
    prompt_list: List[Dict[str,str]],
    augment_types: List[str],
    llm,
    objective: Optional[str]=None,
    special_notes: Optional[str]=None,
    llm_information: Optional[str]=None,
    number_of_augments: int=1
) -> List[str]:
    """
    For each base prompt, for each augment type => call LLM with BURP_AUGMENTATION_PLUGIN_PROMPT.
    Parse LLM JSON => "augmented_prompts".
    """
    all_augmented_prompts = []

    for item in prompt_list:
        original_prompt = item.get("prompt","")
        for a_type in augment_types:
            instructions = BURP_AUGMENTATION_PLUGIN_PROMPT.format(
                objective=objective or "",
                llm_information=llm_information or "",
                special_notes=special_notes or "",
                original_prompt=original_prompt,
                augment_type=a_type,
                number_of_augments=number_of_augments
            )
            raw_resp = await llm.get_response(instructions)

            cleaned = raw_resp.strip("`").strip()
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:].strip()

            try:
                parsed = json.loads(cleaned)
                if not isinstance(parsed, dict) or "augmented_prompts" not in parsed:
                    raise ValueError("Missing 'augmented_prompts' key in response.")
                all_augmented_prompts.extend(parsed["augmented_prompts"])
            except Exception as parse_err:
                print("Parse error =>", parse_err)
                print("Raw response =>", raw_resp)
                raise ValueError(f"Could not parse LLM response => {parse_err}")

    return all_augmented_prompts
