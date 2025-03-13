"""
app/endpoints/bulk_analyze_http_transactions
"""

import os
import json
import traceback
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.services.model_connector import create_model_connector
from app.prompts.prompt_definitions import (
    ANALYSIS_SYSTEM_PROMPT,
    SUMMARY_SYSTEM_PROMPT,
    CHATBOT_ACTIVITY_SYSTEM_PROMPT
)

router = APIRouter()

# ------------------------------------------------------------------------------
# 1) GET /available_models => Now includes "GCP" if desired
# ------------------------------------------------------------------------------
@router.get("/available_models/", tags=["Analyze HTTP Requests Batch"])
async def get_available_models():
    """
    Returns JSON with the lists of models for each provider, e.g.:
      {
        "providers": {
          "Azure": ["azure-gpt-3.5", "azure-gpt-4"],
          "OpenAI": ["gpt-3.5-turbo", "gpt-4"],
          "Ollama": ["ollama-7b", "ollama-phi4"],
          "GCP": ["gemini-2.0-flash-exp","gemini-1.5-flash-002"]
        }
      }
    """
    azure_str = os.getenv("AZURE_MODELS", "azure-gpt-3.5,azure-gpt-4")
    openai_str = os.getenv("OPENAI_MODELS", "gpt-3.5-turbo,gpt-4")
    ollama_str = os.getenv("OLLAMA_MODELS", "ollama-7b,ollama-phi4")
    # Include GCP environment variable
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


# ------------------------------------------------------------------------------
# Data models
# ------------------------------------------------------------------------------
class HTTPTransaction(BaseModel):
    table_index: int = -1
    request: str
    response: str

class AnalyzeTransactionsPayload(BaseModel):
    model_type: str  # "OpenAI", "AzureOpenAI", "Ollama", or "GCP"
    model_id: str
    transactions: List[HTTPTransaction]


# Helper functions
def remove_code_fences(txt: str) -> str:
    lines = txt.strip().splitlines()
    cleaned = []
    for line in lines:
        if line.strip().startswith("```"):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip("`\n\r\t ")

def chunk_transactions(transactions: List[HTTPTransaction], size=2):
    for i in range(0, len(transactions), size):
        yield transactions[i : i+size]

async def call_model(prompt: str, model_type: str, model_id: str, response_schema=None) -> str:
    connector = create_model_connector(
        model_type=model_type,
        model_id=model_id,
        system_prompt="",
        response_schema=response_schema
    )
    return await connector.get_response(prompt)

def build_tx_text_for_tableindex(txns: List[HTTPTransaction]) -> str:
    s = ""
    for t in txns:
        s += (
            f"TRANSACTION #{t.table_index}:\n"
            f"HTTP REQUEST:\n{t.request}\n\n"
            f"HTTP RESPONSE:\n{t.response}\n\n"
        )
    return s

# ------------------------------
# JSON schemas for responses
# ------------------------------
analysis_response_schema = {
    "type": "object",
    "properties": {
        "TRANSACTION ANALYSIS": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "Request Number": {"type": "number"},
                    "Threat Level": {"type": "string"},
                    "Detected Threats": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "Explanation": {"type": "string"}
                },
                "required": [
                    "Request Number",
                    "Threat Level",
                    "Detected Threats",
                    "Explanation"
                ]
            }
        }
    },
    "required": ["TRANSACTION ANALYSIS"]
}

summary_response_schema = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"}
    },
    "required": ["summary"]
}

chatbot_activity_response_schema = {
    "type": "object",
    "properties": {
        "transactions_with_chatbot_activity": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "transaction_number": {"type": "number"},
                    "explanation": {"type": "string"}
                },
                "required": ["transaction_number","explanation"]
            }
        }
    },
    "required": ["transactions_with_chatbot_activity"]
}


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# 1) /analyze_http_requests_batch (Security Analysis)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
analysis_system_prompt = ANALYSIS_SYSTEM_PROMPT

@router.post("/", response_class=JSONResponse, tags=["Analyze HTTP Requests Batch"])
async def analyze_http_transactions(request: Request, input_data: AnalyzeTransactionsPayload):
    """
    If >2 transactions => chunk them, gather partial analyses, then combine.
    Otherwise single shot.
    Returns: {"TRANSACTION ANALYSIS": [...]} strictly.
    """
    try:
        print("\n--- [analyze_http_requests_batch] Received ---")
        raw_body = await request.body()
        print("[analyze_http_requests_batch] Raw JSON:\n", raw_body.decode("utf-8", "ignore"))

        txns = input_data.transactions
        if len(txns) == 0:
            return JSONResponse(content={"TRANSACTION ANALYSIS":[]})

        if len(txns) <= 2:
            return await single_analyze_call(txns, input_data.model_type, input_data.model_id)
        else:
            return await chunked_analyze_call(txns, input_data.model_type, input_data.model_id)

    except Exception as e:
        print("[analyze_http_requests_batch] EXCEPTION:\n", traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


async def single_analyze_call(txns: List[HTTPTransaction], model_type: str, model_id: str) -> JSONResponse:
    tx_text = build_tx_text_for_tableindex(txns)
    prompt = (
        "IMPORTANT:\n"
        "You MUST return valid JSON in the form {\"TRANSACTION ANALYSIS\":[...]}.\n"
        "No triple backticks or disclaimers.\n\n"
        + analysis_system_prompt +
        "\n\nHTTP TRANSACTIONS:\n" + tx_text
    )
    first_response = await call_model(prompt, model_type, model_id, analysis_response_schema)
    cleaned_first = remove_code_fences(first_response)

    try:
        parsed = json.loads(cleaned_first)
        return JSONResponse(content=parsed)
    except:
        fix_prompt = (
            "You did not provide valid JSON. Here is the original prompt again:\n\n"
            f"{prompt}\n\n"
            "Please respond with exactly {\"TRANSACTION ANALYSIS\":[...]} with no extra keys."
        )
        second_response = await call_model(fix_prompt, model_type, model_id, analysis_response_schema)
        cleaned_second = remove_code_fences(second_response)
        try:
            parsed2 = json.loads(cleaned_second)
            return JSONResponse(content=parsed2)
        except:
            raise HTTPException(status_code=500, detail="No valid JSON after fallback in single_analyze_call.")


async def chunked_analyze_call(txns: List[HTTPTransaction], model_type: str, model_id: str) -> JSONResponse:
    partial_analyses = []
    chunks = list(chunk_transactions(txns, 2))

    # Step 1: partial calls -> plain text
    for idx, cList in enumerate(chunks, start=1):
        chunk_text = build_tx_text_for_tableindex(cList)
        part_prompt = (
            f"CHUNK #{idx}:\n"
            "Provide a PLAIN TEXT partial security analysis for these transactions.\n\n"
            + analysis_system_prompt +
            "\n\n" + chunk_text
        )
        part_resp = await call_model(part_prompt, model_type, model_id, response_schema=None)
        if not part_resp.strip():
            part_resp = "(No partial analysis provided.)"
        partial_analyses.append(part_resp.strip())

    # Step 2: combine partials => final JSON
    combined_input = "We have the following partial analyses:\n\n"
    for i, text in enumerate(partial_analyses, start=1):
        combined_input += f"PARTIAL {i}:\n{text}\n\n"

    combined_input += (
        "Now combine them into a single valid JSON of the form:\n"
        "{\"TRANSACTION ANALYSIS\":[...]} with no extra keys or disclaimers.\n"
    )

    final_resp = await call_model(combined_input, model_type, model_id, analysis_response_schema)
    cleaned_final = remove_code_fences(final_resp)

    try:
        parsed_final = json.loads(cleaned_final)
        return JSONResponse(content=parsed_final)
    except:
        fix_prompt = (
            "You did not return valid JSON. Here is the combine prompt again:\n\n"
            f"{combined_input}\n\n"
            "Please respond with strictly {\"TRANSACTION ANALYSIS\":[...]} with no extra keys."
        )
        fallback = await call_model(fix_prompt, model_type, model_id, analysis_response_schema)
        cf = remove_code_fences(fallback)
        try:
            parsed_fb = json.loads(cf)
            return JSONResponse(content=parsed_fb)
        except:
            raise HTTPException(status_code=500, detail="No valid JSON after fallback in chunked_analyze_call.")


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# 2) summary_http_requests_batch => Summaries
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
summary_system_prompt = SUMMARY_SYSTEM_PROMPT

@router.post("/summary_http_requests_batch/", response_class=JSONResponse, tags=["Analyze HTTP Requests Batch"])
async def summarize_http_transactions(request: Request, input_data: AnalyzeTransactionsPayload):
    """
    Summarize the set of transactions. Return strictly {"summary":"..."}.
    If >2 => do chunk-based approach; else single shot.
    """
    try:
        print("\n--- [summary_http_requests_batch] Received ---")
        raw_body = await request.body()
        print("[summary_http_requests_batch] Raw JSON:\n", raw_body.decode('utf-8', 'ignore'))

        txns = input_data.transactions
        if not txns:
            return JSONResponse(content={"summary":"No transactions to summarize."})

        if len(txns) <= 2:
            return await single_summary_call(txns, input_data.model_type, input_data.model_id)
        else:
            return await chunked_summary_call(txns, input_data.model_type, input_data.model_id)
    except Exception as e:
        print("[summary_http_requests_batch] EXCEPTION:\n", traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


async def single_summary_call(txns: List[HTTPTransaction], model_type: str, model_id: str) -> JSONResponse:
    tx_text = build_tx_text_for_tableindex(txns)
    prompt = (
        "IMPORTANT:\n"
        "Return strictly {\"summary\":\"...\"}.\n"
        + summary_system_prompt +
        "\n\nTransactions:\n" + tx_text
    )
    r1 = await call_model(prompt, model_type, model_id, summary_response_schema)
    c1 = remove_code_fences(r1)
    try:
        parsed = json.loads(c1)
        return JSONResponse(content=parsed)
    except:
        fix_prompt=(
            "You did not produce valid JSON. Original prompt:\n\n"
            f"{prompt}\n\n"
            "Return exactly {\"summary\":\"...\"} with no extra keys."
        )
        r2=await call_model(fix_prompt, model_type, model_id, summary_response_schema)
        c2=remove_code_fences(r2)
        try:
            parsed2=json.loads(c2)
            return JSONResponse(content=parsed2)
        except:
            raise HTTPException(status_code=500, detail="No valid JSON after fallback in single_summary_call.")


async def chunked_summary_call(txns: List[HTTPTransaction], model_type: str, model_id: str) -> JSONResponse:
    partials=[]
    chunks=list(chunk_transactions(txns, 2))

    # partial text summaries
    for idx, cList in enumerate(chunks, start=1):
        c_text = build_tx_text_for_tableindex(cList)
        part_prompt=(
            f"CHUNK #{idx}:\n"
            "Summarize in plain text (no JSON). Then we will combine.\n\n"
            + summary_system_prompt +
            "\n\n" + c_text
        )
        pr=await call_model(part_prompt, model_type, model_id, None)
        if not pr.strip():
            pr="(No partial summary provided.)"
        partials.append(pr.strip())

    combine_input="We have partial summaries:\n\n"
    for i, s in enumerate(partials, start=1):
        combine_input+=f"PARTIAL {i}:\n{s}\n\n"

    combine_input+=(
        "Combine into final JSON => {\"summary\":\"...\"}, no extra keys."
    )
    final=await call_model(combine_input, model_type, model_id, summary_response_schema)
    cf=remove_code_fences(final)

    try:
        parsed=json.loads(cf)
        return JSONResponse(content=parsed)
    except:
        fix_prompt=(
            "Invalid JSON. Original combine request:\n\n"
            f"{combine_input}\n\n"
            "Please return exactly {\"summary\":\"...\"}"
        )
        second=await call_model(fix_prompt, model_type, model_id, summary_response_schema)
        sc=remove_code_fences(second)
        try:
            parsed2=json.loads(sc)
            return JSONResponse(content=parsed2)
        except:
            raise HTTPException(status_code=500, detail="No valid JSON after fallback in chunked_summary_call.")


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# 3) find_chatbot_activity => Chatbot usage detection
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
chatbot_activity_system_prompt = CHATBOT_ACTIVITY_SYSTEM_PROMPT

@router.post("/find_chatbot_activity/", response_class=JSONResponse, tags=["Analyze HTTP Requests Batch"])
async def find_chatbot_activity(request: Request, input_data: AnalyzeTransactionsPayload):
    """
    If >2 => chunk them, else single shot.
    Return strictly {"transactions_with_chatbot_activity":[...]}.
    """
    try:
        print("\n--- [find_chatbot_activity] Received ---")
        raw_body=await request.body()
        print("[find_chatbot_activity] Raw JSON:\n", raw_body.decode('utf-8','ignore'))

        txns=input_data.transactions
        if not txns:
            return JSONResponse(content={"transactions_with_chatbot_activity":[]})

        if len(txns)<=2:
            return await single_find_chatbot_call(txns, input_data.model_type, input_data.model_id)
        else:
            return await chunked_find_chatbot_call(txns, input_data.model_type, input_data.model_id)
    except Exception as e:
        print("[find_chatbot_activity] EXCEPTION:\n", traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


async def single_find_chatbot_call(txns: List[HTTPTransaction], model_type: str, model_id: str) -> JSONResponse:
    tx_text=build_tx_text_for_tableindex(txns)
    prompt=(
        "IMPORTANT:\n"
        "Return {\"transactions_with_chatbot_activity\":[...]} strictly.\n\n"
        + chatbot_activity_system_prompt +
        "\n\nTransactions:\n" + tx_text
    )
    r1=await call_model(prompt, model_type, model_id, chatbot_activity_response_schema)
    c1=remove_code_fences(r1)
    try:
        parsed=json.loads(c1)
        return JSONResponse(content=parsed)
    except:
        fix_prompt=(
            "Invalid JSON. Original prompt:\n\n"
            f"{prompt}\n\n"
            "Please return {\"transactions_with_chatbot_activity\":[...]} exactly."
        )
        r2=await call_model(fix_prompt, model_type, model_id, chatbot_activity_response_schema)
        c2=remove_code_fences(r2)
        try:
            parsed2=json.loads(c2)
            return JSONResponse(content=parsed2)
        except:
            raise HTTPException(status_code=500, detail="No valid JSON after fallback in single_find_chatbot.")


async def chunked_find_chatbot_call(txns: List[HTTPTransaction], model_type: str, model_id: str) -> JSONResponse:
    partials=[]
    chunks=list(chunk_transactions(txns, 2))

    for idx,cList in enumerate(chunks, start=1):
        c_text=build_tx_text_for_tableindex(cList)
        p=(
            f"CHUNK #{idx}:\n"
            "Identify chatbot usage in plain text only (no JSON). We'll combine next.\n\n"
            + chatbot_activity_system_prompt +
            "\n\n" + c_text
        )
        pr=await call_model(p, model_type, model_id, None)
        if not pr.strip():
            pr="(No partial chatbot detection provided.)"
        partials.append(pr.strip())

    combine_prompt=(
        "We have partial chatbot usage findings:\n\n"
    )
    for i,summ in enumerate(partials, start=1):
        combine_prompt += f"PARTIAL {i}:\n{summ}\n\n"

    combine_prompt += (
        "Now combine them into final JSON => {\"transactions_with_chatbot_activity\":[...]}\nNo extra keys."
    )
    final=await call_model(combine_prompt, model_type, model_id, chatbot_activity_response_schema)
    fc=remove_code_fences(final)
    try:
        parsed=json.loads(fc)
        return JSONResponse(content=parsed)
    except:
        fix_prompt=(
            "Invalid JSON. Original combine prompt:\n\n"
            f"{combine_prompt}\n\n"
            "Return exactly {\"transactions_with_chatbot_activity\":[...]}"
        )
        second=await call_model(fix_prompt, model_type, model_id, chatbot_activity_response_schema)
        sc=remove_code_fences(second)
        try:
            parsed2=json.loads(sc)
            return JSONResponse(content=parsed2)
        except:
            raise HTTPException(status_code=500, detail="No valid JSON after fallback in chunked_find_chatbot.")


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# 4) chat_with_gemini => an interactive endpoint
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatWithGeminiPayload(BaseModel):
    model_type: str   # "OpenAI", "AzureOpenAI", "Ollama", or "GCP"
    model_id: str
    conversation_history: List[ChatMessage]
    user_prompt: str
    selected_transactions: List[HTTPTransaction] = []


@router.post("/chat_with_gemini", response_class=JSONResponse, tags=["Analyze HTTP Requests Batch"])
async def chat_with_gemini(request: Request, input_data: ChatWithGeminiPayload) -> Any:
    """
    Chat-based endpoint with optional transactions context.
    If more than 2 transactions => do partial chunk approach => final combine.
    """
    try:
        print("\n--- [chat_with_gemini] Received ---")
        raw_body=await request.body()
        print("[chat_with_gemini] Raw JSON:\n", raw_body.decode('utf-8','ignore'))

        conversation_text=build_conversation_text(input_data.conversation_history)
        conversation_text += f"User: {input_data.user_prompt}\n"

        txns=input_data.selected_transactions
        # Decide chunk or single
        if len(txns)<=2:
            final_answer=await single_chat_call(conversation_text, txns, input_data)
            return build_chat_response(input_data, final_answer)
        else:
            return await chunked_chat_call(conversation_text, txns, input_data)

    except Exception as e:
        print("[chat_with_gemini] EXCEPTION:\n", traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


async def single_chat_call(conversation_text:str, txns:List[HTTPTransaction], input_data:ChatWithGeminiPayload)->str:
    if txns:
        tx_str=build_tx_text_for_tableindex(txns)
        prompt=(
            "You are a helpful assistant. We have a running conversation.\n"
            "Below are some transactions referencing 'TRANSACTION #<table_index>'.\n\n"
            + conversation_text + tx_str +
            "\nAssistant:"
        )
    else:
        prompt=(
            "You are a helpful assistant. We have a running conversation.\n\n"
            + conversation_text +
            "\nAssistant:"
        )
    return await call_model(prompt, input_data.model_type, input_data.model_id, response_schema=None)


async def chunked_chat_call(conversation_text:str, txns:List[HTTPTransaction], input_data:ChatWithGeminiPayload)->dict:
    partials=[]
    chunked=list(chunk_transactions(txns, 2))

    for idx, cList in enumerate(chunked,start=1):
        c_str=build_tx_text_for_tableindex(cList)
        partial_prompt=(
            f"CHUNK #{idx}, referencing 'TRANSACTION #<table_index>'.\n\n"
            "Give a PARTIAL discussion. Not final.\n\n"
            + conversation_text + "\n" + c_str +
            "\nAssistant:"
        )
        p_resp=await call_model(partial_prompt, input_data.model_type, input_data.model_id, None)
        partials.append(p_resp.strip())

    combine_prompt="We have partial responses:\n\n"
    for i,s in enumerate(partials, start=1):
        combine_prompt+=f"PARTIAL {i}:\n{s}\n\n"

    combine_prompt+=(
        f"The user's question is: \"{input_data.user_prompt}\"\n\n"
        "Combine these partials into one final, cohesive answer.\nAssistant:"
    )
    final_answer=await call_model(combine_prompt, input_data.model_type, input_data.model_id, None)
    return build_chat_response(input_data, final_answer)


def build_conversation_text(history: List[ChatMessage]) -> str:
    """
    Convert the existing conversation history into a text format
    e.g. "System: ...\nAssistant: ...\nUser: ...\n"
    """
    text=""
    for msg in history:
        role=msg.role.lower()
        content=msg.content
        if role=="system":
            text+=f"System: {content}\n"
        elif role=="assistant":
            text+=f"Assistant: {content}\n"
        else:
            text+=f"User: {content}\n"
    return text

def build_chat_response(input_data: ChatWithGeminiPayload, final_text: str)->dict:
    """
    Append user + assistant messages to updated conversation history, return JSON.
    """
    updated_history = list(input_data.conversation_history)
    updated_history.append(ChatMessage(role="user", content=input_data.user_prompt))
    updated_history.append(ChatMessage(role="assistant", content=final_text))
    return {
        "assistant_message": final_text,
        "conversation_history": [m.dict() for m in updated_history]
    }


# Optional endpoint just for example
@router.get("/openai_models")
async def fetch_openai_models():
    """
    Example to fetch remote OpenAI models if OPENAI_API_KEY is set.
    Otherwise fallback to known list.
    """
    import os
    import requests

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return {"models": ["gpt-3.5-turbo", "gpt-4"]}  # fallback

    try:
        resp = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {api_key}"}
        )
        resp.raise_for_status()
        data = resp.json()
        model_list = []
        for m in data.get("data", []):
            mid = m.get("id", "")
            if mid:
                model_list.append(mid)
        # Maybe filter or sort
        model_list = sorted(set(model_list))
        if not model_list:
            model_list = ["gpt-3.5-turbo", "gpt-4"]
        return {"models": model_list}
    except Exception as e:
        return {"models": ["gpt-3.5-turbo", "gpt-4"]}  # fallback
