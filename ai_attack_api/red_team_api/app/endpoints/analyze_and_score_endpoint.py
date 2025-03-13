"""
app/endpoints/analyze_and_score
"""


import os
import json
import base64
import requests
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.services.model_connector import create_model_connector
from app.prompts.prompt_definitions import (
    OPTION_PROMPTS,
    SECURITY_EVAL_SYSTEM_PROMPT,
    BULK_ANALYSIS_SYSTEM_PROMPT
)

router = APIRouter()

def remove_code_fences(txt: str) -> str:
    lines = txt.strip().splitlines()
    cleaned_lines = []
    for line in lines:
        if line.strip().startswith("```"):
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines).strip("`\n\r\t ")

# -------------------------------------------------------------------
#  1) GET /available_models => from .env
# -------------------------------------------------------------------
@router.get("/available_models", response_class=JSONResponse)
def available_models():
    """
    Returns a dictionary of model lists from environment variables:
      { "providers": { "Azure":[...], "OpenAI":[...], "Ollama":[...], "GCP":[...] } }
    so the Jython extension can unify Azure/OpenAI/Ollama/GCP references.
    """
    azure_str = os.getenv("AZURE_MODELS", "azure-gpt-3.5,azure-gpt-4")
    openai_str = os.getenv("OPENAI_MODELS", "gpt-3.5-turbo,gpt-4")
    ollama_str = os.getenv("OLLAMA_MODELS", "ollama-7b,ollama-phi4")
    # Add GCP models from .env if present
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

# ---------------------------
# Pydantic models
# ---------------------------
class OptionAnalyzeRequest(BaseModel):
    model_type: str
    model_id: str
    option_key: str
    request_text: str
    response_text: str

class AnalyzeHttpTransactionRequest(BaseModel):
    model_type: str
    model_id: str
    string_one: str
    string_two: str

class BulkAnalysisItem(BaseModel):
    request: str
    response: str
    score: Optional[str] = None
    category: Optional[str] = None

class BulkAnalysisRequest(BaseModel):
    model_type: str
    model_id: str
    data: List[BulkAnalysisItem]

class ExportRequest(BaseModel):
    headers: List[str]
    rows: List[List[str]]
    format: str

class BenchmarkRequest(BaseModel):
    model_type: str
    model_id: str
    headers: List[str]
    rows: List[List[str]]

analysis_response_schema = {
    "type": "object",
    "properties": {
        "analysis": {"type": "string"}
    },
    "required": ["analysis"]
}

# -------------------------------------------------------------------
# 2) /option_analyze
# -------------------------------------------------------------------
@router.post("/option_analyze", response_class=JSONResponse, tags=["Witty Analysis Endpoints"])
async def option_analyze(request: OptionAnalyzeRequest):
    try:
        prompt_template = OPTION_PROMPTS.get(request.option_key,"No recognized key")
        full_prompt = (
            f"HTTP REQUEST:\n{request.request_text}\n\n"
            f"HTTP RESPONSE:\n{request.response_text}\n\n"
            f"{prompt_template}"
        )
        connector = create_model_connector(
            model_type=request.model_type,
            model_id=request.model_id,
            system_prompt="",
            response_schema=analysis_response_schema
        )
        first_resp = await connector.get_response(full_prompt)
        cleaned = remove_code_fences(first_resp)
        try:
            j = json.loads(cleaned)
            return {"analysis": j.get("analysis","")}
        except:
            fix_prompt=(
                "You did not return valid JSON. Original:\n\n"
                f"{full_prompt}\n\n"
                "Respond with {\"analysis\":\"...\"} exactly."
            )
            second=await connector.get_response(fix_prompt)
            c2=remove_code_fences(second)
            try:
                p2=json.loads(c2)
                return {"analysis": p2.get("analysis","")}
            except:
                return {"analysis": cleaned}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------------------------------------------
# 3) /analyze_http_transaction
# -------------------------------------------------------------------
@router.post("/analyze_http_transaction", response_class=JSONResponse, tags=["Witty Analysis Endpoints"])
async def analyze_http_transaction(req: AnalyzeHttpTransactionRequest):
    try:
        system_text = SECURITY_EVAL_SYSTEM_PROMPT or ""
        prompt = (
            system_text
            + "\n\n"
            + "Perform a security analysis on the following data.\n"
            + "Return strictly JSON => {\"analysis\":\"...\"}.\n\n"
            f"HTTP REQUEST:\n{req.string_one}\n\n"
            f"HTTP RESPONSE:\n{req.string_two}\n"
        )
        connector = create_model_connector(
            model_type=req.model_type,
            model_id=req.model_id,
            system_prompt="",
            response_schema=analysis_response_schema
        )
        first_resp = await connector.get_response(prompt)
        cleaned = remove_code_fences(first_resp)
        try:
            parsed = json.loads(cleaned)
            return parsed
        except:
            fix_prompt = (
                "You did not respond with valid JSON. Original prompt:\n\n"
                f"{prompt}\n\n"
                "Please respond with {\"analysis\":\"...\"} only."
            )
            second_resp = await connector.get_response(fix_prompt)
            c2 = remove_code_fences(second_resp)
            try:
                p2 = json.loads(c2)
                return p2
            except:
                return {"analysis": cleaned}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------------------------------------------
# 4) /bulk_analysis
# -------------------------------------------------------------------
@router.post("/bulk_analysis", response_class=JSONResponse, tags=["Witty Analysis Endpoints"])
async def bulk_analysis(req: BulkAnalysisRequest):
    try:
        conn = create_model_connector(
            model_type=req.model_type,
            model_id=req.model_id,
            system_prompt="",
            response_schema=None
        )
        scores=[]
        categories=[]
        for item in req.data:
            prompt=(
                BULK_ANALYSIS_SYSTEM_PROMPT
                + "\n\nHTTP REQUEST:\n" + item.request
                + "\n\nHTTP RESPONSE:\n" + item.response
                + "\n\nReturn JSON => {\"score\":\"0|1\",\"category\":\"...\"}"
            )
            raw=await conn.get_response(prompt)
            cleaned=remove_code_fences(raw)
            try:
                j2=json.loads(cleaned)
                s=j2.get("score","1")
                c=j2.get("category","uncategorized")
            except:
                s="1"
                c="uncategorized"
            scores.append(s)
            categories.append(c)
        return {"scores":scores,"categories":categories}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------------------------------------------
# 5) /export
# -------------------------------------------------------------------
@router.post("/export", tags=["Witty Analysis Endpoints"])
def export_data(req: ExportRequest):
    import pandas as pd
    from io import BytesIO

    df = pd.DataFrame(req.rows, columns=req.headers)
    fmt=req.format.lower()
    if fmt=="csv":
        content=df.to_csv(index=False).encode("utf-8")
    elif fmt=="excel":
        import openpyxl
        buffer=BytesIO()
        df.to_excel(buffer,index=False,engine='openpyxl')
        content=buffer.getvalue()
    elif fmt=="parquet":
        buffer=BytesIO()
        df.to_parquet(buffer,index=False)
        content=buffer.getvalue()
    else:
        raise HTTPException(status_code=400, detail="Unsupported export format.")
    b64=base64.b64encode(content).decode("utf-8")
    return {"file_content_base64": b64}

# -------------------------------------------------------------------
# 6) /benchmark => extended metrics
# -------------------------------------------------------------------
@router.post("/benchmark", tags=["Witty Analysis Endpoints"])
async def benchmark_data(req: BenchmarkRequest):
    """
    Evaluate all rows, fill Score/Category if missing => returns extended stats:
      - average_request_length, longest_request, shortest_request
      - average_response_length, longest_response, shortest_response
      - redirect_count (status code 300..399)
      - server_distribution (parsing "Server:" in the response text lines)
      - content_type_distribution (parsing "Content-Type:" lines)
      plus the existing fields
    """
    import pandas as pd
    df = pd.DataFrame(req.rows, columns=req.headers)
    if "Request" not in df.columns or "Response" not in df.columns:
        raise HTTPException(status_code=400, detail="Data must have 'Request'/'Response'.")

    # If missing
    if "Status" not in df.columns:
        df["Status"]="N/A"
    if "Score" not in df.columns:
        df["Score"]=None
    if "Category" not in df.columns:
        df["Category"]=None

    # fill missing Score/Category
    missingMask = df["Score"].isnull() | df["Category"].isnull()
    if missingMask.any():
        from pydantic import parse_obj_as
        sub_df=df[missingMask].copy()
        items=[]
        for i,row in sub_df.iterrows():
            items.append({
                "request":row["Request"],
                "response":row["Response"],
                "score":None,
                "category":None
            })
        bReq=BulkAnalysisRequest(
            model_type=req.model_type,
            model_id=req.model_id,
            data=parse_obj_as(List[BulkAnalysisItem], items)
        )
        connector = create_model_connector(
            model_type=bReq.model_type,
            model_id=bReq.model_id,
            system_prompt="",
            response_schema=None
        )
        newScores=[]
        newCats=[]
        for it in bReq.data:
            p=(
                BULK_ANALYSIS_SYSTEM_PROMPT
                + "\n\nHTTP REQUEST:\n" + it.request
                + "\n\nHTTP RESPONSE:\n" + it.response
                + "\n\nReturn JSON => {\"score\":\"0|1\",\"category\":\"...\"}"
            )
            raw=await connector.get_response(p)
            cleaned=remove_code_fences(raw)
            try:
                x=json.loads(cleaned)
                s=x.get("score","1")
                c=x.get("category","wizard_magic")
            except:
                s="1"
                c="wizard_magic"
            newScores.append(s)
            newCats.append(c)

        for idx_, rowID in enumerate(sub_df.index):
            df.at[rowID,"Score"]=newScores[idx_]
            df.at[rowID,"Category"]=newCats[idx_]

    total_requests=len(df)
    fail_count=(df["Score"]=="1").sum()
    fail_percentage=(fail_count/total_requests*100 if total_requests>0 else 0.0)

    # 1) Extended: measure request length
    df["req_len"] = df["Request"].apply(lambda x: len(x) if isinstance(x,str) else 0)
    avg_req_len = df["req_len"].mean() if total_requests>0 else 0.0
    max_req_len = df["req_len"].max() if total_requests>0 else 0
    min_req_len = df["req_len"].min() if total_requests>0 else 0

    # 2) Extended: measure response length
    df["resp_len"] = df["Response"].apply(lambda x: len(x) if isinstance(x,str) else 0)
    avg_resp_len = df["resp_len"].mean() if total_requests>0 else 0.0
    max_resp_len = df["resp_len"].max() if total_requests>0 else 0
    min_resp_len = df["resp_len"].min() if total_requests>0 else 0

    # 3) Extended: count redirects => statuses in 300..399
    def is_redirect(status_str):
        try:
            sc=int(status_str)
            return (sc>=300 and sc<400)
        except:
            return False
    df["is_redirect"] = df["Status"].apply(is_redirect)
    redirect_count = df["is_redirect"].sum()

    # 4) server_distribution => parse lines in "Response", looking for "Server:" line
    def find_server_header(resp_str):
        lines = resp_str.split('\n')
        for ln in lines:
            if ln.lower().startswith("server:"):
                parts=ln.split(":",1)
                if len(parts)>1:
                    return parts[1].strip()
        return None
    df["server_header"] = df["Response"].apply(lambda s: find_server_header(s) if isinstance(s,str) else None)
    server_series = df["server_header"].dropna()
    server_dist = server_series.value_counts().to_dict()

    # 5) content_type_distribution => parse lines in "Response" for "Content-Type:"
    def find_content_type(resp_str):
        lines = resp_str.split('\n')
        for ln in lines:
            if ln.lower().startswith("content-type:"):
                parts=ln.split(":",1)
                if len(parts)>1:
                    return parts[1].strip().lower()
        return None
    df["content_type"] = df["Response"].apply(lambda s: find_content_type(s) if isinstance(s,str) else None)
    ctype_series = df["content_type"].dropna()
    content_type_dist = ctype_series.value_counts().to_dict()

    # method distribution
    df["_method"] = df["Request"].apply(lambda x: x.split(' ',1)[0] if isinstance(x,str) else "")
    method_dist = df["_method"].value_counts().to_dict()

    # status code distribution
    sc_dist = df["Status"].value_counts().to_dict()
    sc_dist={str(k):int(v) for k,v in sc_dist.items()}

    # Category stats
    cat_dist = df["Category"].value_counts().to_dict()
    category_stats={}
    for cat_name,cat_count in cat_dist.items():
        sub=df[df["Category"]==cat_name]
        subfail=(sub["Score"]=="1").sum()
        catfailpct=(subfail/cat_count*100 if cat_count>0 else 0.0)
        category_stats[cat_name]={
            "count":int(cat_count),
            "fail_count":int(subfail),
            "fail_percentage": catfailpct
        }

    result={
        "total_requests": int(total_requests),
        "total_that_need_review": int(fail_count),
        "fail_percentage": float(fail_percentage),

        # Extended request stats
        "average_request_length": float(avg_req_len),
        "longest_request": int(max_req_len),
        "shortest_request": int(min_req_len),

        # Extended response stats
        "average_response_length": float(avg_resp_len),
        "longest_response": int(max_resp_len),
        "shortest_response": int(min_resp_len),

        # Extended redirect count
        "redirect_count": int(redirect_count),

        # Existing fields
        "status_code_distribution": sc_dist,
        "method_distribution": method_dist,
        "category_stats": category_stats,

        # Extended distributions
        "server_distribution": server_dist, 
        "content_type_distribution": content_type_dist
    }

    def convert_numpy_types(o):
        if isinstance(o, dict):
            return {k: convert_numpy_types(v) for k,v in o.items()}
        elif isinstance(o, list):
            return [convert_numpy_types(x) for x in o]
        elif isinstance(o, np.integer):
            return int(o)
        elif isinstance(o, np.floating):
            return float(o)
        elif isinstance(o, np.ndarray):
            return o.tolist()
        else:
            return o

    return convert_numpy_types(result)
