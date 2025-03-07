from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

# Import your endpoints from 'app.endpoints.*'
from app.endpoints import (
    prompt_augmenter_payload_processor_endpoint,
    automated_conversations_endpoint,
    bulk_analyze_http_transactions_endpoint,
    analyze_and_score_endpoint,
)

load_dotenv()

app = FastAPI(
    title="Red Team Attack API",
    description="API for executing various red team attacks on LLMs, including single-shot attacks, multi-turn interactions, benchmarks, and prompt augmentation.",
    version="1.0.0"
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to known domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health Check
@app.get("/health", tags=["Utility"])
async def health_check():
    return {"status": "healthy"}

# Exception Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=400,
        content={
            "detail": exc.errors(),
            "body": str(exc.body)
        },
    )

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred."},
    )

# ----------------------------------------------------------------
#  Include Routers
# ----------------------------------------------------------------

# 1) Used in prompt_augmenter_payload_processor_endpoint"
app.include_router(
    prompt_augmenter_payload_processor_endpoint.router,
    prefix="/api/v1/prompt_augmenter_payload_processor_endpoint",
    tags=["Burp Suite Prompt Augmentor and Payload Processor"]
)

# 2) Used in automated_conversations_endpoint
app.include_router(
    automated_conversations_endpoint.router,
    prefix="/api/v1/automated_conversations_endpoint",
    tags=["Automated Conversations"]
)

# 3) Used in analyze_and_score_endpoint
app.include_router(
    analyze_and_score_endpoint.router,
    prefix="/api/v1/analyze_and_score_endpoint",
    tags=["Analyze and Score Transactions"]
)

# 4) Used in bulk_analyze_http_transactions_endpoint
app.include_router(
    bulk_analyze_http_transactions_endpoint.router,
    prefix="/api/v1/bulk_analyze_http_transactions_endpoint",
    tags=["Analyze HTTP Requests in Bulk"]
)
