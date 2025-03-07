# start_server.py
import os
from dotenv import load_dotenv
import uvicorn

# Load environment variables from .env file
load_dotenv()

# Set default host and port, you can change as needed
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))

if __name__ == "__main__":
    # Start the uvicorn server with the loaded environment variables
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=True)
