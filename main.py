from fastapi import FastAPI
from routes import authentication

app = FastAPI()

# Include the router
app.include_router(authentication.router)

@app.get("/")
def read_root():
    return {"message": "Welcome to the FastAPI app"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)