from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, constr
from typing import Optional
import openai
import os
from dotenv import load_dotenv
from . import models, auth
from .database import engine, get_db

# Load environment variables
load_dotenv()

# Create database tables
models.Base.metadata.create_all(bind=engine)

# Initialize FastAPI
app = FastAPI(title="AI Risk Detector API")

origins = [
    "http://localhost:3000", # Local dev
    "https://ai-risk-detector.vercel.app", # My frontend
    "http://localhost:3001" # Landing page
]
# CORS

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure OpenAI
openai.api_key = os.getenv("OPENAI_API_KEY")


# Pydantic models
class UserCreate(BaseModel):
    email: EmailStr
    password: constr(max_length=72)
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class WaitlistCreate(BaseModel):
    name: str
    email: EmailStr
    company: Optional[str] = None

class AnalyzeRequest(BaseModel):
    text: str

# Root endpoint
@app.get("/")
async def root():
    return {"message": "AI Risk Detector API is running!"}

# Auth endpoints
@app.post("/auth/signup")
async def signup(user: UserCreate, db: Session = Depends(get_db)):
    """
    Create new user account
    """
    # Check if user exists
    existing_user = db.query(models.User).filter(
        models.User.email == user.email
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # Create new user
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Create access token
    access_token = auth.create_access_token(data={"sub": user.email})
    
    return {
        "success": True,
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": db_user.id,
            "email": db_user.email,
            "full_name": db_user.full_name
        }
    }

@app.post("/auth/login")
async def login(user_login: UserLogin, db: Session = Depends(get_db)):
    """
    Login user
    """
    user = db.query(models.User).filter(
        models.User.email == user_login.email
    ).first()
    
    if not user or not auth.verify_password(user_login.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password"
        )
    
    # Create access token
    access_token = auth.create_access_token(data={"sub": user.email})
    
    return {
        "success": True,
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name
        }
    }

@app.get("/auth/me")
async def get_me(current_user: models.User = Depends(auth.get_current_user)):
    """
    Get current user info
    """
    return {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "created_at": current_user.created_at.isoformat()
    }

# Analysis endpoints
@app.post("/analyze")
async def analyze_text(
    request: AnalyzeRequest,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    """
    Analyze AI-generated text for hallucinations (requires authentication)
    """
    try:
        text = request.text
        
        # Call GPT to analyze
        response = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": """You are an AI hallucination detector. 
                    Analyze the given text and determine if it contains hallucinations, 
                    fabricated information, or unverifiable claims. 
                    
                    Respond in this EXACT format:
                    RISK_SCORE: [number from 0-100, where 0=no risk, 100=high risk]
                    HALLUCINATION: [YES/NO]
                    REASON: [brief explanation]
                    RECOMMENDATIONS: [what to fix]
                    """
                },
                {
                    "role": "user",
                    "content": f"Analyze this AI output for hallucinations:\n\n{text}"
                }
            ],
            temperature=0.3,
            max_tokens=500
        )
        
        # Get the response
        analysis = response.choices[0].message.content
        
        # Parse the response
        lines = analysis.split('\n')
        risk_score = 0
        is_hallucination = "UNKNOWN"
        reason = ""
        recommendations = ""
        
        for line in lines:
            if line.startswith("RISK_SCORE:"):
                try:
                    risk_score = int(line.split(":")[1].strip())
                except:
                    risk_score = 50
            elif line.startswith("HALLUCINATION:"):
                is_hallucination = line.split(":")[1].strip()
            elif line.startswith("REASON:"):
                reason = line.split(":", 1)[1].strip()
            elif line.startswith("RECOMMENDATIONS:"):
                recommendations = line.split(":", 1)[1].strip()
        
        # Save to database with user_id
        db_analysis = models.Analysis(
            user_id=current_user.id,
            input_text=text[:500],
            risk_score=risk_score,
            is_hallucination=is_hallucination,
            reason=reason,
            recommendations=recommendations,
            full_analysis=analysis
        )
        db.add(db_analysis)
        db.commit()
        db.refresh(db_analysis)
        
        return {
            "success": True,
            "analysis_id": db_analysis.id,
            "risk_score": risk_score,
            "is_hallucination": is_hallucination,
            "reason": reason,
            "recommendations": recommendations,
            "full_analysis": analysis
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@app.get("/my-analyses")
async def get_my_analyses(
    limit: int = 20,
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get current user's analysis history
    """
    analyses = db.query(models.Analysis).filter(
        models.Analysis.user_id == current_user.id
    ).order_by(
        models.Analysis.created_at.desc()
    ).limit(limit).all()
    
    return {
        "success": True,
        "count": len(analyses),
        "analyses": [
            {
                "id": a.id,
                "risk_score": a.risk_score,
                "is_hallucination": a.is_hallucination,
                "reason": a.reason,
                "recommendations": a.recommendations,
                "full_analysis": a.full_analysis, 
                "created_at": a.created_at.isoformat(),
                "preview": a.input_text[:100] + "..." if len(a.input_text) > 100 else a.input_text
            }
            for a in analyses
        ]
    }

@app.get("/stats")
async def get_user_stats(
    current_user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get user statistics
    """
    total_analyses = db.query(models.Analysis).filter(
        models.Analysis.user_id == current_user.id
    ).count()
    
    high_risk_count = db.query(models.Analysis).filter(
        models.Analysis.user_id == current_user.id,
        models.Analysis.risk_score >= 70
    ).count()
    
    avg_risk = db.query(models.Analysis).filter(
        models.Analysis.user_id == current_user.id
    ).with_entities(models.Analysis.risk_score).all()
    
    avg_risk_score = sum([a[0] for a in avg_risk]) / len(avg_risk) if avg_risk else 0
    
    return {
        "total_analyses": total_analyses,
        "high_risk_count": high_risk_count,
        "avg_risk_score": round(avg_risk_score, 1)
    }

# Waitlist endpoints
@app.post("/waitlist")
async def join_waitlist(waitlist: WaitlistCreate, db: Session = Depends(get_db)):
    """
    Add user to waitlist
    """
    try:
        existing = db.query(models.Waitlist).filter(
            models.Waitlist.email == waitlist.email
        ).first()
        
        if existing:
            return {
                "success": False,
                "message": "Email already registered"
            }
        
        db_waitlist = models.Waitlist(
            name=waitlist.name,
            email=waitlist.email,
            company=waitlist.company
        )
        db.add(db_waitlist)
        db.commit()
        db.refresh(db_waitlist)
        
        return {
            "success": True,
            "message": "Successfully joined waitlist",
            "position": db.query(models.Waitlist).count()
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@app.get("/waitlist/count")
async def waitlist_count(db: Session = Depends(get_db)):
    """
    Get waitlist count
    """
    count = db.query(models.Waitlist).count()
    return {"count": count}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)