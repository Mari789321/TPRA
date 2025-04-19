from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from typing import List, Optional
from datetime import datetime, timedelta
import uuid
#from app.models.agent import TPRAgent
from tpra_realty.backend.app.models.agent import TPRAgent
#from app.models.permission import TPRAPermission
from ...models.permission import TPRAPermission
from app.models.land import TPRALand
# Ensure the correct path to activity_log is used
from app.models.logs.activity_log import TPRActivityLog  # Update the path if the file is in a subdirectory
from app.models.transactions import Transaction  # Update the path if the file is named 'transactions.py'
from app.schemas.agent import (
    AgentCreate, 
    AgentResponse,
    AgentUpdate,
    AgentLandPermission,
    AgentStatsResponse
)
from app.services.agent_service import AgentService
from app.services.auth import get_current_active_agent, get_current_active_admin
from app.services.document_service import DocumentService
from app.db.session import get_db
from app.utils.encryption import AESCipher
from app.utils.file_upload import upload_to_s3
from app.core.config import settings

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
aes = AESCipher()

@router.post("/", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def create_agent(
    agent_data: AgentCreate,
    db: Session = Depends(get_db),
    current_admin=Depends(get_current_active_admin)
):
    """
    Create a new TPRA agent (Admin only)
    - Validates all required fields
    - Generates TPRA_ID automatically
    - Encrypts sensitive data before storage
    """
    try:
        # Check if agent already exists with same Aadhaar or PAN
        existing_agent = db.query(TPRAgent).filter(
            (TPRAgent.aadhar_id == aes.encrypt(agent_data.aadhar_id)) |
            (TPRAgent.pan_card == aes.encrypt(agent_data.pan_card))
        ).first()
        
        if existing_agent:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Agent with same Aadhaar or PAN already exists"
            )
        
        agent = AgentService.create_agent(db, agent_data, current_admin.tpra_id)
        
        # Log the activity
        db.add(TPRActivityLog(
            user_id=current_admin.tpra_id,
            user_type="ADMIN",
            action="CREATE_AGENT",
            entity_type="AGENT",
            entity_id=agent.agent_id,
            details={
                "created_by": current_admin.tpra_id,
                "agent_level": agent_data.agent_level
            }
        ))
        db.commit()
        
        return agent
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/me", response_model=AgentResponse)
async def get_current_agent(
    current_agent=Depends(get_current_active_agent),
    db: Session = Depends(get_db)
):
    """Get current authenticated agent's details"""
    return AgentService.get_agent_by_id(db, current_agent.tpra_id)

@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    current_agent=Depends(get_current_active_agent)
):
    """
    Get agent details by TPRA_ID
    - Only accessible by admin or the agent themselves
    """
    if current_agent.agent_level < 5 and current_agent.tpra_id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view this agent"
        )
    
    agent = AgentService.get_agent_by_id(db, agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    return agent

@router.put("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: str,
    agent_data: AgentUpdate,
    db: Session = Depends(get_db),
    current_agent=Depends(get_current_active_agent)
):
    """
    Update agent details
    - Only admin or the agent themselves can update
    - Certain fields require admin level
    """
    if current_agent.agent_level < 5 and current_agent.tpra_id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only update your own profile"
        )
    
    # Check if trying to update restricted fields without admin access
    if (agent_data.agent_level is not None or 
        agent_data.is_active is not None) and current_agent.agent_level < 5:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin level required to update agent level or status"
        )
    
    try:
        updated_agent = AgentService.update_agent(db, agent_id, agent_data)
        
        # Log the activity
        db.add(TPRActivityLog(
            user_id=current_agent.tpra_id,
            user_type="AGENT",
            action="UPDATE_AGENT",
            entity_type="AGENT",
            entity_id=updated_agent.agent_id,
            details={
                "updated_by": current_agent.tpra_id,
                "fields_updated": list(agent_data.dict(exclude_unset=True).keys())
            }
        ))
        db.commit()
        
        return updated_agent
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/{agent_id}/upload-declaration", status_code=status.HTTP_201_CREATED)
async def upload_declaration_video(
    agent_id: str,
    video: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_agent=Depends(get_current_active_agent)
):
    """
    Upload agent declaration video
    - Only the agent themselves or admin can upload
    - Video is encrypted and stored in S3
    """
    if current_agent.agent_level < 5 and current_agent.tpra_id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only upload your own declaration video"
        )
    
    agent = AgentService.get_agent_by_id(db, agent_id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found"
        )
    
    try:
        # Validate video file
        if not video.content_type.startswith('video/'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only video files are allowed"
            )
        
        # Generate encrypted filename
        file_ext = video.filename.split('.')[-1]
        encrypted_filename = f"agent_declarations/{agent_id}/{uuid.uuid4()}.{file_ext}"
        
        # Encrypt and upload
        file_content = await video.read()
        encrypted_content = aes.encrypt(file_content.decode('latin-1'))
        
        s3_url = upload_to_s3(
            encrypted_content.encode('latin-1'),
            encrypted_filename,
            content_type=video.content_type
        )
        
        # Update agent record
        agent.declare_video_url = s3_url
        db.commit()
        db.refresh(agent)
        
        # Log the activity
        db.add(TPRActivityLog(
            user_id=current_agent.tpra_id,
            user_type="AGENT",
            action="UPLOAD_DECLARATION",
            entity_type="AGENT",
            entity_id=agent.agent_id,
            details={
                "file_size": len(file_content),
                "content_type": video.content_type
            }
        ))
        db.commit()
        
        return {"message": "Declaration video uploaded successfully", "s3_url": s3_url}
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/{agent_id}/lands", response_model=List[AgentLandPermission])
async def get_agent_lands(
    agent_id: str,
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_agent=Depends(get_current_active_agent)
):
    """
    Get all lands associated with an agent
    - Includes lands created by the agent and lands with granted permissions
    - Only accessible by admin or the agent themselves
    """
    if current_agent.agent_level < 5 and current_agent.tpra_id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only view your own lands"
        )
    
    try:
        # Get lands created by this agent
        created_lands = db.query(TPRALand).filter(
            TPRALand.created_by == agent_id
        )
        
        if active_only:
            created_lands = created_lands.filter(TPRALand.is_approved == True)
        
        created_lands = created_lands.all()
        
        # Get lands with permissions granted to this agent
        permission_lands = db.query(TPRAPermission).filter(
            TPRAPermission.agent_id == agent_id
        )
        
        if active_only:
            permission_lands = permission_lands.filter(
                TPRAPermission.is_active == True,
                TPRAPermission.expires_at > datetime.utcnow()
            )
        
        permission_lands = permission_lands.join(
            TPRALand,
            TPRALand.land_id == TPRAPermission.land_id
        ).all()
        
        # Format response
        response = []
        
        for land in created_lands:
            response.append({
                "land_id": land.tpra_land_id,
                "access_type": "OWNER",
                "access_level": "FULL",
                "granted_at": land.created_at,
                "land_details": {
                    "land_type": land.land_type,
                    "location": land.location,
                    "approval_status": land.approval_status,
                    "price": land.price
                }
            })
        
        for perm in permission_lands:
            response.append({
                "land_id": perm.land.tpra_land_id,
                "access_type": "GRANTED",
                "access_level": perm.access_level,
                "granted_at": perm.granted_at,
                "granted_by": perm.granted_by,
                "expires_at": perm.expires_at,
                "land_details": {
                    "land_type": perm.land.land_type,
                    "location": perm.land.location,
                    "approval_status": perm.land.approval_status,
                    "price": perm.land.price
                }
            })
        
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.post("/{agent_id}/grant-permission", status_code=status.HTTP_201_CREATED)
async def grant_land_permission(
    agent_id: str,
    permission_data: AgentLandPermission,
    db: Session = Depends(get_db),
    current_agent=Depends(get_current_active_agent)
):
    """
    Grant land access permission to another agent
    - Only land owner or agents with MANAGE permission can grant access
    - Admin can grant any permission
    """
    if current_agent.agent_level < 5 and current_agent.tpra_id != permission_data.granted_by:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin can grant permissions on behalf of others"
        )
    
    try:
        # Verify target agent exists
        target_agent = AgentService.get_agent_by_id(db, agent_id)
        if not target_agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target agent not found"
            )
        
        # Verify land exists
        land = db.query(TPRALand).filter(
            TPRALand.tpra_land_id == permission_data.land_id
        ).first()
        if not land:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Land not found"
            )
        
        # Check if current user has permission to grant access
        if current_agent.agent_level < 5:  # Not admin
            if land.created_by != current_agent.tpra_id:  # Not land owner
                # Check for MANAGE permission
                has_permission = db.query(TPRAPermission).filter(
                    TPRAPermission.agent_id == current_agent.tpra_id,
                    TPRAPermission.land_id == land.land_id,
                    TPRAPermission.access_level == "MANAGE",
                    TPRAPermission.is_active == True,
                    TPRAPermission.expires_at > datetime.utcnow()
                ).first()
                
                if not has_permission:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="No permission to grant access for this land"
                    )
        
        # Check if permission already exists
        existing_permission = db.query(TPRAPermission).filter(
            TPRAPermission.agent_id == target_agent.agent_id,
            TPRAPermission.land_id == land.land_id
        ).first()
        
        expires_at = None
        if permission_data.expires_days:
            expires_at = datetime.utcnow() + timedelta(days=permission_data.expires_days)
        
        if existing_permission:
            # Update existing permission
            existing_permission.access_level = permission_data.access_level
            existing_permission.expires_at = expires_at
            existing_permission.is_active = True
            existing_permission.granted_by = current_agent.tpra_id
            existing_permission.granted_at = datetime.utcnow()
        else:
            # Create new permission
            permission = TPRAPermission(
                agent_id=target_agent.agent_id,
                land_id=land.land_id,
                access_level=permission_data.access_level,
                granted_by=current_agent.tpra_id,
                expires_at=expires_at
            )
            db.add(permission)
        
        db.commit()
        
        # Log the activity
        db.add(TPRActivityLog(
            user_id=current_agent.tpra_id,
            user_type="AGENT",
            action="GRANT_PERMISSION",
            entity_type="LAND",
            entity_id=land.land_id,
            details={
                "target_agent": agent_id,
                "access_level": permission_data.access_level,
                "expires_at": expires_at.isoformat() if expires_at else None
            }
        ))
        db.commit()
        
        return {"message": "Permission granted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/{agent_id}/stats", response_model=AgentStatsResponse)
async def get_agent_stats(
    agent_id: str,
    time_range: str = "30d",  # 7d, 30d, 90d, 1y
    db: Session = Depends(get_db),
    current_agent=Depends(get_current_active_agent)
):
    """
    Get agent performance statistics
    - Number of listings
    - Number of successful transactions
    - Total commission earned
    - Approval rate
    - Only accessible by admin or the agent themselves
    """
    if current_agent.agent_level < 5 and current_agent.tpra_id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Can only view your own stats"
        )
    
    try:
        # Calculate time range
        now = datetime.utcnow()
        if time_range == "7d":
            start_date = now - timedelta(days=7)
        elif time_range == "30d":
            start_date = now - timedelta(days=30)
        elif time_range == "90d":
            start_date = now - timedelta(days=90)
        elif time_range == "1y":
            start_date = now - timedelta(days=365)
        else:
            start_date = now - timedelta(days=30)  # Default
        
        # Get agent
        agent = AgentService.get_agent_by_id(db, agent_id)
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found"
            )
        
        # Get land stats
        total_lands = db.query(TPRALand).filter(
            TPRALand.created_by == agent_id
        ).count()
        
        approved_lands = db.query(TPRALand).filter(
            TPRALand.created_by == agent_id,
            TPRALand.is_approved == True
        ).count()
        
        recent_lands = db.query(TPRALand).filter(
            TPRALand.created_by == agent_id,
            TPRALand.created_at >= start_date
        ).count()
        
        # Get transaction stats
        total_transactions = db.query(Transaction).filter(
            Transaction.agent_id == agent_id,
            Transaction.status == "COMPLETED"
        ).count()
        
        recent_transactions = db.query(Transaction).filter(
            Transaction.agent_id == agent_id,
            Transaction.status == "COMPLETED",
            Transaction.transaction_date >= start_date
        ).count()
        
        total_commission = db.query(func.sum(Transaction.commission_amount)).filter(
            Transaction.agent_id == agent_id,
            Transaction.status == "COMPLETED"
        ).scalar() or 0
        
        recent_commission = db.query(func.sum(Transaction.commission_amount)).filter(
            Transaction.agent_id == agent_id,
            Transaction.status == "COMPLETED",
            Transaction.transaction_date >= start_date
        ).scalar() or 0
        
        # Calculate approval rate
        approval_rate = (approved_lands / total_lands * 100) if total_lands > 0 else 0
        
        return {
            "agent_id": agent_id,
            "time_range": time_range,
            "start_date": start_date.isoformat(),
            "total_lands": total_lands,
            "approved_lands": approved_lands,
            "approval_rate": round(approval_rate, 2),
            "recent_lands": recent_lands,
            "total_transactions": total_transactions,
            "recent_transactions": recent_transactions,
            "total_commission": float(total_commission),
            "recent_commission": float(recent_commission),
            "agent_level": agent.agent_level,
            "join_date": agent.created_at.isoformat()
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@router.get("/district/{district_code}", response_model=List[AgentResponse])
async def get_agents_by_district(
    district_code: str,
    active_only: bool = True,
    min_level: int = 1,
    db: Session = Depends(get_db),
    current_agent=Depends(get_current_active_agent)
):
    """
    Get all agents in a specific district
    - District code should be 3 letters (e.g., "TRY" for Trichy)
    - Only accessible by admin or agents with level 3+
    """
    if current_agent.agent_level < 3 and current_agent.agent_level < 5:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent level 3+ required to view other agents"
        )
    
    if len(district_code) != 3:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="District code must be 3 characters"
        )
    
    try:
        agents = db.query(TPRAgent).filter(
            TPRAgent.tpra_id.like(f"TPRA-{district_code.upper()}%"),
            TPRAgent.agent_level >= min_level
        )
        
        if active_only:
            agents = agents.filter(TPRAgent.is_active == True)
        
        return [AgentService._map_to_response(agent) for agent in agents.all()]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


