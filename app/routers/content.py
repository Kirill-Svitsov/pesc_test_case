from fastapi import APIRouter, Depends
from app.dependencies import get_current_user, require_role
from app.models import User

router = APIRouter(prefix="/content", tags=["content"])


@router.get("/common")
async def get_common_content(current_user: User = Depends(get_current_user)):
    return {
        "message": "Common content for all authenticated users",
        "user": current_user.username,
        "role": current_user.role,
        "data": {"info": "This is public content for everyone"},
    }


@router.get("/user")
async def get_user_content(current_user: User = Depends(require_role("user"))):
    return {
        "message": "User-specific content",
        "role": "user",
        "data": {
            "dashboard": "/user/dashboard",
            "profile_settings": "/settings",
            "user_stats": {"posts": 0, "comments": 0},
        },
    }


@router.get("/admin")
async def get_admin_content(current_user: User = Depends(require_role("admin"))):
    return {
        "message": "Admin-specific content",
        "role": "admin",
        "data": {
            "admin_panel": "/admin/dashboard",
            "user_management": "/admin/users",
            "system_logs": "/admin/logs",
            "statistics": {"total_users": 0, "active_sessions": 0},
        },
    }


@router.get("/mixed")
async def get_mixed_content(current_user: User = Depends(get_current_user)):
    """Гибридный контент — разный в зависимости от роли"""
    base = {
        "message": "Role-based dynamic content",
        "user": current_user.username,
        "role": current_user.role,
    }

    if current_user.role == "admin":
        base["admin_section"] = {
            "metrics": {"cpu": 45, "memory": 62},
            "pending_approvals": 3,
        }
    else:
        base["user_section"] = {
            "recent_activity": "Last login: today",
            "preferences": "Theme: system",
        }

    return base
