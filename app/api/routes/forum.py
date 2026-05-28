from fastapi import APIRouter

router = APIRouter(prefix="/forum", tags=["forum"])

@router.get("")
def get_forum():
    return {
        "message": "forum endpoint"
    }