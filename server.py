from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

# JWT（アプリ内でcredentialを包む用）
# pip install "python-jose[cryptography]"
from jose import jwt
from jose.exceptions import JWTError


app = FastAPI(title="yt_micro_server", version="0.1.0")

# =========================
# 共通：レスポンス
# =========================


class ApiResponse(BaseModel):
    ok: bool = True
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def ok(data: Dict[str, Any]) -> ApiResponse:
    return ApiResponse(ok=True, data=data, error=None)


def ng(message: str, code: int = status.HTTP_400_BAD_REQUEST) -> None:
    raise HTTPException(status_code=code, detail=message)


# =========================
# 認証：Bearer必須（get_credential以外）
# =========================
bearer = HTTPBearer(auto_error=False)


class AuthContext(BaseModel):
    token: str
    # 必要ならここに user_id / scopes / roles 等を入れて拡張可能


def require_bearer_token(
    cred: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
) -> AuthContext:
    if cred is None or cred.scheme.lower() != "bearer" or not cred.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # ここでJWT検証などを行いたければ実装してください
    return AuthContext(token=cred.credentials)


# =========================
# リクエストモデル（任意のクラスに置換可）
# =========================
class GetCredentialRequest(BaseModel):
    # 例：クライアント識別や用途など（不要なら削除OK）
    client_id: Optional[str] = None


class VideoCreateRequest(BaseModel):
    filename: str
    content_type: str = Field(default="video/mp4")
    total_size: Optional[int] = None
    chunk_size: Optional[int] = None


class VideoGetRequest(BaseModel):
    video_id: str


class UploadChunkVideoRequest(BaseModel):
    video_id: str
    upload_session_id: str
    chunk_index: int
    total_chunks: int
    data_base64: str  # 実運用では signed URL 方式を推奨


class UploadChunkThumbnailRequest(BaseModel):
    video_id: str
    content_type: str = Field(default="image/jpeg")
    data_base64: str


class AttributeUpdateRequest(BaseModel):
    video_id: str
    title: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None


class PlaylistGetRequest(BaseModel):
    # 例：絞り込み条件
    include_items: bool = True


class PlaylistCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    video_ids: List[str] = Field(default_factory=list)


# =========================
# 疑似ストア（例）
# ※実運用ではDB/Redis/ObjectStorage等へ置換してください
# =========================
VIDEOS: Dict[str, Dict[str, Any]] = {}
PLAYLISTS: Dict[str, Dict[str, Any]] = {}
UPLOAD_SESSIONS: Dict[str, Dict[str, Any]] = {}


# =========================
# authorization/get_credential
# =========================
def _load_google_private_credential() -> Dict[str, Any]:
    """
    GoogleのサービスアカウントJSON相当を環境変数などから組み立てる例です。
    実運用では Secret Manager 等の利用を推奨します。
    """
    client_email = os.getenv("GOOGLE_CLIENT_EMAIL", "")
    private_key = os.getenv("GOOGLE_PRIVATE_KEY", "")
    token_uri = os.getenv("GOOGLE_TOKEN_URI",
                          "https://oauth2.googleapis.com/token")

    # .env等で \n が入っているケース対策
    private_key = private_key.replace("\\n", "\n")

    if not client_email or not private_key:
        ng("Google credential is not configured (env vars missing).",
           status.HTTP_500_INTERNAL_SERVER_ERROR)

    return {
        "type": "service_account",
        "client_email": client_email,
        "private_key": private_key,
        "token_uri": token_uri,
    }


def _wrap_credential_as_jwt(credential: Dict[str, Any]) -> str:
    """
    アプリ内JWTとしてcredentialを包む例です（HS256）。
    ※フロントへ private_key を渡すのは危険です。必要最小限の短命トークンにする設計を推奨します。
    """
    secret = os.getenv("APP_JWT_SECRET", "")
    if not secret:
        ng("APP_JWT_SECRET is not configured.",
           status.HTTP_500_INTERNAL_SERVER_ERROR)

    now = datetime.now(timezone.utc)
    payload = {
        "iss": "your-api",
        "aud": "your-client",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "cred": credential,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


@app.post("/authorization/get_credential", response_model=ApiResponse)
def authorization_get_credential(body: GetCredentialRequest) -> ApiResponse:
    cred = _load_google_private_credential()
    token = _wrap_credential_as_jwt(cred)
    return ok({"credential_jwt": token})


# =========================
# video/create
# =========================
@app.post("/video/create", response_model=ApiResponse)
def video_create(
    body: VideoCreateRequest,
    auth: AuthContext = Depends(require_bearer_token),
) -> ApiResponse:
    video_id = str(uuid.uuid4())
    upload_session_id = str(uuid.uuid4())

    VIDEOS[video_id] = {
        "video_id": video_id,
        "filename": body.filename,
        "content_type": body.content_type,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "owner_token_hint": auth.token[:8],  # 例（実運用では user_id など）
        "status": "created",
        "attributes": {"title": None, "description": None, "tags": []},
        "storage": {"video_object": None, "thumbnail_object": None},
    }

    UPLOAD_SESSIONS[upload_session_id] = {
        "upload_session_id": upload_session_id,
        "video_id": video_id,
        "received_chunks": set(),
        "total_chunks": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # 実運用では、ここで signed URL / chunk upload URL を返す設計が安全です
    return ok(
        {
            "video_id": video_id,
            "upload_session_id": upload_session_id,
            "recommended": {
                "use_signed_url": True,
                "note": "base64 chunk upload is just a placeholder in this sample.",
            },
        }
    )


# =========================
# video/get
# =========================
@app.post("/video/get", response_model=ApiResponse)
def video_get(
    body: VideoGetRequest,
    auth: AuthContext = Depends(require_bearer_token),
) -> ApiResponse:
    v = VIDEOS.get(body.video_id)
    if not v:
        ng("video not found", status.HTTP_404_NOT_FOUND)

    # 実運用：署名付きDL URLなどを返す
    return ok(
        {
            "video": {
                "video_id": v["video_id"],
                "filename": v["filename"],
                "content_type": v["content_type"],
                "status": v["status"],
                "attributes": v["attributes"],
                "download": {"url": None, "expires_in": None},
                "thumbnail": {"url": None, "expires_in": None},
            }
        }
    )


# =========================
# upload/chunk/video
# =========================
@app.post("/upload/chunk/video", response_model=ApiResponse)
def upload_chunk_video(
    body: UploadChunkVideoRequest,
    auth: AuthContext = Depends(require_bearer_token),
) -> ApiResponse:
    v = VIDEOS.get(body.video_id)
    if not v:
        ng("video not found", status.HTTP_404_NOT_FOUND)

    session = UPLOAD_SESSIONS.get(body.upload_session_id)
    if not session or session["video_id"] != body.video_id:
        ng("upload session not found", status.HTTP_404_NOT_FOUND)

    if body.chunk_index < 0 or body.chunk_index >= body.total_chunks:
        ng("invalid chunk index")

    # ここで body.data_base64 をデコードしてストレージに保存する想定
    # （サンプルなので保存は省略）
    session["received_chunks"].add(body.chunk_index)
    session["total_chunks"] = body.total_chunks

    done = len(session["received_chunks"]) == body.total_chunks
    if done:
        v["status"] = "uploaded"

    return ok(
        {
            "video_id": body.video_id,
            "upload_session_id": body.upload_session_id,
            "received": len(session["received_chunks"]),
            "total": body.total_chunks,
            "completed": done,
        }
    )


# =========================
# upload/chunk/thumbnail
# =========================
@app.post("/upload/chunk/thumbnail", response_model=ApiResponse)
def upload_chunk_thumbnail(
    body: UploadChunkThumbnailRequest,
    auth: AuthContext = Depends(require_bearer_token),
) -> ApiResponse:
    v = VIDEOS.get(body.video_id)
    if not v:
        ng("video not found", status.HTTP_404_NOT_FOUND)

    # ここで body.data_base64 をデコードして保存する想定（サンプルなので省略）
    v["storage"]["thumbnail_object"] = f"thumbnail/{body.video_id}"

    return ok({"video_id": body.video_id, "thumbnail_saved": True})


# =========================
# attribute/update
# =========================
@app.post("/attribute/update", response_model=ApiResponse)
def attribute_update(
    body: AttributeUpdateRequest,
    auth: AuthContext = Depends(require_bearer_token),
) -> ApiResponse:
    v = VIDEOS.get(body.video_id)
    if not v:
        ng("video not found", status.HTTP_404_NOT_FOUND)

    attr = v["attributes"]
    if body.title is not None:
        attr["title"] = body.title
    if body.description is not None:
        attr["description"] = body.description
    if body.tags is not None:
        attr["tags"] = body.tags

    return ok({"video_id": body.video_id, "attributes": attr})


# =========================
# playlist/get
# =========================
@app.post("/playlist/get", response_model=ApiResponse)
def playlist_get(
    body: PlaylistGetRequest,
    auth: AuthContext = Depends(require_bearer_token),
) -> ApiResponse:
    playlists = []
    for p in PLAYLISTS.values():
        if body.include_items:
            playlists.append(p)
        else:
            playlists.append(
                {k: p[k] for k in ["playlist_id", "name", "description", "created_at"]})
    return ok({"playlists": playlists})


# =========================
# playlist/create
# =========================
@app.post("/playlist/create", response_model=ApiResponse)
def playlist_create(
    body: PlaylistCreateRequest,
    auth: AuthContext = Depends(require_bearer_token),
) -> ApiResponse:
    playlist_id = str(uuid.uuid4())
    PLAYLISTS[playlist_id] = {
        "playlist_id": playlist_id,
        "name": body.name,
        "description": body.description,
        "video_ids": body.video_ids,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "owner_token_hint": auth.token[:8],
    }
    return ok({"playlist_id": playlist_id})
