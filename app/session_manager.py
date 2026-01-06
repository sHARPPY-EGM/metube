"""
Session Manager for managing per-session download queues.
Each user session gets its own DownloadQueue instance.
"""
import os
import asyncio
import logging
from ytdl import DownloadQueue, DownloadQueueNotifier
import socketio

log = logging.getLogger('session_manager')

class SessionManager:
    """Manages download queues per user session."""
    
    def __init__(self, config, sio):
        self.config = config
        self.sio = sio
        self.queues = {}  # session_id -> DownloadQueue
        self.notifiers = {}  # session_id -> Notifier
        
    def _get_session_id(self, request_or_sid):
        """Get or create session ID from request or Socket.IO sid."""
        if isinstance(request_or_sid, str):
            # Socket.IO sid
            return request_or_sid
        
        # HTTP request - get session ID from aiohttp_session
        try:
            import aiohttp_session
            import asyncio
            
            # For async context, we need to get the session
            # This is a bit tricky - we'll need to make this method async
            # For now, let's use a different approach
            session_id = getattr(request_or_sid, '_session_id', None)
            if session_id:
                return session_id
            
            # Generate a session ID based on the request
            # Use the session cookie if available, or create a new one
            session_cookie = request_or_sid.cookies.get('metube_session')
            if session_cookie:
                # Use cookie value as part of session ID
                import hashlib
                session_id = hashlib.sha256(session_cookie.value.encode()).hexdigest()[:16]
            else:
                # Fallback: use request remote
                session_id = f"http_{request_or_sid.remote}"
            
            # Store in request for future use
            request_or_sid._session_id = session_id
            return session_id
        except Exception as e:
            log.warning(f"Error getting session ID: {e}")
            # Fallback to request remote
            return f"http_{getattr(request_or_sid, 'remote', 'unknown')}"
    
    async def _get_session_id_async(self, request):
        """Async version to get session ID from HTTP request."""
        try:
            import aiohttp_session
            session = await aiohttp_session.get_session(request)
            session_id = session.get('download_session_id')
            if not session_id:
                # Generate new session ID
                import secrets
                session_id = secrets.token_urlsafe(16)
                session['download_session_id'] = session_id
            return session_id
        except Exception as e:
            log.warning(f"Error getting session ID: {e}")
            return f"http_{getattr(request, 'remote', 'unknown')}"
    
    def get_queue(self, session_id, serializer):
        """Get or create DownloadQueue for session."""
        if session_id not in self.queues:
            notifier = SessionNotifier(self.sio, session_id, serializer)
            queue = DownloadQueue(self.config, notifier, session_id)
            self.queues[session_id] = queue
            self.notifiers[session_id] = notifier
            # Initialize the queue
            asyncio.create_task(queue.initialize())
        return self.queues[session_id]
    
    async def get_queue_async(self, request_or_sid, serializer):
        """Get or create DownloadQueue for session (async version)."""
        if isinstance(request_or_sid, str):
            session_id = request_or_sid
        else:
            session_id = await self._get_session_id_async(request_or_sid)
        
        return self.get_queue(session_id, serializer)
    
    def remove_session(self, session_id):
        """Remove session and cleanup its queue."""
        if session_id in self.queues:
            # Note: We might want to cancel ongoing downloads first
            del self.queues[session_id]
            del self.notifiers[session_id]


class SessionNotifier(DownloadQueueNotifier):
    """Session-specific notifier that emits to specific Socket.IO session."""
    
    def __init__(self, sio, session_id, serializer):
        self.sio = sio
        self.session_id = session_id
        self.serializer = serializer
        self.room = f"session_{session_id}"
    
    async def added(self, dl):
        log.info(f"Session {self.session_id}: Download added - {dl.title}")
        await self.sio.emit('added', self.serializer.encode(dl), room=self.room)
        # Also emit to the specific session ID if it's a Socket.IO sid
        await self.sio.emit('added', self.serializer.encode(dl), to=self.session_id)
    
    async def updated(self, dl):
        log.debug(f"Session {self.session_id}: Download updated - {dl.title}")
        await self.sio.emit('updated', self.serializer.encode(dl), room=self.room)
        await self.sio.emit('updated', self.serializer.encode(dl), to=self.session_id)
    
    async def completed(self, dl):
        log.info(f"Session {self.session_id}: Download completed - {dl.title}")
        await self.sio.emit('completed', self.serializer.encode(dl), room=self.room)
        await self.sio.emit('completed', self.serializer.encode(dl), to=self.session_id)
    
    async def canceled(self, id):
        log.info(f"Session {self.session_id}: Download canceled - {id}")
        await self.sio.emit('canceled', self.serializer.encode(id), room=self.room)
        await self.sio.emit('canceled', self.serializer.encode(id), to=self.session_id)
    
    async def cleared(self, id):
        log.info(f"Session {self.session_id}: Download cleared - {id}")
        await self.sio.emit('cleared', self.serializer.encode(id), room=self.room)
        await self.sio.emit('cleared', self.serializer.encode(id), to=self.session_id)

