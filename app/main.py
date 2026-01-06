#!/usr/bin/env python3
# pylint: disable=no-member,method-hidden

import os
import sys
import asyncio
from pathlib import Path
from aiohttp import web
from aiohttp.log import access_logger
import ssl
import socket
import socketio
import logging
import json
import pathlib
import re
from watchfiles import DefaultFilter, Change, awatch

from ytdl import DownloadQueueNotifier, DownloadQueue
from yt_dlp.version import __version__ as yt_dlp_version
from auth import AuthManager
from session_manager import SessionManager
import aiohttp_session
from aiohttp_session.cookie_storage import EncryptedCookieStorage
import secrets

log = logging.getLogger('main')

def parseLogLevel(logLevel):
    match logLevel:
        case 'DEBUG':
            return logging.DEBUG
        case 'INFO':
            return logging.INFO
        case 'WARNING':
            return logging.WARNING
        case 'ERROR':
            return logging.ERROR
        case 'CRITICAL':
            return logging.CRITICAL
        case _:
            return None

# Configure logging before Config() uses it so early messages are not dropped.
# Only configure if no handlers are set (avoid clobbering hosting app settings).
if not logging.getLogger().hasHandlers():
    logging.basicConfig(level=parseLogLevel(os.environ.get('LOGLEVEL', 'INFO')) or logging.INFO)

class Config:
    _DEFAULTS = {
        'DOWNLOAD_DIR': '.',
        'AUDIO_DOWNLOAD_DIR': '%%DOWNLOAD_DIR',
        'TEMP_DIR': '%%DOWNLOAD_DIR',
        'DOWNLOAD_DIRS_INDEXABLE': 'false',
        'CUSTOM_DIRS': 'true',
        'CREATE_CUSTOM_DIRS': 'true',
        'CUSTOM_DIRS_EXCLUDE_REGEX': r'(^|/)[.@].*$',
        'DELETE_FILE_ON_TRASHCAN': 'false',
        'STATE_DIR': '.',
        'URL_PREFIX': '',
        'PUBLIC_HOST_URL': 'download/',
        'PUBLIC_HOST_AUDIO_URL': 'audio_download/',
        'OUTPUT_TEMPLATE': '%(title)s.%(ext)s',
        'OUTPUT_TEMPLATE_CHAPTER': '%(title)s - %(section_number)s %(section_title)s.%(ext)s',
        'OUTPUT_TEMPLATE_PLAYLIST': '%(playlist_title)s/%(title)s.%(ext)s',
        'DEFAULT_OPTION_PLAYLIST_STRICT_MODE' : 'false',
        'DEFAULT_OPTION_PLAYLIST_ITEM_LIMIT' : '0',
        'YTDL_OPTIONS': '{}',
        'YTDL_OPTIONS_FILE': '',
        'ROBOTS_TXT': '',
        'HOST': '0.0.0.0',
        'PORT': '8081',
        'HTTPS': 'false',
        'CERTFILE': '',
        'KEYFILE': '',
        'BASE_DIR': '',
        'DEFAULT_THEME': 'auto',
        'DOWNLOAD_MODE': 'limited',
        'MAX_CONCURRENT_DOWNLOADS': 3,
        'LOGLEVEL': 'INFO',
        'ENABLE_ACCESSLOG': 'false',
    }

    _BOOLEAN = ('DOWNLOAD_DIRS_INDEXABLE', 'CUSTOM_DIRS', 'CREATE_CUSTOM_DIRS', 'DELETE_FILE_ON_TRASHCAN', 'DEFAULT_OPTION_PLAYLIST_STRICT_MODE', 'HTTPS', 'ENABLE_ACCESSLOG')

    def __init__(self):
        for k, v in self._DEFAULTS.items():
            setattr(self, k, os.environ.get(k, v))

        for k, v in self.__dict__.items():
            if isinstance(v, str) and v.startswith('%%'):
                setattr(self, k, getattr(self, v[2:]))
            if k in self._BOOLEAN:
                if v not in ('true', 'false', 'True', 'False', 'on', 'off', '1', '0'):
                    log.error(f'Environment variable "{k}" is set to a non-boolean value "{v}"')
                    sys.exit(1)
                setattr(self, k, v in ('true', 'True', 'on', '1'))

        if not self.URL_PREFIX.endswith('/'):
            self.URL_PREFIX += '/'

        # Convert relative addresses to absolute addresses to prevent the failure of file address comparison
        if self.YTDL_OPTIONS_FILE and self.YTDL_OPTIONS_FILE.startswith('.'):
            self.YTDL_OPTIONS_FILE = str(Path(self.YTDL_OPTIONS_FILE).resolve())

        success,_ = self.load_ytdl_options()
        if not success:
            sys.exit(1)

    def load_ytdl_options(self) -> tuple[bool, str]:
        try:
            self.YTDL_OPTIONS = json.loads(os.environ.get('YTDL_OPTIONS', '{}'))
            assert isinstance(self.YTDL_OPTIONS, dict)
        except (json.decoder.JSONDecodeError, AssertionError):
            msg = 'Environment variable YTDL_OPTIONS is invalid'
            log.error(msg)
            return (False, msg)

        if not self.YTDL_OPTIONS_FILE:
            return (True, '')

        log.info(f'Loading yt-dlp custom options from "{self.YTDL_OPTIONS_FILE}"')
        if not os.path.exists(self.YTDL_OPTIONS_FILE):
            msg = f'File "{self.YTDL_OPTIONS_FILE}" not found'
            log.error(msg)
            return (False, msg)
        try:
            with open(self.YTDL_OPTIONS_FILE) as json_data:
                opts = json.load(json_data)
            assert isinstance(opts, dict)
        except (json.decoder.JSONDecodeError, AssertionError):
            msg = 'YTDL_OPTIONS_FILE contents is invalid'
            log.error(msg)
            return (False, msg)

        self.YTDL_OPTIONS.update(opts)
        return (True, '')

config = Config()
# Align root logger level with Config (keeps a single source of truth).
# This re-applies the log level after Config loads, in case LOGLEVEL was
# overridden by config file settings or differs from the environment variable.
logging.getLogger().setLevel(parseLogLevel(str(config.LOGLEVEL)) or logging.INFO)

class ObjectSerializer(json.JSONEncoder):
    def default(self, obj):
        # First try to use __dict__ for custom objects
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        # Convert iterables (generators, dict_items, etc.) to lists
        # Exclude strings and bytes which are also iterable
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            try:
                return list(obj)
            except:
                pass
        # Fall back to default behavior
        return json.JSONEncoder.default(self, obj)

serializer = ObjectSerializer()

# Initialize authentication manager
auth_manager = AuthManager(config.STATE_DIR)

# Generate secret key for session encryption (persist it)
session_key_file = os.path.join(config.STATE_DIR, '.session_key')
if os.path.exists(session_key_file):
    with open(session_key_file, 'rb') as f:
        session_key = f.read()
else:
    session_key = secrets.token_bytes(32)
    Path(config.STATE_DIR).mkdir(parents=True, exist_ok=True)
    with open(session_key_file, 'wb') as f:
        f.write(session_key)
    try:
        os.chmod(session_key_file, 0o600)
    except Exception:
        pass

app = web.Application()
# Add session middleware
aiohttp_session.setup(app, EncryptedCookieStorage(session_key, cookie_name='metube_session', 
                                                   max_age=60*60,  # 1 hour
                                                   httponly=True,
                                                   samesite='Strict',
                                                   secure=config.HTTPS))

sio = socketio.AsyncServer(cors_allowed_origins='*')
sio.attach(app, socketio_path=config.URL_PREFIX + 'socket.io')
routes = web.RouteTableDef()

# Authentication middleware
@web.middleware
async def auth_middleware(request, handler):
    """Middleware to handle authentication and route protection."""
    path = request.path
    url_prefix = config.URL_PREFIX.rstrip('/')
    
    # Remove URL prefix from path for checking
    if path.startswith(url_prefix):
        path = path[len(url_prefix):]
    if not path.startswith('/'):
        path = '/' + path
    
    # Public routes that don't require authentication
    public_routes = [
        '/api/setup',
        '/api/login',
        '/api/admin/login',
        '/api/setup/status',
        '/api/auth/status',
        '/api/maintenance',
        '/socket.io/',
        '/version',
        '/robots.txt'
    ]
    
    # Check if route is public
    is_public = any(path.startswith(route) for route in public_routes)
    
    # Static files (download, audio_download, UI assets, and static file extensions)
    # Check if it's a static file by extension (JS, CSS, images, fonts, etc.)
    static_extensions = ('.js', '.css', '.ico', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.json', '.webmanifest', '.map')
    is_static_file = any(path.lower().endswith(ext) for ext in static_extensions)
    is_static = path.startswith('/download/') or path.startswith('/audio_download/') or path.startswith('/assets/') or is_static_file
    
    # Setup/login pages
    is_auth_page = path in ['/setup', '/login', '/admin', '/wartungsmodus'] or path == '/'
    
    # If setup is not complete, allow only setup route
    if not auth_manager.is_setup_complete():
        if path != '/setup' and not path.startswith('/api/setup') and not is_public and not is_static:
            if request.headers.get('Accept', '').startswith('application/json'):
                return web.json_response({'error': 'Setup required'}, status=403)
            # Redirect to setup page for HTML requests
            return web.HTTPFound(config.URL_PREFIX.rstrip('/') + '/setup')
    
    # Check maintenance mode (but allow admin access)
    if auth_manager.is_setup_complete():
        session = await aiohttp_session.get_session(request)
        is_admin_authenticated = session.get('admin_authenticated', False)
        
        # If maintenance mode is active
        if auth_manager.is_maintenance_mode() and not is_public and not is_static:
            # Allow admin to access /admin even during maintenance
            if path == '/admin' or path.startswith('/api/admin'):
                # Admin can always access admin panel during maintenance
                return await handler(request)
            # Allow access to maintenance page itself
            elif path == '/wartungsmodus':
                # Allow access to maintenance page
                return await handler(request)
            else:
                # Redirect all other requests to maintenance page
                if request.headers.get('Accept', '').startswith('application/json'):
                    return web.json_response({'error': 'Maintenance mode active'}, status=503)
                return web.HTTPFound(config.URL_PREFIX.rstrip('/') + '/wartungsmodus')
    
    # If setup is complete but password is required
    if auth_manager.is_setup_complete() and auth_manager.is_password_required() and not is_public and not is_static:
        session = await aiohttp_session.get_session(request)
        
        # Allow admin and maintenance page even without site password
        if path == '/admin' or path == '/wartungsmodus' or path.startswith('/api/admin'):
            # Admin and maintenance pages don't require site password
            return await handler(request)
        # Check if user is authenticated
        if not session.get('authenticated', False):
            # Allow access to login page
            if path == '/login':
                return await handler(request)
            
            # Allow access to other auth pages (setup)
            if is_auth_page:
                # Redirect main page to login
                if path == '/' or path == '':
                    return web.HTTPFound(config.URL_PREFIX.rstrip('/') + '/login')
                # Allow access to other auth pages
                return await handler(request)
            
            # For API requests, return 401
            if request.headers.get('Accept', '').startswith('application/json'):
                return web.json_response({'error': 'Authentication required'}, status=401)
            
            # For page requests, redirect to login
            return web.HTTPFound(config.URL_PREFIX.rstrip('/') + '/login')
    
    return await handler(request)

app.middlewares.append(auth_middleware)

class Notifier(DownloadQueueNotifier):
    async def added(self, dl):
        log.info(f"Notifier: Download added - {dl.title}")
        await sio.emit('added', serializer.encode(dl))

    async def updated(self, dl):
        log.debug(f"Notifier: Download updated - {dl.title}")
        await sio.emit('updated', serializer.encode(dl))

    async def completed(self, dl):
        log.info(f"Notifier: Download completed - {dl.title}")
        await sio.emit('completed', serializer.encode(dl))

    async def canceled(self, id):
        log.info(f"Notifier: Download canceled - {id}")
        await sio.emit('canceled', serializer.encode(id))

    async def cleared(self, id):
        log.info(f"Notifier: Download cleared - {id}")
        await sio.emit('cleared', serializer.encode(id))

# Initialize session manager for per-session download queues
session_manager = SessionManager(config, sio)

# Legacy global queue for backwards compatibility during migration
# Will be removed once all endpoints use session_manager
dqueue = DownloadQueue(config, Notifier())
app.on_startup.append(lambda app: dqueue.initialize())

class FileOpsFilter(DefaultFilter):
    def __call__(self, change_type: int, path: str) -> bool:
        # Check if this path matches our YTDL_OPTIONS_FILE
        if path != config.YTDL_OPTIONS_FILE:
            return False

        # For existing files, use samefile comparison to handle symlinks correctly
        if os.path.exists(config.YTDL_OPTIONS_FILE):
            try:
                if not os.path.samefile(path, config.YTDL_OPTIONS_FILE):
                    return False
            except (OSError, IOError):
                # If samefile fails, fall back to string comparison
                if path != config.YTDL_OPTIONS_FILE:
                    return False

        # Accept all change types for our file: modified, added, deleted
        return change_type in (Change.modified, Change.added, Change.deleted)

def get_options_update_time(success=True, msg=''):
    result = {
        'success': success,
        'msg': msg,
        'update_time': None
    }

    # Only try to get file modification time if YTDL_OPTIONS_FILE is set and file exists
    if config.YTDL_OPTIONS_FILE and os.path.exists(config.YTDL_OPTIONS_FILE):
        try:
            result['update_time'] = os.path.getmtime(config.YTDL_OPTIONS_FILE)
        except (OSError, IOError) as e:
            log.warning(f"Could not get modification time for {config.YTDL_OPTIONS_FILE}: {e}")
            result['update_time'] = None

    return result

async def watch_files():
    async def _watch_files():
        async for changes in awatch(config.YTDL_OPTIONS_FILE, watch_filter=FileOpsFilter()):
            success, msg = config.load_ytdl_options()
            result = get_options_update_time(success, msg)
            await sio.emit('ytdl_options_changed', serializer.encode(result))

    log.info(f'Starting Watch File: {config.YTDL_OPTIONS_FILE}')
    asyncio.create_task(_watch_files())

if config.YTDL_OPTIONS_FILE:
    app.on_startup.append(lambda app: watch_files())

@routes.post(config.URL_PREFIX + 'add')
async def add(request):
    log.info("Received request to add download")
    post = await request.json()
    log.info(f"Request data: {post}")
    url = post.get('url')
    quality = post.get('quality')
    if not url or not quality:
        log.error("Bad request: missing 'url' or 'quality'")
        raise web.HTTPBadRequest()
    format = post.get('format')
    folder = post.get('folder')
    custom_name_prefix = post.get('custom_name_prefix')
    playlist_strict_mode = post.get('playlist_strict_mode')
    playlist_item_limit = post.get('playlist_item_limit')
    auto_start = post.get('auto_start')
    download_subtitles = post.get('download_subtitles', False)
    download_thumbnails = post.get('download_thumbnails', True)

    if custom_name_prefix is None:
        custom_name_prefix = ''
    if auto_start is None:
        auto_start = True
    if playlist_strict_mode is None:
        playlist_strict_mode = config.DEFAULT_OPTION_PLAYLIST_STRICT_MODE
    if playlist_item_limit is None:
        playlist_item_limit = config.DEFAULT_OPTION_PLAYLIST_ITEM_LIMIT

    playlist_item_limit = int(playlist_item_limit)
    
    # Get session-specific queue
    dqueue_session = await session_manager.get_queue_async(request, serializer)
    status = await dqueue_session.add(url, quality, format, folder, custom_name_prefix, playlist_strict_mode, playlist_item_limit, auto_start, download_subtitles, download_thumbnails)
    return web.Response(text=serializer.encode(status))

@routes.post(config.URL_PREFIX + 'delete')
async def delete(request):
    post = await request.json()
    ids = post.get('ids')
    where = post.get('where')
    if not ids or where not in ['queue', 'done']:
        log.error("Bad request: missing 'ids' or incorrect 'where' value")
        raise web.HTTPBadRequest()
    
    # Get session-specific queue
    dqueue_session = await session_manager.get_queue_async(request, serializer)
    status = await (dqueue_session.cancel(ids) if where == 'queue' else dqueue_session.clear(ids))
    log.info(f"Download delete request processed for ids: {ids}, where: {where}")
    return web.Response(text=serializer.encode(status))

@routes.post(config.URL_PREFIX + 'start')
async def start(request):
    post = await request.json()
    ids = post.get('ids')
    log.info(f"Received request to start pending downloads for ids: {ids}")
    
    # Get session-specific queue
    dqueue_session = await session_manager.get_queue_async(request, serializer)
    status = await dqueue_session.start_pending(ids)
    return web.Response(text=serializer.encode(status))

@routes.post(config.URL_PREFIX + 'cancel_all')
async def cancel_all(request):
    log.info("Received request to cancel all downloads")
    
    # Get session-specific queue
    dqueue_session = await session_manager.get_queue_async(request, serializer)
    status = await dqueue_session.cancel_all()
    return web.Response(text=serializer.encode(status))

@routes.get(config.URL_PREFIX + 'history')
async def history(request):
    # Get session-specific queue
    dqueue_session = await session_manager.get_queue_async(request, serializer)
    
    history = { 'done': [], 'queue': [], 'pending': []}

    for _, v in dqueue_session.queue.saved_items():
        history['queue'].append(v)
    for _, v in dqueue_session.done.saved_items():
        history['done'].append(v)
    for _, v in dqueue_session.pending.saved_items():
        history['pending'].append(v)

    log.info("Sending download history")
    return web.Response(text=serializer.encode(history))

@sio.event
async def connect(sid, environ):
    log.info(f"Client connected: {sid}")
    
    # Try to get session ID from HTTP session cookie in the Socket.IO handshake
    # Socket.IO handshake includes cookies in environ
    session_id = sid  # Use Socket.IO sid as session ID for now
    
    # Try to extract HTTP session ID from cookies
    try:
        cookies = environ.get('HTTP_COOKIE', '')
        if 'metube_session=' in cookies:
            # We need to get the actual session - but we can't easily do that here
            # So we'll use a mapping approach
            pass
    except:
        pass
    
    # Get session-specific queue for Socket.IO connection
    # Use sid as session_id for Socket.IO connections
    dqueue_session = await session_manager.get_queue_async(sid, serializer)
    
    # Join the session room
    await sio.enter_room(sid, f"session_{sid}")
    
    await sio.emit('all', serializer.encode(dqueue_session.get()), to=sid)
    await sio.emit('configuration', serializer.encode(config), to=sid)
    if config.CUSTOM_DIRS:
        await sio.emit('custom_dirs', serializer.encode(get_custom_dirs()), to=sid)
    if config.YTDL_OPTIONS_FILE:
        await sio.emit('ytdl_options_changed', serializer.encode(get_options_update_time()), to=sid)

def get_custom_dirs():
    def recursive_dirs(base):
        path = pathlib.Path(base)

        # Converts PosixPath object to string, and remove base/ prefix
        def convert(p):
            s = str(p)
            if s.startswith(base):
                s = s[len(base):]

            if s.startswith('/'):
                s = s[1:]

            return s

        # Include only directories which do not match the exclude filter
        def include_dir(d):
            if len(config.CUSTOM_DIRS_EXCLUDE_REGEX) == 0:
                return True
            else:
                return re.search(config.CUSTOM_DIRS_EXCLUDE_REGEX, d) is None

        # Recursively lists all subdirectories of DOWNLOAD_DIR
        dirs = list(filter(include_dir, map(convert, path.glob('**/'))))

        return dirs

    download_dir = recursive_dirs(config.DOWNLOAD_DIR)

    audio_download_dir = download_dir
    if config.DOWNLOAD_DIR != config.AUDIO_DOWNLOAD_DIR:
        audio_download_dir = recursive_dirs(config.AUDIO_DOWNLOAD_DIR)

    return {
        "download_dir": download_dir,
        "audio_download_dir": audio_download_dir
    }

@routes.get(config.URL_PREFIX)
async def index(request):
    # Check if setup is needed
    if not auth_manager.is_setup_complete():
        return web.HTTPFound(config.URL_PREFIX.rstrip('/') + '/setup')
    
    # Check if password is required and user is not authenticated
    session = await aiohttp_session.get_session(request)
    if auth_manager.is_password_required() and not session.get('authenticated', False):
        return web.HTTPFound(config.URL_PREFIX.rstrip('/') + '/login')
    
    response = web.FileResponse(os.path.join(config.BASE_DIR, 'ui/dist/metube/browser/index.html'))
    if 'metube_theme' not in request.cookies:
        response.set_cookie('metube_theme', config.DEFAULT_THEME)
    return response

# API Routes for authentication
@routes.get(config.URL_PREFIX + 'api/setup/status')
async def setup_status(request):
    """Check if setup is needed."""
    return web.json_response({
        'setup_needed': not auth_manager.is_setup_complete()
    })

@routes.get(config.URL_PREFIX + 'api/auth/status')
async def auth_status(request):
    """Get authentication status."""
    session = await aiohttp_session.get_session(request)
    return web.json_response({
        'setup_needed': not auth_manager.is_setup_complete(),
        'password_required': auth_manager.is_password_required(),
        'authenticated': session.get('authenticated', False),
        'has_site_password': auth_manager.has_site_password()
    })

@routes.post(config.URL_PREFIX + 'api/setup')
async def api_setup(request):
    """Create initial admin account."""
    if auth_manager.is_setup_complete():
        return web.json_response({'status': 'error', 'error': 'Setup already complete'}, status=400)
    
    try:
        post = await request.json()
        username = post.get('username', '').strip()
        password = post.get('password', '')
        
        if not username or not password:
            return web.json_response({'status': 'error', 'error': 'Username and password required'}, status=400)
        
        if len(password) < 8:
            return web.json_response({'status': 'error', 'error': 'Password must be at least 8 characters'}, status=400)
        
        if auth_manager.create_admin(username, password):
            # Mark session as authenticated after setup
            session = await aiohttp_session.get_session(request)
            session['authenticated'] = True
            session['admin_authenticated'] = True
            return web.json_response({'status': 'ok'})
        else:
            return web.json_response({'status': 'error', 'error': 'Failed to create admin account'}, status=400)
    except Exception as e:
        log.error(f'Setup error: {e}')
        return web.json_response({'status': 'error', 'error': str(e)}, status=500)

@routes.post(config.URL_PREFIX + 'api/login')
async def api_login(request):
    """Login with site password."""
    if not auth_manager.is_setup_complete():
        return web.json_response({'status': 'error', 'error': 'Setup required'}, status=403)
    
    try:
        post = await request.json()
        password = post.get('password', '')
        
        if auth_manager.verify_site_password(password):
            session = await aiohttp_session.get_session(request)
            session['authenticated'] = True
            return web.json_response({'status': 'ok'})
        else:
            return web.json_response({'status': 'error', 'error': 'Invalid password'}, status=401)
    except Exception as e:
        log.error(f'Login error: {e}')
        return web.json_response({'status': 'error', 'error': str(e)}, status=500)

@routes.post(config.URL_PREFIX + 'api/admin/login')
async def api_admin_login(request):
    """Login as admin."""
    if not auth_manager.is_setup_complete():
        return web.json_response({'status': 'error', 'error': 'Setup required'}, status=403)
    
    try:
        post = await request.json()
        username = post.get('username', '').strip()
        password = post.get('password', '')
        
        if auth_manager.verify_admin(username, password):
            session = await aiohttp_session.get_session(request)
            session['admin_authenticated'] = True
            return web.json_response({'status': 'ok'})
        else:
            return web.json_response({'status': 'error', 'error': 'Invalid credentials'}, status=401)
    except Exception as e:
        log.error(f'Admin login error: {e}')
        return web.json_response({'status': 'error', 'error': str(e)}, status=500)

@routes.post(config.URL_PREFIX + 'api/admin/logout')
async def api_admin_logout(request):
    """Logout admin."""
    session = await aiohttp_session.get_session(request)
    session['admin_authenticated'] = False
    return web.json_response({'status': 'ok'})

@routes.get(config.URL_PREFIX + 'api/admin/status')
async def api_admin_status(request):
    """Get admin authentication status."""
    session = await aiohttp_session.get_session(request)
    return web.json_response({
        'authenticated': session.get('admin_authenticated', False)
    })

@routes.get(config.URL_PREFIX + 'api/maintenance')
async def api_maintenance_info(request):
    """Get maintenance mode information (public endpoint)."""
    return web.json_response({
        'maintenance_mode': auth_manager.is_maintenance_mode(),
        'maintenance_until': auth_manager.get_maintenance_until()
    })

@routes.get(config.URL_PREFIX + 'api/admin/settings')
async def api_admin_get_settings(request):
    """Get admin settings."""
    session = await aiohttp_session.get_session(request)
    if not session.get('admin_authenticated', False):
        return web.json_response({'error': 'Unauthorized'}, status=401)
    
    return web.json_response({
        'password_required': auth_manager.is_password_required(),
        'has_site_password': auth_manager.has_site_password(),
        'maintenance_mode': auth_manager.is_maintenance_mode(),
        'maintenance_until': auth_manager.get_maintenance_until()
    })

@routes.post(config.URL_PREFIX + 'api/admin/settings')
async def api_admin_update_settings(request):
    """Update admin settings."""
    session = await aiohttp_session.get_session(request)
    if not session.get('admin_authenticated', False):
        return web.json_response({'status': 'error', 'error': 'Unauthorized'}, status=401)
    
    try:
        post = await request.json()
        
        # Update site password
        if 'site_password' in post:
            site_password = post['site_password']
            if site_password:
                if not auth_manager.set_site_password(site_password):
                    return web.json_response({'status': 'error', 'error': 'Invalid password'}, status=400)
            else:
                auth_manager.set_site_password('')  # Clear password
        
        # Update password requirement
        if 'password_required' in post:
            auth_manager.set_password_required(bool(post['password_required']))
        
        # Change admin password
        if 'admin_password' in post:
            admin_password_data = post['admin_password']
            if isinstance(admin_password_data, dict) and 'old' in admin_password_data and 'new' in admin_password_data:
                # For simplicity, we'll just verify the old password matches the current one
                # and update to the new one
                old_password = admin_password_data['old']
                new_password = admin_password_data['new']
                
                # Change admin password using the method
                if not auth_manager.change_admin_password(old_password, new_password):
                    return web.json_response({'status': 'error', 'error': 'Failed to change password'}, status=400)
        
        # Update maintenance mode
        if 'maintenance_mode' in post:
            maintenance_mode = bool(post['maintenance_mode'])
            maintenance_until = post.get('maintenance_until')  # ISO timestamp string or None
            auth_manager.set_maintenance_mode(maintenance_mode, maintenance_until)
        
        return web.json_response({'status': 'ok'})
    except Exception as e:
        log.error(f'Admin settings update error: {e}')
        return web.json_response({'status': 'error', 'error': str(e)}, status=500)

@routes.get(config.URL_PREFIX + 'setup')
async def setup_page(request):
    """Setup page for initial admin account creation."""
    # Check if this is a request for a static file (e.g., /setup/main.js should be /main.js)
    path = request.path
    url_prefix = config.URL_PREFIX.rstrip('/')
    if path.startswith(url_prefix):
        path = path[len(url_prefix):]
    if not path.startswith('/'):
        path = '/' + path
    
    # If it's not exactly /setup, check if it's a static file request
    # For paths like /setup/main.js, try to serve /main.js instead
    if path != '/setup' and path.startswith('/setup/'):
        # Remove /setup/ prefix and try to serve the file from root
        file_path = path[len('/setup'):]
        static_file_path = os.path.join(config.BASE_DIR, 'ui/dist/metube/browser', file_path.lstrip('/'))
        if os.path.isfile(static_file_path):
            return web.FileResponse(static_file_path)
        raise web.HTTPNotFound()
    
    if auth_manager.is_setup_complete():
        return web.HTTPFound(config.URL_PREFIX.rstrip('/') + '/')
    return web.FileResponse(os.path.join(config.BASE_DIR, 'ui/dist/metube/browser/index.html'))

@routes.get(config.URL_PREFIX + 'login')
async def login_page(request):
    """Login page for site password."""
    path = request.path
    url_prefix = config.URL_PREFIX.rstrip('/')
    if path.startswith(url_prefix):
        path = path[len(url_prefix):]
    if not path.startswith('/'):
        path = '/' + path
    
    # If it's not exactly /login, check if it's a static file request
    if path != '/login' and path.startswith('/login/'):
        file_path = path[len('/login'):]
        static_file_path = os.path.join(config.BASE_DIR, 'ui/dist/metube/browser', file_path.lstrip('/'))
        if os.path.isfile(static_file_path):
            return web.FileResponse(static_file_path)
        raise web.HTTPNotFound()
    
    if not auth_manager.is_setup_complete():
        return web.HTTPFound(config.URL_PREFIX.rstrip('/') + '/setup')
    
    if not auth_manager.is_password_required():
        return web.HTTPFound(config.URL_PREFIX.rstrip('/') + '/')
    
    session = await aiohttp_session.get_session(request)
    if session.get('authenticated', False):
        return web.HTTPFound(config.URL_PREFIX.rstrip('/') + '/')
    
    return web.FileResponse(os.path.join(config.BASE_DIR, 'ui/dist/metube/browser/index.html'))

@routes.get(config.URL_PREFIX + 'admin')
async def admin_page(request):
    """Admin panel page."""
    path = request.path
    url_prefix = config.URL_PREFIX.rstrip('/')
    if path.startswith(url_prefix):
        path = path[len(url_prefix):]
    if not path.startswith('/'):
        path = '/' + path
    
    # If it's not exactly /admin, check if it's a static file request
    if path != '/admin' and path.startswith('/admin/'):
        file_path = path[len('/admin'):]
        static_file_path = os.path.join(config.BASE_DIR, 'ui/dist/metube/browser', file_path.lstrip('/'))
        if os.path.isfile(static_file_path):
            return web.FileResponse(static_file_path)
        raise web.HTTPNotFound()
    
    # Return the main HTML file for /admin route
    return web.FileResponse(os.path.join(config.BASE_DIR, 'ui/dist/metube/browser/index.html'))

@routes.get(config.URL_PREFIX + 'wartungsmodus')
async def maintenance_page(request):
    """Maintenance mode page."""
    path = request.path
    url_prefix = config.URL_PREFIX.rstrip('/')
    if path.startswith(url_prefix):
        path = path[len(url_prefix):]
    if not path.startswith('/'):
        path = '/' + path
    
    # If it's not exactly /wartungsmodus, check if it's a static file request
    if path != '/wartungsmodus' and path.startswith('/wartungsmodus/'):
        file_path = path[len('/wartungsmodus'):]
        static_file_path = os.path.join(config.BASE_DIR, 'ui/dist/metube/browser', file_path.lstrip('/'))
        if os.path.isfile(static_file_path):
            return web.FileResponse(static_file_path)
        raise web.HTTPNotFound()
    
    return web.FileResponse(os.path.join(config.BASE_DIR, 'ui/dist/metube/browser/index.html'))
    
    if not auth_manager.is_setup_complete():
        return web.HTTPFound(config.URL_PREFIX.rstrip('/') + '/setup')
    
    return web.FileResponse(os.path.join(config.BASE_DIR, 'ui/dist/metube/browser/index.html'))

@routes.get(config.URL_PREFIX + 'robots.txt')
def robots(request):
    if config.ROBOTS_TXT:
        response = web.FileResponse(os.path.join(config.BASE_DIR, config.ROBOTS_TXT))
    else:
        response = web.Response(
            text="User-agent: *\nDisallow: /download/\nDisallow: /audio_download/\n"
        )
    return response

@routes.get(config.URL_PREFIX + 'version')
def version(request):
    return web.json_response({
        "yt-dlp": yt_dlp_version,
        "version": os.getenv("METUBE_VERSION", "dev")
    })

if config.URL_PREFIX != '/':
    @routes.get('/')
    def index_redirect_root(request):
        return web.HTTPFound(config.URL_PREFIX)

    @routes.get(config.URL_PREFIX[:-1])
    def index_redirect_dir(request):
        return web.HTTPFound(config.URL_PREFIX)

routes.static(config.URL_PREFIX + 'download/', config.DOWNLOAD_DIR, show_index=config.DOWNLOAD_DIRS_INDEXABLE)
routes.static(config.URL_PREFIX + 'audio_download/', config.AUDIO_DOWNLOAD_DIR, show_index=config.DOWNLOAD_DIRS_INDEXABLE)
routes.static(config.URL_PREFIX, os.path.join(config.BASE_DIR, 'ui/dist/metube/browser'))
try:
    app.add_routes(routes)
except ValueError as e:
    if 'ui/dist/metube/browser' in str(e):
        raise RuntimeError('Could not find the frontend UI static assets. Please run `node_modules/.bin/ng build` inside the ui folder') from e
    raise e

# https://github.com/aio-libs/aiohttp/pull/4615 waiting for release
# @routes.options(config.URL_PREFIX + 'add')
async def add_cors(request):
    return web.Response(text=serializer.encode({"status": "ok"}))

app.router.add_route('OPTIONS', config.URL_PREFIX + 'add', add_cors)

async def on_prepare(request, response):
    if 'Origin' in request.headers:
        response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'

app.on_response_prepare.append(on_prepare)
 
def supports_reuse_port():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.close()
        return True
    except (AttributeError, OSError):
        return False

def isAccessLogEnabled():
    if config.ENABLE_ACCESSLOG:
        return access_logger
    else:
        return None

if __name__ == '__main__':
    logging.getLogger().setLevel(parseLogLevel(config.LOGLEVEL) or logging.INFO)
    log.info(f"Listening on {config.HOST}:{config.PORT}")

    if config.HTTPS:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=config.CERTFILE, keyfile=config.KEYFILE)
        web.run_app(app, host=config.HOST, port=int(config.PORT), reuse_port=supports_reuse_port(), ssl_context=ssl_context, access_log=isAccessLogEnabled())
    else:
        web.run_app(app, host=config.HOST, port=int(config.PORT), reuse_port=supports_reuse_port(), access_log=isAccessLogEnabled())
