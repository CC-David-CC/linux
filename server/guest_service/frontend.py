"""Explicit controlled frontend; no legacy fallback when configured inputs fail."""
from pathlib import Path
from aiohttp import web
from .coordinator import GuestCoordinator
from .runtime import validate,metadata

class ControlledFrontend:
    def __init__(self,legacy,descriptor,secrets):
        policy=validate(descriptor)
        if legacy.origin!=descriptor['origin'] or legacy.base_path!=descriptor['basePath'] or set(secrets)!={'anonymous','registered'}:raise ValueError('Frontend descriptor/credential context changed')
        self.legacy=legacy;self.descriptor=descriptor;self.policy=policy
        endpoints={role:{'socket':path,'secret':secrets[role]} for role,path in descriptor['workerSockets'].items()}
        self.coordinator=GuestCoordinator(legacy.origin,policy,endpoints,legacy.secret,base_path=legacy.base_path)
    async def assets(self,request):
        raw=request.match_info['path'] or 'index.html'
        if raw=='guest-access/client.mjs':
            file=Path(__file__).resolve().parent/'client.mjs'
            if file.is_symlink() or not file.is_file():raise web.HTTPServiceUnavailable()
            response=web.FileResponse(file);response.content_type='text/javascript';response.headers['Cache-Control']='no-store';return response
        if raw=='config.json':
            config=await self.legacy.configuration();expected=metadata(self.legacy.base_path,self.descriptor['policySHA256'])
            if config.get('identity')!=self.descriptor['issuerPolicy'] or config.get('guestNetwork')!=expected:raise web.HTTPBadGateway(text='Configured guest identity/policy unavailable')
            config['guestNetwork']={**self.legacy.network_metadata(),**expected,'durableAccountLimits':True,'previewPolicy':{'version':'account-bound-preview/1',**self.policy.effective_value()}}
            return web.json_response(config,headers={'Cache-Control':'no-store'})
        return await self.legacy.assets(request)
    async def relay(self,request):return await self.coordinator.relay(request)
