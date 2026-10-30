"""Optional live-session authority for guest wires; separate from file grants."""
import secrets
from urllib.parse import urlsplit
from codiauth import jose
from codiauth.service import Failure
from guest_service.authorization import AUTHORIZE,CHALLENGE,GRANT_TYPE,LIFETIME,context,policy_hash,token

class GuestAuthority:
    def __init__(self,issuer,egress_sha256,application=None):
        self.issuer=issuer;self.application=issuer if application is None else application
        self.policy_sha256=policy_hash(egress_sha256)
        self.audience,_=context(issuer.c.origin,issuer.base_path)

    def challenge(self,data):
        issuer=self.issuer
        if not isinstance(data,dict) or set(data)!={'key','path'} or data['path']!=issuer.base_path+AUTHORIZE:
            raise Failure(400,'Invalid guest-network authorization challenge')
        key=jose.public_jwk(jose.load_public(data['key']))
        with issuer.lock:
            issuer.cleanup()
            if len(issuer.challenges)>=issuer.c.max_challenges:raise Failure(429,'Challenge capacity reached')
            nonce=secrets.token_urlsafe(32)
            issuer.challenges[nonce]={'key':key,'path':data['path'],'expires':issuer.now()+60}
        return {'nonce':nonce,'expires_at':issuer.now()+60}

    def authorize(self,data,key,proof,authorization):
        if not isinstance(data,dict) or set(data)!={'nonce','connection_id','policy_sha256'}:
            raise Failure(400,'Exact guest wire authorization context required')
        token(data['nonce']);token(data['connection_id'])
        if policy_hash(data['policy_sha256'])!=self.policy_sha256:raise Failure(403,'Guest egress policy changed')
        issuer=self.issuer
        with issuer.lock:
            checked=issuer.continue_session({},key,proof,'/api/v1/renew',authorization)
            identity=checked['identity'];session=issuer.sessions[jose.digest(authorization[5:])]
            now=issuer.now();expiry=min(now+LIFETIME,checked['expires_at'],session['deadline'])
            if expiry<=now:raise Failure(401,'Session expired')
            claims={'v':1,'iss':issuer.c.origin,'aud':self.audience,'sub':identity['sub'],
                    'sid':identity['sid'],'kind':identity['kind'],'cnf':{'jwk':identity['key']},
                    'iat':now,'exp':expiry,'jti':secrets.token_urlsafe(32),
                    'nonce':data['nonce'],'connection_id':data['connection_id'],
                    'policy_sha256':self.policy_sha256,'session_deadline':session['deadline']}
            return {'grant':jose.sign(claims,issuer.key,GRANT_TYPE,issuer.kid),'expires_at':expiry}

    def __call__(self,env,start):
        issuer=self.issuer;path=env.get('PATH_INFO','/')
        if path not in (CHALLENGE,AUTHORIZE):return self.application(env,start)
        try:
            if env.get('HTTP_HOST')!=urlsplit(issuer.c.origin).netloc or env.get('HTTP_ORIGIN')!=issuer.c.origin:raise Failure(403,'Unexpected guest authorization origin')
            if env.get('REQUEST_METHOD')!='POST':raise Failure(405,'POST required')
            if env.get('CONTENT_TYPE','').split(';')[0].strip()!='application/json':raise Failure(415,'JSON required')
            if env.get('HTTP_TRANSFER_ENCODING'):raise Failure(400,'Unsupported transfer encoding')
            length=env.get('CONTENT_LENGTH','')
            if not length.isascii() or not length.isdecimal() or len(length)>5 or not 0<int(length)<=16384:raise Failure(413,'Bounded guest authorization request required')
            purpose='guest-challenge-ip:' if path==CHALLENGE else 'guest-authorize-ip:'
            issuer.throttle(purpose+env.get('REMOTE_ADDR','unknown'))
            raw=env['wsgi.input'].read(int(length))
            if len(raw)!=int(length):raise Failure(400,'Truncated request')
            envelope=jose.loads(raw)
            if not isinstance(envelope,dict):raise Failure(400,'Object request required')
            if path==CHALLENGE:result=self.challenge(envelope)
            else:
                body,key,proof=issuer.consume_proof(envelope,AUTHORIZE)
                result=self.authorize(body,key,proof,env.get('HTTP_AUTHORIZATION',''))
            return issuer.json_response(start,200,result)
        except Failure as error:return issuer.json_response(start,error.status,{'error':error.message})
        except (ValueError,TypeError,KeyError,UnicodeError):return issuer.json_response(start,400,{'error':'Invalid guest-network authorization request'})
        except Exception:return issuer.json_response(start,500,{'error':'Guest-network authorization unavailable'})
