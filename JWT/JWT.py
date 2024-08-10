import json
import base64
import hmac
import hashlib
from io import StringIO

class JWT:
    
    def __init__(self, alg, secret, payload = {}, typ = "JWT") -> None:
        self.alg = alg
        self.secret = secret
        self.typ = typ
        self.payload = payload
        pass

    def addPayload(self, key, value, overwrite = False) -> bool:
        if (key in self.payload and not(overwrite)) :
            return False
        else:
            self.payload[key] = value
            return True
        
    def addPayloads(self, payloadsObject, overwrite = False) -> None:
        for key, value in enumerate(payloadsObject):
            self.addPayload(key, value, overwrite)
    
    def getJWT(self) -> str:
        return self.getHeaderBase64() + "." + self.getPayloadBase64() + "." + self.getSignature()
    
    def validateJWT(self, jwtToken, secret, jsonDecode = False, forceArray = False):
        jwtData = jwtToken.split(".")
        base64Header = json.loads(base64.b64decode(jwtData[0]))
        if (base64Header is None):
            return False
        payload = jwtData[1]
        signature = jwtData[2]

        base64UrlSignature = hmac.new(bytes(jwtData[0] + '.' + jwtData[1], 'UTF-8'), secret.encode(), hashlib[base64Header.alg]).hexdigest()
        if base64UrlSignature == signature:
            base64Payload = base64.b64decode(payload)
            if jsonDecode == True:
                jsonDecoded = json.loads(base64Payload)
                if jsonDecoded is not None:
                    return jsonDecoded
                else:
                    return None
            return base64Payload
        else:
            return False
    
    def getHeader(self, asJsonString = True):
        header = {"alg": self.alg, "typ": self.type}

        if asJsonString == True:
            io = StringIO()
            json.dump(header, io)
            return io.getvalue()
        
    def getPayload(self, asJsonString = True):
        if asJsonString == True:
            io = StringIO()
            json.dump(self.payload, io)
            return io.getvalue()
        
        return self.payload
    
    def getPayloadBase64(self, payload = None):
        if payload == None:
            payload = self.getPayload()
        else:
            io = StringIO()
            json.dump(payload, io)
            payload = io.getvalue()

        return base64.b64encode(payload.encode()).decode().replace('+', '-').replace('/', '_').replace('=', '')
        
    def getHeaderBase64(self, header = None):
        if header == None:
            header = self.getHeader()
        else:
            io = StringIO()
            json.dump(header, io)

            header = io.getvalue()
        return header.replace('+', '-').replace('/', '_').replace('=', '')

    def getSignature(self, secret):
        return hmac.new(bytes(self.getHeaderBase64() + '.' + self.getPayloadBase64(), 'UTF-8'), secret.encode(), hashlib[self.alg]).hexdigest()
    
    