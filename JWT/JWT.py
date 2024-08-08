import json
import base64

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

        