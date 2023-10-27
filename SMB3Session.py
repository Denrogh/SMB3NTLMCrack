class SMB3Session:
    def __init__(self, domain, username, sesskey, ntlm_challenge, ntProofStr, ntlm_response):
        self._domain = domain
        self._username = username
        self._sesskey = sesskey
        self._ntlm_challenge = ntlm_challenge
        self._ntProofStr = ntProofStr
        self._ntlm_response = ntlm_response

    def get_domain(self):
        return self._domain

    def set_domain(self, value):
        self._domain = value

    def get_username(self):
        return self._username

    def set_username(self, value):
        self._username = value

    def get_sesskey(self):
        return self._sesskey

    def set_sesskey(self, value):
        self._sesskey = value

    def get_ntlm_challenge(self):
        return self._ntlm_challenge

    def set_ntlm_challenge(self, value):
        self._ntlm_challenge = value

    def get_ntProofStr(self):
        return self._ntProofStr

    def set_ntProofStr(self, value):
        self._ntProofStr = value

    def get_ntlm_response(self):
        return self._ntlm_response

    def set_ntlm_response(self, value):
        self._ntlm_response = value
