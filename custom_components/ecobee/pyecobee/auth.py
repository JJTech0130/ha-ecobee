from abc import ABC, abstractmethod
import logging
import datetime
import requests

logger = logging.getLogger("pyecobee")

class AuthorizationFlow(ABC):
    """Abstract class for authorization flows."""

    def __init__(self, client_id: str, scopes: list[str]):
        """Initialize the authorization flow."""
        self.client_id = client_id
        self.scope = " ".join(scopes)

    @abstractmethod
    def refresh_access_token(self) -> str:
        """Returns a new access token, internally doing whatever refresh process is necessary."""
        pass

class LocalWebFlow(AuthorizationFlow):
    """Authorization flow using the 'Auth0' based flow designed for ecobee.com. Manually parses responses rather than showing a web page."""
    AUTH_ENDPOINT = "https://auth.ecobee.com/authorize"
    WEB_CLIENT_ID = "183eORFPlXyz9BbDZwqexHPBQoVjgadh"

    def __init__(self, auth0: str, scopes: list[str]):
        """Initialize the authorization flow."""
        self.auth0 = auth0
        super().__init__(self.WEB_CLIENT_ID, scopes)

    def refresh_access_token(self) -> str:
        resp = requests.get(self.AUTH_ENDPOINT, cookies={"auth0": self.auth0}, params={
            "client_id": self.client_id,
            "scope": self.scope,
            "response_type": "token",
            "response_mode": "form_post",
            "redirect_uri": "https://www.ecobee.com/home/authCallback",
            "audience": "https://prod.ecobee.com/api/v1",
        })
        print(resp.text)
        if resp.status_code != 200:
            raise Exception(f"Failed to refresh access token: {resp.status_code} {resp.text}")
        
        print("auth0:", resp.cookies["auth0"])
        if (auth0 := resp.cookies.get("auth0")) is None:
            raise Exception("Failed to refresh bearer token: no auth0 cookie in response")
        self.auth0 = auth0

        # Parse the response HTML for the access token and expiration
        # <html><head><title>Submit This Form</title><meta http-equiv="X-UA-Compatible" content="IE=edge"></head><body onload="javascript:document.forms[0].submit()"><form method="post" action="https://www.ecobee.com/home/authCallback"><input type="hidden" name="access_token" value="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlJFWXhNVEpDT0Rnek9UaERRelJHTkRCRlFqZEdNVGxETnpaR1JUZzRNalEwTmtWR01UQkdPQSJ9.eyJpc3MiOiJodHRwczovL2F1dGguZWNvYmVlLmNvbS8iLCJzdWIiOiJhdXRoMHwzMTk1MGNmOC01YTAzLTRjMWQtYjY1Zi0xNTY3ZWRiNDQzNTIiLCJhdWQiOiJodHRwczovL3Byb2QuZWNvYmVlLmNvbS9hcGkvdjEiLCJpYXQiOjE3MjAzODY1MzUsImV4cCI6MTcyMDM5MDEzNSwic2NvcGUiOiJzbWFydFdyaXRlIiwiYXpwIjoiMTgzZU9SRlBsWHl6OUJiRFp3cWV4SFBCUW9WamdhZGgifQ.ea2upoLg6-SRfuRfuTPMoe_NI8ql0A-304Kn3wskzY4KkgBKpdSjO0UfWuAXecPWjPTwgwKS4WbK8jwAb38kukYh7mw1Zt20CTzy9V27izvUdACaUfJ0VegRcD4h-aac2ucKe3KPWJI3D2rnkQ81fyJqbeZ16VRNcL1gXDJcg_T2vaomcnYGklLDrmXmJhvFDvrELgpiCZmWP_q4kCZw3-7sYCR8ueDBZjii87GTuocM3Pn_VyM7WV-koIcLZzL42pFPBVVb9TVSiolRUSUU5dXSItMilKaJr7gIdMvUPMdNMdbyw59yi1mj8oiqMwnAVTwRCv9b4cP8VZsuDIHBYw"/><input type="hidden" name="scope" value="smartWrite"/><input type="hidden" name="expires_in" value="3600"/><input type="hidden" name="token_type" value="Bearer"/></form></body></html>
        if (access_token := resp.text.split('name="access_token" value="')[1].split('"')[0]) is None:
            raise Exception("Failed to refresh bearer token: no access token in response")
        
        if (expires_in := resp.text.split('name="expires_in" value="')[1].split('"')[0]) is None:
            raise Exception("Failed to refresh bearer token: no expiration in response")

        expires_at = datetime.datetime.now() + datetime.timedelta(seconds=int(expires_in))
        logger.debug(f"Access token expires at {expires_at}")

        return access_token

class DeveloperFlow(AuthorizationFlow):
    """Authorization flow using a now-unavailable Developer API key and pin-based pairing."""
    AUTH_ENDPOINT = "https://api.ecobee.com/authorize"
    pass