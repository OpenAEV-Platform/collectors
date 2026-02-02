######################
# SENTINEL API HANDLER #
######################

import msal
import requests


class SentinelApiHandler:
    def __init__(
        self,
        logger,
        tenant_id,
        client_id,
        client_secret,
        ssl_verify=True,
    ):
        # Variables
        self.logger = logger
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.ssl_verify = ssl_verify
        self._auth()

    def _auth(self):
        # Authentication
        app = msal.ConfidentialClientApplication(
            self.client_id,
            authority="https://login.microsoftonline.com/" + self.tenant_id,
            client_credential=self.client_secret,
        )
        result = app.acquire_token_silent(
            "https://api.loganalytics.io/.default", account=None
        )
        if not result:
            result = app.acquire_token_for_client(
                scopes=["https://api.loganalytics.io/.default"]
            )
        if result.get("error"):
            raise RuntimeError(
                f"[ERROR] A problem occurred while authenticating with response: {result}"
            )
        if not result.get("access_token"):
            raise RuntimeError("[ERROR] The response did not include an access token.")
        self.token = result.get("access_token")

    def _query(
        self,
        method,
        url,
        payload=None,
        content_type="application/json",
        type=None,
    ):
        self._auth()
        self.logger.info("Query " + method + " on " + url)
        headers = {"Authorization": "Bearer " + self.token}
        if method != "upload":
            headers["content-type"] = content_type
        if type is not None:
            headers["type"] = type
        if content_type == "application/octet-stream":
            headers["content-disposition"] = (
                "attachment; filename=" + payload["filename"]
            )
            if "name" in payload:
                headers["name"] = payload["name"].strip()
            if "description" in payload:
                headers["description"] = (
                    payload["description"].replace("\n", " ").strip()
                )
        if method == "get":
            r = requests.get(
                url,
                headers=headers,
                params=payload,
                verify=self.ssl_verify,
            )
        elif method == "post":
            if content_type == "application/octet-stream":
                r = requests.post(
                    url,
                    headers=headers,
                    data=payload["document"],
                    verify=self.ssl_verify,
                )
            elif type is not None:
                r = requests.post(
                    url,
                    headers=headers,
                    data=payload["intelDoc"],
                    verify=self.ssl_verify,
                )
            else:
                r = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    verify=self.ssl_verify,
                )
        elif method == "upload":
            f = open(payload["filename"], "w")
            f.write(payload["content"])
            f.close()
            files = {"hash": open(payload["filename"], "rb")}
            r = requests.post(
                url,
                headers=headers,
                files=files,
                verify=self.ssl_verify,
            )
        elif method == "put":
            if type is not None:
                r = requests.put(
                    url,
                    headers=headers,
                    data=payload["intelDoc"],
                    verify=self.ssl_verify,
                )
            elif content_type == "application/xml":
                r = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    verify=self.ssl_verify,
                )
            else:
                r = requests.put(
                    url,
                    headers=headers,
                    json=payload,
                    verify=self.ssl_verify,
                )
        elif method == "patch":
            r = requests.patch(
                url,
                headers=headers,
                json=payload,
                verify=self.ssl_verify,
            )
        elif method == "delete":
            r = requests.delete(url, headers=headers, verify=self.ssl_verify)
        else:
            raise ValueError("Unsupported method")
        if r.status_code == 200:
            try:
                return r.json()
            except requests.exceptions.JSONDecodeError:
                return r.text
        elif r.status_code == 401:
            raise ValueError("Query failed, permission denied")
        else:
            self.logger.info(r.text)
