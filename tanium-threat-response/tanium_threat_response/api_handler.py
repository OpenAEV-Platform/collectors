######################
# TANIUM API HANDLER #
######################

import requests


class TaniumApiHandler:
    def __init__(
        self,
        logger,
        url,
        token,
        ssl_verify=True,
    ):
        # Variables
        self.logger = logger
        self.url = url
        self.token = token
        self.ssl_verify = ssl_verify

    def get_url(self):
        return self.url

    def _query(
        self,
        method,
        uri,
        payload=None,
        content_type="application/json",
        type=None,
    ):
        self.logger.info("Query " + method + " on " + uri)
        headers = {"session": self.token}
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
                self.url + uri,
                headers=headers,
                params=payload,
                verify=self.ssl_verify,
            )
        elif method == "post":
            if content_type == "application/octet-stream":
                r = requests.post(
                    self.url + uri,
                    headers=headers,
                    data=payload["document"],
                    verify=self.ssl_verify,
                )
            elif type is not None:
                r = requests.post(
                    self.url + uri,
                    headers=headers,
                    data=payload["intelDoc"],
                    verify=self.ssl_verify,
                )
            else:
                r = requests.post(
                    self.url + uri,
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
                self.url + uri,
                headers=headers,
                files=files,
                verify=self.ssl_verify,
            )
        elif method == "put":
            if type is not None:
                r = requests.put(
                    self.url + uri,
                    headers=headers,
                    data=payload["intelDoc"],
                    verify=self.ssl_verify,
                )
            elif content_type == "application/xml":
                r = requests.put(
                    self.url + uri,
                    headers=headers,
                    data=payload,
                    verify=self.ssl_verify,
                )
            else:
                r = requests.put(
                    self.url + uri,
                    headers=headers,
                    json=payload,
                    verify=self.ssl_verify,
                )
        elif method == "patch":
            r = requests.patch(
                self.url + uri,
                headers=headers,
                json=payload,
                verify=self.ssl_verify,
            )
        elif method == "delete":
            r = requests.delete(self.url + uri, headers=headers, verify=self.ssl_verify)
        else:
            raise ValueError("Unsupported method")
        if r.status_code == 200:
            try:
                return r.json()["data"]
            except requests.exceptions.JSONDecodeError:
                return r.text
        elif r.status_code == 401:
            raise ValueError("Query failed, permission denied")
        else:
            self.logger.info(r.text)
