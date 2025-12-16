from pyoaev.security_domain.types import SecurityDomains


class OpenAEVSecurityDomain:


    NETWORK_KEYWORDS = ["network", "ftp", "smb", "llmnr", "nmap"]

    WEB_APP_KEYWORDS = ["web"]

    EMAIL_INFILTRATION_KEYWORDS = ["mail", "phishing"]

    DATA_EXFILTRATION_KEYWORDS = ["exfiltrat"]

    URL_FILTERING_KEYWORDS = ["bitsadmin"]

    CLOUD_KEYWORDS = ["aws", "azure", "gcp"]


    def _find_in_keywords(self, keywords, search):
        return any(keyword.lower() in search.lower() for keyword in keywords)


    def get_associated_security_domains(self, name):
        domains = []
        domains.append(SecurityDomains.ENDPOINT.value)

        if self._find_in_keywords(self.NETWORK_KEYWORDS, name):
            domains.append(SecurityDomains.NETWORK.value)
        if self._find_in_keywords(self.WEB_APP_KEYWORDS, name):
            domains.append(SecurityDomains.WEB_APP.value)
        if self._find_in_keywords(self.EMAIL_INFILTRATION_KEYWORDS, name):
            domains.append(SecurityDomains.EMAIL_INFILTRATION.value)
        if self._find_in_keywords(self.DATA_EXFILTRATION_KEYWORDS, name):
            domains.append(SecurityDomains.DATA_EXFILTRATION.value)
        if self._find_in_keywords(self.URL_FILTERING_KEYWORDS, name):
            domains.append(SecurityDomains.URL_FILTERING.value)
        if self._find_in_keywords(self.CLOUD_KEYWORDS, name):
            domains.append(SecurityDomains.CLOUD.value)

        return domains