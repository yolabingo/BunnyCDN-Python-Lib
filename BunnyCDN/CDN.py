import json
import requests
from requests.exceptions import HTTPError
from urllib import parse


class CDN:
    # initializer function
    def __init__(self, api_key):

        """
        Parameters
        ----------
        api_key     : String
                      BunnyCDN account api key

        """
        assert api_key != "", "api_key for the account must be specified"
        self.headers = {
            "AccessKey": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.base_url = "https://bunnycdn.com/api/"

    def _Geturl(self, Task_name):
        """
        This function is helper for the other methods in code
        to create appropriate url.

        """
        if Task_name[0] == "/":
            if Task_name[-1] == "/":
                url = self.base_url + parse.quote(Task_name[1:-1])
            else:
                url = self.base_url + parse.quote(Task_name[1:])
        elif Task_name[-1] == "/":
            url = self.base_url + parse.quote(Task_name[1:-1])
        else:
            url = self.base_url + parse.quote(Task_name)
        return url

    def AddCertificate(self,
                       PullZoneId,
                       Hostname,
                       Certificate,
                       CertificateKey):
        """
        This function adds custom certificate to the given pullzone

        Parameters
        ----------
        PullZoneId          : int64
                              The ID of the Pull Zone to which the certificate
                              will be added.

        Hostname            : string
                              The hostname to which the certificate belongs to.

        Certificate         : string
                              A base64 encoded binary certificate file data
                              Value must be of format 'base64'

        CertificateKey      : string
                              A base64 encoded binary certificate key file data
                              Value must be of format 'base64'
        """
        values = json.dumps(
            {
                "PullZoneId": PullZoneId,
                "Hostname": Hostname,
                "Certificate": Certificate,
                "CertificateKey": CertificateKey,
            }
        )

        try:
            response = requests.post(
                self._Geturl("pullzone/addCertificate"),
                data=values,
                headers=self.headers,
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": f"Certificated Added successfully Hostname:{Hostname}",
            }

    def AddBlockedIp(self, PullZoneId, BlockedIp):
        """
        This method adds an IP to the list of blocked IPs that are not
        allowed to access the zone.

        Parameters
        ----------
        PullZoneId      : int64
                          The ID of the Pull Zone to which the IP block
                          will be added.
        BlockedIP       : string
                          The IP address that will be blocked
        """
        values = json.dumps(
            {"PullZoneId": PullZoneId,
             "BlockedIp": BlockedIp}
            )

        try:
            response = requests.post(
                self._Geturl("pullzone/addBlockedIp"), data=values,
                headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": "Ip successfully added to list of blocked IPs",
            }

    def RemoveBlockedIp(self, PullZoneId, BlockedIp):
        """
        This method removes mentioned IP from the list of blocked IPs
        that are not allowed to access the zone.

        Parameters
        ----------
        PullZoneId      : int64
                          The ID of the Pull Zone to which the
                          IP block will be added.
        BlockedIP       : string
                          The IP address that will be blocked
        """
        values = json.dumps({"PullZoneId": PullZoneId, "BlockedIp": BlockedIp})

        try:
            response = requests.post(
                self._Geturl("pullzone/removeBlockedIp"),
                data=values,
                headers=self.headers,
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": "Ip removed from blocked IPs list "
            }

    def StorageZoneData(self):
        """
        This function returns a list of details of each storage zones
        in user's account

        """
        try:
            response = requests.get(self._Geturl("storagezone"),
                                    headers=self.headers)
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            storage_summary = []
            for storagezone in response.json():
                storage_zone_details = {}
                storage_zone_details["Id"] = storagezone["Id"]
                storage_zone_details["Storage_Zone_Name"] = storagezone["Name"]
                storage_zone_details["Usage"] = storagezone["StorageUsed"]
                hostnames = []
                pullzone = []
                for data in storagezone["PullZones"]:
                    pullzone.append(data["Name"])
                    for host_name in data["Hostnames"]:
                        hostnames.append(host_name["Value"])
                storage_zone_details["host_names"] = hostnames
                storage_zone_details["PullZones"] = pullzone
                storage_summary.append(storage_zone_details)
            return storage_summary

    def StorageZoneList(self):
        """
        Returns list of dictionaries containing storage zone
        name and storage zone id
        """
        try:
            response = requests.get(self._Geturl("storagezone"),
                                    headers=self.headers)
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            storage_list = []
            for storagezone in response.json():
                storage_list.append({storagezone["Name"]: storagezone["Id"]})
            return storage_list

    def AddStorageZone(
        self, storage_zone_name, storage_zone_region="DE",
        ReplicationRegions=["DE"]
    ):
        """
        This method creates a new storage zone

        Parameters
        ----------
        storage_zone_name        : string
                                   The name of the storage zone
                                        1.Matches regex pattern: ^[a-zA-Z0-9]+$
                                        2.Length of string must be less than,
                                          or equal to 20
                                        3.Length of string must be
                                          greater than, or equal to 3

        storage_zone_region      : string
        (optional)                 The main region code of storage zone
                                        1.Matches regex pattern: ^[a-zA-Z0-9]+$
                                        2.Length of string must be less than,
                                          or equal to 2
                                        3.Length of string must be
                                          greater than, or equal to 2

        ReplicationsRegions      : array
        (optional)                 The list of active replication regions
                                   for the zone

        """
        values = json.dumps(
            {
                "Name": storage_zone_name,
                "Region": storage_zone_region,
                "ReplicationRegions": ReplicationRegions,
            }
        )
        try:
            response = requests.post(
                self._Geturl("storagezone"), data=values, headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": response.json(),
            }

    def GetStorageZone(self, storage_zone_id):

        """
        This function returns details about the storage zone
        whose id is mentioned

        Parameters
        ----------
        storage_zone_id     :   int64
                                The ID of the Storage Zone to return

        """
        try:
            response = requests.get(
                self._Geturl(f"storagezone/{storage_zone_id}"),
                headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return response.json()

    def DeleteStorageZone(self, storage_zone_id):
        """
        This method deletes the Storage zone with id : storage_zone_id

        Parameters
        ----------
        storage_zone_id :   int64
                            The ID of the storage zone that should be deleted
        """
        try:
            response = requests.delete(
                self._Geturl(f"storagezone/{storage_zone_id}"),
                headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "Success",
                "HTTP": response.status_code,
                "msg": "Deleted Storagezone successfully",
            }

    def PurgeUrlCache(self, url):
        """
        This method purges the given URL from our edge server cache.

        Parameters
        ----------
        url : string
              The URL of the file that will be purged.
              Use a CDN enabled URL such as http://myzone.b-cdn.net/style.css
        """
        try:
            response = requests.post(
                self._Geturl("purge"), params={"url": url},
                headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "Success",
                "HTTP": response.status_code,
                "msg": f"Purged Cache for url:{url}",
            }

    def Billing(self):
        """
        This method returns the current billing summary of the account

        """
        try:
            response = requests.get(self._Geturl("billing"),
                                    headers=self.headers)
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return response.json()

    def ApplyCode(self, couponCode):
        """
        This method applys promo code to the account

        Parameters
        ----------
        couponCode  :  The promo code that will be applied

        """
        try:
            response = requests.get(
                self._Geturl("billing/applycode"),
                params={"couponCode": couponCode},
                headers=self.headers,
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": f"Applied promo code:{couponCode} successfully",
            }

    def Stats(
        self,
        dateFrom=None,
        dateTo=None,
        pullZone=None,
        serverZoneId=None,
        loadErrors=True,
    ):
        """
        This method returns the statistics associated
        with your account as json object

        Parameters
        ----------

        dateFrom        : string
        (optional)        The start date of the range the statistics
                          should be returned for. Format: yyyy-mm-dd

        dateTo          : string
        (optional)        The end date of the range the statistics
                          should be returned for. Format: yyyy-MM-dd

        pullZone        : int64
        (optional)        The ID of the Pull Zone for which the
                          statistics should be returned

        serverZoneId    : int64
        (optional)        The server zone for which the data
                          should be returned.

        loadErrors      : boolean
        (optional)        Set to true by default
        """

        params = {
            "dateFrom": dateFrom,
            "dateTo": dateTo,
            "pullZone": pullZone,
            "serverZoneId": serverZoneId,
            "loadErrors": loadErrors,
        }

        try:
            response = requests.get(
                self._Geturl("statistics"), params=params, headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return response.json()

    def GetPullZoneList(self):
        """
        This function fetches the list of pullzones in the User's Account

        Parameters
        ----------
        None
        """
        try:
            response = requests.get(self._Geturl("pullzone"),
                                    headers=self.headers)
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            pullzone_list = []
            for pullzone in response.json():
                pullzone_list.append({pullzone["Name"]: pullzone["Id"]})
            return pullzone_list

    def CreatePullZone(self, Name, OriginURL, Type, StorageZoneId=None):
        """
        This function creates a new Pulzone in User's Account
        Parameters
        ----------
        Name                : string
                              The name of the new pull zone

        Type                : string
                              number
                              The pricing type of the pull zone to be added.
                              0 = Standard, 1 = High Volume

        OriginURL           : string
                              The origin URL where the pull zone files
                              are pulled from.

        StorageZoneId       : int64
                              The ID(number) of the storage zone to which
                              the pull zone will be linked (Optional)

        """

        if StorageZoneId is None:
            values = json.dumps(
                {"Name": Name,
                 "Type": Type,
                 "OriginURL": OriginURL}
                )
        else:
            values = {
                "Name": Name,
                "Type": Type,
                "OriginURL": OriginURL,
                "StorageZoneId": StorageZoneId,
            }
        try:
            response = requests.post(
                self._Geturl("pullzone"), data=values, headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return response.json()

    def GetPullZone(self, PullZoneID):
        """
        This function returns the pullzone details
        for the zone with the given ID

        Parameters
        ----------
        PullZoneID            : int64
                                The ID (number) of the pullzone to return
        """
        try:
            response = requests.get(
                self._Geturl(f"pullzone/{PullZoneID}"), headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return response.json()

    def UpdatePullZone(
        self,
        PullZoneID,
        OriginUrl,
        AllowedReferrers,
        BlockedReferrers,
        BlockedIps,
        EnableGeoZoneUS,
        EnableGeoZoneEU,
        EnableGeoZoneASIA,
        EnableGeoZoneSA,
        EnableGeoZoneAF,
        BlockRootPathAccess,
        BlockPostRequests,
        EnableQueryStringOrdering,
        EnableWebpVary,
        EnableAvifVary,
        EnableMobileVary,
        EnableCountryCodeVary,
        EnableHostnameVary,
        EnableCacheSlice,
        ZoneSecurityEnabled,
        ZoneSecurityIncludeHashRemoteIP,
        IgnoreQueryStrings,
        MonthlyBandwidthLimit,
        AccessControlOriginHeaderExtensions,
        EnableAccessControlOriginHeader,
        DisableCookies,
        BudgetRedirectedCountries,
        BlockedCountries,
        CacheControlMaxAgeOverride,
        CacheControlBrowserMaxAgeOverride,
        AddHostHeader,
        AddCanonicalHeader,
        EnableLogging,
        LoggingIPAnonymizationEnabled,
        PermaCacheStorageZoneId,
        AWSSigningEnabled,
        AWSSigningKey,
        AWSSigningRegionName,
        AWSSigningSecret,
        EnableOriginShield,
        OriginShieldZoneCode,
        EnableTLS1,
        EnableTLS1_1,
        CacheErrorResponses,
        VerifyOriginSSL,
        LogForwardingEnabled,
        LogForwardingHostname,
        LogForwardingPort,
        LogForwardingToken,
        LogForwardingProtocol,
        LoggingSaveToStorage,
        LoggingStorageZoneId,
        FollowRedirects,
        ConnectionLimitPerIPCount,
        RequestLimit,
        WAFEnabled,
        WAFDisabledRuleGroups,
        WAFDisabledRules,
        WAFEnableRequestHeaderLogging,
        WAFRequestHeaderIgnores,
        ErrorPageEnableCustomCode,
        ErrorPageCustomCode,
        ErrorPageEnableStatuspageWidget,
        ErrorPageStatuspageCode,
        ErrorPageWhitelabel,
        OptimizerEnabled,
        OptimizerDesktopMaxWidth,
        OptimizerMobileMaxWidth,
        OptimizerImageQuality,
        OptimizerMobileImageQuality,
        OptimizerEnableWebP,
        OptimizerEnableManipulationEngine,
        OptimizerMinifyCSS,
        OptimizerMinifyJavaScript,
        OptimizerWatermarkEnabled,
        OptimizerWatermarkUrl,
        OptimizerWatermarkPosition,
        OptimizerWatermarkOffset,
        OptimizerWatermarkMinImageSize,
        OptimizerAutomaticOptimizationEnabled,
        OptimizerClasses,
        OptimizerForceClasses,
        Type,
        OriginRetries,
        OriginConnectTimeout,
        OriginResponseTimeout,
        UseStaleWhileUpdating,
        UseStaleWhileOffline,
        OriginRetry5XXResponses,
        OriginRetryConnectionTimeout,
        OriginRetryResponseTimeout,
        OriginRetryDelay,
        QueryStringVaryParameters,
        OriginShieldEnableConcurrencyLimit,
        OriginShieldMaxConcurrentRequests,
        EnableCookieVary,
        CookieVaryParameters,
        EnableSafeHop,
        OriginShieldQueueMaxWaitTime,
        OriginShieldMaxQueuedRequests,
        UseBackgroundUpdate,
        EnableAutoSSL,
        LogAnonymizationType,
        LogFormat,
        LogForwardingFormat,
        ShieldDDosProtectionType,
        ShieldDDosProtectionEnabled,
    ):

        """ 
        This function updates the pullzone with the given ID

        Parameters
        ----------
        PullZoneID                            : int64
                                                The ID of the Pull Zone that should
                                                be updated
        OriginUrl                             : string
                                                Sets the origin URL of the Pull Zone
        AllowedReferrers                      : array of strings
                                                Sets the list of referrer hostnames
                                                that are allowed to access the pull
                                                zone. Requests containing the header
                                                Referer: hostname that is not on the
                                                list will be rejected. If empty, all
                                                the referrers are allowed
        BlockedReferrers                      : array of strings
                                                Sets the list of referrer hostnames
                                                that are blocked from accessing the
                                                pull zone.
        BlockedIps                            : array of strings
                                                Sets the list of IPs that are
                                                blocked from accessing the pull
                                                zone. Requests coming from the
                                                following IPs will be rejected. If
                                                empty, all the IPs will be allowed
        EnableGeoZoneUS                       : boolean
                                                Determines if the delivery from the
                                                North America region should be
                                                enabled for this pull zone
        EnableGeoZoneEU                       : boolean
                                                Determines if the delivery from the
                                                Europe region should be enabled for
                                                this pull zone
        EnableGeoZoneASIA                     : boolean
                                                Determines if the delivery from the
                                                Asia / Oceania regions should be
                                                enabled for this pull zone
        EnableGeoZoneSA                       : boolean
                                                Determines if the delivery from the
                                                South America region should be
                                                enabled for this pull zone
        EnableGeoZoneAF                       : boolean
                                                Determines if the delivery from the
                                                Africa region should be enabled for
                                                this pull zone
        BlockRootPathAccess                   : boolean
                                                Determines if the zone should block
                                                requests to the root of the zone.
        BlockPostRequests                     : boolean
                                                Determines if the POST requests to
                                                this zone should be rejected.
        EnableQueryStringOrdering             : boolean
                                                Determines if the query string
                                                ordering should be enabled.
        EnableWebpVary                        : boolean
                                                Determines if the WebP Vary feature
                                                should be enabled.
        EnableAvifVary                        : boolean
                                                Determines if the AVIF Vary feature
                                                should be enabled.
        EnableMobileVary                      : boolean
                                                Determines if the Mobile Vary
                                                feature is enabled.
        EnableCountryCodeVary                 : boolean
                                                Determines if the Country Code Vary
                                                feature should be enabled.
        EnableHostnameVary                    : boolean
                                                Determines if the Hostname Vary
                                                feature should be enabled.
        EnableCacheSlice                      : boolean
                                                Determines if cache slicing
                                                (Optimize for video) should be
                                                enabled for this zone
        ZoneSecurityEnabled                   : boolean
                                                Determines if the zone token
                                                authentication security should be
                                                enabled
        ZoneSecurityIncludeHashRemoteIP       : boolean
                                                Determines if the token
                                                authentication IP validation should
                                                be enabled
        IgnoreQueryStrings                    : boolean
                                                Determines if the Pull Zone should
                                                ignore query strings when serving
                                                cached objects (Vary by Query
                                                String)
        MonthlyBandwidthLimit                 : int64
                                                Sets the monthly limit of bandwidth
                                                in bytes that the pullzone is
                                                allowed to use
        AccessControlOriginHeaderExtensions   : array of strings
                                                Sets the list of extensions that
                                                will return the CORS headers
        EnableAccessControlOriginHeader       : boolean
                                                Determines if CORS headers should be
                                                enabled
        DisableCookies                        : boolean
                                                Determines if the Pull Zone should
                                                automatically remove cookies from
                                                the responses
        BudgetRedirectedCountries             : array of strings
                                                Sets the list of two letter Alpha2
                                                country codes that will be
                                                redirected to the cheapest possible
                                                region
        BlockedCountries                      : array of strings
                                                Sets the list of two letter Alpha2
                                                country codes that will be blocked
                                                from accessing the zone
        CacheControlMaxAgeOverride            : int64
                                                Sets the cache control override
                                                setting for this zone
        CacheControlBrowserMaxAgeOverride     : int64
                                                Sets the browser cache control
                                                override setting for this zone
        AddHostHeader                         : boolean
                                                Determines if the zone should
                                                forward the requested host header to
                                                the origin
        AddCanonicalHeader                    : boolean
                                                Determines if the canonical header
                                                should be added by this zone
        EnableLogging                         : boolean
                                                Determines if the logging should be
                                                enabled for this zone
        LoggingIPAnonymizationEnabled         : boolean
                                                Determines if the log anonoymization
                                                should be enabled
        PermaCacheStorageZoneId               : int64
                                                The ID of the storage zone that
                                                should be used as the Perma-Cache
        AWSSigningEnabled                     : boolean
                                                Determines if the AWS signing should
                                                be enabled or not
        AWSSigningKey                         : string
                                                Sets the AWS signing key
        AWSSigningRegionName                  : string
                                                Sets the AWS signing region name
        AWSSigningSecret                      : string
                                                Sets the AWS signing secret key
        EnableOriginShield                    : boolean
                                                Determines if the origin shield
                                                should be enabled
        OriginShieldZoneCode                  : string
                                                Determines the zone code where the
                                                origin shield should be set up
        EnableTLS1                            : boolean
                                                Determines if the TLS 1 should be
                                                enabled on this zone
        EnableTLS1_1                          : boolean
                                                Determines if the TLS 1.1 should be
                                                enabled on this zone
        CacheErrorResponses                   : boolean
                                                Determines if the cache error
                                                responses should be enabled on the
                                                zone
        VerifyOriginSSL                       : boolean
                                                Determines if the SSL certificate
                                                should be verified when connecting
                                                to the origin
        LogForwardingEnabled                  : boolean
                                                Sets the log forwarding token for
                                                the zone
        LogForwardingHostname                 : string
                                                Sets the log forwarding destination
                                                hostname for the zone
        LogForwardingPort                     : int32
                                                Sets the log forwarding port for the
                                                zone
        LogForwardingToken                    : string
                                                Sets the log forwarding token for
                                                the zone
        LogForwardingProtocol                 : integer
                                                Sets the log forwarding protocol
                                                type
        LoggingSaveToStorage                  : boolean
                                                Determines if the logging permanent
                                                storage should be enabled
        LoggingStorageZoneId                  : int64
                                                Sets the Storage Zone id that should
                                                contain the logs from this Pull Zone
        FollowRedirects                       : boolean
                                                Determines if the zone should follow
                                                redirects return by the oprigin and
                                                cache the response
        ConnectionLimitPerIPCount             : int32
                                                Determines the maximum number of
                                                connections per IP that will be
                                                allowed to connect to this Pull Zone
        RequestLimit                          : int32
                                                Determines the maximum number of
                                                requests per second that will be
                                                allowed to connect to this Pull Zone
        WAFEnabled                            : boolean
                                                Determines if WAF should be enabled
                                                on the zone
        WAFDisabledRuleGroups                 : array of strings
                                                Determines the enabled WAF rule
                                                groups
        WAFDisabledRules                      : array of strings
                                                Determines the disabled WAF rules
        WAFEnableRequestHeaderLogging         : boolean
                                                Determines if WAF should enable
                                                request headers logging
        WAFRequestHeaderIgnores               : array of strings
                                                Determines the list of headers that
                                                will be ignored in the WAF logs
        ErrorPageEnableCustomCode             : boolean
                                                Determines if custom error page code
                                                should be enabled.
        ErrorPageCustomCode                   : string
                                                Contains the custom error page code
                                                that will be returned
        ErrorPageEnableStatuspageWidget       : boolean
                                                Determines if the statuspage widget
                                                should be displayed on the error
                                                pages
        ErrorPageStatuspageCode               : string
                                                The statuspage code that will be
                                                used to build the status widget
        ErrorPageWhitelabel                   : boolean
                                                Determines if the error pages should
                                                be whitelabel or not
        OptimizerEnabled                      : boolean
                                                Determines if the optimizer should
                                                be enabled for this zone
        OptimizerDesktopMaxWidth              : int32
                                                Determines the maximum automatic
                                                image size for desktop clients
        OptimizerMobileMaxWidth               : int32
                                                Determines the maximum automatic
                                                image size for mobile clients
        OptimizerImageQuality                 : int32
                                                Determines the image quality for
                                                desktop clients
        OptimizerMobileImageQuality           : int32
                                                Determines the image quality for
                                                mobile clients
        OptimizerEnableWebP                   : boolean
                                                Determines if the WebP optimization
                                                should be enabled
        OptimizerEnableManipulationEngine     : boolean
                                                Determines the image manipulation
                                                should be enabled
        OptimizerMinifyCSS                    : boolean
                                                Determines if the CSS minifcation
                                                should be enabled
        OptimizerMinifyJavaScript             : boolean
                                                Determines if the JavaScript
                                                minifcation should be enabled
        OptimizerWatermarkEnabled             : boolean
                                                Determines if image watermarking
                                                should be enabled
        OptimizerWatermarkUrl                 : string
                                                Sets the URL of the watermark image
        OptimizerWatermarkPosition            : integer
                                                Sets the position of the watermark
                                                image
        OptimizerWatermarkOffset              : double
                                                Sets the offset of the watermark
                                                image
        OptimizerWatermarkMinImageSize        : int32
                                                Sets the minimum image size to which
                                                the watermark will be added
        OptimizerAutomaticOptimizationEnabled : boolean
                                                Determines if the automatic image
                                                optimization should be enabled
        OptimizerClasses                      : array of objects
                                                Determines the list of optimizer
                                                classes
        OptimizerForceClasses                 : boolean
                                                Determines if the optimizer classes
                                                should be forced
        Type                                  : integer
                                                The type of the pull zone. Premium =
                                                0, Volume = 1
        OriginRetries                         : int32
                                                The number of retries to the origin
                                                server
        OriginConnectTimeout                  : int32
                                                The amount of seconds to wait when
                                                connecting to the origin. Otherwise
                                                the request will fail or retry.
        OriginResponseTimeout                 : int32
                                                The amount of seconds to wait when
                                                waiting for the origin reply.
                                                Otherwise the request will fail or
                                                retry.
        UseStaleWhileUpdating                 : boolean
                                                Determines if we should use stale
                                                cache while cache is updating
        UseStaleWhileOffline                  : boolean
                                                Determines if we should use stale
                                                cache while the origin is offline
        OriginRetry5XXResponses               : boolean
                                                Determines if we should retry the
                                                request in case of a 5XX response.
        OriginRetryConnectionTimeout          : boolean
                                                Determines if we should retry the
                                                request in case of a connection
                                                timeout.
        OriginRetryResponseTimeout            : boolean
                                                Determines if we should retry the
                                                request in case of a response
                                                timeout.
        OriginRetryDelay                      : int32
                                                Determines the amount of time that
                                                the CDN should wait before retrying
                                                an origin request.
        QueryStringVaryParameters             : array of strings
                                                Contains the list of vary parameters
                                                that will be used for vary cache by
                                                query string. If empty, all
                                                parameters will be used to construct
                                                the key
        OriginShieldEnableConcurrencyLimit    : boolean
                                                Determines if the origin shield
                                                concurrency limit is enabled.
        OriginShieldMaxConcurrentRequests     : int32
                                                Determines the number of maximum
                                                concurrent requests allowed to the
                                                origin.
        EnableCookieVary                      : boolean
                                                Determines if the Cookie Vary
                                                feature is enabled.
        CookieVaryParameters                  : array of strings
                                                Contains the list of vary parameters
                                                that will be used for vary cache by
                                                cookie string. If empty, cookie vary
                                                will not be used.
        EnableSafeHop                         : boolean
        OriginShieldQueueMaxWaitTime          : int32
                                                Determines the max queue wait time
        OriginShieldMaxQueuedRequests         : int32
                                                Determines the max number of origin
                                                requests that will remain in the
                                                queue
        UseBackgroundUpdate                   : boolean
                                                Determines if cache update is
                                                performed in the background.
        EnableAutoSSL                         : boolean
                                                If set to true, any hostnames added
                                                to this Pull Zone will automatically
                                                enable SSL.
        LogAnonymizationType                  : integer
                                                Sets the log anonymization type for
                                                this pull zone
        LogFormat                             : integer
        LogForwardingFormat                   : integer
        ShieldDDosProtectionType              : integer
        ShieldDDosProtectionEnabled           : boolean

        """
        values = json.dumps(
            {
                "PullZoneID": PullZoneID,
                "OriginUrl": OriginUrl,
                "AllowedReferrers": AllowedReferrers,
                "BlockedReferrers": BlockedReferrers,
                "BlockedIps": BlockedIps,
                "EnableGeoZoneUS": EnableGeoZoneUS,
                "EnableGeoZoneEU": EnableGeoZoneEU,
                "EnableGeoZoneASIA": EnableGeoZoneASIA,
                "EnableGeoZoneSA": EnableGeoZoneSA,
                "EnableGeoZoneAF": EnableGeoZoneAF,
                "BlockRootPathAccess": BlockRootPathAccess,
                "BlockPostRequests": BlockPostRequests,
                "EnableQueryStringOrdering": EnableQueryStringOrdering,
                "EnableWebpVary": EnableWebpVary,
                "EnableAvifVary": EnableAvifVary,
                "EnableMobileVary": EnableMobileVary,
                "EnableCountryCodeVary": EnableCountryCodeVary,
                "EnableHostnameVary": EnableHostnameVary,
                "EnableCacheSlice": EnableCacheSlice,
                "ZoneSecurityEnabled": ZoneSecurityEnabled,
                "ZoneSecurityIncludeHashRemoteIP": ZoneSecurityIncludeHashRemoteIP,
                "IgnoreQueryStrings": IgnoreQueryStrings,
                "MonthlyBandwidthLimit": MonthlyBandwidthLimit,
                "AccessControlOriginHeaderExtensions": AccessControlOriginHeaderExtensions,
                "EnableAccessControlOriginHeader": EnableAccessControlOriginHeader,
                "DisableCookies": DisableCookies,
                "BudgetRedirectedCountries": BudgetRedirectedCountries,
                "BlockedCountries": BlockedCountries,
                "CacheControlMaxAgeOverride": CacheControlMaxAgeOverride,
                "CacheControlBrowserMaxAgeOverride": CacheControlBrowserMaxAgeOverride,
                "AddHostHeader": AddHostHeader,
                "AddCanonicalHeader": AddCanonicalHeader,
                "EnableLogging": EnableLogging,
                "LoggingIPAnonymizationEnabled": LoggingIPAnonymizationEnabled,
                "PermaCacheStorageZoneId": PermaCacheStorageZoneId,
                "AWSSigningEnabled": AWSSigningEnabled,
                "AWSSigningKey": AWSSigningKey,
                "AWSSigningRegionName": AWSSigningRegionName,
                "AWSSigningSecret": AWSSigningSecret,
                "EnableOriginShield": EnableOriginShield,
                "OriginShieldZoneCode": OriginShieldZoneCode,
                "EnableTLS1": EnableTLS1,
                "EnableTLS1_1": EnableTLS1_1,
                "CacheErrorResponses": CacheErrorResponses,
                "VerifyOriginSSL": VerifyOriginSSL,
                "LogForwardingEnabled": LogForwardingEnabled,
                "LogForwardingHostname": LogForwardingHostname,
                "LogForwardingPort": LogForwardingPort,
                "LogForwardingToken": LogForwardingToken,
                "LogForwardingProtocol": LogForwardingProtocol,
                "LoggingSaveToStorage": LoggingSaveToStorage,
                "LoggingStorageZoneId": LoggingStorageZoneId,
                "FollowRedirects": FollowRedirects,
                "ConnectionLimitPerIPCount": ConnectionLimitPerIPCount,
                "RequestLimit": RequestLimit,
                "WAFEnabled": WAFEnabled,
                "WAFDisabledRuleGroups": WAFDisabledRuleGroups,
                "WAFDisabledRules": WAFDisabledRules,
                "WAFEnableRequestHeaderLogging": WAFEnableRequestHeaderLogging,
                "WAFRequestHeaderIgnores": WAFRequestHeaderIgnores,
                "ErrorPageEnableCustomCode": ErrorPageEnableCustomCode,
                "ErrorPageCustomCode": ErrorPageCustomCode,
                "ErrorPageEnableStatuspageWidget": ErrorPageEnableStatuspageWidget,
                "ErrorPageStatuspageCode": ErrorPageStatuspageCode,
                "ErrorPageWhitelabel": ErrorPageWhitelabel,
                "OptimizerEnabled": OptimizerEnabled,
                "OptimizerDesktopMaxWidth": OptimizerDesktopMaxWidth,
                "OptimizerMobileMaxWidth": OptimizerMobileMaxWidth,
                "OptimizerImageQuality": OptimizerImageQuality,
                "OptimizerMobileImageQuality": OptimizerMobileImageQuality,
                "OptimizerEnableWebP": OptimizerEnableWebP,
                "OptimizerEnableManipulationEngine": OptimizerEnableManipulationEngine,
                "OptimizerMinifyCSS": OptimizerMinifyCSS,
                "OptimizerMinifyJavaScript": OptimizerMinifyJavaScript,
                "OptimizerWatermarkEnabled": OptimizerWatermarkEnabled,
                "OptimizerWatermarkUrl": OptimizerWatermarkUrl,
                "OptimizerWatermarkPosition": OptimizerWatermarkPosition,
                "OptimizerWatermarkOffset": OptimizerWatermarkOffset,
                "OptimizerWatermarkMinImageSize": OptimizerWatermarkMinImageSize,
                "OptimizerAutomaticOptimizationEnabled": OptimizerAutomaticOptimizationEnabled,
                "OptimizerClasses": OptimizerClasses,
                "OptimizerForceClasses": OptimizerForceClasses,
                "Type": Type,
                "OriginRetries": OriginRetries,
                "OriginConnectTimeout": OriginConnectTimeout,
                "OriginResponseTimeout": OriginResponseTimeout,
                "UseStaleWhileUpdating": UseStaleWhileUpdating,
                "UseStaleWhileOffline": UseStaleWhileOffline,
                "OriginRetry5XXResponses": OriginRetry5XXResponses,
                "OriginRetryConnectionTimeout": OriginRetryConnectionTimeout,
                "OriginRetryResponseTimeout": OriginRetryResponseTimeout,
                "OriginRetryDelay": OriginRetryDelay,
                "QueryStringVaryParameters": QueryStringVaryParameters,
                "OriginShieldEnableConcurrencyLimit": OriginShieldEnableConcurrencyLimit,
                "OriginShieldMaxConcurrentRequests": OriginShieldMaxConcurrentRequests,
                "EnableCookieVary": EnableCookieVary,
                "CookieVaryParameters": CookieVaryParameters,
                "EnableSafeHop": EnableSafeHop,
                "OriginShieldQueueMaxWaitTime": OriginShieldQueueMaxWaitTime,
                "OriginShieldMaxQueuedRequests": OriginShieldMaxQueuedRequests,
                "UseBackgroundUpdate": UseBackgroundUpdate,
                "EnableAutoSSL": EnableAutoSSL,
                "LogAnonymizationType": LogAnonymizationType,
                "LogFormat": LogFormat,
                "LogForwardingFormat": LogForwardingFormat,
                "ShieldDDosProtectionType": ShieldDDosProtectionType,
                "ShieldDDosProtectionEnabled": ShieldDDosProtectionEnabled,
            }
        )
        try:
            response = requests.post(
                self._Geturl(f"pullzone/{PullZoneID}"),
                data=values,
                headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": "Update successful",
            }

    def DeletePullZone(self, PullZoneID):
        """
        This function deletes the pullzone with the given ID

        Parameters
        ----------
        PullZoneID            : int64
                                The ID (number) of the pullzone to delete

        """
        try:
            response = requests.delete(
                self._Geturl(f"pullzone/{PullZoneID}"), headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": "Successfully Deleted Pullzone",
            }

    def PurgePullZoneCache(self, PullZoneID):
        """
        This function purges the full cache of given pullzone

        Parameters
        ----------
        PullZoneID            : int64
                                The ID (number) of the pullzone
                                who's cache is to be Purged
        """
        try:
            response = requests.post(
                self._Geturl(f"pullzone/{PullZoneID}/purgeCache"),
                headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": "successfully purged the cache of the given pullzone ",
            }

    def AddorUpdateEdgerule(
        self,
        PullZoneID,
        ActionParameter1,
        ActionParameter2,
        Enabled,
        Description,
        ActionType,
        TriggerMatchingType,
        Triggers,
        GUID=None,
    ):

        """
        This function Adds or Updates the Edgerule

        Parameters
        ----------
        PullZoneID              :int64
                                 The Id(number) of the pullzone whose edgerule
                                 is to be updated or where new edgerule has to
                                 be added

        GUID                    :number
                                 Guid of the edgerule
                                 (exclude when adding a new edgerule)

        ActionParameter1        :string
                                 The action parameter 1 of the edge rule

        ActionParameter2        :string
                                 The action parameter 2 of the edge rule

        Enabled                 :boolean
                                 The boolean

        Description             :string
                                 The description of the Edge rule

        ActionType              :number
                                 The action type of the edge rule.
                                 The possible values are: ForceSSL = 0
                                 Redirect = 1,OriginUrl = 2
                                 OverrideCacheTime = 3,BlockRequest = 4,
                                 SetResponseHeader = 5,SetRequestHeader = 6,
                                 ForceDownload =7,DisableTokenAuthentication=8,
                                 EnableTokenAuthentication = 9

        TriggerMatchingType     :number
                                 Trigger matching type

        Triggers                :array

        """
        if GUID is None:
            values = json.dumps(
                {
                    "ActionParameter1": ActionParameter1,
                    "ActionParameter2": ActionParameter2,
                    "Enabled": Enabled,
                    "Description": Description,
                    "ActionType": ActionType,
                    "TriggerMatchingType": TriggerMatchingType,
                    "Triggers": Triggers,
                }
            )
            try:
                response = requests.post(
                  self._Geturl(f"pullzone/{PullZoneID}/edgerules/addOrUpdate"),
                  data=values,
                  headers=self.headers,
                )
                response.raise_for_status()
            except HTTPError as http:
                return {"status": "error",
                        "HTTP": response.status_code,
                        "msg": http}
            except Exception as err:
                return {"status": "error",
                        "HTTP": response.status_code,
                        "msg": err}
            else:
                return {
                    "status": "success",
                    "HTTP": response.status_code,
                    "msg": "successfully added edgerule ",
                }
        else:
            values = json.dumps(
                {
                    "GUID": GUID,
                    "ActionParameter1": ActionParameter1,
                    "ActionParameter2": ActionParameter2,
                    "Enabled": Enabled,
                    "Description": Description,
                    "ActionType": ActionType,
                    "TriggerMatchingType": TriggerMatchingType,
                    "Triggers": Triggers,
                }
            )

            try:
                response = requests.post(
                  self._Geturl(f"pullzone/{PullZoneID}/edgerules/addOrUpdate"),
                  data=values,
                  headers=self.headers,
                )
                response.raise_for_status()
            except HTTPError as http:
                return {"status": "error",
                        "HTTP": response.status_code,
                        "msg": http}
            except Exception as err:
                return {"status": "error",
                        "HTTP": response.status_code,
                        "msg": err}
            else:
                return {
                    "status": "success",
                    "HTTP": response.status_code,
                    "msg": "successfully updated edgerule ",
                }

    def DeleteEdgeRule(self, PullZoneID, EdgeRuleID):
        """
        This function deletes the edgerule

        Parameters
         ---------
        PullZoneID          :number
                             ID of the pullzone that holds the edgerule

        EdgeRuleID          :string
                             ID of the edgerule to be deleted

        """
        try:
            response = requests.delete(
                self._Geturl(f"pullzone/{PullZoneID}/edgerules/{EdgeRuleID}"),
                headers=self.headers,
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": "Successfully Deleted edgerule",
            }

    def AddCustomHostname(self, PullZoneID, Hostname):
        """
        This function is used to add custom hostname to a pullzone

        Parameters
        ----------
        PullZoneID:         : int64
                              ID of the pullzone to which hostname
                              will be added

        Hostname:           : string
                              The hostname that will be registered

        """
        values = json.dumps({"Hostname": Hostname})

        try:
            response = requests.post(
                self._Geturl(f"pullzone/{PullZoneID}/addHostname"),
                data=values,
                headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": "Update was Successfull",
            }

    def DeleteCustomHostname(self, PullZoneID, Hostname):

        """
        This function is used to delete custom hostname of a pullzone

        Parameters
        ----------
        PullZoneID:         :number
                             ID of the pullzone of which custom hostname
                             will be delted

        Hostname:           :string
                             The hostname that will be deleted

        """
        params = {"Hostname": Hostname}
        try:
            response = requests.delete(
                self._Geturl(f"pullzone/{PullZoneID}/removeHostname"),
                json=params,
                headers=self.headers,
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": "Successfully Deleted Hostname",
            }

    def SetForceSSL(self, PullZoneID, Hostname, ForceSSL):
        """
        This function is used to enable or disable the ForceSSL
        setting for a pulzone

        Parameters
        ----------
        PullZoneID          :number
                             The id of the pull zone that the hostname
                             belongs to

        Hostname            :string
                             The hostname that will be updated

        ForceSSL            :boolean
                             If enabled, the zone will force redirect
                             to the SSL version of the URLs

        """
        values = json.dumps(
            {"Hostname": Hostname,
             "ForceSSL": ForceSSL}
        )
        try:
            response = requests.post(
                self._Geturl(f"pullzone/{PullZoneID}/setForceSSL"),
                data=values,
                headers=self.headers
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {
                "status": "success",
                "HTTP": response.status_code,
                "msg": "successfully added Hostname ",
            }

    def LoadFreeCertificate(self, Hostname):
        """
        This function Loads a FREE SSL Certificate to the domain
        provided by Let's Encrypt

        Parameters
        ----------
        Hostname            : string
                              Hostname that the ForceSSL certificate
                              will be loaded for

        """
        try:
            response = requests.get(
                self._Geturl("pullzone/loadFreeCertificate"),
                params={'hostname': Hostname},
                headers=self.headers,
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return self.GetPullZoneList()

    def GetVideoLibrary(self, id):
        '''
        Returns the Video Library details for the given ID

        Parameters
        ----------
        id       :  number
                    The ID of the Video Library to return

        '''
        try:
            response = requests.get(
             self._Geturl("videolibrary"), params={'id': id},
             headers=self.headers,
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {"status": "success",
                    "HTTP": response.status_code,
                    "msg": response.json()
                    }

    def DeleteVideoLibrary(self, id):
        '''
        Deletes the Video Library with the given ID

        Parameters
        ----------
        id      : number
                  The ID of the library that should be deleted
        '''
        try:
            response = requests.delete(
             self._Geturl(f"videolibrary/{id}"),
             headers=self.headers,
            )
            response.raise_for_status()
        except HTTPError as http:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": http}
        except Exception as err:
            return {"status": "error",
                    "HTTP": response.status_code,
                    "msg": err}
        else:
            return {"status": "success",
                    "HTTP": response.status_code,
                    "msg": "Deleted Video Library"
                    }
