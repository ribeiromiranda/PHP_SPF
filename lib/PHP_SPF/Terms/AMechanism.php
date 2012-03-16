<?php
/****************************************************************
* Licensed to the Apache Software Foundation (ASF) under one   *
* or more contributor license agreements.  See the NOTICE file *
* distributed with this work for additional information        *
* regarding copyright ownership.  The ASF licenses this file   *
* to you under the Apache License, Version 2.0 (the            *
* "License"); you may not use this file except in compliance   *
* with the License.  You may obtain a copy of the License at   *
*                                                              *
*   http://www.apache.org/licenses/LICENSE-2.0                 *
*                                                              *
* Unless required by applicable law or agreed to in writing,   *
* software distributed under the License is distributed on an  *
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY       *
* KIND, either express or implied.  See the License for the    *
* specific language governing permissions and limitations      *
* under the License.                                           *
****************************************************************/

namespace PHP_SPF\Terms;

use PHP_SPF\Core\IPAddr;
use PHP_SPF\Core\Exceptions\PermErrorException;
use PHP_SPF\Core\SPFTermsRegexps;
use PHP_SPF\Core\MacroExpand;
use PHP_SPF\Core\SPFCheckerDNSResponseListener;
use PHP_SPF\Core\Inet6Util;
use PHP_SPF\Core\SPFChecker;

/**
 * This class represent the a mechanism
 *
 */
class AMechanism extends GenericMechanism implements SPFCheckerDNSResponseListener {

    public static final function ATTRIBUTE_AMECHANISM_IPV4CHECK() {
        return "AMechanism.ipv4check";
    }

    /**
     * ABNF: A = "a" [ ":" domain-spec ] [ dual-cidr-length ]
     */
    public static final function REGEX() {
        return  "[aA]" . "(?:\\:"
            . SPFTermsRegexps::DOMAIN_SPEC_REGEX() . ")?" . "(?:"
            . self::DUAL_CIDR_LENGTH_REGEX() . ")?";
    }


    private $ip4cidr;

    private $ip6cidr;

    private $expandedChecker;

    public function __construct() {
        $this->expandedChecker = new ExpandedChecker();
    }

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public function checkSPF(SPFSession $spfData) {
        // update currentDepth
        $spfData->increaseCurrentDepth();

        $spfData->pushChecker($this->expandedChecker);

        return $this->macroExpand->checkExpand($this->getDomain(), $spfData, MacroExpand::DOMAIN);
    }

    /**
     * @see org.apache.james.jspf.terms.GenericMechanism#config(Configuration)
     */
    public function config(Configuration $params) {
        parent::config($params);
        if (params.groupCount() >= 2 && params.group(2) != null) {
            $this->ip4cidr = intval($params->group(2));
            if ($ip4cidr > 32) {
                throw new PermErrorException("Ivalid IP4 CIDR length");
            }
        } else {
            $this->ip4cidr = 32;
        }
        if ($params->groupCount() >= 3 && $params->group(3) != null) {
            $this->ip6cidr = intval($params->group(3).toString());
            if ($this->ip6cidr > 128) {
                throw new PermErrorException("Ivalid IP6 CIDR length");
            }
        } else {
            $this->ip6cidr = 128;
        }
    }

    /**
     * Check if the given ipaddress array contains the provided ip.
     *
     * @param checkAddress
     *            The ip wich should be contained in the given ArrayList
     * @param addressList
     *            The ip ArrayList.
     * @return true or false
     * @throws PermErrorException
     */
    public function checkAddressList(IPAddr $checkAddress, array $addressList, $cidr) {
        for ($i = 0; $i < count($addressList); $i++) {
            $ip = $addressList[$i];

            // Check for empty record
            if ($ip != null) {
                // set the mask in the address.
                // TODO should we use cidr from the parameters or the input checkAddress cidr?
                $ipAddr = IPAddr::getAddress($ip, $checkAddress->getMaskLength());
                if ($checkAddress->getMaskedIPAddress()->equals(
                        $ipAddr->getMaskedIPAddress())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @return Returns the ip4cidr.
     */
    protected function getIp4cidr() {
        return $this->ip4cidr;
    }

    /**
     * @return Returns the ip6cidr.
     */
    protected function getIp6cidr() {
        return $this->ip6cidr;
    }

    /**
     * @see java.lang.Object#toString()
     */
    protected function toString($mechKey = 'a') {
        $res = '';
        $res .= $mechKey;
        if ($this->getDomain() != null) {
            $res .= ":" . $this->getDomain();
        }
        if ($this->getIp4cidr() != 32) {
            $res .= "/"+ $this->getIp4cidr();
        }
        if ($this->getIp6cidr() != 128) {
            $res .= "//" . $this->getIp4cidr();
        }
        return $res;
    }


    /**
     * Retrieve a list of AAAA records
     */
    public function getAAAARecords($strServer) {
        $listAAAAData = null;
        if (IPAddr::isIPV6($strServer)) {
            // Address is already an IP address, so add it to list
            $listAAAAData = array();
            $listAAAAData[] = $strServer;
        }
        return $listAAAAData;
    }


    /**
     * Get a list of IPAddr's for a server
     *
     * @param strServer
     *            The hostname or ipAddress whe should get the A-Records for
     * @return The ipAddresses
     */
    public function getARecords($strServer) {
        $listAData = null;
        if (IPAddr::isIPAddr($strServer)) {
            $listAData = array();
            $listAData[] = $strServer;
        }
        return $listAData;
    }

    /**
     * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
     */
    public function onDNSResponse(DNSResponse $response, SPFSession $spfSession) {
        $listAData = null;
        try {
            $listAData = $response->getResponse();
        } catch (TimeoutException $e) {
            throw new TempErrorException("Timeout querying dns server");
        }
        // no a records just return null
        if ($listAData == null) {
            $spfSession->setAttribute(Directive::ATTRIBUTE_MECHANISM_RESULT(), false);
            return null;
        }

        $this->ipv4check = (boolean) $spfSession->getAttribute(self::ATTRIBUTE_AMECHANISM_IPV4CHECK());
        if ($this->ipv4check->booleanValue()) {

            $checkAddress = IPAddr::getAddress($spfSession->getIpAddress(),
                    $this->getIp4cidr());

            if ($this->checkAddressList($this->checkAddress, $listAData, $this->getIp4cidr())) {
                $spfSession->setAttribute(Directive::ATTRIBUTE_MECHANISM_RESULT(), true);
                return null;
            }

        } else {

            $checkAddress = IPAddr::getAddress($spfSession->getIpAddress(),
                    $this->getIp6cidr());

            if ($this->checkAddressList($checkAddress, $listAData, $this->getIp6cidr())) {
                $spfSession->setAttribute(Directive::ATTRIBUTE_MECHANISM_RESULT(), true);
                return null;
            }
        }

        $spfSession->setAttribute(Directive::ATTRIBUTE_MECHANISM_RESULT(), false);
        return null;
    }

}


final class ExpandedChecker implements SPFChecker {

    /**
     * (non-Javadoc)
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public function checkSPF(SPFSession $spfData) {
        // Get the right host.
        $host = $this->expandHost($spfData);

        // get the ipAddress
        try {
            $validIPV4Address = Inet6Util::isValidIPV4Address($spfData->getIpAddress());
            $spfData->setAttribute(ATTRIBUTE_AMECHANISM_IPV4CHECK, Boolean.valueOf(validIPV4Address));
            if ($validIPV4Address) {

                $aRecords = $this->getARecords(host);
                if (aRecords == null) {
                    try {
                        $request = new DNSRequest($host, DNSRequest::A);
                        return new DNSLookupContinuation($request, AMechanism.this);
                    } catch (NoneException $e) {
                        return $this->onDNSResponse(new DNSResponse($aRecords), $spfData);
                    }
                } else {
                    return $this->onDNSResponse(new DNSResponse($aRecords), $spfData);
                }

            } else {

                $aaaaRecords = $this->getAAAARecords(host);
                if ($aaaaRecords == null) {
                    try {
                        $request = new DNSRequest($host, DNSRequest::AAAA);
                        return new DNSLookupContinuation($request, AMechanism.this);
                    } catch (NoneException $e) {
                        return $this->onDNSResponse(new DNSResponse($aaaaRecords), $spfData);
                    }
                } else {
                    return $this->onDNSResponse(new DNSResponse($aaaaRecords), $spfData);
                }

            }
            // PermError / TempError
            // TODO: Should we replace this with the "right" Exceptions ?
        } catch (\Exception $e) {
            $this->log->debug("No valid ipAddress: ",e);
            throw new PermErrorException("No valid ipAddress: " . $spfData->getIpAddress());
        }
    }
}