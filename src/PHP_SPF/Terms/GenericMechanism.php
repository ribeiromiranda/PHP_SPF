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

use PHP_SPF\Core\MacroExpandEnabled;
use PHP_SPF\Core\LogEnabled;
use PHP_SPF\Core\SPFSession;
use PHP_SPF\Core\Logger;
use PHP_SPF\Core\MacroExpand;

/**
 * This abstract class represent a gerneric mechanism
 *
 */
abstract class GenericMechanism implements Mechanism, ConfigurationEnabled, LogEnabled, MacroExpandEnabled {

    /**
     * ABNF: ip4-cidr-length = "/" 1*DIGIT
     */
    protected static final function IP4_CIDR_LENGTH_REGEX() {
        return "/(\\d+)";
    }


    /**
     * ABNF: ip6-cidr-length = "/" 1*DIGIT
     */
    protected static final function IP6_CIDR_LENGTH_REGEX() {
        return "/(\\d+)";
    }

    /**
     * ABNF: dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]
     */
    protected static final function DUAL_CIDR_LENGTH_REGEX() {
        return "(?:"
            . self::IP4_CIDR_LENGTH_REGEX() . ")?" + "(?:/" . self::IP6_CIDR_LENGTH_REGEX()
            . ")?";
    }

    private $domain;

    protected $log;

    protected $macroExpand;

    /**
     * Expand the hostname
     *
     * @param spfData The SPF1Data to use
     * @throws PermErrorException get Thrown if invalid macros are used
     */
    protected function expandHost(SPFSession $spfData) {
        $host = $this->getDomain();
        if ($host == null) {
            $host = $spfData->getCurrentDomain();
        } else {
            // throws a PermErrorException that we cat pass through
            $host = $this->macroExpand->expand($host, $spfData, MacroExpand::DOMAIN);
        }
        return $host;
    }

    /**
     * @see org.apache.james.jspf.terms.ConfigurationEnabled#config(Configuration)
     */
    public function config(Configuration $params) {
        if ($params->groupCount() >= 1 && $params->group(1) != null) {
            $domain = $params->group(1);
        } else {
            $domain = null;
        }
    }

    /**
     * @return Returns the domain.
     */
    protected function getDomain() {
        return $this->domain;
    }

    /**
     * @see org.apache.james.jspf.core.LogEnabled#enableLogging(org.apache.james.jspf.core.Logger)
     */
    public function enableLogging(Logger $logger) {
        $this->log = $logger;
    }

    /**
     * @see org.apache.james.jspf.core.MacroExpandEnabled#enableMacroExpand(org.apache.james.jspf.core.MacroExpand)
     */
    public function enableMacroExpand(MacroExpand $macroExpand) {
        $this->macroExpand = $macroExpand;
    }
}
