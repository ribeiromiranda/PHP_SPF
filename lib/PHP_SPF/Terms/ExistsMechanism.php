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

use PHP_SPF\Core\SPFChecker;
use PHP_SPF\Core\DNSLookupContinuation;
use PHP_SPF\Core\Exceptions\TimeoutException;
use PHP_SPF\Core\SPFTermsRegexps;
use PHP_SPF\Core\SPFCheckerDNSResponseListener;
use PHP_SPF\Core\DNSRequest;

/**
 * This class represent the exists mechanism
 */
class ExistsMechanism extends GenericMechanism implements SPFCheckerDNSResponseListener {



    /**
     * ABNF: exists = "exists" ":" domain-spec
     */
    public static final function REGEX() {
        return "[eE][xX][iI][sS][tT][sS]" + "\\:" . SPFTermsRegexps::DOMAIN_SPEC_REGEX();
    }

    private $expandedChecker;

    public function __construct() {
        parent::__construct();
        $this->expandedChecker = new ExpandedChecker();
    }

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public function checkSPF(SPFSession $spfData) {
        // update currentDepth
        $spfData->increaseCurrentDepth();

        $spfData->pushChecker(expandedChecker);
        return $this->macroExpand->checkExpand($this->getDomain(), $spfData, MacroExpand::DOMAIN);
    }

    /**
     * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
     */
    public function onDNSResponse(DNSResponse $response, SPFSession $spfSession) {
        $aRecords;

        try {
            $aRecords = $response->getResponse();
        } catch (TimeoutException $e) {
            $spfSession->setAttribute(Directive::ATTRIBUTE_MECHANISM_RESULT(), false);
            return null;
        }

        if ($aRecords != null && count($aRecords) > 0) {
            $spfSession->setAttribute(Directive::ATTRIBUTE_MECHANISM_RESULT(), true);
            return null;
        }

        // No match found
        $spfSession->setAttribute(Directive::ATTRIBUTE_MECHANISM_RESULT(), false);
        return null;
    }

    /**
     * @see java.lang.Object#toString()
     */
    public function toString() {
        return "exists:" . $this->getDomain();
    }

}

final class ExpandedChecker implements SPFChecker {

    /*
     * (non-Javadoc)
    * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
    */
    public function checkSPF(SPFSession $spfData) {
        $host = $this->expandHost($spfData);
        return new DNSLookupContinuation(new DNSRequest($host, DNSRequest::A), ExistsMechanism.this);
    }
}