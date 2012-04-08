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

namespace PHP_SPF\Executor;

use PHP_SPF\Core\Exceptions\SPFErrorConstants;
use PHP_SPF\Core\SPFSession;

/**
 * This class is used to return the result of an SPF lookup.
 *
 */
class SPFResult  {

    protected $headerTextAsString = "";

    protected $HEADER_NAME = "Received-SPF";

    protected $result = null;

    protected $explanation = null;

    /**
     * Construct SPFResult
     *
     * @param spfSession the SPFSession
     */
    public function __construct(SPFSession $spfSession = null) {
        $this->setSPFSession($spfSession);
    }

    /**
     * Initialize the result.
     *
     * @param spfSession
     */
    protected function setSPFSession(SPFSession $spfSession) {
        $this->explanation = $spfSession->getExplanation();
        $this->result = $spfSession->getCurrentResultExpanded();
        $this->headerTextAsString = $this->generateHeader($this->result, $spfSession);
    }
    //$this->
    /**
     * Get the full SPF-Header (headername and headertext)
     *
     * @return SPF-Header
     */
    public function getHeader() {
        return $this->HEADER_NAME . ": " . $this->getHeaderText();
    }

    /**
     * Get the SPF-Headername
     *
     * @return headername
     */
    public function getHeaderName() {
        return $this->HEADER_NAME;
    }

    /**
     * Get SPF-Headertext
     *
     * @return headertext
     */
    public function getHeaderText() {
        return $this->headerTextAsString != null ? $this->headerTextAsString : "";
    }

    /**
     * Generate a SPF-Result header
     *
     * @param result The result we should use to generate the header
     */
    private function generateHeader($result, SPFSession $spfData) {
        $headerText = '';

        if ($result == SPFErrorConstants::PASS_CONV) {
            $headerText .= $result . " (spfCheck: domain of "
                    . $spfData->getCurrentDomain() . " designates "
                    . $spfData->getIpAddress() . " as permitted sender) ";
        } else if ($result === SPFErrorConstants::FAIL_CONV) {
            $headerText .= $result . " (spfCheck: domain of "
                    . $spfData->getCurrentDomain() . " does not designate "
                    . $spfData->getIpAddress() . " as permitted sender) ";
        } else if ($result === SPFErrorConstants::NEUTRAL_CONV
                || $result === SPFErrorConstants::NONE_CONV) {
            $headerText .= $result . " (spfCheck: " . $spfData->getIpAddress()
                    . " is neither permitted nor denied by domain of "
                    . $spfData->getCurrentDomain() . ") ";

        } else if ($result === SPFErrorConstants::SOFTFAIL_CONV) {
            $headerText .= $result . " (spfCheck: transitioning domain of "
                    . $spfData->getCurrentDomain() . " does not designate "
                    . $spfData->getIpAddress() . " as permitted sender) ";
        } else if ($result === SPFErrorConstants::PERM_ERROR_CONV) {
            $headerText .= "{$result} (spfCheck: Error in processing SPF Record) ";

        } else if (result.equals(SPFErrorConstants::TEMP_ERROR_CONV)) {
            $headerText .= "{$result} (spfCheck: Error in retrieving data from DNS) ";

        }

        if (strlen($headerText) > 0) {
            $headerText .= "client-ip=" . $spfData->getIpAddress()
                    . "; envelope-from=" . $spfData->getMailFrom() . "; helo="
                    . $spfData->getHostName() . ";";
            $headerTextAsString = $headerText;
        }

        return $headerText;
    }

    /**
     * Get the result string
     *
     * @see SPF1Utils
     * @return result
     */
    public function getResult() {
        return $this->result;
    }

    /**
     * Get the explanation string
     * If no explanation exists return the empty string
     *
     * @return explanation
     */
    public function getExplanation() {
        return $this->explanation != null ? $this->explanation : "";
    }
}
