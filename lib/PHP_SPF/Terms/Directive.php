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

use PHP_SPF\Core\Exceptions\PermErrorException;
use PHP_SPF\Core\Logger;
use PHP_SPF\Core\SPFSession;
use PHP_SPF\Core\SPFChecker;

/**
 * A Directive is a mechanism with a resulting qualifier.
 */
class Directive implements SPFChecker {

    public static final function ATTRIBUTE_MECHANISM_RESULT() {
        return "Mechanism.result";
    }

    protected $qualifier = "+";

    private $mechanism = null;

    private $log;

    private $resultChecker;

    /**
     * Construct Directive
     *
     * @param qualifier The qualifier to use. Valid qualifier are: +, -, ~, ?
     * @param mechanism The Mechanism
     * @throws PermErrorException Get thrown if a PermError should returned
     */
    public function __construct($qualifier, Mechanism $mechanism, Logger $logger) {
        $this->log = $logger;
        if ($qualifier == null) {
            throw new PermErrorException("Qualifier cannot be null");
        }
        $this->qualifier = $qualifier;
        if ($mechanism == null) {
            throw new PermErrorException("Mechanism cannot be null");
        }
        $this->resultChecker  = new MechanismResultChecker();
        $this->mechanism = $mechanism;
    }

    /**
     * Run the Directive
     *
     * @param spfSession The SPFSession to use
     * @return The qualifier which was returned
     * @throws PermErrorException get thrown if a PermError should returned
     * @throws TempErrorException get thrown if a TempError should returned
     * @throws NoneException get thrown if a NoneException should returned;
     * @throws NeutralException
     */
    public function checkSPF(SPFSession $spfSession) {
        // if already have a current result we don't run this
        if ($spfSession->getCurrentResult() == null && $spfSession->getCurrentResultExpanded() == null) {

            $spfSession->removeAttribute(self::ATTRIBUTE_MECHANISM_RESULT());

            $spfSession->pushChecker($resultChecker);

            $spfSession->pushChecker($mechanism);

        }
        return null;
    }

    /**
     * Return the Mechanism which should be run
     *
     * @return the Mechanism
     */
    public function getMechanism() {
        return mechanism;
    }

    /**
     * Return the Qualifier
     *
     * @return the qualifier
     */
    public function getQualifier() {
        return qualifier;
    }

    public function toString() {
        return qualifier + mechanism;
    }
}

class MechanismResultChecker implements SPFChecker {
    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public function checkSPF(SPFSession $spfData) {
        $res = (boolean) $spfData->getAttribute(ATTRIBUTE_MECHANISM_RESULT);
        if ($res != null ? res.booleanValue() : true) {
            if ($this->qualifier === '') {
                $spfData.setCurrentResult(SPF1Constants.PASS);
            } else {
                $spfData.setCurrentResult(qualifier);
            }

            $this->log->info("Processed directive matched: " + Directive.this + " returned " + spfData.getCurrentResult());
        } else {
            $this->log->debug("Processed directive NOT matched: " . $this);
        }
        return null;
    }
}