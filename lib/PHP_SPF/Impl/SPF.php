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

namespace PHP_SPF\Impl;

use PHP_SPF\Core\Logger;
use PHP_SPF\Core\Exceptions\SPFErrorConstants;
use PHP_SPF\Core\SPFSession;
use PHP_SPF\Core\SPF1Utils;
use PHP_SPF\Core\SPFChecker;

/**
 * This class is used to generate a SPF-Test and provided all intressting data.
 */
class SPF implements SPFChecker {


    private $dnsProbe;

    private $parser;

    private $log;

    private $defaultExplanation = null;

    private $useBestGuess = false;

    private $fallBack;

    private $override;

    private $useTrustedForwarder = false;

    private $mustEquals = false;

    private $macroExpand;

    private $executor;

    /**
     * Uses passed logger and passed dnsServicer
     *
     * @param dnsProbe the dns provider
     * @param logger the logger to use
     */
    public function __construct(DNSService $dnsProbe, Logger $logger) {
        super();
        $this->dnsProbe = dnsProbe;
        $this->log = logger;
        $wiringService = new WiringServiceTable();
        $wiringService.put(LogEnabled.cclass, $this->log);
        $wiringService.put(DNSServiceEnabled.cclass, $this->dnsProbe);
        $this->macroExpand = new MacroExpand($logger->getChildLogger("macroExpand"), this.dnsProbe);
        $wiringService.put(MacroExpandEnabled.cclass, $this->macroExpand);
        $this->parser = new RFC4408SPF1Parser($logger->getChildLogger("parser"), new DefaultTermsFactory($logger->getChildLogger("termsfactory"), $wiringService));
        // We add this after the parser creation because services cannot be null
        $wiringService.put(SPFCheckEnabled.cclass, $this);
        $this->executor = new SynchronousSPFExecutor($this->log, $dnsProbe);
    }


    /**
     * Uses passed services
     *
     * @param dnsProbe the dns provider
     * @param parser the parser to use
     * @param logger the logger to use
     */
/*     public SPF(DNSService dnsProbe, SPFRecordParser parser, Logger logger, MacroExpand macroExpand, SPFExecutor executor) {
        super();
        this.dnsProbe = dnsProbe;
        this.parser = parser;
        this.log = logger;
        this.macroExpand = macroExpand;
        this.executor = executor;
    } */




    /**
     * Run check for SPF with the given values.
     *
     * @param ipAddress
     *            The ipAddress the connection is comming from
     * @param mailFrom
     *            The mailFrom which was provided
     * @param hostName
     *            The hostname which was provided as HELO/EHLO
     * @return result The SPFResult
     */
   /*  public SPFResult checkSPF$ ipAddress, $mailFrom, $hostName) {
        SPFSession spfData = null;

        // Setup the data
        spfData = new SPFSession(mailFrom, hostName, ipAddress);


        SPFChecker resultHandler = new DefaultSPFChecker(log);

        spfData.pushChecker(resultHandler);
        spfData.pushChecker(this);

        FutureSPFResult ret = new FutureSPFResult(log);

        executor.execute(spfData, ret);

        // if we call ret.getResult it waits the result ;-)
        //        log.info("[ipAddress=" + ipAddress + "] [mailFrom=" + mailFrom
        //                + "] [helo=" + hostName + "] => " + ret.getResult());

        return ret;

    } */


    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public function checkSPF(SPFSession $spfData){

        // if we already have a result we don't need to add further processing.
        if (spfData.getCurrentResultExpanded() == null && spfData.getCurrentResult() == null) {
            $policyChecker = new PolicyChecker($this->getPolicies());
            $recordChecker = new SPFRecordChecker();

            $spfData.pushChecker(recordChecker);
            $spfData.pushChecker(policyChecker);
        }

        return null;
    }

    /**
     * Return a default policy for SPF
     */
    public function getPolicies() {

        $policies = array();

        if ($this->override != null) {
            $policies[] = new SPFPolicyChecker($this->override);
        }

        $policies[] = new InitialChecksPolicy();

        if (mustEquals) {
            policies.add(new SPFStrictCheckerRetriever());
        } else {
            policies.add(new SPFRetriever());
        }

        if (useBestGuess) {
            policies.add(new SPFPolicyPostFilterChecker(new BestGuessPolicy()));
        }

        policies.add(new SPFPolicyPostFilterChecker(new ParseRecordPolicy(parser)));

        if (fallBack != null) {
            policies.add(new SPFPolicyPostFilterChecker(fallBack));
        }

        policies.add(new SPFPolicyPostFilterChecker(new NoSPFRecordFoundPolicy()));

        // trustedForwarder support is enabled
        if (useTrustedForwarder) {
            policies.add(new SPFPolicyPostFilterChecker(new TrustedForwarderPolicy(log)));
        }

        policies.add(new SPFPolicyPostFilterChecker(new NeutralIfNotMatchPolicy()));

        policies.add(new SPFPolicyPostFilterChecker(new DefaultExplanationPolicy(log, defaultExplanation, macroExpand)));

        return policies;
    }

    /**
     * Set the amount of time (in seconds) before an TermError is returned when
     * the dnsserver not answer. Default is 20 seconds.
     *
     * @param timeOut The timout in seconds
     */
    public function setTimeOut($timeOut) {
        log.debug("TimeOut was set to: " + timeOut);
        dnsProbe.setTimeOut(timeOut);
    }

    /**
     * Set the default explanation which will be used if no explanation is found in the SPF Record
     *
     * @param defaultExplanation The explanation to use if no explanation is found in the SPF Record
     */
    public function setDefaultExplanation($defaultExplanation) {
        $this->defaultExplanation = defaultExplanation;
    }

    /**
     * Set to true for using best guess. Best guess will set the SPF-Record to "a/24 mx/24 ptr ~all"
     * if no SPF-Record was found for the doamin. When this was happen only pass or netural will be returned.
     * Default is false.
     *
     * @param useBestGuess true to enable best guess
     */
    public function setUseBestGuess($useBestGuess) {
        $this->useBestGuess  = $useBestGuess;
    }


    /**
     * Return the FallbackPolicy object which can be used to
     * provide default spfRecords for hosts which have no records
     *
     * @return the FallbackPolicy object
     */
    public function getFallbackPolicy() {
        // Initialize fallback policy
        if ($this->fallBack == null) {
            $this->fallBack =  new FallbackPolicy($this->log->getChildLogger("fallbackpolicy"), $parser);
        }
        return $this->fallBack;
    }

    /**
     * Set to true to enable trusted-forwarder.org whitelist. The whitelist will only be queried if
     * the last Mechanism is -all or ?all.
     * See http://trusted-forwarder.org for more informations
     * Default is false.
     *
     * @param useTrustedForwarder true or false
     */
    public function setUseTrustedForwarder($useTrustedForwarder) {
        $this->useTrustedForwarder = $useTrustedForwarder;
    }

    /**
     * Return the OverridePolicy object which can be used to
     * override spfRecords for hosts
     *
     * @return the OverridePolicy object
     */
    public function getOverridePolicy() {
        if ($this->override == null) {
            $this->override = new OverridePolicy($this->log->getChildLogger("overridepolicy"), $parser);
        }
        return $this->override;
    }

    /**
     * Set to true if a PermError should returned when a domain publish a SPF-Type
     * and TXT-Type SPF-Record and both are not equals. Defaults false
     *
     * @param mustEquals true or false
     */
    public function setSPFMustEqualsTXT($mustEquals) {
        $this->mustEquals = $mustEquals;
    }
}

class SPFRecordChecker implements SPFChecker {

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public function checkSPF(SPFSession $spfData) {

        $spfRecord = $spfData->getAttribute(SPF1Utils::ATTRIBUTE_SPF1_RECORD);
        // make sure we cleanup the record, for recursion support
        $spfData.removeAttribute(SPF1Utils::ATTRIBUTE_SPF1_RECORD);

        $policyCheckers = array();

        $i = spfRecord.iterator();
        while ($i.hasNext()) {
            $checker = i.next();
            policyCheckers.add(checker);
        }

        while (policyCheckers.size() > 0) {
            $removeLast = policyCheckers.removeLast();
            $spfData.pushChecker(removeLast);
        }

        return null;
    }
}

class PolicyChecker implements SPFChecker {

    private $policies;

    public function __construct(array $policies) {
        $this->policies = $policies;
    }

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public function checkSPF(SPFSession $spfData) {

        while (count($this->policies) > 0) {
            $removeLast = $this->policies.removeLast();
            $spfData->pushChecker(removeLast);
        }

        return null;
    }
}

class SPFPolicyChecker implements SPFChecker {
    private $policy;

    /**
     * @param policy
     */
    public function __construct(Policy $policy) {
        $this->policy = $policy;
    }

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public function checkSPF(SPFSession $spfData) {
        $res = $spfData.getAttribute(SPF1Utils::ATTRIBUTE_SPF1_RECORD);
        if (res == null) {
            $res = policy.getSPFRecord(spfData.getCurrentDomain());
            spfData.setAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD, res);
        }
        return null;
    }

    public function toString() {
        return "PC:" . $policy->toString();
    }
}

class SPFPolicyPostFilterChecker implements SPFChecker {
    private $policy;

    /**
     * @param policy
     */
    public function __construct(PolicyPostFilter $policy) {
        $this->policy = $policy;
    }

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public function checkSPF(SPFSession $spfData) {
        $res = $spfData.getAttribute(SPF1Utils::ATTRIBUTE_SPF1_RECORD);
        $res = $this->policy->getSPFRecord($spfData->getCurrentDomain(), $res);
        $spfData->setAttribute(SPF1Utils::ATTRIBUTE_SPF1_RECORD, $res);
        return null;
    }

    public function toString() {
        return "PFC:" . $this->policy->toString();
    }
}


class DefaultSPFChecker implements SPFChecker, SPFCheckerExceptionCatcher {

    private $log;

    public function __construct(Logger $log) {
        $this->log = $log;
    }

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public function checkSPF(SPFSession $spfData) {
        if ($spfData->getCurrentResultExpanded() == null) {
            $resultChar = $spfData->getCurrentResult() != null ? $spfData->getCurrentResult() : "";
            $result = SPF1Utils::resultToName($resultChar);
            $spfData->setCurrentResultExpanded($result);
        }
        return null;
    }

    /**
     * @see org.apache.james.jspf.core.SPFCheckerExceptionCatcher#onException(java.lang.Exception, org.apache.james.jspf.core.SPFSession)
     */
    public function onException(\Exception $exception, SPFSession $session) {
        $result;
        if ($exception instanceof SPFResultException) {
            $result = $exception->getResult();
            if (!SPFErrorConstants::NEUTRAL_CONV.equals(result)) {
                $this->log->warn($exception->getMessage(), $exception);
            }
        } else {
            // this should never happen at all. But anyway we will set the
            // result to neutral. Safety first ..
            $this->log->error($exception->getMessage(), $exception);
            $result = SPFErrorConstants::NEUTRAL_CONV;
        }
        $session->setCurrentResultExpanded($result);
    }
}