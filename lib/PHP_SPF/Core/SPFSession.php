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

namespace PHP_SPF\Core;

/**
 *
 * This Class is used as a container between the other classes. All necessary
 * values get stored here and get retrieved from here.
 *
 */
use PHP_SPF\Core\Exceptions\PermErrorException;

class SPFSession implements MacroData {

    private $ipAddress = ""; // also used for (i)<sending-host>

    private $mailFrom = ""; // (s)<responsible-sender>

    private $hostName = ""; // (h)<sender-domain>

    private $currentSenderPart = ""; // (l)

    private $currentDomain = ""; // (d)<current-domain>

    private $inAddress = "in-addr"; // (v)

    private $clientDomain = null; // (p)

    private $senderDomain = ""; // (o)

    private $readableIP = null; // (c)

    private $receivingDomain = null; // (r)

    private $currentDepth = 0;

    /**
     * The maximum mechanismn which are allowed to use
     */
    const MAX_DEPTH = 10;

    private $explanation = null;

    private $currentResult = null;

    private $ignoreExplanation = false;

    private $attributes = array();

    private $checkers;// = new Stack<SPFChecker>();

    private $currentResultExpanded;

    /**
     * Build the SPFSession from the given parameters
     *
     * @param mailFrom
     *            The emailaddress of the sender
     * @param heloDomain
     *            The helo provided by the sender
     * @param clientIP
     *            The ipaddress of the client
     *
     */
    public function __construct($mailFrom, $heloDomain, $clientIP) {
        $this->mailFrom = trim($mailFrom);
        $this->hostName = trim($heloDomain);

        try {
            $this->ipAddress = IPAddr::getProperIpAddress(trim($clientIP));
            // get the in Address
            $this->inAddress = IPAddr::getInAddress($clientIP);
        } catch (PermErrorException $e) {
            // ip was not rfc conform
            $this->setCurrentResultExpanded(e.getResult());
        }

        // if nullsender is used postmaster@helo will be used as email
        if ($mailFrom === "") {
            $this->currentSenderPart = "postmaster";
            $this->senderDomain = hostName;
            $this->mailFrom = currentSenderPart + "@" + hostName;
        } else {
            $fromParts = explode('@', $this->mailFrom);
            // What to do when mailFrom is "@example.com" ?
            if (count($fromParts) > 1) {
                $this->senderDomain = $fromParts[count($fromParts)-1];
                $this->currentSenderPart = substr($this->mailFrom, 0, strlen($this->mailFrom) - strlen($this->senderDomain) - 1);
                if (count($this->currentSenderPart) == 0) {
                    $this->currentSenderPart = "postmaster";
                }
            } else {
                $this->currentSenderPart = "postmaster";
                $this->senderDomain = $this->mailFrom;
            }
        }
        $this->currentDomain = $this->senderDomain;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getCurrentSenderPart()
     */
    public function getCurrentSenderPart() {
        return $this->currentSenderPart;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getMailFrom()
     */
    public function getMailFrom() {
        return $this->mailFrom;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getHostName()
     */
    public function getHostName() {
        return hostName;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getCurrentDomain()
     */
    public function getCurrentDomain() {
        return currentDomain;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getInAddress()
     */
    public function getInAddress() {
        return inAddress;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getClientDomain()
     */
    public function getClientDomain() {
        return $this->clientDomain;
    }

    /**
     * Sets the calculated clientDomain
     * @param clientDomain the new clientDomain
     */
    public function setClientDomain($clientDomain) {
        $this->clientDomain = $clientDomain;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getSenderDomain()
     */
    public function getSenderDomain() {
        return senderDomain;
    }

    /**
     * Get the ipAddress which was used to connect
     *
     * @return ipAddres
     */
    public function getIpAddress() {
        return $this->ipAddress;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getMacroIpAddress()
     */
    public function getMacroIpAddress() {

        if (IPAddr::isIPV6($this->ipAddress)) {
            try {
                return IPAddr::getAddress($this->ipAddress)->getNibbleFormat();
            } catch (PermErrorException $e) {
            }
        }

        return $ipAddress;

    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getTimeStamp()
     */
    public function getTimeStamp() {
        return microtime();
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getReadableIP()
     */
    public function getReadableIP() {
        if ($this->readableIP == null) {
            $this->readableIP = IPAddr::getReadableIP($this->ipAddress);
        }
        return $this->readableIP;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getReceivingDomain()
     */
    public function getReceivingDomain() {
        return $this->receivingDomain;
    }

    /**
     * Sets the new receiving domain
     *
     * @param receivingDomain the new receiving domain
     */
    public function setReceivingDomain($receivingDomain) {
        $this->receivingDomain = $receivingDomain;
    }

    /**
     * Increase the current depth:
     *
     * if we reach maximum calls we must throw a PermErrorException. See
     * SPF-RFC Section 10.1. Processing Limits
     */
    public function increaseCurrentDepth() {
        $this->currentDepth++;
        if ($this->currentDepth > self::MAX_DEPTH)
            throw new PermErrorException(
                    "Maximum mechanism/modifiers calls done: {$this->currentDepth}");
    }

    /**
     * Set the currentDomain
     *
     * @param domain The current used domain
     */
    public function setCurrentDomain($domain) {
        $this->currentDomain = $domain;
    }

    /**
     * Set the explanation which will returned when a fail match
     *
     * @param explanation
     *            This String is set as explanation
     */
    public function setExplanation($explanation) {
        $this->explanation = $explanation;
    }

    /**
     * Get the explanation
     *
     * @return explanation
     */
    public function getExplanation() {
        return $this->explanation;
    }

    /**
     * Set the current result
     *
     * @param result
     *            result
     */
    public function setCurrentResult($result) {
        $this->currentResult = $result;
    }

    /**
     * Get the current result
     *
     * @return current result
     */
    public function getCurrentResult() {
        return $this->currentResult;
    }

    /**
     * Get set to true if the explanation should be ignored
     *
     * @param ignoreExplanation true or false
     */
    public function setIgnoreExplanation($ignoreExplanation) {
        $this->ignoreExplanation = $ignoreExplanation;
    }

    /**
     * Return true if the explanation should be ignored
     *
     * @return true of false
     */
    public function ignoreExplanation() {
        return $this->ignoreExplanation;
    }

    /**
     * Retrieve a stored attribute
     *
     * @param key the attribute key
     * @return the stored attribute
     */
    public function getAttribute($key) {
        return $this->attributes[$key];
    }

    /**
     * Sets a new attribute in the session
     *
     * @param key attribute key
     * @param value the value for this attribute
     */
    public function setAttribute($key, $value) {
        $this->attributes.put(key, value);
    }

    /**
     * Remove the attribute stored under the given key
     *
     * @param key the key of the attribute
     * @return object the attribute which was stored with the key
     */
    public function removeAttribute($key) {
        return $this->attributes.remove(key);
    }

    /**
     * Add the given SPFChecker on top of the stack
     *
     * @param checker
     */
    public function pushChecker(SPFChecker $checker) {
        $this->checkers.push(checker);
    }

    /**
     * Remove the SPFChecker on the top and return it. If no SPFChecker is left
     * null is returned
     *
     * @return the last checker
     */
    public function popChecker() {
        if ($this->checkers.isEmpty()) {
            return null;
        } else {
            $checker = $this->checkers.pop();
            return $checker;
        }
    }

    /**
     * @param result
     */
    public function setCurrentResultExpanded($result) {
        $this->currentResultExpanded = $result;
    }

    /**
     * @return current result converted/expanded
     */
    public function getCurrentResultExpanded() {
        return $this->currentResultExpanded;
    }

}