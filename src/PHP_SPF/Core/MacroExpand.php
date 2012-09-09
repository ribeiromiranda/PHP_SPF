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

use PHP_SPF\Core\Exceptions\PermErrorException;

/**
 * This Class is used to convert all macros which can used in SPF-Records to the
 * right values!
 *
 */
class MacroExpand {

    private $domainSpecPattern;

    private $macroStringPattern;

    private $macroLettersPattern;

    private $macroLettersExpPattern;

    private $cellPattern;

    private $log;

    private $dnsProbe;

    const EXPLANATION = true;

    const DOMAIN = false;

    const ATTRIBUTE_MACRO_EXPAND_CHECKED_RECORD = "MacroExpand.checkedRecord";

    /**
     * Construct MacroExpand
     *
     * @param logger the logget to use
     * @param dnsProbe the dns service to use
     */
    public function __construct(Logger $logger, DNSService $dnsProbe = null) {
        // This matches 2 groups
        $this->domainSpecPattern = SPFTermsRegexps::process(SPFTermsRegexps::DOMAIN_SPEC_REGEX_R());
        // The real pattern replacer
        $this->macroStringPattern = SPFTermsRegexps::process(SPFTermsRegexps::MACRO_STRING_REGEX_TOKEN());
        // The macro letters pattern
        $this->macroLettersExpPattern = SPFTermsRegexps::process(SPFTermsRegexps::MACRO_LETTER_PATTERN_EXP());
        $this->macroLettersPattern = SPFTermsRegexps::process(SPFTermsRegexps::MACRO_LETTER_PATTERN());
        $this->log = $logger;
        $this->dnsProbe = $dnsProbe;
    }

    public function checkExpand($input, SPFSession $session, $isExplanation) {
        if ($input != null) {
            $host = $this->expand($input, $session, $isExplanation);
            if ($host == null) {
                return new DNSLookupContinuation(new DNSRequest(IPAddr
                        ::getAddress($session->getIpAddress())->getReverseIP(),
                        DNSRequest::PTR), new PTRResponseListener());
            }
        }
        return null;
    }

    public function expand($input, MacroData $macroData, $isExplanation) {
        try {
            if ($isExplanation) {
                return $this->expandExplanation($input, $macroData);
            } else {
                return $this->expandDomain($input, $macroData);
            }
        } catch (RequireClientDomainException $e) {
            return null;
        }
    }

    /**
     * This method expand the given a explanation
     *
     * @param input
     *            The explanation which should be expanded
     * @return expanded The expanded explanation
     * @throws PermErrorException
     *             Get thrown if invalid macros are used
     * @throws RequireClientDomain
     */
    private function expandExplanation($input, MacroData $macroData) {

        $this->log->debug("Start do expand explanation: " + input);

        $parts = input.split(" ");
        $res = new StringBuffer();
        for ($i = 0; $i < parts.length; $i++) {
            if ($i > 0) {
                res.append(" ");
            }
            res.append($this->expandMacroString($parts[$i], $macroData, true));
        }
        log.debug("Done expand explanation: " + res);

        return res.toString();
    }

    /**
     * This method expand the given domain. So all known macros get replaced
     *
     * @param input
     *            The domain which should be expand
     * @return expanded The domain with replaced macros
     * @throws PermErrorException
     *             This get thrown if invalid macros are used
     * @throws RequireClientDomain
     */
    private function expandDomain($input, MacroData $macroData){

        $this->log->debug("Start expand domain: {$input}");

        if (preg_match("/{$this->domainSpecPattern}/", $input, $inputMatcher) == 0) {
            throw new PermErrorException("Invalid DomainSpec: {$input}");
        }

        $res = '';
        if ($inputMatcher[1] != null && strlen($inputMatcher[1]) > 0) {
            $res .= $this->expandMacroString($inputMatcher[1], $macroData, false);
        }
        if ($inputMatcher[2] != null && strlen($inputMatcher[2]) > 0) {
            if (strpos($inputMatcher[2], '.') === 0) {
                $res .= $inputMatcher[2];
            } else {
                $res .= $this->expandMacroString($inputMatcher[2], $macroData, false);
            }
        }

        $domainName = $this->expandMacroString($input, $macroData, false);
        // reduce to less than 255 characters, deleting subdomains from left
        $split = 0;
        while (strlen($domainName) > 255 && $split > -1) {
            $split = $domainName.indexOf(".");
            $domainName = substr($domainName, $split + 1);
        }

        $this->log->debug("Domain expanded: {$domainName}");
        return $domainName;
    }

    /**
     * Expand the given String
     *
     * @param input
     *            The inputString which should get expanded
     * @return expanded The expanded given String
     * @throws PermErrorException
     *             This get thrown if invalid macros are used
     * @throws RequireClientDomain
     */
    private function expandMacroString($input, MacroData $macroData, $isExplanation) {

        var_dump('expandMacroString');
        exit;
        $decodedValue = '';
        preg_match("/{$this->macroStringPattern}/", $input, $inputMatcher);
        $macroCell;
        $pos = 0;

        while ($inputMatcher.find()) {
            $match2 = $inputMatcher->group();
            if ($pos != $inputMatcher.start()) {
                throw new PermErrorException("Middle part does not match: "+input.substring(0,pos)+">>"+input.substring(pos, inputMatcher.start())+"<<"+input.substring(inputMatcher.start())+" ["+input+"]");
            }
            if ($match2.length() > 0) {
                if (match2.startsWith("%{")) {
                    $macroCell = input.substring(inputMatcher.start() + 2, inputMatcher
                            .end() - 1);
                    inputMatcher
                    .appendReplacement(decodedValue, escapeForMatcher(replaceCell(macroCell, macroData, isExplanation)));
                } else if (match2.length() == 2 && match2.startsWith("%")) {
                    // handle the % escaping
                    /*
                     * From RFC4408:
                    *
                    * A literal "%" is expressed by "%%".
                    *   "%_" expands to a single " " space.
                    *   "%-" expands to a URL-encoded space, viz., "%20".
                    */
                    if ("%_".equals(match2)) {
                        inputMatcher.appendReplacement(decodedValue, " ");
                    } else if ("%-".equals(match2)) {
                        inputMatcher.appendReplacement(decodedValue, "%20");
                    } else {
                        inputMatcher.appendReplacement(decodedValue, escapeForMatcher(match2.substring(1)));
                    }
                }
            }

            $pos = inputMatcher.end();
        }

        if (input.length() != pos) {
            throw new PermErrorException("End part does not match: "+input.substring(pos));
        }

        inputMatcher.appendTail(decodedValue);

        return decodedValue.toString();
    }

    /**
     * Replace the macros in given String
     *
     * @param replaceValue
     *            The String in which known macros should get replaced
     * @return returnData The String with replaced macros
     * @throws PermErrorException
     *             Get thrown if an error in processing happen
     * @throws RequireClientDomain
     */
    private function replaceCell($replaceValue, MacroData $macroData, $isExplanation) {

        $variable = "";
        $domainNumber = "";
        $isReversed = false;
        $delimeters = ".";


        // Get only command character so that 'r' command and 'r' modifier don't
        // clash
        $commandCharacter = replaceValue.substring(0, 1);

        // Find command
        if ($isExplanation) {
            $cellMatcher = macroLettersExpPattern.matcher(commandCharacter);
        } else {
            $cellMatcher = macroLettersPattern.matcher(commandCharacter);
        }
        if (cellMatcher.find()) {
            if (cellMatcher.group().toUpperCase().equals(cellMatcher.group())) {
                $variable = encodeURL(matchMacro(cellMatcher.group(), macroData));
            } else {
                $variable = matchMacro(cellMatcher.group(), macroData);
            }
            // Remove Macro code so that r macro code does not clash with r the
            // reverse modifier
            $replaceValue = $replaceValue.substring(1);
        } else {
            throw new PermErrorException("MacroLetter not found: "+replaceValue);
        }

        // Find number of domains to use
        $this->cellPattern = Pattern.compile("\\d+");
        $this->cellMatcher = cellPattern.matcher(replaceValue);
        while (cellMatcher.find()) {
            $domainNumber = cellMatcher.group();
            if (Integer.parseInt(domainNumber) == 0) {
                throw new PermErrorException(
                        "Digit transformer must be non-zero");
            }
        }
        // find if reversed
        $this->cellPattern = Pattern.compile("r");
        $cellMatcher = $this->cellPattern.matcher(replaceValue);
        while (cellMatcher.find()) {
            $isReversed = true;
        }

        // find delimeters
        $this->cellPattern = Pattern.compile("[\\.\\-\\+\\,\\/\\_\\=]+");
        $cellMatcher = cellPattern.matcher(replaceValue);
        while ($cellMatcher.find()) {
            $delimeters = cellMatcher.group();
        }

        // Reverse domains as necessary
        $data = split(variable, delimeters);
        if ($isReversed) {
            $data = reverse(data);
        }

        // Truncate domain name to number of sub sections
        if (! $domainNumber === '') {
            $returnData = subset(data, Integer.parseInt(domainNumber));
        } else {
            $returnData = subset(data);
        }

        return $returnData;

    }

    /**
     * Get the value for the given macro like descripted in the RFC
     *
     * @param macro
     *            The macro we want to get the value for
     * @return rValue The value for the given macro
     * @throws PermErrorException
     *             Get thrown if the given variable is an unknown macro
     * @throws RequireClientDomain requireClientDomain if the client domain is needed
     *             and not yet resolved.
     */
    private function matchMacro($macro, MacroData $macroData) {

        $rValue = null;

        $variable = macro.toLowerCase();
        if (variable.equalsIgnoreCase("i")) {
            $rValue = macroData.getMacroIpAddress();
        } else if (variable.equalsIgnoreCase("s")) {
            $rValue = macroData.getMailFrom();
        } else if (variable.equalsIgnoreCase("h")) {
            $rValue = macroData.getHostName();
        } else if (variable.equalsIgnoreCase("l")) {
            $rValue = macroData.getCurrentSenderPart();
        } else if (variable.equalsIgnoreCase("d")) {
            $rValue = macroData.getCurrentDomain();
        } else if (variable.equalsIgnoreCase("v")) {
            $rValue = macroData.getInAddress();
        } else if (variable.equalsIgnoreCase("t")) {
            $rValue = Long.toString(macroData.getTimeStamp());
        } else if (variable.equalsIgnoreCase("c")) {
            $rValue = macroData.getReadableIP();
        } else if (variable.equalsIgnoreCase("p")) {
            $rValue = macroData.getClientDomain();
            if (rValue == null) {
                throw new RequireClientDomainException();
            }
        } else if (variable.equalsIgnoreCase("o")) {
            $rValue = macroData.getSenderDomain();
        } else if (variable.equalsIgnoreCase("r")) {
            $rValue = macroData.getReceivingDomain();
            if ($rValue == null) {
                $rValue = "unknown";
                $dNames = dnsProbe.getLocalDomainNames();

                for ($i = 0; i < dNames.size(); $i++) {
                    // check if the domainname is a FQDN
                    if (SPF1Utils::checkFQDN(dNames.get(i).toString())) {
                        $rValue = dNames.get(i).toString();
                        if (macroData instanceof SPFSession) {
                            $macroData->setReceivingDomain($rValue);
                        }
                        break;
                    }
                }
            }
        }

        if ($rValue == null) {
            throw new PermErrorException("Unknown command : {$variable}");

        } else {
            $this->log.debug("Used macro: " + macro + " replaced with: " + rValue);

            return $rValue;
        }
    }

    /**
     * Create an ArrayList by the given String. The String get splitted by given
     * delimeters and one entry in the Array will be made for each splited
     * String
     *
     * @param data
     *            The String we want to put in the Array
     * @param delimeters
     *            The delimeter we want to use to split the String
     * @return ArrayList which contains the String parts
     */
    private function split($data, $delimeters) {

        $currentChar;
        $element = new StringBuffer();
        $splitParts = array();

        for ($i = 0; i < data.length(); $i++) {
            $currentChar = data.substring(i, i + 1);
            if ($delimeters.indexOf(currentChar) > -1) {
                $splitParts.add(element.toString());
                $element.setLength(0);
            } else {
                $element.append(currentChar);
            }
        }
        splitParts.add(element.toString());
        return $splitParts;
    }

    /**
     * Reverse an ArrayList
     *
     * @param data
     *            The ArrayList we want to get reversed
     * @return reversed The reversed given ArrayList
     */
    private function reverse(array $data) {

        $reversed = array();
        for ($i = 0; i < data.size(); $i++) {
            reversed.add(0, data.get(i));
        }
        return $reversed;
    }

    /**
     * Convert a ArrayList to a String which holds the entries seperated by dots
     *
     * @param data The ArrayList which should be converted
     * @param length The ArrayLength
     * @return A String which holds all entries seperated by dots
     */
    private function subset(array $data, $length = null) {

        if ($length === null) {
            $length = count($data);
        }

        $buildString = new StringBuffer();
        if (data.size() < length) {
            $length = data.size();
        }
        $start = data.size() - length;
        for ($i = start; i < data.size(); $i++) {
            if (buildString.length() > 0) {
                buildString.append(".");
            }
            buildString.append(data.get(i));
        }
        return buildString.toString();

    }

    /**
     * Encode the given URL to UTF-8
     *
     * @param data
     *            url to encode
     * @return encoded URL
     */
    private function encodeURL($data) {

        try {
            // TODO URLEncoder method is not RFC2396 compatible, known
            // difference
            // is Space character gets converted to "+" rather than "%20"
            // Is there anything else which is not correct with URLEncoder?
            // Couldn't find a RFC2396 encoder
            $data = URLEncoder::encode($data, "UTF-8");
        } catch (UnsupportedEncodingException $e) {
            // This shouldn't happen ignore it!
        }

        // workaround for the above descripted problem
        return $data.replaceAll("\\+", "%20");

    }

    /**
     * Because Dollar signs may be treated as references to captured subsequences in method Matcher.appendReplacement
     * its necessary to escape Dollar signs because its allowed in the local-part of an emailaddress.
     *
     * See JSPF-71 for the bugreport
     *
     * @param raw
     * @return escaped string
     */
    private function escapeForMatcher($raw) {
        $sb = '';
        for ($i = 0; $i < strlen($raw); $i++) {
            $c = $raw[$i];
            if ($c == '$' || $c == '\\') {
                $sb .= '\\';
            }
            $sb .= $c;
        }
        return $sb;
    }
}