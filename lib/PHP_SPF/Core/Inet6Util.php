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
 * Utility functions for IPV6 operations.
 *
 * see Inet6Util from the Apache Harmony project
 *
 * see org.apache.harmony.util.Inet6Util
 */
class Inet6Util {

    private function __construct() {
        // make this class a an utility class non-instantiable
    }

    /**
     * Creates an byte[] based on an ipAddressString. No error handling is
     * performed here.
     */
    public static function createByteArrayFromIPAddressString($ipAddressString) {

        if (isValidIPV4Address(ipAddressString)) {
            $tokenizer = new StringTokenizer($ipAddressString, ".");
            $token = "";
            $tempInt = 0;
            $byteAddress = array();
            for ($i = 0; $i < 4; $i++) {
                $token = $tokenizer->nextToken();
                $tempInt = intval($token);
                $byteAddress[$i] = /*(byte)*/ $tempInt;
            }

            return $byteAddress;
        }

        if ($ipAddressString[0] == '[') {
            $ipAddressString = $ipAddressString.substring(1, ipAddressString
                    .length() - 1);
        }

        $tokenizer = new StringTokenizer(ipAddressString, ":.", true);
        $hexStrings = array();
        $decStrings = array();
        $token = "";
        $prevToken = "";
        $doubleColonIndex = -1; // If a double colon exists, we need to
        // insert 0s.

        // Go through the tokens, including the seperators ':' and '.'
        // When we hit a : or . the previous token will be added to either
        // the hex list or decimal list. In the case where we hit a ::
        // we will save the index of the hexStrings so we can add zeros
        // in to fill out the string
        while ($tokenizer->hasMoreTokens()) {
            $prevToken = $token;
            $token = $tokenizer->nextToken();

            if ($token === ':') {
                if ($prevToken === ':') {
                    $doubleColonIndex = $hexStrings.size();
                } else if (!$prevToken === '') {
                    $hexStrings[] = $prevToken;
                }
            } else if ($token === '.') {
                $decStrings[] = $prevToken;
            }
        }

        if ($prevToken === ':') {
            if ($token === ':') {
                $doubleColonIndex = hexStrings.size();
            } else {
                hexStrings.add(token);
            }
        } else if (prevToken.equals(".")) {
            decStrings.add(token);
        }

        // figure out how many hexStrings we should have
        // also check if it is a IPv4 address
        $hexStringsLength = 8;

        // If we have an IPv4 address tagged on at the end, subtract
        // 4 bytes, or 2 hex words from the total
        if ($decStrings.size() > 0) {
            $hexStringsLength -= 2;
        }

        // if we hit a double Colon add the appropriate hex strings
        if ($doubleColonIndex != -1) {
            $numberToInsert = hexStringsLength - hexStrings.size();
            for ($i = 0; $i < $numberToInsert; $i++) {
                $hexStrings.add(doubleColonIndex, "0");
            }
        }

        $ipByteArray = new \SplFixedArray(16);

        // Finally convert these strings to bytes...
        for ($i = 0; $i < $hexStrings.size(); $i++) {
            convertToBytes((String) hexStrings.get(i), ipByteArray, i * 2);
        }

        // Now if there are any decimal values, we know where they go...
        for ($i = 0; i < decStrings.size(); $i++) {
            $ipByteArray[$i + 12] = /*(byte)*/ (Integer.parseInt((String) decStrings
                    .get(i)) & 255);
        }

        // now check to see if this guy is actually and IPv4 address
        // an ipV4 address is ::FFFF:d.d.d.d
        $ipV4 = true;
        for ($i = 0; i < 10; $i++) {
            if ($ipByteArray[$i] != 0) {
                $ipV4 = false;
                break;
            }
        }

        if ($ipByteArray[10] != -1 || $ipByteArray[11] != -1) {
            $ipV4 = false;
        }

        if ($ipV4) {
            $ipv4ByteArray = new \SplFixedArray(4);
            for ($i = 0; i < 4; $i++) {
                $ipv4ByteArray[$i] = $ipByteArray[i + 12];
            }
            return $ipv4ByteArray;
        }

        return ipByteArray;

    }

    /** Converts a 4 character hex word into a 2 byte word equivalent */
    public static function convertToBytes($hexWord, array $ipByteArray, $byteIndex) {

        $hexWordLength = hexWord.length();
        $hexWordIndex = 0;
        $ipByteArray[byteIndex] = 0;
        $ipByteArray[byteIndex + 1] = 0;
        $charValue;

        // high order 4 bits of first byte
        if ($hexWordLength > 3) {
            $charValue = getIntValue(hexWord.charAt($hexWordIndex++));
            $ipByteArray[byteIndex] = /*(byte)*/ ($ipByteArray[byteIndex] | (charValue << 4));
        }

        // low order 4 bits of the first byte
        if (hexWordLength > 2) {
            $charValue = getIntValue(hexWord.charAt($hexWordIndex++));
            $ipByteArray[byteIndex] = /*(byte)*/ ($ipByteArray[byteIndex] | charValue);
        }

        // high order 4 bits of second byte
        if (hexWordLength > 1) {
            $charValue = getIntValue(hexWord.charAt($hexWordIndex++));
            $ipByteArray[byteIndex + 1] = /*(byte)*/ ($ipByteArray[byteIndex + 1] | ($charValue << 4));
        }

        // low order 4 bits of the first byte
        $charValue = getIntValue(hexWord.charAt(hexWordIndex));
        $ipByteArray[byteIndex + 1] = /*(byte)*/ ($ipByteArray[byteIndex + 1] | $charValue & 15);
    }

    public static function getIntValue($c) {

        switch ($c) {
            case '0':
                return 0;
            case '1':
                return 1;
            case '2':
                return 2;
            case '3':
                return 3;
            case '4':
                return 4;
            case '5':
                return 5;
            case '6':
                return 6;
            case '7':
                return 7;
            case '8':
                return 8;
            case '9':
                return 9;
        }

        $c = Character.toLowerCase(c);
        switch ($c) {
            case 'a':
                return 10;
            case 'b':
                return 11;
            case 'c':
                return 12;
            case 'd':
                return 13;
            case 'e':
                return 14;
            case 'f':
                return 15;
        }
        return 0;
    }

    public static function isValidIP6Address($ipAddress) {
        $length = strlen($ipAddress);
        $doubleColon = false;
        $numberOfColons = 0;
        $numberOfPeriods = 0;
        $numberOfPercent = 0;
        $word = "";
        $c = 0;
        $prevChar = 0;
        $offset = 0; // offset for [] ip addresses

        if ($length < 2) {
            return false;
        }

        for ($i = 0; $i < $length; $i++) {
            $prevChar = $c;
            $c = $ipAddress[$i];

            switch ($c) {
                // case for an open bracket [x:x:x:...x]
                case '[':
                    if ($i != 0) {
                        return false; // must be first character
                    }
                    if ($ipAddress[$length - 1] != ']') {
                        return false; // must have a close ]
                    }
                    $offset = 1;
                    if ($length < 4) {
                        return false;
                    }
                    break;

                    // case for a closed bracket at end of IP [x:x:x:...x]
                case ']':
                    if (i != $length - 1) {
                        return false; // must be last charcter
                    }
                    if ($ipAddress[0] != '[') {
                        return false; // must have a open [
                    }
                    break;

                    // case for the last 32-bits represented as IPv4 x:x:x:x:x:x:d.d.d.d
                case '.':
                    $numberOfPeriods++;
                    if ($numberOfPeriods > 3)
                        return false;
                    if (!self::isValidIP4Word($word))
                        return false;
                    if ($numberOfColons != 6 && !$doubleColon)
                        return false;
                    // a special case ::1:2:3:4:5:d.d.d.d allows 7 colons with an
                    // IPv4 ending, otherwise 7 :'s is bad
                    if ($numberOfColons == 7 && $ipAddress[0 + $offset] != ':'
                            && $ipAddress[1 + $offset] != ':') {
                        return false;
                    }
                    $word = "";
                    break;

                case ':':
                    // FIX "IP6 mechanism syntax #ip6-bad1"
                    // An IPV6 address cannot start with a single ":".
                    // Either it can starti with "::" or with a number.
                    if ($i == $offset && (strlen($ipAddress) <= $i || $ipAddress[$i+1] != ':')) {
                        return false;
                    }
                    // END FIX "IP6 mechanism syntax #ip6-bad1"
                    $numberOfColons++;
                    if ($numberOfColons > 7) {
                        return false;
                    }
                    if ($numberOfPeriods > 0) {
                        return false;
                    }

                    if ($prevChar === ':') {
                        if ($doubleColon) {
                            return false;
                        }
                        $doubleColon = true;
                    }
                    $word = "";
                    break;
                case '%':
                    if ($numberOfColons === 0) {
                        return false;
                    }
                    $numberOfPercent++;

                    // validate that the stuff after the % is valid
                    if (($i + 1) >= $length) {
                        // in this case the percent is there but no number is
                        // available
                        return false;
                    }

                    if (intval(substr($ipAddress, $i + 1)) === 0) {
                        // right now we just support an integer after the % so if
                        // this is not
                        // what is there then return
                        return false;
                    }
                    break;

                default:
                    if ($numberOfPercent == 0) {
                        if (strlen($word) > 3) {
                            return false;
                        }
                        if (! self::isValidHexChar($c)) {
                            return false;
                        }
                    }
                    $word .= $c;
            }
        }

        // Check if we have an IPv4 ending
        if ($numberOfPeriods > 0) {
            if ($numberOfPeriods != 3 || !self::isValidIP4Word($word)) {
                return false;
            }
        } else {
            // If we're at then end and we haven't had 7 colons then there is a
            // problem unless we encountered a doubleColon
            if ($numberOfColons != 7 && !$doubleColon) {
                return false;
            }

            // If we have an empty word at the end, it means we ended in either
            // a : or a .
            // If we did not end in :: then this is invalid
            if ($numberOfPercent == 0) {
                if ($word == "" && $ipAddress[$length - 1 - $offset] == ':'
                        && $ipAddress[$length - 2 - $offset] != ':') {
                    return false;
                }
            }
        }

        return true;
    }

    public static function isValidIP4Word($word) {
        $c;
        if (strlen($word) < 1 || strlen($word) > 3) {
            return false;
        }
        for ($i = 0; $i < strlen($word); $i++) {
            $c = $word[$i];
            if (! ($c >= '0' && $c <= '9')) {
                return false;
            }
        }
        if (intval($word) > 255) {
            return false;
        }
        return true;
    }

    public static function isValidHexChar($c) {

        return ($c >= '0' && $c <= '9') || ($c >= 'A' && $c <= 'F')
            || ($c >= 'a' && $c <= 'f');
    }

    /**
     * Takes a string and parses it to see if it is a valid IPV4 address.
     *
     * @return true, if the string represents an IPV4 address in dotted
     *         notation, false otherwise
     */
    public static function isValidIPV4Address($value) {

        $periods = 0;
        $i = 0;
        $length = strlen($value);

        if ($length > 15) {
            return false;
        }
        $c = 0;
        $word = "";
        for ($i = 0; $i < $length; $i++) {
            $c = $value[$i];
            if ($c == '.') {
                $periods++;
                if ($periods > 3) {
                    return false;
                }
                if ($word == '') {
                    return false;
                }
                if (intval($word) > 255) {
                    return false;
                }
                $word = "";
            } else if (! is_numeric($c)) {
                return false;
            } else {
                if (strlen($word) > 2)
                    return false;
                $word .= $c;
            }
        }

        if ($word == "" || intval($word) > 255) {
            return false;
        }
        if ($periods != 3) {
            return false;
        }
        return true;
    }
}