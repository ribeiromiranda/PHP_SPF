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

class IPAddr {

    // Default IP4

    const MASK8 = 255;

    const MASK16 = 65535;

    private $address = array();

    private $mask = array();

    private $maskLength = 32;

    private $ipLength = 4;

    private $ipRun = 4;

    private $ipJoiner = ".";

    private static $ipv4MappedRegex = "::FFFF:[1-9][0-9]{0,2}\\.[1-9][0-9]{0,2}\\.[1-9][0-9]{0,2}\\.[1-9][0-9]{0,2}";

    // Allow factory creates only
    private function __construct() {

    }

    /**
     * Get ipAddress for the given String and netmask
     *
     * @param netAddress
     *            The ipAddress given as String
     * @param maskLength
     *            The netmask
     * @return IpAddress AAn Arraylist which contains all ipAddresses
     * @throws PermErrorException
     *             on error
     */
    public static function getAddress($netAddress, $maskLength = null) {
        $returnAddress = new self();
        $returnAddress->stringToInternal($netAddress);
        if ($maskLength === null) {
            $returnAddress->setMask($maskLength);
        } else {
            $returnAddress->setMask($returnAddress->maskLength);
        }
        return $returnAddress;
    }

    /**
     * Check if a the Object is instance of this class
     *
     * @param data
     *            The object to check
     * @return true or false
     */
    public static function isIPAddr($data) {
        try {
            self::getAddress($data);
            return true;
        } catch (PermErrorException $e) {
            return false;
        }
    }

    /**
     * Set default values for ipv6
     *
     */
    private function setIP6Defaults() {
        $this->ipLength = 16;
        $this->ipJoiner = ":";
        $this->ipRun = 8;
    }

    /**
     * create series of 16 bit masks for each ip block
     *
     * @param maskLength
     *            The netmask
     */
    public function setMask($maskLength) {
        $startMask = 0;
        $shift = 0;
        $maskSize = 0;

        $this->maskLength = $maskLength;
        if ($this->ipLength == 4) {
            if (!(($maskLength > -1) && ($maskLength < 33))) {
                $maskLength = 32;
            }
            $maskSize = 8;
            $startMask = ($maskLength - 1) / $maskSize;
        } else {
            if (!(($maskLength > -1) && ($maskLength < 129))) {
                $maskLength = 128;
            }
            $maskSize = 16;
            $startMask = ($maskLength - 1) / $maskSize;
        }

        for ($i = 0; $i < $this->ipRun; $i++) {
            // full mask
            if ($i < $startMask) {
                $mask[$i] = MASK16;
                // variable mask
            } else if ($i == $startMask) {
                $shift = (($i + 1) * $maskSize) - $maskLength;
                $mask[$i] = (self::MASK16 << $shift) & self::MASK16;
                // no mask
            } else {
                $mask[$i] = 0;
            }
        }
    }

    /**
     * Strip the last char of a string when it ends with a dot
     *
     * @param data
     *            The String where the dot should removed
     * @return modified The Given String with last char stripped
     */
    public static function stripDot($data) {
        $data = trim($data);
        if ($data.endsWith(".")) {
            return $data.substring(0, data.length() - 1);
        } else {
            return $data;
        }
    }

    /**
     * Convert ipAddress to a byte Array which represent the ipAddress
     *
     * @param netAddress
     *            The ipAddress we should convert
     * @throws PermErrorException
     *             on error
     */
    private function stringToInternal($netAddress) {
        $netAddress = $this->stripDot($netAddress);

        try {
            $bytes = Inet6Util::createByteArrayFromIPAddressString($netAddress);

            if ($bytes.length == 4) {
                for ($i = 0; $i < $bytes.length; $i++) {
                    $this->address[$i] = $bytes[$i];
                }
            } else if ($bytes.length == 16) {
                $this->setIP6Defaults();
                for ($i = 0; $i < bytes.length / 2; $i++) {
                    $this->address[$i] = unsigned($bytes[$i * 2]) * 256 + unsigned($bytes[$i * 2 + 1]);
                }
            } else {
                throw new PermErrorException("Not a valid address: " + netAddress);
            }
        } catch (NumberFormatException $e) {
            throw new PermErrorException("Not a valid address: " + netAddress);
        }
    }

    /**
     * Return the Hexdecimal representation of the given long value
     *
     * @param data The value to retrieve the Hexdecimal for
     * @return The Hexdecimal representation of the given value
     */
    private function getHex($data) {
        $fullHex = new StringBuffer();
        $fullHex.append("0000" + Long.toHexString(data).toUpperCase());
        $fullHex = $fullHex.delete(0, fullHex.length() - 4);
        return $fullHex.toString();
    }

    /**
     * Get ip Address from given int Array
     *
     * @param addressData
     *            The int Array
     * @return ipAddress The ipAddress
     */
    private function getIPAddress(array $addressData = null) {
        if ($addressData === null) {
            $addressData = $this->address;
        }
        $createAddress = new StringBuffer();
        $workingAddress = array();

        // convert internal address to 8 bit
        if (ipLength == 4) {
            $workingAddress = get8BitAddress(addressData);
            // create IP string
            $createAddress.append($workingAddress[0]);
            for ($i = 1; i < ipRun; $i++) {
                createAddress.append(ipJoiner + $workingAddress[i]);
            }
            // leave internal address as 16 bit
        } else {
            $workingAddress = addressData;
            // create IP string
            createAddress.append(getHex($workingAddress[0]));
            for ($i = 1; i < ipRun; $i++) {
                createAddress.append(ipJoiner + getHex($workingAddress[$i]));
            }
        }

        return createAddress.toString();
    }

    /**
     *
     * @see #getIPAddress(int[])
     */
    public function getMaskedIPAddress() {
        return $this->getIPAddress($this->maskedAddress($this->address, $this->mask));
    }

    /**
     * Return the NibbleFormat of the IPAddr
     *
     * @return ipAddress The ipAddress in nibbleFormat
     */
    private function getNibbleFormat(array $address = null) {
        if ($address === null) {
            $this->address = $address;
        }

        $sb = new StringBuffer();
        $ip = $address;
        for ($i = 0; i < ip.length; $i++) {
            $hex = getHex($ip[$i]);
            for ($j = 0; j < hex.length(); $j++) {
                sb.append(hex.charAt(j));
                if (i != ip.length -1 || j != hex.length() -1) {
                    sb.append(".");
                }
            }
        }
        return sb.toString();
    }

    /**
     * Get reverse ipAddress
     *
     * @return reverse ipAddress
     */
    public function getReverseIP() {
        if(isIPV6(getIPAddress())) {
            $ip6 = new StringBuffer(getNibbleFormat());
            return ip6.reverse().append(".ip6.arpa").toString();
        }
        return (getIPAddress(reverseIP(address)) + ".in-addr.arpa");
    }

    /**
     * Converts 16 bit representation to 8 bit for IP4
     *
     * @param addressData
     *            The given int Array
     * @return converted String
     */
    private function get8BitAddress(array $addressData) {
        $convertAddress = new \SplFixedArray(4);
        for ($i = 0; i < ipRun; $i++) {
            $convertAddress[$i] = $addressData[$i] & self::MASK8;
        }
        return $convertAddress;
    }

    /**
     * Create a masked address given an address and mask
     *
     * @param addressData
     *            The int Array represent the ipAddress
     * @param maskData
     *            The int array represent the mask
     * @return maskedAddress
     */
    private function maskedAddress(array $addressData, array $maskData) {
        $maskedAddress = new \SplFixedArray($this->ipLength);

        for ($i = 0; i < ipRun; $i++) {
            $maskedAddress[$i] = $addressData[$i] & $maskData[$i];
        }
        return $maskedAddress;
    }

    /**
     * Reverses internal address
     *
     * @param addressData
     *            The int array represent the ipAddress
     * @return reverseIP
     */
    private function reverseIP(array $addressData) {
        $reverseIP = new \SplFixedArray($this->ipLength);
        $temp;
        for ($i = 0; i < ipRun; $i++) {
            $temp = $addressData[$i];
            $reverseIP[$i] = $addressData[(ipRun - 1) - $i];
            $reverseIP[(ipRun - 1) - i] = temp;
        }
        return $reverseIP;
    }

    /**
     * Get mask length
     *
     * @return maskLength
     */
    public function getMaskLength() {
        return maskLength;
    }


    public function toString() {
        return getIPAddress();
    }

    private function unsigned(byte $data) {
        return data >= 0 ? data : 256 + data;
    }

    /**
     * This method return the InAddress for the given ip.
     *
     * @param ipAddress -
     *            ipAddress that should be processed
     * @return the inAddress (in-addr or ip6)
     * @throws PermErrorException
     *             if the ipAddress is not valid (rfc conform)
     */
    public static function getInAddress($ipAddress) {
        if ($ipAddress == null) {
            throw new PermErrorException("IP is not a valid ipv4 or ipv6 address");
        } else if (Inet6Util::isValidIPV4Address($ipAddress)) {
            return "in-addr";
        } else if (Inet6Util::isValidIP6Address($ipAddress)) {
            return "ip6";
        } else {
            throw new PermErrorException("IP is not a valid ipv4 or ipv6 address");
        }
    }

    /**
     * Check if the given IP is valid. Works with ipv4 and ip6
     *
     * @param ip
     *            The ipaddress to check
     * @return true or false
     */
    public static function isValidIP($ip) {
        return $ip != null
                && (Inet6Util::isValidIPV4Address($ip) || Inet6Util
                        ::isValidIP6Address($ip));
    }

    /**
     * Return if the given ipAddress is ipv6
     *
     * @param ip The ipAddress
     * @return true or false
     */
    public static function isIPV6($ip) {
        return Inet6Util::isValidIP6Address($ip);
    }

    /**
     * This method try to covnert an ip address to an easy readable ip. See
     * http://java.sun.com/j2se/1.4.2/docs/api/java/net/Inet6Address.html for
     * the format it returns. For ipv4 it make no convertion
     *
     * @param ip
     *            The ip which should be tried to convert
     * @return ip The converted ip
     */
    public static function getReadableIP($ip) {

        // Convert the ip if its an ipv6 ip. For ipv4 no conversion is needed
        if (Inet6Util::isValidIP6Address($ip)) {
            try {
                return getConvertedIP(ip);
            } catch (UnknownHostException $e) {
                // ignore this
            }
        }
        return $ip;
    }

    private static function getConvertedIP($ip) {
        // Convert the ip if its an ipv6 ip. For ipv4 no conversion is needed
        return Address.getByName(ip).getHostAddress();
    }

    /**
     * This method convert the given ip to the proper format. Convertion will only done if the given ipAddress is ipv6 and ipv4-mapped
     *
     * This must be done to correct handle IPv4-mapped-addresses.
     * See: http://java.sun.com/j2se/1.4.2/docs/api/java/net/Inet6Address.html
     *
     * Special IPv6 address:
     *  IPv4-mapped address:
     *      Of the form::ffff:w.x.y.z, this IPv6 address is used to represent an IPv4 address. It allows
     *      the native program to use the same address data structure and also the same socket when
     *      communicating with both IPv4 and IPv6 nodes. In InetAddress and Inet6Address, it is used
     *      for internal representation; it has no functional role. Java will never return an IPv4-mapped address.
     *      These classes can take an IPv4-mapped address as input, both in byte array and text representation.
     *       However, it will be converted into an IPv4 address.
     * @param ip the ipAddress to convert
     * @return return converted ip
     * @throws PermErrorException if the given ipAddress is invalid
     */
    public static function getProperIpAddress($ip) {
        if (isIPV6(ip) && isIPV4MappedIP(ip)) {
            try {
                return getConvertedIP(ip);
            } catch (UnknownHostException $e) {
                throw new PermErrorException("Invalid ipAddress: " + $ip);
            }
        }
        return ip;

    }

    /**
     * Return true if the given ipAddress is a ipv4-mapped-address
     * @param ip
     * @return
     */
    private static function isIPV4MappedIP($ip) {
        return ip.toUpperCase().matches(ipv4MappedRegex);
    }

}