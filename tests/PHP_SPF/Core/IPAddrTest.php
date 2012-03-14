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

class IPAddrTest  extends \PHPUnit_Framework_TestCase {

    public function testValidIp4Address() {
        $this->assertEquals("in-addr", IPAddr::getInAddress("123.212.255.213"));
        $this->assertEquals("in-addr", IPAddr::getInAddress("0.0.0.0"));
        $this->assertEquals("in-addr", IPAddr::getInAddress("255.255.255.255"));
    }

    public function testValidIp4OverIpv6Address() {
        $this->assertEquals("ip6", IPAddr::getInAddress("0:0:0:0:0:0:13.1.68.3"));
        $this->assertEquals("ip6", IPAddr::getInAddress("0:0:0:0:0:FFFF:129.144.52.38"));
        $this->assertEquals("ip6", IPAddr::getInAddress("::13.1.68.3"));
        $this->assertEquals("ip6", IPAddr::getInAddress("::FFFF:129.144.52.38"));
    }

    public function testValidIp6Address() {
        $this->assertEquals("ip6", IPAddr::getInAddress("FEDC:BA98:7654:3210:FEDC:BA98:7654:3210"));
        $this->assertEquals("ip6", IPAddr::getInAddress("1080:0:0:0:8:800:200C:417A"));
        $this->assertEquals("ip6", IPAddr::getInAddress("FF01:0:0:0:0:0:0:101"));
        $this->assertEquals("ip6", IPAddr::getInAddress("0:0:0:0:0:0:0:1"));
        $this->assertEquals("ip6", IPAddr::getInAddress("0:0:0:0:0:0:0:0"));
        $this->assertEquals("ip6", IPAddr::getInAddress("1080::8:800:200C:417A"));
        $this->assertEquals("ip6", IPAddr::getInAddress("FF01::101"));
        $this->assertEquals("ip6", IPAddr::getInAddress("::1"));
        $this->assertEquals("ip6", IPAddr::getInAddress("::"));
    }

    public function testInvalidIp6Address() {
        try {
            $this->assertEquals("ip6", IPAddr::getInAddress("12AB:0:0:CD3"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
        try {
            $this->assertEquals("ip6", IPAddr::getInAddress("1080:0:0:0:8::800:200C:417A"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
        try {
            $this->assertEquals("ip6", IPAddr::getInAddress("FF01:0:0:0:0:0:0:00000"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
        try {
            $this->assertEquals("ip6", IPAddr::getInAddress("0:0:0:0:0:0:0:0:1"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
        try {
            $this->assertEquals("ip6", IPAddr::getInAddress("0:0:0:0:0:0:0:O"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
        try {
            $this->assertEquals("ip6", IPAddr::getInAddress("1080::8:800::200C:417A"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
        try {
            $this->assertEquals("ip6", IPAddr::getInAddress("FF01:::101"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
        try {
            $this->assertEquals("ip6", IPAddr::getInAddress(":1:"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
        try {
            $this->assertEquals("ip6", IPAddr::getInAddress(":"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
    }

    public function testInvalidIp4AddressGreatThan255() {
        try {
            $this->assertEquals("in-addr", IPAddr::getInAddress("333.212.255.213"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
        try {
            $this->assertEquals("in-addr", IPAddr::getInAddress("1.2.3."));
            $this->fail();
        } catch (PermErrorException $e) {
        }
        try {
            $this->assertEquals("in-addr", IPAddr::getInAddress("1.2.3.a"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
        try {
            $this->assertEquals("in-addr", IPAddr::getInAddress("1.1.1.1111"));
            $this->fail();
        } catch (PermErrorException $e) {
        }
    }
}