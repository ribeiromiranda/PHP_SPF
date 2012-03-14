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

class MacroExpandTest  extends \PHPUnit_Framework_TestCase {

    protected $defIp4me = null;

    protected $defIp6me = null;

    protected function setUp() {
        parent::setUp();
        $this->defIp4me = new MacroExpand(new ConsoleLogger(), null);
        $this->defIp6me = new MacroExpand(new ConsoleLogger(), null);
    }

    public function testPercS()  {
        $this->assertEquals("strong-bad@email.example.com", $this->defIp4me
                ->expand('%{s}', new rfcIP4MacroData(), MacroExpand::DOMAIN));
    }

    public function testPercK() {
        try {
            $this->defIp4me.expand("%{k}", new rfcIP4MacroData(), MacroExpand::DOMAIN);
            $this->fail("%{k} is not a valid expansion");
        } catch (PermErrorException $e) {
        }
    }

    public function testPercentAloneIsError() {
        try {
            $this->defIp4me.expand("%{s}%", new rfcIP4MacroData(), MacroExpand::DOMAIN);
            $this->fail("invalid percent at end of line");
        } catch (PermErrorException $e) {
        }
    }

    public function testDoublePercent() {
        $this->assertEquals("%", $this->defIp4me.expand("%%", new rfcIP4MacroData(), MacroExpand::DOMAIN));
    }

    public function testPercO() {
        $this->assertEquals("email.example.com", $this->defIp4me->expand("%{o}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
    }

    public function testPercD() {
        $this->assertEquals("email.example.com", $this->defIp4me->expand("%{d}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
        $this->assertEquals("email.example.com", $this->defIp4me->expand("%{d4}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
        $this->assertEquals("email.example.com", $this->defIp4me->expand("%{d3}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
        $this->assertEquals("example.com", $this->defIp4me->expand("%{d2}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
        $this->assertEquals("com", $this->defIp4me->expand("%{d1}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
        $this->assertEquals("com.example.email", $this->defIp4me->expand("%{dr}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
        $this->assertEquals("example.email", $this->defIp4me->expand("%{d2r}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
    }

    public function testPercL() {
        $this->assertEquals("strong-bad", $this->defIp4me->expand("%{l}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
        $this->assertEquals("strong.bad", $this->defIp4me->expand("%{l-}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
        $this->assertEquals("strong-bad", $this->defIp4me->expand("%{lr}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
        $this->assertEquals("bad.strong", $this->defIp4me->expand("%{lr-}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
        $this->assertEquals("strong", $this->defIp4me->expand("%{l1r-}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
    }

    public function testExample1() {
        $this->assertEquals("3.2.0.192.in-addr._spf.example.com", defIp4me
                .expand("%{ir}.%{v}._spf.%{d2}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
    }

    public function testExample2() {
        $this->assertEquals("bad.strong.lp._spf.example.com", defIp4me
                .expand("%{lr-}.lp._spf.%{d2}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
    }

    public function testExample3() {
        $this->assertEquals("bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
                $this->defIp4me->expand("%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
    }

    public function testExample4() {
        $this->assertEquals("3.2.0.192.in-addr.strong.lp._spf.example.com", $this->defIp4me
                ->expand("%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", new rfcIP4MacroData(), MacroExpand::DOMAIN));
    }

    public function testExample5() {
        $this->assertEquals("example.com.trusted-domains.example.net", defIp4me
                .expand("%{d2}.trusted-domains.example.net", new rfcIP4MacroData(), MacroExpand::DOMAIN));
    }

    public function testExample6_ipv6() {
        $this->assertEquals(
                "1.0.B.C.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.B.D.0.1.0.0.2.ip6._spf.example.com",
                defIp6me.expand("%{ir}.%{v}._spf.%{d2}", new rfcIP6MacroData(), MacroExpand.EXPLANATION));
    }

    public function testLocalPartWithSpecialChars() {

        $this->assertEquals(
                '+exists:CL.192.0.2.3.FR.test{$LNAME}@email.example.com.spf.test.com',
                $this->defIp4me->expand('+exists:CL.%{i}.FR.%{s}.spf.test.com',
                        new rfcIP4MacroDataTest1(), MacroExpand::DOMAIN));

        // not sure if \ is allowed in email, but anyway make sure we correctly handle also backslash.
        $this->assertEquals(
                '+exists:CL.192.0.2.3.FR.tes\\t{$LNAME}@email.example.com.spf.test.com',
                $this->defIp4me->expand('+exists:CL.%{i}.FR.%{s}.spf.test.com',
                        new rfcIP4MacroDataTest2(), MacroExpand::DOMAIN));
    }

}

class rfcIP4MacroData implements MacroData {
    public function getCurrentSenderPart() {
        return "strong-bad";
    }

    public function getMailFrom() {
        return "strong-bad@email.example.com";
    }

    public function getHostName() {
        return "email.example.com";
    }

    public function getCurrentDomain() {
        return "email.example.com";
    }

    public function getInAddress() {
        return "in-addr";
    }

    public function getClientDomain() {
        return "clientdomain";
    }

    public function getSenderDomain() {
        return "email.example.com";
    }

    public function getMacroIpAddress() {
        return "192.0.2.3";
    }

    public function getTimeStamp() {
        return System.currentTimeMillis();
    }

    public function getReadableIP() {
        return "192.0.2.3";
    }

    public function getReceivingDomain() {
        return "receivingdomain";
    }
}

final class rfcIP4MacroDataTest1 extends rfcIP4MacroData {
    public function getMailFrom() {
        return 'test{$LNAME}@email.example.com';
        }

    public function getCurrentSenderPart() {
        return 'test{$LNAME}';
    }
}

final class rfcIP4MacroDataTest2 extends rfcIP4MacroData {
    public function getMailFrom() {
        return 'tes\\t{$LNAME}@email.example.com';
    }

    public function getCurrentSenderPart() {
        return 'tes\\t{$LNAME}';
    }
}

final class rfcIP6MacroData extends rfcIP4MacroData {
    public function getInAddress() {
        return "ip6";
    }

    public function getMacroIpAddress() {
        return "2.0.0.1.0.D.B.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.C.B.0.1";
    }

    public function getReadableIP() {
        return "2001:DB8::CB01";
    }
}