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

namespace PHP_SPF;


use PHP_SPF\Core\ConsoleLogger;

use PHP_SPF\Core\Exceptions\PermErrorException;

class SPF1ParserTest extends \PHPUnit_Framework_TestCase {

    public function __construct($name) {
        parent::__construct($name);

        $tests = self::loadTests();
        $i = $tests.iterator();
        while (i.hasNext()) {
            $def = i.next();
            if ($name  === $def->recIn) {
                $data = $def;
                break;
            }
        }
        $this->assertNotNull($data);
        $this->parser = new RFC4408SPF1Parser(new ConsoleLogger(), new DefaultTermsFactory(new ConsoleLogger()));
    }

    public static function suite() {
        return new SPF1RecordTestSuite();
    }

    private $data;

    private $parser;

    public function __construct(SPF1RecordTestDef $def, SPFRecordParser $parser) {
        parent::__construct($def->recIn);
        $this->data = $def;
        $this->parser = $parser;
    }

    protected function runTest() {

        try {

            System.out.println("testing [" + data.recIn + "]");

            parser.parse(data.recIn);

            assertEquals("Expected <" + data.errMsg + "> but was <"
                    + "no errors" + ">", data.errMsg, "no errors");
        } catch (NoneException $e) {
            e.printStackTrace();
            assertNotNull(data.errMsg);
            assertTrue("Expected <" + data.errMsg + "> but was <"
                    + e.getMessage() + ">", !"no errors".equals(data.errMsg));
            // assertEquals("Expected <" + data.errMsg + "> but was <"
            // + e.getMessage() + ">", data.errMsg, e.getMessage());
        } catch (PermErrorException $e) {
            e.printStackTrace();
            assertNotNull(data.errMsg);
            assertTrue("Expected <" + data.errMsg + "> but was <"
                    + e.getMessage() + ">\n" + data.recOut + "\n"
                    + data.recOutAuto, !"no errors".equals(data.errMsg));
            // assertEquals("Expected <" + data.errMsg + "> but was <"
            // + e.getMessage() + ">", data.errMsg, e.getMessage());
        }

    }

    public static function loadTests() {
        $tests = array();

        $br = new BufferedReader(new InputStreamReader(Thread
                .currentThread().getContextClassLoader().getResourceAsStream(
                        "org/apache/james/jspf/test_parser.txt")));

        $line;

        $p = "[ ]+";

        $def = null;

        while (($line = $br.readLine()) != null) {
            // skip comments and empty lines
            if ($line.length() != 0 && $line[0] != '#') {
                $tokens = $p.split(line, 3);

                if ($tokens.length >= 2) {

                    if ("spftest" === $tokens[0]) {
                        if ($def != null && def.recIn != null) {
                            tests.add(def);
                        }
                        $def = new SPF1RecordTestDef();
                        $def->name = $tokens[2];
                    } else if ("/.*/" === $tokens[1] || "jspf" === $tokens[1]) {

                        if ("rec-in" === $tokens[0]) {
                            if ($def->recIn == null)
                                $def->recIn = $tokens[2]->replaceFirst(
                                        "SPF record in:  ", "");
                        } else if ("err-msg" === $tokens[0]) {
                            if ($def.errMsg == null) {
                                $def->errMsg = $tokens[2];
                            }
                        } else if ("rec-out" === $tokens[0]) {
                            if ($def->recOut == null)
                                $def->recOut = $tokens[2]->replaceFirst(
                                        "SPF record:  ", "");
                        } else if ("rec-out-auto" === $tokens[0]) {
                            if ($tokens.length == 3) {
                                if ($def->recOutAuto == null)
                                    $def->recOutAuto = $tokens[2];
                            } else {
                                if ($def->recOutAuto == null)
                                    $def->recOutAuto = "";
                            }
                        }
                    }

                } else {
                    throw new IllegalStateException("Bad format: " + line);
                }
            }

        }

        if (def != null && def.recIn != null) {
            tests.add(def);
        }

        br.close();

        return tests;
    }
}


class SPF1RecordTestSuite extends \PHPUnit_Framework_TestSuite {

    public function __construct() {
        parent::__construct();
        $tests = SPF1ParserTest::loadTests();
        $i = $tests.iterator();
        $parser = new RFC4408SPF1Parser(new ConsoleLogger(), new DefaultTermsFactoryTest1(new ConsoleLogger()));
        while ($i.hasNext()) {
            $this->addTest(new SPF1ParserTest($i->next(), $parser));
        }
    }

}

class SPF1RecordTestDef {
    public $name = null;

    public $recIn = null;

    public $errMsg = null;

    public $recOutAuto = null;

    public $recOut = null;
}

