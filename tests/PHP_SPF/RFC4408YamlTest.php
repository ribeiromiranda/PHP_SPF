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


class RFC4408YamlTest extends AbstractYamlTest {

    const YAMLFILE2 = "rfc4408-tests-2009.10.yml";

    /**
     * @param name
     * @throws IOException

    public RFC4408YamlTest(String name) throws IOException {
        super(name);
    }

    protected RFC4408YamlTest(SPFYamlTestDescriptor def) {
        super(def);
    }

    protected RFC4408YamlTest(SPFYamlTestDescriptor def, String test) {
        super(def, test);
    }
    */

    protected function getFilename() {
        return self::YAMLFILE2;
    }

    public static function suite() {
        return new RFC4408Suite();
    }



    protected function setLogger(Logger $logger) {
        $this->log = $logger;
    }

    /**
     * This method has been created for spf spec people to let them better read the
     * output of our tests against their yaml file
     *
     * @param args
     * @throws Throwable
     */
    public static function main(array $args) {
        $l = new Log4JLogger(org.apache.log4j.Logger.getLogger("ROOT"));

        $tests = SPFYamlTestDescriptor::loadTests(self::YAMLFILE2);
        $i = $tests->iterator();
        while (i.hasNext()) {
            $o = $i.next();
            $ttt = $o->getTests().keySet().iterator();
            while (ttt.hasNext()) {
                $t = new RFC4408YamlTest(o,(String) ttt.next());
                $t.setLogger(l);
                TestRunner::run(t);
            }
        }
    }

}

class RFC4408Suite extends TestSuite {

    public function __construct() {
        try {
            $tests = SPFYamlTestDescriptor::loadTests(self::YAMLFILE2);
            $i = $tests.iterator();
            while (i.hasNext()) {
                $o = $i.next();
                $ttt = $o.getTests().keySet().iterator();
                while (ttt.hasNext()) {
                    addTest(new RFC4408YamlTest(o, ttt.next()));
                }
            }
        } catch (RuntimeException $e) {
            if ("Unable to load the file".equals(e.getMessage())) {
                System.err.println("WARNING: RFC4408 tests disabled.");
                System.err.println("The RFC4408 test-suite is not bundled with jspf due to licensing issues.");
                System.err.println("You can download the yaml testsuite at the following url:");
                System.err.println("  http://www.openspf.org/source/project/test-suite/");
                System.err.println("and place an rfc4408-tests.yml file in the /src/test/resources/org/apache/james/jspf folder.");
            }
        }
    }

}
