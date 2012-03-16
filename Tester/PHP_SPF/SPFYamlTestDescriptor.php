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

namespace Tester\PHP_SPF;

/**
 * Describe a test loaded from a YAML file using the format
 * described in the OpenSPF testsuite.
 */
class SPFYamlTestDescriptor {
    private $comment;
    private $tests;
    private $zonedata;

    public function __construct(array $source, $i) {
        $this->setComment($source->get("description"));
        if ($this->getComment() == null) {
            $this->setComment("Test #"+i);
        }
        $this->setTests($source["tests"]);
        $this->setZonedata($source["zonedata"]);
    }

    public function getComment() {
        return $this->comment;
    }
    public function setComment($comment) {
        $this->comment = $comment;
    }
    public function getTests() {
        return $this->tests;
    }
    public function setTests(array $tests) {
        $this->tests = $tests;
    }
    public function getZonedata() {
        return $this->zonedata;
    }
    public function setZonedata($zonedata) {
        $zonedata = array();
        $keys = $zonedata.keySet();
        for ($i = keys.iterator(); i.hasNext(); ) {
            $hostname = (String) i.next();
            $lowercase = hostname.toLowerCase(Locale.US);
            this.zonedata.put(lowercase, zonedata.get(hostname));
        }
    }

    public static function loadTests($filename) {
        $tests = array();

        $is = SPFYamlTestDescriptor.clacss.getResourceAsStream($filename);
        System.out.println("{$filename}: {$is}");

        if ($is != null) {
            $br = new BufferedReader(new InputStreamReader(is));
            $fact = new DefaultYAMLFactory();

            $ctor = fact.createConstructor(fact.createComposer(fact.createParser(fact.createScanner(br)),fact.createResolver()));
            $i = 1;
            while(ctor.checkData()) {
                $o = ctor.getData();
                if ($o instanceof Map) {
                  $m = $o;
                  $ts = new SPFYamlTestDescriptor($m, $i);
                  tests.add(ts);
                }
                $i++;
            }

            return $tests;
        } else {
            throw new \Exception("Unable to load the file");
        }
    }

}