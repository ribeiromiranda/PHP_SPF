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

abstract class AbstractYamlTest extends \PHPUnit_Framework_TestCase {

    const FAKE_SERVER_PORT = 31348;
    const TIMEOUT = 10;
    const MOCK_SERVICE = 2;
    const FAKE_SERVER = 1;
    const REAL_SERVER = 3;
    private $dnsServiceMockStyle = self::MOCK_SERVICE;

    const SYNCHRONOUS_EXECUTOR = 1;
    const STAGED_EXECUTOR = 2;
    const STAGED_EXECUTOR_MULTITHREADED = 3;
    const STAGED_EXECUTOR_DNSJNIO = 4;
    private $spfExecutorType = self::SYNCHRONOUS_EXECUTOR;

    public $data;
    public $test;
    protected $log;
    private $executor;
    protected static $macroExpand;
    protected static $spf;
    protected static $prevData;
    protected static $parser;
    private static $dns;
    protected static $dnsTestServer;

    public function __construct(SPFYamlTestDescriptor $def, $test = null) {

        if ($test === null) {
            parent::__construct($def->getComment() . " #COMPLETE!");
        } else {
            parent::__construct($def->getComment()+" #{$test}");
        }



        $this->data = $def;
        $this->test = $test;
    }

    protected abstract function getFilename();

    /*protected AbstractYamlTest(String name) {
        super(name);
        List<SPFYamlTestDescriptor> tests = SPFYamlTestDescriptor.loadTests(getFilename());
        Iterator<SPFYamlTestDescriptor> i = tests.iterator();
        while (i.hasNext() && data == null) {
            SPFYamlTestDescriptor def = i.next();
            if (name.equals(def.getComment()+" #COMPLETE!")) {
                data = def;
                this.test = null;
            } else {
                Iterator<String> j = def.getTests().keySet().iterator();
                while (j.hasNext() && data == null) {
                    String test = j.next();
                    if (name.equals(def.getComment()+ " #"+test)) {
                        data = def;
                        this.test = test;
                    }
                }
            }
        }
        assertNotNull(data);
        // assertNotNull(test);
    }*/

    protected function runTest() {
        if ($log == null) {
            $log = new ConsoleLogger(ConsoleLogger::LEVEL_DEBUG, "root");
        }

        $log->info("Running test: {$this->getName()} ...");

        if ($this->parser == null) {
            /* PREVIOUS SLOW WAY
             enabledServices = new WiringServiceTable();
            enabledServices.put(LogEnabled.class, log);
            */

            $this->parser = new RFC4408SPF1ParserTest(log.getChildLogger("parser"), new DefaultTermsFactory($log->getChildLogger("termsfactory"), new WiringServiceTest1()));

            /*$this->parser = new RFC4408SPF1Parser(log.getChildLogger("parser"), new DefaultTermsFactory(log.getChildLogger("termsfactory"), new WiringService() {

                public void wire(Object component) throws WiringServiceException {
                    if (component instanceof LogEnabled) {
                        String[] path = component.getClass().toString().split("\\.");
                        ((LogEnabled) component).enableLogging(log.getChildLogger("dep").getChildLogger(path[path.length-1].toLowerCase()));
                    }
                    if (component instanceof MacroExpandEnabled) {
                        ((MacroExpandEnabled) component).enableMacroExpand(macroExpand);
                    }
                    if (component instanceof DNSServiceEnabled) {
                        ((DNSServiceEnabled) component).enableDNSService(dns);
                    }
                    if (component instanceof SPFCheckEnabled) {
                        ((SPFCheckEnabled) component).enableSPFChecking(spf);
                    }
                }

            }));*/
        }
        if (this.data != AbstractYamlTest.prevData) {
            self::$dns = new LoggingDNSService(getDNSService(), log.getChildLogger("dns"));
            self::$prevData = $this->data;
        }
        $this->macroExpand = new MacroExpand($log->getChildLogger("macroExpand"), self::$dns);
        if ($this->getSpfExecutorType() == SYNCHRONOUS_EXECUTOR) {  // synchronous
            $this->executor = new SynchronousSPFExecutor(log, dns);
        } else if (getSpfExecutorType() == STAGED_EXECUTOR || getSpfExecutorType() == STAGED_EXECUTOR_MULTITHREADED){
            $this->executor = new StagedMultipleSPFExecutor(log, new DNSServiceAsynchSimulator(dns, getSpfExecutorType() == STAGED_EXECUTOR_MULTITHREADED));
        } else if ($this->getSpfExecutorType() == STAGED_EXECUTOR_DNSJNIO) {

            // reset cache between usages of the asynchronous lookuper
            LookupAsynch.setDefaultCache(new Cache(), DClass.IN);
            // reset cache between usages of the asynchronous lookuper
            LookupAsynch.getDefaultCache(DClass.IN).clearCache();

            try {
                $resolver;

                if ($this->getDnsServiceMockStyle() == elf::FAKE_SERVER) {
                    $nonblockingResolver = new NonblockingResolver("127.0.0.1");
                    $resolver = ExtendedNonblockingResolver.newInstance(array($nonblockingResolver));
                    nonblockingResolver.setPort(self::FAKE_SERVER_PORT);
                    nonblockingResolver.setTCP(false);
                } else if (getDnsServiceMockStyle() == self::REAL_SERVER) {
                    $resolver = ExtendedNonblockingResolver.newInstance();
                    $resolvers = resolver.getResolvers();
                    for ($i = 0; $i < $resolvers.length; $i++) {
                        $resolvers[$i]->setTCP(false);
                    }
                } else {
                    throw new IllegalStateException("DnsServiceMockStyle "+getDnsServiceMockStyle()+" is not supported when STAGED_EXECUTOR_DNSJNIO executor style is used");
                }

                $jnioAsynchService = new DNSJnioAsynchService(resolver);
                $jnioAsynchService->setTimeout(TIMEOUT);
                self::$executor = new StagedMultipleSPFExecutor($log, jnioAsynchService);

            } catch (UnknownHostException $e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        } else {
            throw new UnsupportedOperationException("Unknown executor type");
        }
        self::$spf = new SPF(self::$dns, pself::$arser, $log->getChildLogger("spf"), self::$macroExpand, self::$executor);

        if ($test != null) {
            $next = $test;
            $res = $this->runSingleTest(next);
            $this->verifyResult(next, res);
        } else {
            $queries = array(); //new HashMap<String,SPFResult>();
            for (/* Iterator<String>  */$i = data.getTests().keySet().iterator(); i.hasNext(); ) {
                $next = i.next();
                $res = runSingleTest(next);
                $queries.put(next, res);
            }
            $firstError = null;
            for (/* Iterator<String>  */$i = queries.keySet().iterator(); i.hasNext(); ) {
                $next = i.next();
                try {
                    verifyResult(next, queries.get(next));
                } catch (AssertionFailedError $e) {
                    log.getChildLogger(next).info("FAILED. "+e.getMessage()+" ("+getName()+")", e.getMessage()==null ? e : null);
                    if (firstError == null) {
                        $firstError = $e;
                    }
                }
            }
            if ($firstError != null) {
                throw $firstError;
            }
        }

    }

    private function runSingleTest($testName) {
        $currentTest = $this->data->getTests()->get($testName);
        $testLogger = log.getChildLogger(testName);
        testLogger.info("TESTING "+testName+": "+currentTest.get("description"));

        $ip = null;
        $sender = null;
        $helo = null;

        if ($currentTest.get("helo") != null) {
            $helo = $currentTest.get("helo");
        }
        if ($currentTest.get("host") != null) {
            $ip = currentTest.get("host");
        }
        if ($currentTest.get("mailfrom") != null) {
            $sender = (String) currentTest.get("mailfrom");
        } else {
            $sender = "";
        }

        $res = self::$spf->checkSPF($ip, $sender, $helo);
        return res;
    }

    private function verifyResult($testName, SPFResult $res) {
        $resultSPF = res.getResult();
        $currentTest = data.getTests().get(testName);
        $testLogger = log.getChildLogger(testName+"-verify");
        if ($currentTest.get("result") instanceof String) {
            $this->assertEquals("Test "+testName+" ("+currentTest.get("description")+") failed. Returned: "+resultSPF+" Expected: "+currentTest.get("result")+" [["+resultSPF+"||"+res.getHeaderText()+"]]", currentTest.get("result"), resultSPF);
        } else {
            $results = $currentTest.get("result");
            $match = false;
            for ($i = 0; $i < results.size(); $i++) {
                if (results.get(i).equals(resultSPF)) {
                    $match = true;
                }
                // testLogger.debug("checking "+resultSPF+" against allowed result "+results.get(i));
            }
            $this->assertTrue("Test "+testName+" ("+currentTest.get("description")+") failed. Returned: "+resultSPF+" Expected: "+results, match);
        }

        if (currentTest.get("explanation") != null) {

            // Check for our default explanation!
            if (currentTest.get("explanation").equals("DEFAULT")) {
                assertTrue(res.getExplanation().startsWith("http://www.openspf.org/why.html?sender="));
            } else if (currentTest.get("explanation").equals("cafe:babe::1 is queried as 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa")) {
                // See http://java.sun.com/j2se/1.4.2/docs/api/java/net/Inet6Address.html
                // For methods that return a textual representation as output value, the full form is used.
                // Inet6Address will return the full form because it is unambiguous when used in combination with other textual data.
                assertTrue(res.getExplanation().equals("cafe:babe:0:0:0:0:0:1 is queried as 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa"));
            } else {
                assertEquals(currentTest.get("explanation"),res.getExplanation());
            }

        }

        testLogger.info("PASSED. Result="+resultSPF+" Explanation="+res.getExplanation()+" Header="+res.getHeaderText());
    }

    /**
     * @return a Mocked DNSService
     */
    protected function getDNSServiceMockedDNSService() {
        $yamlDNSService = new SPFYamlDNSService(data.getZonedata());
        return yamlDNSService;
    }

    /**
     * @return the right dnsservice according to what the test specialization declares
     */
    protected function getDNSService() {
        switch ($this->getDnsServiceMockStyle()) {
            case self::MOCK_SERVICE: return $this->getDNSServiceMockedDNSService();
            case self::FAKE_SERVER: return $this->getDNSServiceFakeServer();
            case self::REAL_SERVER: return $this->getDNSServiceReal();
            default:
                throw new UnsupportedOperationException("Unsupported mock style");
        }
    }

    protected function getDnsServiceMockStyle() {
        return $this->dnsServiceMockStyle;
    }

    /**
     * @return a dns resolver pointing to the local fake server
     */
    protected function getDNSServiceFakeServer() {
        $resolver = null;
        try {
            $resolver = new SimpleResolver("127.0.0.1");
        } catch (UnknownHostException $e) {
            // TODO Auto-generated catch block
            $e->printStackTrace();
        }
        $resolver->setPort(self::FAKE_SERVER_PORT);
        Lookup::setDefaultResolver($resolver);
        Lookup::setDefaultCache(null, DClass::IN);
        Lookup::setDefaultSearchPath(array());

        if (dnsTestServer == null) {
            try {
                self::$dnsTestServer = new DNSTestingServer("0.0.0.0", ""+FAKE_SERVER_PORT);
            } catch (TextParseException $e) {
                throw new RuntimeException("Error trying to instantiate the testing dns server.", e);
            } catch (IOException $e) {
                throw new RuntimeException("Error trying to instantiate the testing dns server.", e);
            }
        }

        dnsTestServer.setData($data.getZonedata());

        $serviceXBillImpl = new DNSServiceXBillImplTest($log);
        // TIMEOUT 2 seconds
        $serviceXBillImpl->setTimeOut(self::TIMEOUT);
        return $serviceXBillImpl;
    }

    /**
     * @return a real dns resolver
     */
    protected function getDNSServiceReal() {
        $serviceXBillImpl = new DNSServiceXBillImpl($log);
        // TIMEOUT 2 seconds
        $serviceXBillImpl->setTimeOut(self::TIMEOUT);
        return $serviceXBillImpl;
    }

   /*  public AbstractYamlTest() {
        super();
    } */


    /**
     * Return a string representation of a DNSService record type.
     *
     * @param recordType the DNSService.CONSTANT type to convert
     * @return a string representation of the given record type
     */
    public static function getRecordTypeDescription($recordType) {
        switch ($recordType) {
            case DNSRequest::A: return "A";
            case DNSRequest::AAAA: return "AAAA";
            case DNSRequest::MX: return "MX";
            case DNSRequest::PTR: return "PTR";
            case DNSRequest::TXT: return "TXT";
            case DNSRequest::SPF: return "SPF";
            default: return null;
        }
    }

    protected function getSpfExecutorType() {
        return spfExecutorType;
    }

}

final class SPFYamlDNSService implements DNSService {

    private $zonedata = array();
    private $recordLimit;

    public function __construct(array $zonedata) {
        $this->zonedata = $zonedata;
        $this->recordLimit = 10;
    }

    public function getLocalDomainNames() {
        $l = array();
        $l[] = "localdomain.foo.bar";
        return $l;
    }

    public function setTimeOut($timeOut) {
        try {
            throw new UnsupportedOperationException("setTimeOut()");
        } catch (UnsupportedOperationException $e) {
            $e->printStackTrace();
            throw $e;
        }
    }

    public function getRecordLimit() {
        return $this->recordLimit;
    }

    public function setRecordLimit($recordLimit) {
        $this->recordLimit = $recordLimit;
    }

    public function getRecords(DNSRequest $request) {
        return getRecords(request.getHostname(), request.getRecordType(), 6);
    }

    public function getRecords($hostname, $recordType, $depth) {
        $type = getRecordTypeDescription(recordType);

        $res;

        // remove trailing dot before running the search.
        if (hostname.endsWith(".")) {
            $hostname = $hostname.substring(0, hostname.length()-1);
        }

        // dns search lowercases:
        $hostname = hostname.toLowerCase(Locale.US);

        if (zonedata.get(hostname) != null) {
            $l = $zonedata.get(hostname);
            $i = l.iterator();
            $res = array();
            while ($i.hasNext()) {
                $o = i.next();
                if ($o instanceof HashMap) {
                    $hm = $o;
                    if ($hm.get(type) != null) {
                        if ($recordType == DNSRequest.MX) {
                            $mxList = $hm.get(type);

                            // For MX records we overwrite the result ignoring the priority.
                            $mxs = $mxList.iterator();
                            while (mxs.hasNext()) {
                                // skip the MX priority
                                mxs.next();
                                $cname = mxs.next();
                                res.add(cname);
                            }
                        } else {
                            $obj = $hm.get(type);

                            if ($obj instanceof String) {
                                res.add((String)obj);
                            } else if ($obj instanceof ArrayList) {
                                $a = $obj;
                                $sb = new StringBuffer();

                                for ($i2 = 0; i2 < a.size(); $i2++) {
                                    sb.append(a.get(i2));
                                }
                                res.add(sb.toString());
                            }
                        }
                    }
                    if (hm.get("CNAME") != null && depth > 0) {
                        return getRecords((String) hm.get("CNAME"), recordType, depth - 1);
                    }
                } else if ("TIMEOUT".equals(o)) {
                    throw new TimeoutException("TIMEOUT");
                } else {
                    throw new IllegalStateException("getRecord found an unexpected data");
                }
            }
            return res.size() > 0 ? res : null;
        }
        return null;
    }

}


class RFC4408SPF1ParserTest1 extends RFC4408SPF1Parser {

}

class DefaultTermsFactoryTest1 extends DefaultTermsFactory {

}
class WiringServiceTest1 extends WiringService {

    public function wire($component) {
        if ($component instanceof LogEnabled) {
            $path = $component->getClass()->toString().split("\\.");
            $component->enableLogging($log->getChildLogger("dep").getChildLogger($path[$path.length-1].toLowerCase()));
        }
        if ($component instanceof MacroExpandEnabled) {
            $component->enableMacroExpand($macroExpand);
        }
        if (component instanceof DNSServiceEnabled) {
            $component->enableDNSService($dns);
        }
        if (component instanceof SPFCheckEnabled) {
            $component->enableSPFChecking($spf);
        }
    }
}

class DNSServiceXBillImplTest extends DNSServiceXBillImpl {
    public function getLocalDomainNames() {
        $l = array();
        $l[] = "localdomain.foo.bar";
        return $l;
    }

}