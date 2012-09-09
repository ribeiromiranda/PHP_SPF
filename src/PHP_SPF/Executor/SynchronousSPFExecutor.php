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

namespace PHP_SPF\Executor;


use PHP_SPF\Core\Exceptions\SPFResultException;
/**
 * Synchronous implementation of SPFExecuter. All queries will get executed synchronously
 */


class SynchronousSPFExecutor implements SPFExecutor {

    private $log;

    private $dnsProbe;

    public function __construct(Logger $log, DNSService $service) {
        $this->log = $log;
        $this->dnsProbe = $service;
    }

    /**
     * @see org.apache.james.jspf.executor.SPFExecutor#execute(org.apache.james.jspf.core.SPFSession, org.apache.james.jspf.executor.FutureSPFResult)
     */
    public function execute(SPFSession $session, FutureSPFResult $result) {
        $checker;
        while (($checker = $session->popChecker()) != null) {
            // only execute checkers we added (better recursivity)
            $this->log->debug("Executing checker: {$checker}");
            try {
                $cont = $checker->checkSPF($session);
                // if the checker returns a continuation we return it
                while ($cont != null) {
                    $response;
                    try {
                        $response = new DNSResponse($dnsProbe->getRecords($cont->getRequest()));
                    } catch (TimeoutException $e) {
                        $response = new DNSResponse($e);
                    }
                    $cont = $cont->getListener()->onDNSResponse($response, $session);
                }

            } catch (\Exception $e) {
                while ($e != null) {
                    while ($checker == null || ! ($checker instanceof SPFCheckerExceptionCatcher)) {
                        $checker = $session->popChecker();
                    }
                    try {
                        $checker->onException($e, $session);
                        $e = null;
                    } catch (SPFResultException $ex) {
                        $e = $ex;
                    }
                    $checker = null;

                }
            }
        }

        $result->setSPFResult($session);
    }
}