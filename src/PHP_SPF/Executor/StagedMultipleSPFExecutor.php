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
 * Async implementation of SPFExecutor
 *
 */
class StagedMultipleSPFExecutor implements SPFExecutor {

    const ATTRIBUTE_STAGED_EXECUTOR_CONTINUATION = "StagedMultipleSPFExecutor.continuation";



    // Use short as id because the id header is limited to 16 bit
    // From RFC1035 4.1.1. Header section format :
    //
    // ID              A 16 bit identifier assigned by the program that
    //                 generates any kind of query.  This identifier is copied
    //                 the corresponding reply and can be used by the requester
    //                 to match up replies to outstanding queries.
    //
    private static $id;

    private function nextId() {
        return $this->id++;
    }

    private $log;
    private $dnsProbe;
    private $worker;
    private $sessions;
    private $results;
    private $responseQueue;

    public function __construct(Logger $log, DNSAsynchLookupService $service) {
        $this->log = $log;
        $this->dnsProbe = service;

        $this->responseQueue = new ResponseQueueImpl();

        $this->sessions = Collections.synchronizedMap(array());
        $this->results = Collections.synchronizedMap(array());

        $this->worker = new Thread($this);
        $this->worker->setDaemon(true);
        $this->worker->setName("SPFExecutor");
        $this->worker->start();
    }

    /**
        * Execute the non-blocking part of the processing and returns.
        * If the working queue is full (50 pending responses) this method will not return
        * until the queue is again not full.
        *
        * @see org.apache.james.jspf.executor.SPFExecutor#execute(org.apache.james.jspf.core.SPFSession, org.apache.james.jspf.executor.FutureSPFResult)
        */
        public function execute(SPFSession $session, FutureSPFResult $result, $throttle = true) {
            $checker;
            while (($checker = $session->popChecker()) != null) {
                // only execute checkers we added (better recursivity)
                $this->log.debug("Executing checker: " + checker);
                try {
                    $cont = $checker->checkSPF($session);
                    // if the checker returns a continuation we return it
                    if (cont != null) {
                        $this->invokeAsynchService($session, $result, $cont, $throttle);
                        return;
                    }
                } catch (\Exception $e) {
                    while ($e != null) {
                        while ($checker == null || !($checker instanceof SPFCheckerExceptionCatcher)) {
                            $checker = $session->popChecker();
                        }
                        try {
                            $checker->onException($e, $session);
                            $e = null;
                        } catch (SPFResultException $ex) {
                            $e = $ex;
                        }
                        $this->checker = null;
                    }
                }
            }
            $result->setSPFResult($session);
        }

        /**
         * throttle should be true only when the caller thread is the client and not the worker thread.
         * We could even remove the throttle parameter and check the currentThread.
         * This way the worker is never "blocked" while outside callers will be blocked if our
         * queue is too big (so this is not fully "asynchronous").
         */
        private function invokeAsynchService(SPFSession $session,
                FutureSPFResult $result, DNSLookupContinuation $cont, $throttle) {
            while ($throttle && $results.size() > 50) {
                try {
                    $this->wait(100);
                } catch (InterruptedException $e) {
                }
            }
            $nextId = $this->nextId();
            $this->sessions[$nextId] = $session;
            $this->results[$nextId] = $result;
            $this->session->setAttribute(self::ATTRIBUTE_STAGED_EXECUTOR_CONTINUATION, $cont);
            $this->dnsProbe->getRecordsAsynch($cont->getRequest(), $nextId, $responseQueue);
        }

        public function run() {
            while (true) {
                $resp = $this->responseQueue->removeResponse();

                $respId = $resp->getId();
                $session = $sessions->remove($respId);
                $result = $results->remove($respId);

                $cont = $session->getAttribute(self::ATTRIBUTE_STAGED_EXECUTOR_CONTINUATION);

                $response;
                if ($resp->getException() != null) {
                    $response = new DNSResponse($resp->getException());
                } else {
                    $response = new DNSResponse($resp->getValue());
                }


                try {
                    $cont = $cont->getListener()->onDNSResponse($response, $session);

                    if ($cont != null) {
                        $this->invokeAsynchService($session, $result, $cont, false);
                    } else {
                        $this->execute($session, $result, false);
                    }

                } catch (\Exception $e) {
                    $checker = null;
                    while ($e != null) {
                        while ($checker == null || !($checker instanceof SPFCheckerExceptionCatcher)) {
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
                    $this->execute($session, $result, false);
                }
            }
        }
}

class ResponseQueueImpl implements IResponseQueue {

    private $waitingThreads = 0;

    /**
     * @see org.apache.james.jspf.executor.IResponseQueue#insertResponse(org.apache.james.jspf.executor.IResponse)
     */
    public function insertResponse(IResponse $r) {
        $this->addLast($r);
        $this->notify();
    }

    /**
     * @see org.apache.james.jspf.executor.IResponseQueue#removeResponse()
     */
    public function removeResponse() {
        if ( ($this->size() - $this->waitingThreads <= 0) ) {
            try {
                $this->waitingThreads++;
                $this->wait();
            }
            catch (InterruptedException $e)  {
                Thread.interrupted();
            }
            $this->waitingThreads--;
        }
        return $this->removeFirst();
    }
}