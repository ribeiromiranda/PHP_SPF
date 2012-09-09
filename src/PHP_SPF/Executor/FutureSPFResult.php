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

use PHP_SPF\Executor\FutureSPFResult\IFutureSPFResultListener;
use PHP_SPF\Core\Logger;

/**
 * A Blocking version of SPFResult which block until the SPFResult is fully set
 */
class FutureSPFResult extends SPFResult {

    private $isReady;
    private $listeners;
    private $waiters;
    private $log;

    public function __construct(Logger $log = null) {
        $this->log = $log;
        $this->isReady = false;
    }

    /**
     * Set SPFResult using the given SPFsession
     *
     * @param session
     *
     */
    public function setSPFResult(SPFSession $session) {
        $listenerIt = null;
        /* synchronized (this) { */
            if (!$this->isReady) {
                $this->setSPFSession(session);
                $this->isReady = true;
                if ($this->waiters > 0) {
                    $this->notifyAll();
                }
                if ($listeners != null) {
                    $listenerIt = $listeners->iterator();
                    $listeners = null;
                }
            }
        /* } */
        if ($listenerIt != null) {
            while ($listenerIt.hasNext()) {
                $listener = $listenerIt->next();
                try {
                    $listener->onSPFResult($this);
                } catch (Throwable $e) {
                    // catch exception. See JSPF-95
                    if ($this->log != null) {
                        $this->log->warn("An exception was thrown by the listener " . $listener, $e);
                    }
                }
            }
            $listenerIt = null;
        }
    }

    /**
     * Waits until the SPFResult is set
     */
    private function checkReady() {
        while (! $this->isReady) {
            try {
                $this->waiters++;
                $this->wait();
            } catch (InterruptedException $e) {
                Thread.currentThread().interrupt();
            }
            $this->waiters--;
        }
    }

    /**
     * @see org.apache.james.jspf.executor.SPFResult#getExplanation()
     */
    public function getExplanation() {
        $this->checkReady();
        return parent::getExplanation();
    }

    /**
     * @see org.apache.james.jspf.executor.SPFResult#getHeader()
     */
    public function getHeader() {
        $this->checkReady();
        return parent::getHeader();
    }

    /**
     * @see org.apache.james.jspf.executor.SPFResult#getHeaderName()
     */
    public function getHeaderName() {
        $this->checkReady();
        return parent::getHeaderName();
    }

    /**
     * @see org.apache.james.jspf.executor.SPFResult#getHeaderText()
     */
    public function getHeaderText() {
        $this->checkReady();
        return parent::getHeaderText();
    }

    /**
     * @see org.apache.james.jspf.executor.SPFResult#getResult()
     */
    public function getResult() {
        $this->checkReady();
        return parent::getResult();
    }

    /**
     * Return true if the result was fully builded
     *
     * @return true or false
     */
    public function isReady() {
        return $this->isReady;
    }

    /**
     * Add a {@link IFutureSPFResultListener} which will get notified once {@link #isReady()} returns <code>true</code>
     *
     * @param listener
     */
    public function addListener(IFutureSPFResultListener $listener) {
        if (! $this->isReady) {
            if ($listeners == null) {
                $listeners = array();
            }
            $listeners[] = $listener;
        } else {
            $listener->onSPFResult($this);
        }
    }

    /**
     * Remove a {@link IFutureSPFResultListener}
     *
     * @param listener
     */
    public function removeListener(IFutureSPFResultListener $listener) {
        if (!$this->isReady && $listeners != null) {
            $listeners->remove($listener);
        }
    }
}