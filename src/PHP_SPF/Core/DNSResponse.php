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

use PHP_SPF\Core\Exceptions\TimeoutException;

/**
 * Represent a DNSResponse
 *
 */
class DNSResponse {

    private $response = array();

    private $exception;

    public function __construct($arg1) {
        if ($arg1 instanceof TimeoutException) {
            $this->exception = $exception;
            $this->response = null;
        } else {
            $this->exception = null;
            $this->response = $response;
        }
    }

    /**
     * Returns the DNS response
     *
     * @return the dns repsonse
     * @throws TimeoutException get thrown if an timeout was returned while tried to
     *         process a dns request
     */
    public function getResponse() {
        if ($this->exception != null) {
            throw $this->exception;
        } else {
            return $this->response;
        }
    }

    /**
     * @see java.lang.Object#toString()
     */
    public function toString() {
        if ($this->exception != null) {
            return "EXCEPTION!";
        } else if ($this->response != null) {
            return $this->response->toString();
        } else {
            return "NULL?";
        }
    }
}