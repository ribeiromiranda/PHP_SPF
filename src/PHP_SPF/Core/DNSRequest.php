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

/**
 * Represent a DNSRequest
 */
final class DNSRequest {

    /** The record types for the lookups */
    const A = 1;
    const AAAA = 2;
    const MX = 3;
    const PTR = 4;
    const TXT = 5;
    const SPF = 6;

    /**
     * The hostname to be resolved
     */
    private $hostname;

    /**
     * The record type to look for
     */
    private $recordType;

    public function __construct($hostname, $recordType) {
        if ($recordType == self::MX || $recordType == self::A || $recordType == self::AAAA) {
            try {
                Name::fromString($hostname);
            } catch (TextParseException $e) {
                throw new NoneException(e.getMessage());
            }
        }
        $this->hostname = $hostname;
        $this->recordType = $recordType;
    }

    /**
     * Return the hostname to process the request for
     *
     * @return the hostname
     */
    public final function getHostname() {
        return $this->hostname;
    }

    /**
     * Return the RecordType which is use for this request
     *
     * @return the RecordType
     */
    public final function getRecordType() {
        return $this->recordType;
    }

    /**
     * @see java.lang.Object#toString()
     */
    public function toString() {
        return "{$this->getHostname()}#{$this->getRecordType()}";
    }
}
