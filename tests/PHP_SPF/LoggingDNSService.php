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

use PHP_SPF\Core\DNSService;

class LoggingDNSService implements DNSService {

    private $dnsService;
    private $logger;

    public function __construct(DNSService $service, Logger $logger) {
        $this->dnsService = $service;
        $this->logger = $logger;
    }

    /**
     * (non-Javadoc)
     * @see org.apache.james.jspf.core.DNSService#getRecordLimit()
     */
    public function getRecordLimit() {
        return dnsService.getRecordLimit();
    }

    /**
     * (non-Javadoc)
     * @see org.apache.james.jspf.core.DNSService#setRecordLimit(int)
     */
    public function setRecordLimit($recordLimit) {
        $this->dnsService->setRecordLimit(recordLimit);
    }

    /**
     * (non-Javadoc)
     * @see org.apache.james.jspf.core.DNSService#getLocalDomainNames()
     */
    public function getLocalDomainNames() {
        $res = dnsService.getLocalDomainNames();
        $logBuff = '';
        $logBuff .= "getLocalDomainNames() = ";
        if ($res != null) {
            for ($i = 0; $i < $res.size(); $i++) {
                $logBuff .= $res.get($i);
                if ($i == res.size() - 1) {
                    $logBuff .= "";
                } else {
                    $logBuff .= ",";
                }
            }
        } else {
            $logBuff .= "getLocalDomainNames-ret: null";
        }
        $logger->debug($logBuff);
        return $res;

    }

    /**
     * (non-Javadoc)
     * @see org.apache.james.jspf.core.DNSService#setTimeOut(int)
     */
    public function setTimeOut($timeOut) {
        $this->dnsService->setTimeOut($timeOut);
    }

    /**
     * (non-Javadoc)
     * @see org.apache.james.jspf.core.DNSService#getRecords(org.apache.james.jspf.core.DNSRequest)
     */
    public function getRecords(DNSRequest $request) {
        try {
            $result = $this->dnsService->getRecords($request);
            $logBuff = '';
            $logBuff .= "getRecords(" . $request->getHostname() . "," . $request->getRecordType() . ") = ";
            if (result != null) {
                for ($i = 0; $i < $result.size(); $i++) {
                    logBuff.append(result.get(i));
                    if (i == result.size() - 1) {
                        logBuff.append("");
                    } else {
                        logBuff.append(",");
                    }
                }
            } else {
                logBuff.append("getRecords-ret: null");
            }
            logger.debug(logBuff.toString());
            return result;
        } catch (TimeoutException $e) {
            $this->logger->debug("getRecords(" . $request->getHostname()
                    . ") = TempErrorException[" . $e->getMessage() . "]");
            throw $e;
        }
    }
}