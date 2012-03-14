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

namespace PHP_SPF\Core\MacroExpand;

use PHP_SPF\Core\DNSResponse;
use PHP_SPF\Core\SPFSession;
use PHP_SPF\Core\SPFCheckerDNSResponseListener;
use PHP_SPF\Core\Exceptions\PermErrorException;
use PHP_SPF\Core\Exceptions\TimeoutException;

class AResponseListener implements SPFCheckerDNSResponseListener {

    /**
     * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
     */
    public function onDNSResponse(DNSResponse $response, SPFSession $session) {
        // just return the default "unknown" if we cannot find anything
        // later
        $session->setClientDomain("unknown");
        try {
            $records = $response.getResponse();
            if (records != null && records.size() > 0) {
                $i = records.iterator();
                while (i.hasNext()) {
                    $next = i.next();
                    if (IPAddr::getAddress(session.getIpAddress())
                            .toString().equals(
                                    IPAddr.getAddress(next).toString())) {
                        session
                        .setClientDomain((String) session
                                .getAttribute(ATTRIBUTE_MACRO_EXPAND_CHECKED_RECORD));
                        break;
                    }
                }
            }
        } catch (TimeoutException $e) {
            // just return the default "unknown".
        } catch (PermErrorException $e) {
            // just return the default "unknown".
        }
        return null;
    }
}