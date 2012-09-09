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

namespace PHP_SPF\Impl;

use PHP_SPF\Core\DNSService;

/**
 * This class contains helper to get all neccassary DNS infos that are needed
 * for SPF
 */
class DNSServiceXBillImpl implements DNSService {

    // The logger
    protected $log;

    // The record limit for lookups
    protected $recordLimit;

    // The resolver used for the lookup
    protected $resolver;

    /**
     * Constructor to specify a custom resolver.
     */
    public function __construct(Logger $logger, Resolver $resolver = null) {

        if ($resolver === null) {
            $resolver = Lookup::getDefaultResolver();
        }

        $this->log = $logger;
        $this->resolver = $resolver;
        // Default record limit is 10
        $this->recordLimit = 10;
    }

    /**
     * NOTE if this class is created with the default constructor it
     * will use the static DefaultResolver from DNSJava and this method
     * will change it's timeout.
     * Other tools using DNSJava in the same JVM could be affected by
     * this timeout change.
     *
     * @see org.apache.james.jspf.core.DNSService#setTimeOut(int)
     */
    public function setTimeOut($timeOut) {
        $this->resolver->setTimeout($timeOut);
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getLocalDomainNames()
     */
    public function getLocalDomainNames() {
        $names = array();

        $this->log->debug("Start Local ipaddress lookup");
        try {
            $ia[] = InetAddress.getAllByName(InetAddress::getLocalHost()->getHostName());

            for ($i = 0; i < $ia.length; $i++) {
                $host = $ia[$i]->getHostName();
                $names[] = $host;

                $this->log->debug("Add hostname {$host} to list");
            }
        } catch (UnknownHostException $e) {
            // just ignore this..
        }
        return names;

    }

    /**
     * @return the current record limit
     */
    public function getRecordLimit() {
        return $this->recordLimit;
    }

    /**
     * Set a new limit for the number of records for MX and PTR lookups.
     * @param recordLimit
     */
    public function setRecordLimit($recordLimit) {
        $this->recordLimit = $recordLimit;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getRecords(org.apache.james.jspf.core.DNSRequest)
     */
    public function getRecords(DNSRequest $request) {
        $recordTypeDescription;
        $dnsJavaType;
        switch ($request->getRecordType()) {
            case DNSRequest::A: $recordTypeDescription = "A"; $dnsJavaType = Type.A; break;
            case DNSRequest::AAAA: $recordTypeDescription = "AAAA"; $dnsJavaType = Type.AAAA; break;
            case DNSRequest::MX: $recordTypeDescription = "MX"; $dnsJavaType = Type.MX; break;
            case DNSRequest::PTR: $recordTypeDescription = "PTR"; $dnsJavaType = Type.PTR; break;
            case DNSRequest::TXT: $recordTypeDescription = "TXT"; $dnsJavaType = Type.TXT; break;
            case DNSRequest::SPF: $recordTypeDescription= "SPF"; $dnsJavaType = Type.SPF; break;
            default: // TODO fail!
                return null;
        }
        try {

            $this->log->debug("Start {$recordTypeDescription}-Record lookup for : {$request->getHostname()}");

            $query = new Lookup($request->getHostname(), dnsJavaType);
            $query->setResolver($resolver);

            $rr = $query->run();
            $queryResult = $query->getResult();


            if (queryResult == Lookup.TRY_AGAIN) {
                throw new TimeoutException(query.getErrorString());
            }

            $records = self::convertRecordsToList(rr);

            log.debug("Found " + (rr != null ? rr.length : 0) + " "+recordTypeDescription+"-Records");
            return records;
        } catch (TextParseException $e) {
            // i think this is the best we could do
            log.debug("No "+recordTypeDescription+" Record found for host: " + request.getHostname());
            return null;
        }
    }

    /**
     * Convert the given Record array to a List
     *
     * @param rr Record array
     * @return list
     */
    public static function convertRecordsToList(array $rr) {
        $records;
        if ($rr != null && rr.length > 0) {
            $records = array();
            for ($i = 0; $i < $rr.length; $i++) {
                switch ($rr[$i].getType()) {
                    case Type.A:
                        $a = $rr[$i];
                        records.add(a.getAddress().getHostAddress());
                        break;
                    case Type.AAAA:
                        $aaaa = $rr[$i];
                        $records.add(aaaa.getAddress().getHostAddress());
                        break;
                    case Type.MX:
                        $mx = $rr[$i];
                        $records.add(mx.getTarget().toString());
                        break;
                    case Type.PTR:
                        $ptr = $rr[$i];
                        $records.add(IPAddr.stripDot(ptr.getTarget().toString()));
                        break;
                    case Type.TXT:
                        $txt = $rr[$i];
                        if ($txt.getStrings().size() == 1) {
                            records.add((String)txt.getStrings().get(0));
                        } else {
                            $sb = '';
                            for ($it = $txt->getStrings().iterator(); $it.hasNext();) {
                                $k = $it.next();
                                $sb .= $k;
                            }
                            records.add(sb.toString());
                        }
                        break;
                    case Type.SPF:
                        $spf = $rr[$i];
                        if ($spf->getStrings().size() == 1) {
                            records.add($spf->getStrings().get(0));
                        } else {
                            $sb = '';
                            for ($it = $spf.getStrings().iterator(); $it
                            .hasNext();) {
                                $k = $it.next();
                                $sb .= $k;
                            }
                            $records[] = $sb->toString();
                        }
                        break;
                    default:
                        return null;
                }
            }
        } else {
            $records = null;
        }
        return $records;
    }
}
