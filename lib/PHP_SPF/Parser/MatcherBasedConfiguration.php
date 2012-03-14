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

namespace PHP_SPF\Parser;

/**
 *
 * Provides a MatchResult view of a subset of another MatchResult
 */
class MatcherBasedConfiguration implements Configuration {

    private $wrapped;

    private $start;

    private $count;

    /**
     * @param w
     *            Original MatchResult
     * @param start
     *            the position where the subresult start
     * @param count
     *            number of groups part of the subresult
     */
    public function __contruct(Matcher $w, $start, $count) {
        $this->wrapped = $w;
        $this->count = $count;
        $this->start = $start;
    }

    /**
     * @see org.apache.james.jspf.terms.Configuration#group(int)
     */
    public function group($arg0) {
        return $this->wrapped.group($arg0 + $start);
    }

    /**
     * @see org.apache.james.jspf.terms.Configuration#groupCount()
     */
    public function groupCount() {
        return $this->count;
    }

}