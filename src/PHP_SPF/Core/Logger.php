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
 * This is a facade for the different logging subsystems. It offers a simplified
 * interface that follows IOC patterns and a simplified priority/level/severity
 * abstraction.
 */
interface Logger {

    /**
     * Log a debug message.
     *
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public function debug($message, $throwable = null);

    /**
     * Determine if messages of priority "debug" will be logged.
     *
     * @return true if "debug" messages will be logged
     */
    public function isDebugEnabled();

    /**
     * Log a info message.
     *
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public function info($message, $throwable = null);

    /**
     * Determine if messages of priority "info" will be logged.
     *
     * @return true if "info" messages will be logged
     */
    public function isInfoEnabled();


    /**
     * Log a warn message.
     *
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public function warn($message, $throwable = null);

    /**
     * Determine if messages of priority "warn" will be logged.
     *
     * @return true if "warn" messages will be logged
     */
    public function isWarnEnabled();

    /**
     * Log a error message.
     *
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public function error($message, $throwable = null);

    /**
     * Determine if messages of priority "error" will be logged.
     *
     * @return true if "error" messages will be logged
     */
    public function isErrorEnabled();

    /**
     * Log a fatalError message.
     *
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public function fatalError($message, $throwable = null);

    /**
     * Determine if messages of priority "fatalError" will be logged.
     *
     * @return true if "fatalError" messages will be logged
     */
    public function isFatalErrorEnabled();

    /**
     * Create a new child logger. The name of the child logger is
     * [current-loggers-name].[passed-in-name] Throws
     * <code>IllegalArgumentException</code> if name has an empty element name
     *
     * @param name
     *            the subname of this logger
     * @return the new logger
     */
    public function getChildLogger($name);
}
