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


/**
 * Implementation of the Logger interface using the Log4J implementation
 * strategy.
 */
class Log4JLogger implements Logger {
    private $m_Logger;

    public function __construct($log4jLogger) {
        $this->m_Logger = $log4jLogger;
    }

    /**
     * Log a debug message.
     *
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public function debug($message, $throwable = null) {
        m_Logger.debug(message, throwable);
    }

    /**
     * Determine if messages of priority "debug" will be logged.
     *
     * @return true if "debug" messages will be logged
     */
    public function isDebugEnabled() {
        return m_Logger.isDebugEnabled();
    }

    /**
     * Log a info message.
     *
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public function info($message, $throwable = null) {
        m_Logger.info(message, throwable);
    }

    /**
     * Determine if messages of priority "info" will be logged.
     *
     * @return true if "info" messages will be logged
     */
    public function isInfoEnabled() {
        return m_Logger.isInfoEnabled();
    }

    /**
     * Log a warn message.
     *
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public function warn($message, $throwable = null) {
        m_Logger.warn(message, throwable);
    }

    /**
     * Determine if messages of priority "warn" will be logged.
     *
     * @return true if "warn" messages will be logged
     */
    public function isWarnEnabled() {
        return m_Logger.isEnabledFor(Level.WARN);
    }

    /**
     * Log a error message.
     *
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public function error($message, $throwable = null) {
        m_Logger.error(message, throwable);
    }

    /**
     * Determine if messages of priority "error" will be logged.
     *
     * @return true if "error" messages will be logged
     */
    public function isErrorEnabled() {
        return m_Logger.isEnabledFor(Level.ERROR);
    }

    /**
     * Log a fatalError message.
     *
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public function fatalError($message, $throwable = null) {
        m_Logger.fatal(message, throwable);
    }

    /**
     * Determine if messages of priority "fatalError" will be logged.
     *
     * @return true if "fatalError" messages will be logged
     */
    public function isFatalErrorEnabled() {
        return m_Logger.isEnabledFor(Level.FATAL);
    }

    /**
     * Create a new child logger. The name of the child logger is
     * [current-loggers-name].[passed-in-name] Throws
     * <code>IllegalArgumentException</code> if name has an empty element name
     *
     * @param name
     *            the subname of this logger
     * @return the new logger
     */
    public function getChildLogger($name) {
        $newName = m_Logger.getName() + "." + $name;
        $childLog4JLogger = org.apache.log4j.Logger.getLogger(newName);
        $child = new Log4JLogger($childLog4JLogger);
        return $child;
    }
}
