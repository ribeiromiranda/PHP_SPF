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

/**
 * Logger sending everything to the standard output streams.
 * This is mainly for the cases when you have a utility that
 * does not have a logger to supply.
 */
final class ConsoleLogger implements Logger {

    /** Typecode for debugging messages. */
    const LEVEL_DEBUG = 0;

    /** Typecode for informational messages. */
    const LEVEL_INFO = 1;

    /** Typecode for warning messages. */
    const LEVEL_WARN = 2;

    /** Typecode for error messages. */
    const LEVEL_ERROR = 3;

    /** Typecode for fatal error messages. */
    const LEVEL_FATAL = 4;

    /** Typecode for disabled log levels. */
    const LEVEL_DISABLED = 5;

    private $m_logLevel;

    /**
     * Current logger path.
     */
    private $m_path;

    /**
     * Creates a new ConsoleLogger.
     * @param logLevel log level typecode
     */
    public function __construct( $logLevel = self::LEVEL_DEBUG, $path = "ROOT")
    {
        $this->m_logLevel = $logLevel;
        $this->m_path = $path;
    }


    /**
     * Logs a debugging message and an exception.
     *
     * @param message a <code>String</code> value
     * @param throwable a <code>Throwable</code> value
     */
    public function debug( $message, $throwable = null)
    {
        if( $this->m_logLevel <= self::LEVEL_DEBUG )
        {
            echo "[DEBUG] " ;
            echo $this->m_path . " ";
            echo $message;

            if( null != $throwable )
            {
                throwable.printStackTrace( System.out );
            }
        }
    }

    /**
     * Returns <code>true</code> if debug-level logging is enabled, false otherwise.
     *
     * @return <code>true</code> if debug-level logging
     */
    public function isDebugEnabled()
    {
        return $this->m_logLevel <= self::LEVEL_DEBUG;
    }

    /**
     * Logs an informational message and an exception.
     *
     * @param message a <code>String</code> value
     * @param throwable a <code>Throwable</code> value
     */
    public function info( $message, $throwable = null )
    {
        if( $this->m_logLevel <= self::LEVEL_INFO )
        {
            System.out.print( "[INFO] " );
            System.out.print( m_path+" " );
            System.out.println( message );

            if( null != $throwable )
            {
                throwable.printStackTrace( System.out );
            }
        }
    }

    /**
     * Returns <code>true</code> if info-level logging is enabled, false otherwise.
     *
     * @return <code>true</code> if info-level logging is enabled
     */
    public function isInfoEnabled()
    {
        return $this->m_logLevel <= self::LEVEL_INFO;
    }

    /**
     * Logs a warning message and an exception.
     *
     * @param message a <code>String</code> value
     * @param throwable a <code>Throwable</code> value
     */
    public function warn( $message, $throwable = null )
    {
        if( $this->m_logLevel <= self::LEVEL_WARN )
        {
            System.out.print( "[WARNING] " );
            System.out.print( m_path+" " );
            System.out.println( message );

            if( null != $throwable )
            {
                throwable.printStackTrace( System.out );
            }
        }
    }

    /**
     * Returns <code>true</code> if warn-level logging is enabled, false otherwise.
     *
     * @return <code>true</code> if warn-level logging is enabled
     */
    public function isWarnEnabled()
    {
        return $this->m_logLevel <= self::LEVEL_WARN;
    }

    /**
     * Logs an error message and an exception.
     *
     * @param message a <code>String</code> value
     * @param throwable a <code>Throwable</code> value
     */
    public function error( $message, $throwable = null )
    {
        if( $this->m_logLevel <= self::LEVEL_ERROR )
        {
            System.out.print( "[ERROR] " );
            System.out.print( m_path+" " );
            System.out.println( message );

            if( null != $throwable )
            {
                throwable.printStackTrace( System.out );
            }
        }
    }

    /**
     * Returns <code>true</code> if error-level logging is enabled, false otherwise.
     *
     * @return <code>true</code> if error-level logging is enabled
     */
    public function isErrorEnabled()
    {
        return $this->m_logLevel <= self::LEVEL_ERROR;
    }

    /**
     * Logs a fatal error message and an exception.
     *
     * @param message a <code>String</code> value
     * @param throwable a <code>Throwable</code> value
     */
    public function fatalError( $message, $throwable = null )
    {
        if( $this->m_logLevel <= self::LEVEL_FATAL )
        {
            System.out.print( "[FATAL ERROR] " );
            System.out.print( m_path+" " );
            System.out.println( message );

            if( null != $throwable )
            {
                throwable.printStackTrace( System.out );
            }
        }
    }

    /**
     * Returns <code>true</code> if fatal-level logging is enabled, false otherwise.
     *
     * @return <code>true</code> if fatal-level logging is enabled
     */
    public function isFatalErrorEnabled()
    {
        return $this->m_logLevel <= self::LEVEL_FATAL;
    }

    /**
     * Just returns this logger (<code>ConsoleLogger</code> is not hierarchical).
     *
     * @param name ignored
     * @return this logger
     */
    public function getChildLogger($name)
    {
        return new self($this->m_logLevel, "{$this->m_path}.{$name}");
    }
}