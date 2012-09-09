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
 * This constants are used by Terms to define their matching rules.
 */
abstract class SPFTermsRegexps {

    public static function ALPHA_PATTERN() {
        return "[a-zA-Z]";
    }

    public static function MACRO_LETTER_PATTERN_EXP() {
        return "[rctlsodipvhRCTLSODIPVH]";
    }

    public static function MACRO_LETTER_PATTERN() {
        return "[lsodipvhLSODIPVH]";
    }

    public static function TRANSFORMERS_REGEX () {
        return "\\d*[r]?";
    }

    public static function DELEMITER_REGEX() {
        return "[\\.\\-\\+,/_\\=]";
    }

    public static function MACRO_LETTERS_REGEX() {
        return self::MACRO_LETTER_PATTERN_EXP() . self::TRANSFORMERS_REGEX() . self::DELEMITER_REGEX() . '*';
    }

    public static function MACRO_EXPAND_REGEX() {
        return "\\%(?:\\{" . self::MACRO_LETTERS_REGEX() . "\\}|\\%|\\_|\\-)";
    }

    public static function MACRO_LITERAL_REGEX() {
        return "[\\x21-\\x24\\x26-\\x7e]";
    }

    /**
     * This is used by the MacroExpander
     */
    public static function MACRO_STRING_REGEX_TOKEN() {
        return self::MACRO_EXPAND_REGEX() . "|" . self::MACRO_LITERAL_REGEX() . "{1}";
    }


    /**
     * ABNF: macro-string = *( macro-expand / macro-literal )
     */
    public static function MACRO_STRING_REGEX() {
        "(?:" + self::MACRO_STRING_REGEX_TOKEN() +")*";
    }

    public static function ALPHA_DIGIT_PATTERN() {
        return "[a-zA-Z0-9]";
    }

    /**
     * ABNF: toplabel = ( *alphanum ALPHA *alphanum ) / ( 1*alphanum "-" *(
     * alphanum / "-" ) alphanum ) ; LDH rule plus additional TLD restrictions ;
     * (see [RFC3696], Section 2)
     */
    public static function TOP_LABEL_REGEX() {
        return "(?:" .
        self::ALPHA_DIGIT_PATTERN() . "*" . self::ALPHA_PATTERN()
        . "{1}" . self::ALPHA_DIGIT_PATTERN() . "*|(?:"
        . self::ALPHA_DIGIT_PATTERN() . "+" . "\\-" . "(?:"
        . self::ALPHA_DIGIT_PATTERN() . "|\\-)*"
        . self::ALPHA_DIGIT_PATTERN() . "))";
    }

    /**
     * ABNF: domain-end = ( "." toplabel [ "." ] ) / macro-expand
     */
    public static function DOMAIN_END_REGEX() {
        return "(?:\\." . self::TOP_LABEL_REGEX()
            . "\\.?" . "|" . self::MACRO_EXPAND_REGEX() . ")";
    }


    /**
     * ABNF: domain-spec = macro-string domain-end
     */
    public static function DOMAIN_SPEC_REGEX() {
        return "(" .
            self::MACRO_STRING_REGEX() . self::DOMAIN_END_REGEX() . ")";
    }


    /**
     * Spring MACRO_STRING from DOMAIN_END (domain end starts with .)
     */
    public static function DOMAIN_SPEC_REGEX_R() {
        return "(" .
            self::MACRO_STRING_REGEX() . ")(" . self::DOMAIN_END_REGEX() . ")";
    }

    public static function process($regexp) {
        return str_replace('/', '\/', $regexp);
    }

}