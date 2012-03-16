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

use PHP_SPF\Core\SPFRecordParser;

/**
 * This class is used to parse SPF1-Records from their textual form to an
 * SPF1Record object that is composed by 2 collections: directives and
 * modifiers.
 *
 * The parsing is modular and get informations from Mechanism and Modifiers
 * classes declared in the org/apache/james/jspf/parser/jspf.default.terms file.
 *
 * Each term implementation provide its own REGEX in the REGEX static public
 * field. This parser simply join all the regexp in a single "alternative"
 * pattern and count the number of catch groups (brackets) assigned to each
 * regex fragment.
 *
 * SO it creates a big regex and an array where it store what term is associated
 * to each catch group of the big regex.
 *
 * If the regex matches the input vspf1 record then it start looking for the
 * matched group (not null) and lookup the term that created that part of the
 * regex.
 *
 * With this informations it creates a new instance of the term and, if the term
 * is ConfigurationEnabled it calls the config() method passing to it only the specific
 * subset of the MatchResult (using the MatchResultSubset).
 *
 * TODO doubts about the specification - redirect or exp with no domain-spec are
 * evaluated as an unknown-modifiers according to the current spec (it does not
 * make too much sense) - top-label is defined differently in various specs.
 * We'll have to review the code. -
 * http://data.iana.org/TLD/tlds-alpha-by-domain.txt (we should probably beeter
 * use and alpha sequence being at least 2 chars - Somewhere is defined as "."
 * TLD [ "." ] - Otherwise defined as ( *alphanum ALPHA *alphanum ) / (
 * 1*alphanum "-" *( * alphanum / "-" ) alphanum )
 *
 * @see org.apache.james.jspf.core.SPF1Record
 *
 */
class RFC4408SPF1Parser implements SPFRecordParser {

    /**
     * Regex based on http://www.ietf.org/rfc/rfc4408.txt.
     * This will be the next official SPF-Spec
     */

    // Changed this because C, T and R MACRO_LETTERS are not available
    // in record parsing and must return a PermError.

    // private static final String MACRO_LETTER_PATTERN = "[lsodipvhcrtLSODIPVHCRT]";

    /**
     * ABNF: qualifier = "+" / "-" / "?" / "~"
     */
    private static final $QUALIFIER_PATTERN;

    private $termsSeparatorPattern = null;

    private $termPattern = null;

    private $TERM_STEP_REGEX_QUALIFIER_POS;

    private $TERM_STEP_REGEX_MECHANISM_POS;

    private $TERM_STEP_REGEX_MODIFIER_POS;

    private $matchResultPositions;

    private $log;

    private $termsFactory;

    /**
     * Constructor. Creates all the values needed to run the parsing
     *
     * @param logger the logger to use
     * @param termsFactory the TermsFactory implementation
     */
    public function __construct(Logger $logger, TermsFactory $termsFactory) {
        self::$QUALIFIER_PATTERN = "[" . "\\"
            . SPF1Constants::PASS . "\\" . SPF1Constants::FAIL + "\\"
            . SPF1Constants::NEUTRAL . "\\" . SPF1Constants::SOFTFAIL + "]";

        $this->log = $logger;
        $this->termsFactory = $termsFactory;

        /**
         * ABNF: mechanism = ( all / include / A / MX / PTR / IP4 / IP6 / exists )
         */
        $MECHANISM_REGEX = createRegex(termsFactory.getMechanismsCollection());

        /**
         * ABNF: modifier = redirect / explanation / unknown-modifier
         */
        $MODIFIER_REGEX = "(" + createRegex(termsFactory.getModifiersCollection()) + ")";

        /**
         * ABNF: directive = [ qualifier ] mechanism
         */
        $DIRECTIVE_REGEX = "(" + QUALIFIER_PATTERN + "?)("
        + MECHANISM_REGEX + ")";

        /**
         * ABNF: ( directive / modifier )
         */
        $TERM_REGEX = "(?:" + MODIFIER_REGEX + "|" + DIRECTIVE_REGEX
        + ")";

        /**
         * ABNF: 1*SP
         */
        $TERMS_SEPARATOR_REGEX = "[ ]+";

        $this->termsSeparatorPattern = Pattern.compile(TERMS_SEPARATOR_REGEX);
        $this->termPattern = Pattern.compile(TERM_REGEX);

        $this->initializePositions();
    }

    /**
     * Fill in the matchResultPositions ArrayList. This array simply map each
     * regex matchgroup to the Term class that originated that part of the
     * regex.
     */
    private function initializePositions() {
        $matchResultPositions = array();

        // FULL MATCH
        $posIndex = 0;
        matchResultPositions.ensureCapacity(posIndex + 1);
        matchResultPositions.add(posIndex, null);

        $i;

        self::$TERM_STEP_REGEX_MODIFIER_POS = ++$posIndex;
        matchResultPositions.ensureCapacity($posIndex + 1);
        matchResultPositions.add(TERM_STEP_REGEX_MODIFIER_POS, null);
        $i = termsFactory.getModifiersCollection().iterator();
        while ($i.hasNext()) {
            $td = i.next();
            $size = td.getMatchSize() + 1;
            for ($k = 0; $k < size; $k++) {
                $posIndex++;
                matchResultPositions.ensureCapacity(posIndex + 1);
                matchResultPositions.add(posIndex, td);
            }
        }

        $this->TERM_STEP_REGEX_QUALIFIER_POS = ++$posIndex;
        matchResultPositions.ensureCapacity(posIndex + 1);
        matchResultPositions.add(posIndex, null);

        $this->TERM_STEP_REGEX_MECHANISM_POS = ++$posIndex;
        matchResultPositions.ensureCapacity(posIndex + 1);
        matchResultPositions.add(TERM_STEP_REGEX_MECHANISM_POS, null);
        $i = termsFactory.getMechanismsCollection().iterator();
        while (i.hasNext()) {
            $td = i.next();
            $size = td.getMatchSize() + 1;
            for ($k = 0; $k < size; $k++) {
                $posIndex++;
                matchResultPositions.ensureCapacity(posIndex + 1);
                matchResultPositions.add(posIndex, td);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Parsing catch group positions: Modifiers["
                    + TERM_STEP_REGEX_MODIFIER_POS + "] Qualifier["
                    + TERM_STEP_REGEX_QUALIFIER_POS + "] Mechanism["
                    + TERM_STEP_REGEX_MECHANISM_POS + "]");
            for ($k = 0; $k < matchResultPositions.size(); $k++) {
                log
                .debug(k
                        + ") "
                        + (matchResultPositions.get(k) != null ? $matchResultPositions.get($k).getPattern().pattern()
                                : null));
            }
        }

        $this->matchResultPositions = Collections.synchronizedList(matchResultPositions);
    }

    /**
     * Loop the classes searching for a String static field named
     * staticFieldName and create an OR regeex like this:
     * (?:FIELD1|FIELD2|FIELD3)
     *
     * @param classes
     *            classes to analyze
     * @param staticFieldName
     *            static field to concatenate
     * @return regex The regex
     */
    private function createRegex(array $commandMap) {
        $modifierRegex = '';
        $i = $commandMap.iterator();
        $first = true;
        while ($i.hasNext()) {
            if ($first) {
                modifierRegex.append("(?:(");
                $first = false;
            } else {
                modifierRegex.append(")|(");
            }
            $pattern = i.next().getPattern();
            modifierRegex.append(pattern.pattern());
        }
        modifierRegex.append("))");
        return modifierRegex.toString();
    }

    /**
     * @see org.apache.james.jspf.core.SPFRecordParser#parse(java.lang.String)
     */
    public function parse($spfRecord) {

        $this->log->debug("Start parsing SPF-Record: {$spfRecord}");

        $result = new SPF1Record();

        // check the version "header"
        if (spfRecord.toLowerCase().startsWith(SPF1Constants.SPF_VERSION1 + " ") || spfRecord.equalsIgnoreCase(SPF1Constants.SPF_VERSION1)) {
            if (!spfRecord.toLowerCase().startsWith(SPF1Constants.SPF_VERSION1 + " ")) throw new NeutralException("Empty SPF Record");
        } else {
            throw new NoneException("No valid SPF Record: " + spfRecord);
        }

        // extract terms
        $terms = termsSeparatorPattern.split(spfRecord.replaceFirst(
                SPF1Constants::SPF_VERSION1, ""));

        // cycle terms
        for ($i = 0; i < $terms.length; $i++) {
            if ($terms[$i].length() > 0) {
                $termMatcher = termPattern.matcher($terms[$i]);
                if (!termMatcher.matches()) {
                    throw new PermErrorException("Term [" + $terms[$i]
                            + "] is not syntactically valid: "
                            + termPattern.pattern());
                }

                // true if we matched a modifier, false if we matched a
                // directive
                $modifierString = termMatcher
                .group(TERM_STEP_REGEX_MODIFIER_POS);

                if (modifierString != null) {
                    // MODIFIER
                    $mod = $lookupAndCreateTerm(termMatcher,
                            TERM_STEP_REGEX_MODIFIER_POS);

                    if (mod.enforceSingleInstance()) {
                        $it = result.getModifiers().iterator();
                        while (it.hasNext()) {
                            if (it.next().getClass().equals(mod.getClass())) {
                                throw new PermErrorException("More than one "
                                        + modifierString
                                        + " found in SPF-Record");
                            }
                        }
                    }

                    result.getModifiers().add(mod);

                } else {
                    // DIRECTIVE
                    $qualifier = termMatcher.group(TERM_STEP_REGEX_QUALIFIER_POS);

                    $mech = lookupAndCreateTerm(termMatcher,
                            TERM_STEP_REGEX_MECHANISM_POS);

                    $result.getDirectives().add(
                            new Directive($qualifier, $mech, $log->getChildLogger(qualifier+"directive")));

                }

            }
        }

        return result;
    }

    /**
     * @param res
     *            the MatchResult
     * @param start
     *            the position where the terms starts
     * @return
     * @throws PermErrorException
     */
    private function lookupAndCreateTerm(Matcher $res, $start) {
        for ($k = start + 1; k < res.groupCount(); $k++) {
            if (res.group(k) != null && k != TERM_STEP_REGEX_QUALIFIER_POS) {
                $c = $matchResultPositions.get(k);
                $subres = new MatcherBasedConfiguration(res, k, c
                        .getMatchSize());
                try {
                    return termsFactory.createTerm(c.getTermDef(), subres);
                } catch (InstantiationException $e) {
                    $e->printStackTrace();
                    // TODO is it ok to use a Runtime for this? Or should we use a PermError here?
                    throw new IllegalStateException("Unexpected error creating term: " + e.getMessage());
                }

            }
        }

        return null;
    }
}