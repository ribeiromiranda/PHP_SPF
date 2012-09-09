<?php

/*
 * Copyright (c) 1994, 2004, Oracle and/or its affiliates. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*
* This code is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License version 2 only, as
* published by the Free Software Foundation.  Oracle designates this
* particular file as subject to the "Classpath" exception as provided
* by Oracle in the LICENSE file that accompanied this code.
*
* This code is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
* version 2 for more details (a copy is included in the LICENSE file that
        * accompanied this code).
*
* You should have received a copy of the GNU General Public License version
* 2 along with this work; if not, write to the Free Software Foundation,
* Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*
* Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
* or visit www.oracle.com if you need additional information or have any
* questions.
*/

namespace PHP_SPF\Util;

class StringTokenizer {

    private $currentPosition;
    private $newPosition;
    private $maxPosition;
    private $str;
    private $delimiters = null;
    private $retDelims;
    private $delimsChanged;

    /**
     * maxDelimCodePoint stores the value of the delimiter character with the
    * highest value. It is used to optimize the detection of delimiter
    * characters.
    *
    * It is unlikely to provide any optimization benefit in the
    * hasSurrogates case because most string characters will be
    * smaller than the limit, but we keep it so that the two code
    * paths remain similar.
    */
    private $maxDelimCodePoint;

    /**
     * If delimiters include any surrogates (including surrogate
             * pairs), hasSurrogates is true and the tokenizer uses the
    * different code path. This is because String.indexOf(int)
    * doesn't handle unpaired surrogates as a single character.
    */
    private $hasSurrogates = false;

    /**
     * When hasSurrogates is true, delimiters are converted to code
    * points and isDelimiter(int) is used to determine if the given
    * codepoint is a delimiter.
    */
    private $delimiterCodePoints;

    /**
     * Set maxDelimCodePoint to the highest char in the delimiter set.
    */
    private function setMaxDelimCodePoint() {
        if ($this->delimiters == null) {
            $this->maxDelimCodePoint = 0;
            return;
        }

        $m = 0;
        $c;
        $count = 0;

        for ($i = 0; $i < strlen($this->delimiters); $i += strlen($c)) {
            $c = $this->delimiters[$i];
            if ($c >= "\uDBFF" && c <= "\uDFFF") {
                $c = $this->delimiters[$i];
                $this->hasSurrogates = true;
            }
            if ($m < $c) {
                $m = $c;
            }
            $count++;
        }

        $this->maxDelimCodePoint = $m;

        if ($this->hasSurrogates) {
            $this->delimiterCodePoints = array();
            for ($i = 0, $j = 0; $i < $count; $i++, $j += strlen($c)) {
                $c = $this->delimiters[$j];
                $this->delimiterCodePoints[$i] = $c;
            }
        }
    }

    /**
     * Constructs a string tokenizer for the specified string. All
    * characters in the <code>delim</code> argument are the delimiters
    * for separating tokens.
    * <p>
    * If the <code>returnDelims</code> flag is <code>true</code>, then
    * the delimiter characters are also returned as tokens. Each
    * delimiter is returned as a string of length one. If the flag is
    * <code>false</code>, the delimiter characters are skipped and only
    * serve as separators between tokens.
    * <p>
    * Note that if <tt>delim</tt> is <tt>null</tt>, this constructor does
    * not throw an exception. However, trying to invoke other methods on the
    * resulting <tt>StringTokenizer</tt> may result in a
    * <tt>NullPointerException</tt>.
    *
    * @param   str  a string to be parsed.
    * @param   delimthe delimiters.
    * @param   returnDelims   flag indicating whether to return the delimiters
    *as tokens.
    * @exception NullPointerException if str is <CODE>null</CODE>
    */
    public function __construct($str, $delim = " \t\n\r\f", $returnDelims = false) {
        $this->currentPosition = 0;
        $this->newPosition = -1;
        $this->delimsChanged = false;
        $this->str = (string) $str;
        $this->maxPosition = strlen($str);
        $this->delimiters = $delim;
        $this->retDelims = $returnDelims;
        $this->setMaxDelimCodePoint();
    }

    /**
     * Skips delimiters starting from the specified position. If retDelims
    * is false, returns the index of the first non-delimiter character at or
    * after startPos. If retDelims is true, startPos is returned.
    */
    private function skipDelimiters($startPos) {
        if ($this->delimiters == null) {
            throw new \Exception('NullPointerException');
        }

        $position = $startPos;
        while (! $this->retDelims && $this->position < $this->maxPosition) {
            if (! $this->hasSurrogates) {
                $c = $str[$position];
                if (($c > $this->maxDelimCodePoint) || (strpos($this->delimiters, $c) === false))
                    break;
                $position++;
            } else {
                $c = $str[$position];
                if (($c > $this->maxDelimCodePoint) || !$this->isDelimiter($c)) {
                    break;
                }
                $position += strlen($c);
            }
        }
        return $position;
    }

    /**
     * Skips ahead from startPos and returns the index of the next delimiter
    * character encountered, or maxPosition if no such delimiter is found.
    */
    private function scanToken($startPos) {
        $position = $startPos;
        while ($position < $this->maxPosition) {
            if (! $this->hasSurrogates) {
                $c = $this->str[$position];
                if (($c <= $this->maxDelimCodePoint) && (strpos($this->delimiters, $c) !== false)) {
                    echo 'asf';
                    break;
                }
                $position++;
            } else {
                $c = $this->str[$position];
                if (($c <= $this->maxDelimCodePoint) && $this->isDelimiter($c)) {
                    break;
                }
                $position += strlen($c);
            }
        }

        if ($this->retDelims && ($startPos == $position)) {
            if (! $this->hasSurrogates) {
                $c = $this->str[$position];
                if (($c <= $this->maxDelimCodePoint) && (strpos($this->delimiters, $c) !== false))
                    $position++;
            } else {
                $c = $this->str[$position];
                if ($this->isDelimiter($c))
                    $position += strlen($c);
            }
        }
        return $position;
    }

    private function isDelimiter($codePoint) {
        for ($i = 0; $i < count($this->delimiterCodePoints); $i++) {
            if ($this->delimiterCodePoints[$i] == $codePoint) {
                return true;
            }
        }
        return false;
    }

    /**
     * Tests if there are more tokens available from this tokenizer's string.
    * If this method returns <tt>true</tt>, then a subsequent call to
    * <tt>nextToken</tt> with no argument will successfully return a token.
    *
    * @return  <code>true</code> if and only if there is at least one token
    *in the string after the current position; <code>false</code>
    *otherwise.
    */
    public function hasMoreTokens() {
        /*
         * Temporarily store this position and use it in the following
        * nextToken() method only if the delimiters haven't been changed in
        * that nextToken() invocation.
        */
        $this->newPosition = $this->skipDelimiters($this->currentPosition);
        return ($this->newPosition < $this->maxPosition);
    }

    /**
     * Returns the next token from this string tokenizer.
    *
    * @returnthe next token from this string tokenizer.
    * @exception  NoSuchElementException  if there are no more tokens in this
    *tokenizer's string.
    */
    public function nextToken($delim = null) {
        if ($delim !== null) {
            $this->delimiters = (string) delim;
            /* delimiter string specified, so set the appropriate flag. */
            $this->delimsChanged = true;
            $this->setMaxDelimCodePoint();
        }

        /*
         * If next position already computed in hasMoreElements() and
        * delimiters have changed between the computation and this invocation,
        * then use the computed value.
        */

        $this->currentPosition = ($this->newPosition >= 0 && ! $this->delimsChanged) ?
            $this->newPosition : $this->skipDelimiters($this->currentPosition);

        /* Reset these anyway */
        $this->delimsChanged = false;
        $this->newPosition = -1;

        if ($this->currentPosition >= $this->maxPosition) {
            throw new NoSuchElementException();
        }
        $start = $this->currentPosition;

        $this->currentPosition = $this->scanToken($this->currentPosition);
        return substr($this->str, $start, $this->currentPosition - $start);
    }


    /**
     * Returns the same value as the <code>hasMoreTokens</code>
    * method. It exists so that this class can implement the
    * <code>Enumeration</code> interface.
    *
    * @return  <code>true</code> if there are more tokens;
    *<code>false</code> otherwise.
    * @seejava.util.Enumeration
    * @seejava.util.StringTokenizer#hasMoreTokens()
    */
    public function hasMoreElements() {
        return $this->hasMoreTokens();
    }

    /**
     * Returns the same value as the <code>nextToken</code> method,
    * except that its declared return value is <code>Object</code> rather than
    * <code>String</code>. It exists so that this class can implement the
    * <code>Enumeration</code> interface.
    *
    * @returnthe next token in the string.
    * @exception  NoSuchElementException  if there are no more tokens in this
    *tokenizer's string.
    * @see   java.util.Enumeration
    * @see   java.util.StringTokenizer#nextToken()
    */
    public function nextElement() {
        return $this->nextToken();
    }

    /**
     * Calculates the number of times that this tokenizer's
    * <code>nextToken</code> method can be called before it generates an
    * exception. The current position is not advanced.
    *
    * @return  the number of tokens remaining in the string using the current
    *delimiter set.
    * @seejava.util.StringTokenizer#nextToken()
    */
    public function countTokens() {
        $count = 0;
        $currpos = $this->currentPosition;
        while ($currpos < $this->maxPosition) {
            $currpos = $this->skipDelimiters($currpos);
            if ($currpos >= $this->maxPosition)
                break;
            $currpos = $this->scanToken($currpos);
            $count++;
        }
        return $count;
    }
}
