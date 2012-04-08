<?php

namespace PHP_SPF\Executor\FutureSPFResult;

use PHP_SPF\Executor\FutureSPFResult;

/**
 * Listener which will get notified once a {@link FutureSPFResult#isReady()} returns <code>true</code>. So it will not block anymore
 *
 *
 */
interface IFutureSPFResultListener {

    /**
     * Get called once a {@link FutureSPFResult} is ready
     *
     * @param result
     */
    public function onSPFResult(FutureSPFResult $result);
}