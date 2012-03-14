<?php


namespace PHP_SPF;

class SPF {


    protected $h;
    protected $s;
    protected $l;
    protected $o;
    protected $t;
    protected $d;
    protected $p = null;
    protected $r;

    protected $cache = array();
    protected $defexps;
    protected $exps;
    protected $libspf_local;
    protected $lookups = 0;

    protected $strict;
    protected $timeou;
    protected $querytime; # Default to not using a global check

    protected $default_modifier = true;

    protected $authserv = null; # Only used in A-R header generation tests

    /**
     *
    """A query object keeps the relevant information about a single SPF
    query:

    i: ip address of SMTP client in dotted notation
    s: sender declared in MAIL FROM:<>
    l: local part of sender s
    d: current domain, initially domain part of sender s
    h: EHLO/HELO domain
    v: 'in-addr' for IPv4 clients and 'ip6' for IPv6 clients
    t: current timestamp
    p: SMTP client domain name
    o: domain part of sender s
    r: receiver
    c: pretty ip address (different from i for IPv6)

    This is also, by design, the same variables used in SPF macro
    expansion.

    Also keeps cache: DNS cache.
    """
     *
     * @param unknown_type $i
     * @param unknown_type $s
     * @param unknown_type $h
     * @param unknown_type $local
     * @param unknown_type $receiver
     * @param unknown_type $strict
     * @param unknown_type $timeout
     * @param unknown_type $verbose
     * @param unknown_type $querytime
     */
    public function __construct($i, $s, $h, $local = null, $receiver = null, $strict = true,
        $timeout = self::MAX_PER_LOOKUP_TIME, $verbose = false, $querytime = 0) {

        $this->s = $s;
        $this->h = $h;
        if (!$s && $h) {
            $this->s = 'postmaster@' . $h;
            $this->ident = 'helo';
        } else {
            $this->ident = 'mailfrom';
        }

        $this->o = split_email(s, h);

        $this->t = str(int(time.time()));
        $this->d = $this->o;

        if ($receiver) {
            $this->r = $receiver;
        } else {
            $this->r = 'unknown';
        }

            # Since the cache does not track Time To Live, it is created
            # fresh for each query.  It is important for efficiently using
            # multiple results provided in DNS answers.
        $this->defexps = dict(EXPLANATIONS);
        $this->exps = dict(EXPLANATIONS);
        $this->libspf_local = local;    # local policy

            # strict can be False, True, or 2 (numeric) for harsh
        $this->strict = $strict;
        $this->timeout = $timeout;
        $this->querytime = $querytime; # Default to not using a global check
            # timelimit since this is an RFC 4408 MAY
        if ($querytime > 0) {
            $this->timeout = $querytime;
        }
        $this->timer = 0;
        if ($i) {
            $this->set_ip($i);
        }
        $this->verbose = $verbose;
    }

    public function log($mech, $d, $spf) {
        echo "{$mech}: {$d} \"{$spf}\"";
    }

}