TLS test fixtures (never used outside tests): `ca.crt` (a throwaway test CA whose key was
discarded) signed `a.crt`/`a.key` and `b.crt`/`b.key`, both for `dns.test` and `*.dns.test`
(EC P-256, valid for 100 years). `b` stands in for a renewed certificate.
