wai-middleware-ip-block: Block incoming requests by CIDR IP ranges.

This is a WAI middleware for blocking incoming requests by IP range.

Example usage goes here

It uses a simple configuration format. The first line is either "default allow"
or "default deny". Every line after that is of the form "2.4.0.0/16 deny". The
bitmask is optional. Example:
```
default deny
67.189.87.218 allow
20.20.0.0/16 allow
20.20.1.0/24 deny
```

Rules are prioritized by specificity.

**DO NOT USE THIS FOR STRONG SECURITY**. I wrote this in a few hours and it
almost certainly has bugs. Use a real, mature, firewall if at all possible.
