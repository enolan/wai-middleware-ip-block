# wai-middleware-ip-block: Block incoming requests by CIDR IP ranges.

This is a WAI middleware for blocking incoming requests by IP range.

See Haddock for documentation, including the YAML configuration format.

To use this with the Yesod scaffold, modify the `makeApplication` function
in `Application.hs` like so:
```
makeApplication :: App -> IO Application
makeApplication foundation = do
    logWare <- makeLogWare foundation
    -- Create the WAI application and apply middlewares
    appPlain <- toWaiAppPlain foundation
    ipBlock <- ipBlockMiddlewareFromFileEnv "IP_BLOCK_CFG" basicDenyResponse
    return $ ipBlock $ logWare $ defaultMiddlewaresNoLogging appPlain
```

When your server launches, it'll look for an environment variable
`IP_BLOCK_CFG`. That should have the path to a YAML formatted configuration
file. The details of that format are in the Haddock.

**Don't rely on this for security**. I wrote this so I could put a site up on
the internet before I was ready to make it public. IP based blocking is in
general a weak measure and this package in particular has undergone relatively
little testing, none of it adversarial.
