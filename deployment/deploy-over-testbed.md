# Deploy NDNCERT v0.3 over testbed

Three steps:

* Deploy root CA `/ndn` by setting up the NDNCERT CA configuration and run NDNCERT service
* At each site server, run NDNCERT client command line tools to get certificate issued by `/ndn` using the PIN code challenge, set up the CA configuration and run NDNCERT CA service.
* Update the `/ndn`'s configuration file and restart the service.

## Step 1

```bash
sudo ./deploy.sh
```

## Step 2

On each site:

```bash
sudo ./deploy.sh
```

```bash
ndnsec-dump-certificate XXX
```

## Step 3
Stop NDNCERT CA
```bash
sudo systemctl stop ndncert-ca
```

Update CA configuation file ``ca.conf`` with the output certificate just get:
Inside ``ca.conf``, site CAs are configured by sections below:

```
  "redirect-to":
  [
    {
      "ca-prefix": "/example/site1",
      "certificate": "Bv0CvQcwCAdleGFtcGxlCAVzaXRlMQgDS0VZCAh6af3szF4QZwgEc2VsZggJ/QAAAXT6+NCKFAkYAQIZBAA27oAV/QEmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA43hjZT0HUFFJcqwj8lZnd/vg0NrzqvZ4jhsq1c+nv6J3Huc9Uq5jRZwhFQ8nBWT3CeFScO5FUQfNXDIDncZ4vYPFEnockOFVtvmKQ/ELwReUvjH80d1NPGrIVrD0lMRpv2sFr6NW2p7aw6bCSj3OJq7H/+QHDkAryssMZyHwTbPzMZHyYKmxR68CyCCpvLlgp8tYFT+cCrOc3lz3nROK3VFR+apgwubpvl8nbKD10QLcgMHSkLoLEy/Ksq8OH7MQhUEZDjLk/zL9baZ7MiKXtdUZCNTZk13y5z+4aT4TqumLB+obiDXmv6JAi+CkYIMf2ck2IvMV6JgxxIlv3+Ke2wIDAQABFlAbAQEcIQcfCAdleGFtcGxlCAVzaXRlMQgDS0VZCAh6af3szF4QZ/0A/Sb9AP4PMTk3MDAxMDFUMDAwMDAw/QD/DzIwNDAwOTMwVDIyNTQwNBf9AQCCSXOqUX40mAIdKCa+nnfJCGZbNowQPJp5kDnyolj5/Ek9x8czyLcX58xTsgYtiPmL5DxMgkRujRJu9INm0pUJIJRlsqhDOwsrxIjlSgwy5AeexYe7SM3rSwljLxTR4MfBw26pym9iYt8ovHXotCDE+etyKwHzXoOgzxORoPXqBGwobNOPnhDfpzHQBFOrPd8qqLAGioNNk/k2U/uyvBbLoZS4ScNVJpfbcvcmzu/A8H/VyT4234LrlISL9WpWlO8J18yzhrXchFR0ZwCoYge5rLZ4vsQhY1WqXHCsYnRa3la6Txz44EWYEBpmk12qnkPt06KAPvQ82N1CICxFb9NY"
    }
  ]
```

Replace the ``ca-prefix`` and ``certificate`` in this example section with the ones in your case.

Start NDNCERT CA
```bash
sudo systemctl start ndncert-ca
```
