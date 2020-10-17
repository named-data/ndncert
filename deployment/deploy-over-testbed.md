# Deploy NDNCERT v0.3 over testbed

Three steps:

* Deploy root CA `/ndn` by setting up the NDNCERT CA configuration and run NDNCERT service
* At each site server, run NDNCERT client command line tools to get certificate issued by `/ndn` using the PIN code challenge, set up the CA configuration and run NDNCERT CA service.
* Update the `/ndn`'s configuration file and restart the service.

## Step 1

```bash
sudo ./step1-root-ca.sh
```

## Step 2

On each site:

```bash
ndncert-client
```

```bash
sudo ./step-2-site-ca.sh
```

```bash
ndnsec-dump-certificate XXX
```

## Step 3

stop service

update config file

restart service
