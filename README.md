
# MetaDPI for Data Security

> Capture mysql,redis,http,mongodb etc protocol...


## Support List:
- [mysql](#mysql)
- [Redis](#redis)
- [Http](#http)
- [Mongodb](#mongodb)
- Kafka (developing)
- ...

## Demo:
``` bash
$ mdpi en0 mysql
```
## Setup:
- support : `MacOS` `Linux` `Unix`
- not support : `windows`
- If you encounter problems in the `go get` process, try upgrading the go version

### Centos
``` bash
$ yum -y install libpcap-devel
```
### Ubuntu
``` bash
$ apt-get install libpcap-dev
```
### MacOs
``` bash
brew install libpcap
```

### RUN
``` bash
$ make dpi
$ cp -rf $(go env GOPATH)/bin/mdpi /usr/local/bin
$ mdpi --help
```
## Usage:
``` bash
==================================================================================
[Usage]

    mdpi [device] [plug] [plug's params(optional)]

    [Example]
          mdpi en0 redis          Capture redis packet
          mdpi en0 mysql -p 3306  Capture mysql packet

    mdpi --[commend]
         --help "this page"
         --env  "environment variable"
         --list "Plug-in list"
         --ver  "version"
         --dev  "device"
    [Example]
          mdpi --list "show all plug-in"

