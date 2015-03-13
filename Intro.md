# Introduction #

SnortUnified.pm is a perl module to work with Snort unified files, both unified and unified2. It is really easy to work with and in the most basic form can handle a unified file with a few lines of perl.

```
use SnortUnified(qw(:ALL));
use Data::Dumper;

$UF_Data = openSnortUnified(shift);
while ( $record = readSnortUnifiedRecord() ) {
   print Dumper($record);
}
closeSnortUnified();
```

Much more can also be done, check out the samples in the src distro or in the svn browser.

# Details #

SnortUnified is a work in progress. It is working in several production environments processing live data into databases, hashing events for integrity, comparing and automating analysis etc.

I have recently added the capability to register "handlers" and "qualifiers". The intent is to make it easy to filter, modify, enhance, or eliminate information you are not concerned with post processing. EG: Rather than try to use the snort engine in real time to eliminate false positives or modify rules to increase a priority etc, you can easily do it in the post processing loops and let snort focus on detecting the things you are concerned with. Some samples of use can be found in uf\_csv\_handler.pl in the samples directory.

The code is commented but the samples are your best place to look for how to use it. If you have questions, comments, needs, features, etc you can mail me at jasonb [at](at.md) snort [dot](dot.md) org or generally find me in #snort as vrybdpkt.

I am looking for samples of unified2 files with events generated on an ipv6 network with snort running in ipv6 mode (of course) so that I can create the unified2 ipv6 handling code and modify the db schema to support it.

Hope you find it useful, enjoy.