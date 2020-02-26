# dnsfilter
Idea of dnsfilter partially comes from [shdns] but with custom rule support AND that one iplist can have both ipv4 and ipv6 network blocks simultaneously.

Filtering rule supports domain name, server from which the answer came and the iplist that the result belongs to.

TARGET option can be ACCEPT, DROP or DELAY (you need specify the duration used to delay the result). (The earliest coming result will be sent back to the client and the later ones will be ignored)

[shdns]: https://github.com/domosekai/shdns
