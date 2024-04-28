Lists expiration time of soon-to-be expired ssl certificates of all
given domains like:

   ./certificate_watcher.py mdk.fr python.org duckduckgo.com
   mdk.fr:Certificate expires in 2 days

The list of domains can be given as a file, using the `-f` or
`--from-file` argument. In this file, list each domains, one per
line. Blank lines and lines starting with '#' are ignored.

An optional port can be given using the usual syntax `host:port`, for
example `imap.protonmail.com:443`.

An optional IP address can be given using an `@`, this is usefull to
poke multiple backends like:

```
./certificate_watcher.py example.com@10.1.0.1 example.com@10.1.0.2
```

A domain to be resolved can be used in this field to, like:

```
./certificate_watcher.py example.com@backend1.example.com example.com@backend2.example.com
```

The `:port` must appear before `@host`, like:
`example.com:443@fe80::5c5b:9f32:13b1:29c3`.

Exemple domain file:

```
# Our project
example.com
www.example.com
mail.example.com
dev.example.com
demo.example.com
testing.example.com
git.example.com

# Friends
duckduckgo.com
mamot.fr
protonmail.com

# IMAP
imap.protonmail.com:993
```

Usefull as a daily cron, typically like this:

```
certificate_watcher -f /home/you/.certificate_watcher
```

Or if you use IRC:

```
certificate_watcher -f /home/you/.certificate_watcher | irk '#your_project_channel' -
```
