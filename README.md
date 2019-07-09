List sexpiration time of soon-to-be expired ssl certificates of all
given domains like:

   ./certificate_watcher.py mdk.fr python.org duckduckgo.com
   mdk.fr expire in 2 days

The list of domains can be given as a file, using the `-f` or
`--from-file` argument. In this file, list each domains, one per
line. Black lines and lines starting with '#' are ignored.

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
```

Usefull as a daily cron, typically like this:

   certificate_watcher -f /home/you/.certificate_watcher

Or if you use IRC:

   certificate_watcher -f /home/you/.certificate_watcher | irk '#your_project_channel' -
