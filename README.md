# Gentoo tools #

Random utilities I made for managing my Gentoo systems.
Most of these can be invoked with -h or --help to show how to use them.

## kernel-check.rb ##

Check your kernel config for compatibility with packages in the portage tree.

## god.openrc ##

Put this script in /etc/init.d/god, then create symlinks like those for /etc/init.d/net.* and corresponding files in /etc/conf.d/.
Example:

/etc/conf.d/god.gitlab:
```
GOD=/usr/local/bin/god
RUBY=/usr/bin/ruby
GOD_CONF=/etc/god/gitlab.conf
PORT=17166
LOG=/var/log/god-gitlab.log
PIDFILE=/run/god-gitlab.pid
rc_need="postgresql-9.3"
```

GOD_CONF is a ruby file loaded by [god](http://godrb.com/)
