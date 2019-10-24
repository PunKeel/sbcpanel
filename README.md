# SafeBrowsing + cPanel

This standalone binary checks the [Google Safe Browsing API][sb-api] against the
list of domains managed by the local cpanel install. If malevolent domains are
found, they will be reported.

The `mail_alert_safe_database.sh` script will automatically send an email if
such domains are found.


The Safe Browsing database is fetched using the [Update API][update-api], and requires a key to use.


[sb-api]: https://safebrowsing.google.com/
[update-api]: https://developers.google.com/safe-browsing/v4/update-api
