# NAME

**certspotter-metrics** - Output Prometheus metrics about certspotter's operation

# SYNOPSIS

**certspotter-metrics** [`-state_dir` *PATH*]

# DESCRIPTION

**certspotter-metrics** reads a certspotter state directory and writes
Prometheus metrics, in the Prometheus text exposition format, about
certspotter's progress monitoring each Certificate Transparency log.
Metrics are written to standard output.

The intended use is to run **certspotter-metrics** periodically (e.g., from
cron) and expose its output to Prometheus, for example with the
prometheus-node-exporter(1) textfile collector.

**certspotter-metrics** only reads the state directory; it never modifies it.
It is safe to run while certspotter is running, and it does not require
certspotter to be running.

Metrics are output for every log for which certspotter has a state directory
(`$STATE_DIR/logs/LOG_ID`, where `LOG_ID` is the base64url-encoded log ID).
A log has a state directory once certspotter has started monitoring it.
The `log_id` label on each metric is the standard base64 encoding (with
padding) of the 32-byte log ID defined by RFC 6962. See <https://sslmate.com/app/ctlogs>
for a list of human-friendly names for each log ID.

**certspotter-metrics** is experimental, and the metrics may change in a future release.

# OPTIONS

-state\_dir *PATH*

:   Directory where certspotter stores state. Defaults to
    `$CERTSPOTTER_STATE_DIR` if set, or `~/.certspotter` otherwise.
    This should be the same directory used by **certspotter(8)**.

-version

:   Print version information and exit.

# METRICS

All metrics are gauges with a `log_id` label identifying the log the
metric pertains to.  If a metric does not pertain to a log (because
certspotter has not stored the relevant state for the log yet), the log
does not have a sample for that metric.

certspotter\_log\_max\_sth\_size

:   Tree size of the largest signed tree head (STH) certspotter has observed
    from the log; in other words, the number of entries in the log.  Absent
    if certspotter has not yet downloaded an STH from the log.

certspotter\_log\_max\_sth\_timestamp

:   Timestamp, in milliseconds since the Epoch, of the STH reported by
    certspotter\_log\_max\_sth\_size.

certspotter\_log\_download\_position

:   Number of entries certspotter has downloaded from the log, including
    entries that have not yet been verified.

certspotter\_log\_verified\_position

:   Number of entries certspotter has downloaded from the log and verified
    against an STH.

certspotter\_log\_verified\_sth\_timestamp

:   Timestamp, in milliseconds since the Epoch, of the most recent STH
    certspotter has verified for the log. Absent if certspotter has not
    verified an STH for the log. The size of this STH is equal to
    certspotter\_log\_verified\_position.

certspotter\_log\_unverified\_sths

:   Number of unverified STHs certspotter is currently storing for the log.

certspotter\_log\_malformed\_entries

:   Number of malformed entries certspotter has recorded for the log.
    certspotter records an entry as malformed when it cannot parse the
    entry. See **certspotter(8)** for more information.

certspotter\_log\_health\_check\_failures

:   Number of failed health checks certspotter has recorded for the log.
    See **certspotter(8)** for information about health checks.

# EXAMPLES

crontab(5) entry that exposes metrics to the node\_exporter textfile collector
every five minutes (writing to a temporary file and renaming it
ensures that node\_exporter never reads a partially-written file):

    */5 * * * * root certspotter-metrics > /var/lib/node_exporter/certspotter.prom.tmp && mv /var/lib/node_exporter/certspotter.prom.tmp /var/lib/node_exporter/certspotter.prom

Prometheus query to determine download backlog (number entries in the
log that haven't been downloaded yet):

    certspotter_log_max_sth_size-certspotter_log_download_position

# ENVIRONMENT

`CERTSPOTTER_STATE_DIR`

:   Directory for storing state. Overridden by `-state_dir`. Defaults to
    `~/.certspotter`. This should be the same directory used by
    **certspotter(8)**.

`STATE_DIRECTORY`

:   Directory for storing state, if set and certspotter-metrics is running
    under systemd.

# EXIT STATUS

**certspotter-metrics** exits with status 0 on success, 1 on error, or 2 on
invalid usage.

# SEE ALSO

certspotter(8)
