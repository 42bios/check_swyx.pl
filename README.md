# check_swyx.pl

Nagios/Icinga plugin to monitor Swyx call counters via SNMP.

## Features

- Reads total calls
- Reads active internal calls
- Reads active external calls
- Nagios-compatible output with perfdata

## Requirements

- Perl 5.10+
- `Net::SNMP`
- Nagios/Icinga `utils.pm`

## Usage

```bash
./check_swyx.pl -H <host> -C <community>
```

SNMPv3 example:

```bash
./check_swyx.pl -H <host> -v 3 -U <username> -A <authpass> -a SHA1 -X <privpass> -L authPriv
```

## Output

Perfdata fields:

- `total_calls`
- `active_exca`
- `active_inca`

Exit codes:

- `0` OK
- `1` WARNING
- `2` CRITICAL
- `3` UNKNOWN

## Notes

The repository includes the original script (`check_swyx.pl`) and an optional modernized variant (`check_swyx.v2.pl`) for simpler maintenance.

## License

GNU General Public License v2.0 (see source header).